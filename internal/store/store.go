// Package store reads and writes a session's exchanges.
//
// A session keeps its exchanges in segments: the current one,
// exchanges.ndjson, and older ones rotated out of it, exchanges.NNNNNN.ndjson,
// numbered in the order they were written. Each segment has an index beside
// it (exchanges.idx, exchanges.NNNNNN.idx), one line per exchange: where its
// record is and what its summary line says. Reading one exchange, or listing
// a session, then costs the index and not the whole session.
//
// The index only speeds things up. A missing or short index -- a v4.0
// session, or a process that died between writing a record and its index
// line -- is rebuilt from the records.
package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/hxddh/https-traffic-inspector/v5/internal/body"
	"github.com/hxddh/https-traffic-inspector/v5/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v5/internal/textsafe"
)

// File names.
const (
	Current      = "exchanges.ndjson"
	CurrentIndex = "exchanges.idx"
)

var segName = regexp.MustCompile(`^exchanges\.(\d{6})\.ndjson$`)

func segFile(n int) string  { return fmt.Sprintf("exchanges.%06d.ndjson", n) }
func segIndex(n int) string { return fmt.Sprintf("exchanges.%06d.idx", n) }

// Entry is one exchange in the index. An index line holds its fields
// separated by tabs, in this order, with tabs, newlines and backslashes in
// strings escaped: decoding it is a split, not a JSON parse, so even a large
// session's index loads in a few milliseconds.
type Entry struct {
	ID      int     `json:"id"`
	Off     int64   `json:"off"`
	Len     int     `json:"len"`
	Method  string  `json:"m"`
	URL     string  `json:"u"` // as recorded; never shown
	Status  int     `json:"s,omitempty"`
	ErrKind string  `json:"e,omitempty"`
	WS      bool    `json:"ws,omitempty"`
	DurMs   float64 `json:"d"`
	Rule    string  `json:"r,omitempty"`
	Time    string  `json:"t"`
	Summary string  `json:"l"` // the summary line, credentials masked

	seg int // index into Store.segs
}

// Light is the exchange as far as the index knows it: enough to filter,
// count and summarise.
func (e Entry) Light() *exchange.Exchange {
	x := &exchange.Exchange{ID: e.ID, Kind: "http", Method: e.Method, URL: e.URL, Status: e.Status, DurationMs: e.DurMs, Rule: e.Rule, Time: e.Time}
	switch {
	case e.ErrKind == "tunnel":
		x.Kind = "tunnel"
	case strings.HasPrefix(e.ErrKind, "~"):
		x.AppError = &exchange.Error{Kind: e.ErrKind[1:]}
	case e.ErrKind != "":
		x.Error = &exchange.Error{Kind: e.ErrKind}
	}
	if e.WS {
		x.Kind = "websocket"
		x.WebSocket = &exchange.WebSocket{}
	}
	return x
}

// SummaryOf is an exchange's summary line, with credentials masked and the
// error hint of a 4xx/5xx response found in its body.
func SummaryOf(e *exchange.Exchange) string {
	c := *e
	c.URL = textsafe.MaskURL(e.URL)
	if c.Hint == "" && e.Status >= 400 && e.Response != nil {
		c.Hint = HintOf(e.Response)
	}
	return c.SummaryLine()
}

// HintOf finds the error description in a response body.
func HintOf(m *exchange.Message) string {
	b := m.Body
	if b == nil {
		return ""
	}
	if b.Raw != nil {
		raw, err := b.Raw.Bytes()
		if err != nil {
			return ""
		}
		_, hint := body.Render(m.Headers.HTTP(), raw, b.Raw.Truncated, b.Size, 1)
		return hint
	}
	if b.JSON != nil {
		return body.ErrorHint(b.JSON)
	}
	return ""
}

func entryOf(e *exchange.Exchange, off int64, n int) Entry {
	en := Entry{ID: e.ID, Off: off, Len: n, Method: e.Method, URL: e.URL, Status: e.Status,
		WS: e.WebSocket != nil, DurMs: e.DurationMs, Rule: e.Rule, Time: e.Time, Summary: SummaryOf(e)}
	switch {
	case e.Kind == "tunnel":
		en.ErrKind = "tunnel"
	case e.Error != nil:
		en.ErrKind = e.Error.Kind
	case e.AppError != nil:
		en.ErrKind = "~" + e.AppError.Kind
	case e.GRPC != nil && e.GRPC.Code != 0:
		en.ErrKind = "~grpc"
	}
	return en
}

// ---- reading ----

type segment struct {
	path  string
	index string // "" for a plain file
	f     *os.File
	mu    sync.Mutex
}

// Store is an open session, or an exchanges file.
type Store struct {
	Dir     string // "" for a plain file
	Entries []Entry
	segs    []*segment
	maxID   int
}

// Segments lists a session directory's segment files, oldest first, the
// current one last.
func Segments(dir string) ([]string, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var nums []int
	for _, d := range des {
		if m := segName.FindStringSubmatch(d.Name()); m != nil {
			n, _ := strconv.Atoi(m[1])
			nums = append(nums, n)
		}
	}
	sort.Ints(nums)
	var out []string
	for _, n := range nums {
		out = append(out, filepath.Join(dir, segFile(n)))
	}
	if _, err := os.Stat(filepath.Join(dir, Current)); err == nil {
		out = append(out, filepath.Join(dir, Current))
	}
	return out, nil
}

func indexFor(seg string) string {
	if filepath.Base(seg) == Current {
		return filepath.Join(filepath.Dir(seg), CurrentIndex)
	}
	return seg[:len(seg)-len(".ndjson")] + ".idx"
}

// Open opens a session directory, or a single exchanges file. persist lets
// it write an index it had to rebuild; a reader of a running session must
// not, since the session's own process is writing that index.
func Open(path string, persist bool) (*Store, error) {
	return OpenOnly(path, persist, nil)
}

// OpenOnly is Open keeping only the entries whose id want accepts (all when
// want is nil): looking up one exchange then decodes one index line.
func OpenOnly(path string, persist bool, want func(id int) bool) (*Store, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	s := &Store{}
	var files []string
	if fi.IsDir() {
		s.Dir = path
		if files, err = Segments(path); err != nil {
			return nil, err
		}
	} else if filepath.Base(path) == Current {
		s.Dir = filepath.Dir(path)
		if files, err = Segments(s.Dir); err != nil {
			return nil, err
		}
	} else {
		files = []string{path}
	}
	for i, p := range files {
		f, err := os.Open(p)
		if err != nil {
			s.Close()
			return nil, err
		}
		sg := &segment{path: p, f: f}
		if s.Dir != "" {
			sg.index = indexFor(p)
		}
		s.segs = append(s.segs, sg)
		entries, err := loadSegment(sg, persist, want, &s.maxID)
		if err != nil {
			s.Close()
			return nil, err
		}
		for j := range entries {
			entries[j].seg = i
		}
		s.Entries = append(s.Entries, entries...)
	}
	return s, nil
}

// loadSegment reads a segment's index, and indexes the records past its end.
func loadSegment(sg *segment, persist bool, want func(int) bool, maxID *int) ([]Entry, error) {
	var entries []Entry
	var end int64
	keep := func(e Entry) {
		*maxID = max(*maxID, e.ID)
		if want == nil || want(e.ID) {
			entries = append(entries, e)
		}
	}
	if sg.index != "" {
		if b, err := os.ReadFile(sg.index); err == nil {
			// A last line without its newline was torn mid-write: leave it
			// out, and index its record again from the segment.
			if i := bytes.LastIndexByte(b, '\n'); i < len(b)-1 {
				b = b[:i+1]
			}
			for _, line := range bytes.Split(b, []byte{'\n'}) {
				if len(bytes.TrimSpace(line)) == 0 {
					continue
				}
				if want != nil {
					id, off, n, ok := parseHead(line)
					if !ok {
						break
					}
					*maxID = max(*maxID, id)
					end = off + int64(n)
					if !want(id) {
						continue
					}
				}
				e, ok := parseEntry(line)
				if !ok {
					break // a torn last line: index the rest from the records
				}
				keep(e)
				end = e.Off + int64(e.Len)
			}
		}
	}
	fi, err := sg.f.Stat()
	if err != nil {
		return nil, err
	}
	if end > fi.Size() {
		// The index describes a different file: start again.
		entries, end = nil, 0
	}
	if end == fi.Size() {
		return entries, nil
	}
	more, err := scan(sg.f, end, fi.Size())
	if err != nil {
		return nil, err
	}
	if persist && sg.index != "" && len(more) > 0 && want == nil {
		writeIndex(sg.index, entries, more) //nolint:errcheck // only an optimisation
	}
	for _, e := range more {
		keep(e)
	}
	return entries, nil
}

// scan indexes the complete records between from and to.
func scan(f *os.File, from, to int64) ([]Entry, error) {
	r := bufio.NewReaderSize(io.NewSectionReader(f, from, to-from), 256*1024)
	var out []Entry
	off := from
	for {
		line, err := r.ReadBytes('\n')
		complete := len(line) > 0 && line[len(line)-1] == '\n'
		// A last line without its newline is indexed when it is a whole
		// record -- a file written without one -- and left for later when
		// it is a record still being written, which does not parse.
		if len(line) > 0 && (complete || errors.Is(err, io.EOF)) {
			if t := bytes.TrimSpace(line); len(t) > 0 {
				var e exchange.Exchange
				if json.Unmarshal(t, &e) == nil && exchange.SupportedVersion(e.V) {
					out = append(out, entryOf(&e, off, len(line)))
				} else if !complete {
					return out, nil
				}
			}
			off += int64(len(line))
		}
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func writeIndex(path string, keep, more []Entry) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, l := range [][]Entry{keep, more} {
		for i := range l {
			w.Write(l[i].appendLine(nil)) //nolint:errcheck
		}
	}
	if err := w.Flush(); err != nil {
		f.Close() //nolint:errcheck
		return err
	}
	return f.Close()
}

// Read reads one exchange's record.
func (s *Store) Read(e Entry) (*exchange.Exchange, error) {
	sg := s.segs[e.seg]
	buf := make([]byte, e.Len)
	sg.mu.Lock()
	_, err := sg.f.ReadAt(buf, e.Off)
	sg.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sg.path, err)
	}
	var x exchange.Exchange
	if err := json.Unmarshal(bytes.TrimSpace(buf), &x); err != nil {
		return nil, fmt.Errorf("%s at %d: %w", sg.path, e.Off, err)
	}
	return &x, nil
}

// Find returns the entries with this id: one in a v4.1 session, possibly
// more in an older one written with --append.
func (s *Store) Find(id int) []Entry {
	var out []Entry
	for _, e := range s.Entries {
		if e.ID == id {
			out = append(out, e)
		}
	}
	return out
}

// MaxID is the highest id in the store, including entries OpenOnly skipped.
func (s *Store) MaxID() int { return s.maxID }

// Lean drops the entries' summaries and URLs, for a caller that only reads
// records back: two large sessions' indexes then cost little.
func (s *Store) Lean() {
	for i := range s.Entries {
		s.Entries[i].Summary, s.Entries[i].URL = "", ""
	}
}

// Each reads every exchange in order, stopping when fn returns false.
func (s *Store) Each(fn func(*exchange.Exchange) bool) error {
	for _, e := range s.Entries {
		x, err := s.Read(e)
		if err != nil {
			return err
		}
		if !fn(x) {
			return nil
		}
	}
	return nil
}

// CurrentPath is the segment new exchanges are appended to, "" for a plain file.
func (s *Store) CurrentPath() string {
	if s.Dir == "" {
		return ""
	}
	return filepath.Join(s.Dir, Current)
}

// Close closes the segment files.
func (s *Store) Close() {
	for _, sg := range s.segs {
		sg.f.Close() //nolint:errcheck
	}
}

// ---- writing ----

// Writer appends exchanges to a session.
type Writer struct {
	dir     string
	max     int64 // total size kept; 0 keeps everything
	segMax  int64
	f, idx  *os.File
	size    int64
	lastSeg int
	nextID  int
	retryAt int64 // after a rotation that could not rename, try again at this size
	// Dropped counts segments removed to stay under max.
	Dropped int
	buf     bytes.Buffer
}

// minSegment bounds how small a segment gets, however small the limit.
const minSegment = 1 << 20

// OpenWriter opens dir's current segment for appending. Its index is
// brought up to date first, so ids continue from the highest one there.
func OpenWriter(dir string, maxSize int64) (*Writer, error) {
	st, err := Open(dir, true)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	w := &Writer{dir: dir, max: maxSize, nextID: 1}
	if st != nil {
		w.nextID = st.MaxID() + 1
		st.Close()
	}
	if maxSize > 0 {
		w.segMax = max(maxSize/4, minSegment)
	}
	segs, _ := Segments(dir)
	for _, p := range segs {
		if m := segName.FindStringSubmatch(filepath.Base(p)); m != nil {
			n, _ := strconv.Atoi(m[1])
			w.lastSeg = max(w.lastSeg, n)
		}
	}
	if err := w.openCurrent(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) openCurrent() error {
	f, err := os.OpenFile(filepath.Join(w.dir, Current), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	idx, err := os.OpenFile(filepath.Join(w.dir, CurrentIndex), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		f.Close() //nolint:errcheck
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()   //nolint:errcheck
		idx.Close() //nolint:errcheck
		return err
	}
	w.f, w.idx, w.size = f, idx, fi.Size()
	return nil
}

// NextID is the id the session's next exchange should have.
func (w *Writer) NextID() int { return w.nextID }

// Write appends one exchange. Callers serialise calls.
func (w *Writer) Write(e *exchange.Exchange) error {
	w.buf.Reset()
	enc := json.NewEncoder(&w.buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return err
	}
	n := w.buf.Len()
	if _, err := w.f.Write(w.buf.Bytes()); err != nil {
		return err
	}
	en := entryOf(e, w.size, n)
	w.size += int64(n)
	if _, err := w.idx.Write(en.appendLine(nil)); err != nil {
		return err
	}
	if w.segMax > 0 && w.size >= w.segMax && w.size >= w.retryAt {
		return w.rotate()
	}
	return nil
}

// rotate closes the current segment under the next number, opens a new one,
// and removes the oldest segments while the session is over its limit.
//
// On Windows a file another process has open -- httpmon ui or query
// --follow reading the session -- cannot be renamed or removed. Then the
// current segment keeps growing for now, and rotation is tried again later;
// a segment that cannot be removed yet is removed by a later rotation.
func (w *Writer) rotate() error {
	w.f.Close()   //nolint:errcheck
	w.idx.Close() //nolint:errcheck
	next := w.lastSeg + 1
	renamed := os.Rename(filepath.Join(w.dir, Current), filepath.Join(w.dir, segFile(next))) == nil
	if renamed {
		w.lastSeg = next
		if err := os.Rename(filepath.Join(w.dir, CurrentIndex), filepath.Join(w.dir, segIndex(next))); err != nil {
			// The rotated segment is indexed again when read.
			os.Remove(filepath.Join(w.dir, CurrentIndex)) //nolint:errcheck
		}
	}
	if err := w.openCurrent(); err != nil {
		return err
	}
	if !renamed {
		w.retryAt = w.size + w.segMax/4
		return nil
	}
	w.retryAt = 0
	segs, _ := Segments(w.dir)
	var total int64
	sizes := make([]int64, len(segs))
	for i, p := range segs {
		if fi, err := os.Stat(p); err == nil {
			sizes[i] = fi.Size()
			total += fi.Size()
		}
	}
	for i := 0; i < len(segs)-1 && total > w.max; i++ {
		if os.Remove(segs[i]) != nil {
			continue // in use; a later rotation removes it
		}
		os.Remove(indexFor(segs[i])) //nolint:errcheck
		total -= sizes[i]
		w.Dropped++
	}
	return nil
}

// Close closes the current segment.
func (w *Writer) Close() error {
	err := w.f.Close()
	if e := w.idx.Close(); err == nil {
		err = e
	}
	return err
}

// RemoveAll deletes a session directory's exchanges and indexes.
func RemoveAll(dir string) error {
	segs, err := Segments(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, p := range segs {
		for _, f := range []string{p, indexFor(p)} {
			if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	err = os.Remove(filepath.Join(dir, CurrentIndex))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Tail is the last segment and where its indexed records end: following a
// session continues from there.
func (s *Store) Tail() (path string, end int64) {
	if len(s.segs) == 0 {
		if s.Dir != "" {
			return filepath.Join(s.Dir, Current), 0
		}
		return "", 0
	}
	last := len(s.segs) - 1
	for _, e := range s.Entries {
		if e.seg == last {
			end = max(end, e.Off+int64(e.Len))
		}
	}
	return s.segs[last].path, end
}

// IsSegmentOf reports whether fi is one of dir's rotated segments: a file
// that was the current segment and has been rotated, not replaced.
func IsSegmentOf(dir string, fi os.FileInfo) bool {
	segs, _ := Segments(dir)
	for _, p := range segs {
		if filepath.Base(p) == Current {
			continue
		}
		if si, err := os.Stat(p); err == nil && os.SameFile(si, fi) {
			return true
		}
	}
	return false
}

// ---- index lines ----

func appendField(b []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			b = append(b, '\\', '\\')
		case '\t':
			b = append(b, '\\', 't')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		default:
			b = append(b, c)
		}
	}
	return b
}

func unescape(f []byte) string {
	if bytes.IndexByte(f, '\\') < 0 {
		return string(f)
	}
	out := make([]byte, 0, len(f))
	for i := 0; i < len(f); i++ {
		if f[i] == '\\' && i+1 < len(f) {
			i++
			switch f[i] {
			case 't':
				out = append(out, '\t')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			default:
				out = append(out, f[i])
			}
			continue
		}
		out = append(out, f[i])
	}
	return string(out)
}

const entryFields = 12

func (e *Entry) appendLine(b []byte) []byte {
	b = strconv.AppendInt(b, int64(e.ID), 10)
	b = append(b, '\t')
	b = strconv.AppendInt(b, e.Off, 10)
	b = append(b, '\t')
	b = strconv.AppendInt(b, int64(e.Len), 10)
	b = append(b, '\t')
	b = appendField(b, e.Method)
	b = append(b, '\t')
	b = strconv.AppendInt(b, int64(e.Status), 10)
	b = append(b, '\t')
	b = appendField(b, e.ErrKind)
	b = append(b, '\t')
	if e.WS {
		b = append(b, '1')
	}
	b = append(b, '\t')
	b = strconv.AppendFloat(b, e.DurMs, 'f', -1, 64)
	b = append(b, '\t')
	b = appendField(b, e.Rule)
	b = append(b, '\t')
	b = appendField(b, e.Time)
	b = append(b, '\t')
	b = appendField(b, e.URL)
	b = append(b, '\t')
	b = appendField(b, e.Summary)
	return append(b, '\n')
}

// parseHead reads an index line's id, offset and length only.
func parseHead(line []byte) (id int, off int64, n int, ok bool) {
	var f [3][]byte
	for i := range f {
		j := bytes.IndexByte(line, '\t')
		if j < 0 {
			return 0, 0, 0, false
		}
		f[i], line = line[:j], line[j+1:]
	}
	id, err1 := strconv.Atoi(string(f[0]))
	off, err2 := strconv.ParseInt(string(f[1]), 10, 64)
	n, err3 := strconv.Atoi(string(f[2]))
	return id, off, n, err1 == nil && err2 == nil && err3 == nil
}

func parseEntry(line []byte) (Entry, bool) {
	var f [entryFields][]byte
	for i := 0; i < entryFields-1; i++ {
		j := bytes.IndexByte(line, '\t')
		if j < 0 {
			return Entry{}, false
		}
		f[i], line = line[:j], line[j+1:]
	}
	f[entryFields-1] = bytes.TrimRight(line, "\r\n")
	id, err1 := strconv.Atoi(string(f[0]))
	off, err2 := strconv.ParseInt(string(f[1]), 10, 64)
	n, err3 := strconv.Atoi(string(f[2]))
	status, err4 := strconv.Atoi(string(f[4]))
	dur, err5 := strconv.ParseFloat(string(f[7]), 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		return Entry{}, false
	}
	return Entry{
		ID: id, Off: off, Len: n, Method: unescape(f[3]), Status: status, ErrKind: unescape(f[5]),
		WS: len(f[6]) > 0, DurMs: dur, Rule: unescape(f[8]), Time: unescape(f[9]), URL: unescape(f[10]), Summary: unescape(f[11]),
	}, true
}

// Stats summarises a session directory for listing.
type Stats struct {
	Count int    // exchanges kept
	Bytes int64  // size of all segments
	First string // time of the first exchange kept
	Last  string // time of the last
}

// StatDir reads a session directory's indexes.
func StatDir(dir string) (Stats, error) {
	var st Stats
	segs, err := Segments(dir)
	if err != nil {
		return st, err
	}
	for _, p := range segs {
		if fi, err := os.Stat(p); err == nil {
			st.Bytes += fi.Size()
		}
	}
	s, err := Open(dir, false)
	if err != nil {
		return st, err
	}
	defer s.Close()
	st.Count = len(s.Entries)
	if st.Count > 0 {
		st.First, st.Last = s.Entries[0].Time, s.Entries[st.Count-1].Time
	}
	return st, nil
}

// SegmentsAfter lists the rotated segments written after the one fi is,
// oldest first: what a follower of the current segment must read before the
// new current one when it finds the session rotated.
func SegmentsAfter(dir string, fi os.FileInfo) []string {
	segs, _ := Segments(dir)
	var out []string
	found := false
	for _, p := range segs {
		if filepath.Base(p) == Current {
			break
		}
		if found {
			out = append(out, p)
			continue
		}
		if si, err := os.Stat(p); err == nil && os.SameFile(si, fi) {
			found = true
		}
	}
	return out
}
