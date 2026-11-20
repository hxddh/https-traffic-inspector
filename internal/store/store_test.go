package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hxddh/https-traffic-inspector/v5/internal/body"
	"github.com/hxddh/https-traffic-inspector/v5/internal/exchange"
)

func ex(id int, path string, status int, b string) *exchange.Exchange {
	return &exchange.Exchange{V: exchange.Version, ID: id, Method: "GET", Kind: "http",
		URL: "https://api.example.com" + path, Status: status, Time: "2026-11-14T10:00:00.000Z",
		Response: &exchange.Message{Headers: exchange.Headers{"Content-Type": {"application/json"}},
			Body: &body.Rendered{Size: int64(len(b)), Raw: body.NewRaw([]byte(b), false)}}}
}

func writeN(t *testing.T, dir string, maxSize int64, from, n int, pad int) *Writer {
	t.Helper()
	w, err := OpenWriter(dir, maxSize)
	if err != nil {
		t.Fatal(err)
	}
	if w.NextID() != from {
		t.Fatalf("NextID = %d, want %d", w.NextID(), from)
	}
	for i := range n {
		if err := w.Write(ex(from+i, fmt.Sprintf("/item/%d", from+i), 200, `{"pad":"`+strings.Repeat("x", pad)+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func TestWriteIndexRead(t *testing.T) {
	dir := t.TempDir()
	w := writeN(t, dir, 0, 1, 50, 10)
	w.Write(ex(51, "/fail?token=secret", 500, `{"error":{"code":"db_timeout"}}`)) //nolint:errcheck
	w.Close()                                                                     //nolint:errcheck

	s, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.Entries) != 51 || s.MaxID() != 51 {
		t.Fatalf("%d entries, max %d", len(s.Entries), s.MaxID())
	}
	last := s.Entries[50]
	if last.Status != 500 || !strings.Contains(last.Summary, "500 db_timeout") || strings.Contains(last.Summary, "secret") {
		t.Errorf("summary = %q: want the hint and a masked URL", last.Summary)
	}
	e, err := s.Read(s.Find(7)[0])
	if err != nil || e.URL != "https://api.example.com/item/7" {
		t.Errorf("Read(7) = %v, %v", e, err)
	}
	path, end := s.Tail()
	if fi, _ := os.Stat(path); filepath.Base(path) != Current || end != fi.Size() {
		t.Errorf("Tail = %s, %d", path, end)
	}

	// Only the wanted entry is kept, but the highest id is still known.
	only, err := OpenOnly(dir, false, func(id int) bool { return id == 9 })
	if err != nil {
		t.Fatal(err)
	}
	defer only.Close()
	if len(only.Entries) != 1 || only.Entries[0].ID != 9 || only.MaxID() != 51 {
		t.Errorf("OpenOnly: %d entries, max %d", len(only.Entries), only.MaxID())
	}
}

// A session without an index (v4.0), or with a short one, is indexed from
// its records; ids then continue from the highest.
func TestRebuildAndContinue(t *testing.T) {
	dir := t.TempDir()
	writeN(t, dir, 0, 1, 10, 5).Close() //nolint:errcheck
	os.Remove(filepath.Join(dir, CurrentIndex))
	s, err := Open(dir, true)
	if err != nil || len(s.Entries) != 10 {
		t.Fatalf("rebuilt %d entries, %v", len(s.Entries), err)
	}
	s.Close()
	if _, err := os.Stat(filepath.Join(dir, CurrentIndex)); err != nil {
		t.Error("the rebuilt index was not saved")
	}
	// A torn last index line is ignored and the record indexed again.
	idx := filepath.Join(dir, CurrentIndex)
	b, _ := os.ReadFile(idx)
	os.WriteFile(idx, b[:len(b)-5], 0o600) //nolint:errcheck
	w := writeN(t, dir, 0, 11, 2, 5)
	w.Close() //nolint:errcheck
	s, _ = Open(dir, false)
	defer s.Close()
	if len(s.Entries) != 12 || s.Entries[11].ID != 12 {
		t.Errorf("after a torn index: %d entries", len(s.Entries))
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	// 4 MB limit: 1 MB segments; each exchange ~10 KB.
	w := writeN(t, dir, 4<<20, 1, 800, 10_000)
	w.Close() //nolint:errcheck
	segs, _ := Segments(dir)
	if len(segs) < 3 || filepath.Base(segs[len(segs)-1]) != Current {
		t.Fatalf("segments = %v", segs)
	}
	st, _ := StatDir(dir)
	if st.Bytes > 4<<20+minSegment {
		t.Errorf("session is %d bytes, over its limit", st.Bytes)
	}
	if w.Dropped == 0 {
		t.Error("no segment was dropped")
	}
	s, _ := Open(dir, false)
	defer s.Close()
	if s.Entries[len(s.Entries)-1].ID != 800 || s.Entries[0].ID == 1 || len(s.Entries) != st.Count {
		t.Errorf("entries %d..%d (%d)", s.Entries[0].ID, s.Entries[len(s.Entries)-1].ID, len(s.Entries))
	}
	// Reading across segments.
	n := 0
	s.Each(func(*exchange.Exchange) bool { n++; return true }) //nolint:errcheck
	if n != len(s.Entries) {
		t.Errorf("Each read %d of %d", n, len(s.Entries))
	}
	fi, _ := os.Stat(segs[0])
	if !IsSegmentOf(dir, fi) {
		t.Error("a rotated segment is not recognised")
	}
	s.Close() // Windows removes no file that is open
	if err := RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if segs, _ := Segments(dir); len(segs) != 0 {
		t.Errorf("left %v", segs)
	}
}

func TestIndexLineEscaping(t *testing.T) {
	e := Entry{ID: 3, Off: 10, Len: 5, Method: "GET", URL: "u\tv", Rule: "mock: a\\b => 200\nx", Summary: "#3 GET\t→ 200", DurMs: 1.5, WS: true, Time: "t"}
	got, ok := parseEntry(e.appendLine(nil))
	if !ok || got != e {
		t.Errorf("round trip:\n got %+v\nwant %+v", got, e)
	}
	if _, ok := parseEntry([]byte("1\t2\t3")); ok {
		t.Error("a short line parsed")
	}
}

// Regression: a file whose last record had no newline lost that record.
func TestScan_LastRecordWithoutNewline(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.ndjson")
	os.WriteFile(p, []byte(`{"v":3,"id":1,"method":"GET","url":"u1","time":"t","kind":"http","request":{"headers":{}}}`+"\n"+ //nolint:errcheck
		`{"v":3,"id":2,"method":"GET","url":"u2","time":"t","kind":"http","request":{"headers":{}}}`), 0o600)
	s, err := Open(p, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.Entries) != 2 {
		t.Fatalf("%d entries, want 2", len(s.Entries))
	}
	if e, err := s.Read(s.Entries[1]); err != nil || e.URL != "u2" {
		t.Errorf("read %v, %v", e, err)
	}
	// A record still being written (no newline, not yet whole) waits.
	q := filepath.Join(t.TempDir(), "y.ndjson")
	os.WriteFile(q, []byte(`{"v":3,"id":1,"method":"GET","url":"u1","time":"t","kind":"http","request":{"headers":{}}}`+"\n"+`{"v":3,"id":2,"meth`), 0o600) //nolint:errcheck
	s2, _ := Open(q, false)
	defer s2.Close()
	if len(s2.Entries) != 1 {
		t.Errorf("a partial record was indexed: %d entries", len(s2.Entries))
	}
}
