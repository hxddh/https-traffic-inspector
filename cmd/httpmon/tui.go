package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	osc52 "github.com/aymanbagabas/go-osc52/v2"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hxddh/https-traffic-inspector/v4/internal/body"
	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v4/internal/textsafe"
)

// tuiEntry holds one HTTP transaction displayed in the TUI. Every string in
// it has already been masked for display; rawReqHeaders keeps the real values
// for "copy as curl", which the user asks for explicitly.
type tuiEntry struct {
	id          int
	startTime   time.Time
	method      string
	host        string
	path        string
	rawURL      string
	reqHeaders  map[string]string
	reqBody     string
	status      int
	statusText  string
	respHeaders map[string]string
	respBody    string
	respTrailer map[string]string
	duration    time.Duration
	pending     bool

	// for copy-as-curl
	curlURL       string
	rawReqHeaders http.Header
	reqBodyRaw    []byte
	reqBodyWhole  bool

	failed   string // the error, when the exchange got no response
	grpcLine string

	rule string // the rules that touched it: "mock: …; fault: …"

	ws       bool     // an upgraded WebSocket connection
	wsLines  []string // most recent messages, rendered
	wsCount  int
	wsClosed string // summary, once closed
}

// maxTUIEntries bounds the TUI's memory in a long session; the oldest entries
// are dropped first. maxWSLines bounds the messages kept per connection.
const (
	maxTUIEntries = 5000
	maxWSLines    = 200
)

// Messages exchanged with the TUI model via tuiQueue.
type tuiReqMsg struct{ entry *tuiEntry }
type tuiRespMsg struct {
	reqID      int
	status     int
	statusText string
	headers    map[string]string
	body       string
	duration   time.Duration
	upgraded   bool
}
type tuiDoneMsg struct{ exitCode int }

// Bodies arrive after their head: they are sampled as the body streams so that
// delivery is never held up, then sent as a follow-up update.
type tuiReqBodyMsg struct {
	reqID int
	body  string
	raw   []byte
	whole bool
}
type tuiRespBodyMsg struct {
	reqID    int
	body     string
	trailers map[string]string
	grpcLine string
}
type tuiFailMsg struct {
	reqID    int
	err      string
	duration time.Duration
}
type tuiWSMsg struct {
	reqID int
	line  string
}
type tuiWSClosedMsg struct {
	reqID   int
	summary string
}
type tuiNoticeMsg struct{ text string }
type tuiRuleMsg struct {
	reqID int
	rule  string
}
type tuiFlashMsg struct{ text string }

// tuiQueue carries proxy events to the TUI. It is unbounded: proxy
// goroutines must never block on the display, and a fixed-size channel with a
// non-blocking send silently dropped events under load, leaving entries stuck
// as pending forever.
var tuiQueue = newEventQueue()

// tuiSend queues an event for the TUI.
func tuiSend(m tea.Msg) { tuiQueue.push(m) }

type eventQueue struct {
	mu    sync.Mutex
	items []tea.Msg
	ready chan struct{} // signalled when items becomes non-empty
}

func newEventQueue() *eventQueue {
	return &eventQueue{ready: make(chan struct{}, 1)}
}

func (q *eventQueue) push(m tea.Msg) {
	q.mu.Lock()
	q.items = append(q.items, m)
	q.mu.Unlock()
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

// pop blocks until an event is available.
func (q *eventQueue) pop() tea.Msg {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			m := q.items[0]
			q.items[0] = nil
			q.items = q.items[1:]
			q.mu.Unlock()
			return m
		}
		q.mu.Unlock()
		<-q.ready
	}
}

// ---- sink ----

type tuiSink struct{}

var tuiOutput = tuiSink{}

func displayFlat(h http.Header) map[string]string { return flattenHeaders(displayHeaders(h)) }

func (tuiSink) requestHead(id int, f *requestFacts) {
	tuiSend(tuiReqMsg{&tuiEntry{
		id:            id,
		startTime:     f.startTime,
		method:        f.method,
		host:          f.host,
		path:          f.path,
		rawURL:        displayURL(f.rawURL),
		reqHeaders:    displayFlat(f.headers),
		pending:       true,
		curlURL:       f.rawURL,
		rawReqHeaders: f.headers,
	}})
}

func (tuiSink) requestBody(id int, _ *requestFacts, v bodyView) {
	tuiSend(tuiReqBodyMsg{reqID: id, body: truncateForDisplay(v), raw: v.Raw, whole: !v.RawTruncated})
}

func (tuiSink) responseHead(id int, f *responseFacts) {
	tuiSend(tuiRespMsg{
		reqID:      id,
		status:     f.status,
		statusText: f.statusText,
		headers:    displayFlat(f.headers),
		duration:   f.duration,
		upgraded:   f.upgraded,
	})
}

func (tuiSink) responseBody(id int, f *responseFacts, v bodyView) {
	var trailers map[string]string
	if len(f.trailers) > 0 {
		trailers = displayFlat(f.trailers)
	}
	tuiSend(tuiRespBodyMsg{reqID: id, body: truncateForDisplay(v), trailers: trailers, grpcLine: body.GRPCStatusLine(f.headers, f.trailers)})
}

func (tuiSink) failed(id int, _ *requestFacts, err *exchange.Error, dur time.Duration) {
	tuiSend(tuiFailMsg{reqID: id, err: err.Kind + ": " + err.Message, duration: dur})
}

func (tuiSink) exchange(*exchange.Exchange) {} // shown as it unfolded

// incomplete is printed after the UI has closed, like the digest.
func (tuiSink) incomplete(p exchange.Pending) {
	fmt.Fprintln(os.Stderr, textsafe.Line(p.SummaryLine()))
}
func (tuiSink) start(runInfo) {}

// end has nothing to draw on: the UI has closed by then. The digest is
// printed after it, with the notices.
func (tuiSink) end(d *exchange.Digest) {
	fmt.Fprintln(os.Stderr, textsafe.Line(d.String()))
}

func (tuiSink) wsMessage(id int, m wsMessage) {
	line := fmt.Sprintf("%s %s %s", m.at.Format("15:04:05.000"), m.direction(), m.describe())
	if s := m.displayText(); s != "" {
		line += "\n  " + strings.ReplaceAll(s, "\n", "\n  ")
	}
	tuiSend(tuiWSMsg{reqID: id, line: line})
}

func (tuiSink) wsClosed(id int, s wsSummary) {
	tuiSend(tuiWSClosedMsg{reqID: id, summary: s.describe()})
}

func (tuiSink) connect(string) {}

// tuiNotices keeps every notice so they can be printed once the TUI exits;
// on screen only the latest fits.
var (
	tuiNotices   []string
	tuiNoticesMu sync.Mutex
)

func (tuiSink) notice(msg string) {
	tuiNoticesMu.Lock()
	tuiNotices = append(tuiNotices, msg)
	tuiNoticesMu.Unlock()
	tuiSend(tuiNoticeMsg{msg})
}

// printTUINotices writes the notices collected during the session to w.
func printTUINotices(w io.Writer) {
	tuiNoticesMu.Lock()
	defer tuiNoticesMu.Unlock()
	for _, n := range tuiNotices {
		fmt.Fprintf(w, "httpmon: %s\n", textsafe.Line(n)) //nolint:errcheck // stderr
	}
}

// ── Styles ───────────────────────────────────────────────────────────────────

var (
	styleHeader   = lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230")).Padding(0, 1)
	styleSelected = lipgloss.NewStyle().Background(lipgloss.Color("236")).Bold(true)
	stylePending  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleErr      = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleOK       = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleWS       = lipgloss.NewStyle().Foreground(lipgloss.Color("75"))
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleSep      = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
	styleWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
)

// ── Model ────────────────────────────────────────────────────────────────────

type tuiModel struct {
	entries    []*tuiEntry
	byID       map[int]*tuiEntry
	cursor     int // index into visible()
	vp         viewport.Model
	showDetail bool
	width      int
	height     int
	ready      bool
	doneMsg    string

	filter    string // applied search
	searching bool   // typing a search
	input     string // search being typed

	notice   string // latest notice
	notices  int
	flash    string // short-lived feedback, e.g. "copied"
	flashFor int    // entry the flash refers to
}

func newTUIModel() tuiModel { return tuiModel{byID: map[int]*tuiEntry{}} }

// tuiOut is where the TUI draws: the terminal. When stdout is redirected the
// wrapped command's output goes there, so the TUI draws on stderr instead.
var tuiOut io.Writer = os.Stdout

func runTUI() {
	tea.NewProgram(newTUIModel(), tea.WithAltScreen(), tea.WithOutput(tuiOut)).Run() //nolint:errcheck
}

func (m tuiModel) Init() tea.Cmd { return listenTUI() }

func listenTUI() tea.Cmd {
	return func() tea.Msg { return tuiQueue.pop() }
}

// visible returns the entries matching the current search.
func (m *tuiModel) visible() []*tuiEntry {
	if m.filter == "" {
		return m.entries
	}
	var out []*tuiEntry
	for _, e := range m.entries {
		if m.matches(e) {
			out = append(out, e)
		}
	}
	return out
}

// matches reports whether e matches the search: a case-insensitive substring
// of its method, URL, status or error.
func (m *tuiModel) matches(e *tuiEntry) bool {
	q := strings.ToLower(m.filter)
	hay := strings.ToLower(fmt.Sprintf("%s %s %d %s %s", e.method, e.rawURL, e.status, e.failed, ruleTags(e.rule)))
	return strings.Contains(hay, q)
}

func (m *tuiModel) selected() *tuiEntry {
	v := m.visible()
	if m.cursor < 0 || m.cursor >= len(v) {
		return nil
	}
	return v[m.cursor]
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var vpCmd tea.Cmd
	if m.byID == nil {
		m.byID = map[int]*tuiEntry{}
	}

	switch msg := msg.(type) {

	case tea.KeyMsg:
		if m.searching {
			return m.updateSearch(msg), nil
		}
		m.flash = ""
		n := len(m.visible())
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.refreshDetail(true)
			}
			return m, nil
		case "down", "j":
			if m.cursor < n-1 {
				m.cursor++
				m.refreshDetail(true)
			}
			return m, nil
		case "g":
			m.cursor = 0
			m.refreshDetail(true)
			return m, nil
		case "G":
			if n > 0 {
				m.cursor = n - 1
				m.refreshDetail(true)
			}
			return m, nil
		case "enter", " ":
			if n > 0 {
				m.showDetail = !m.showDetail
				m.applySize()
			}
			return m, nil
		case "esc":
			if m.showDetail {
				m.showDetail = false
			} else if m.filter != "" {
				m.setFilter("")
			}
			m.applySize()
			return m, nil
		case "/":
			m.searching, m.input = true, m.filter
			return m, nil
		case "c":
			m.copyAsCurl()
			return m, nil
		case "e":
			m.exportSelected()
			return m, nil
		case "r":
			m.replaySelected()
			return m, nil
		}
		// Keys the list does not use (pgup/pgdn, ctrl+u/ctrl+d, home/end)
		// scroll the detail panel. Without this the viewport never receives
		// key events and long bodies are unreachable.
		if m.showDetail {
			m.vp, vpCmd = m.vp.Update(msg)
		}
		return m, vpCmd

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		if !m.ready {
			m.vp = viewport.New(msg.Width, m.detailH())
			m.ready = true
		}
		m.applySize()
		return m, nil

	case tuiReqMsg:
		// Auto-follow if the cursor was on the newest visible entry.
		follow := m.cursor >= len(m.visible())-1
		m.entries = append(m.entries, msg.entry)
		m.byID[msg.entry.id] = msg.entry
		m.trim()
		if n := len(m.visible()); follow && n > 0 && (m.cursor != n-1 || n == 1) {
			m.cursor = n - 1
			m.refreshDetail(true)
		}
		return m, listenTUI()

	case tuiRespMsg:
		if e := m.byID[msg.reqID]; e != nil {
			e.pending = false
			e.status, e.statusText = msg.status, msg.statusText
			e.respHeaders, e.respBody = msg.headers, msg.body
			e.duration = msg.duration
			e.ws = msg.upgraded
		}
		// Keep the scroll position: the user may be reading the request half
		// of the panel when the response lands.
		m.refreshDetail(false)
		return m, listenTUI()

	case tuiReqBodyMsg:
		if e := m.byID[msg.reqID]; e != nil {
			e.reqBody, e.reqBodyRaw, e.reqBodyWhole = msg.body, msg.raw, msg.whole
		}
		m.refreshDetail(false)
		return m, listenTUI()

	case tuiRespBodyMsg:
		if e := m.byID[msg.reqID]; e != nil {
			e.respBody = msg.body
			e.respTrailer = msg.trailers
			e.grpcLine = msg.grpcLine
		}
		m.refreshDetail(false)
		return m, listenTUI()

	case tuiFailMsg:
		if e := m.byID[msg.reqID]; e != nil {
			e.pending = false
			e.failed = msg.err
			e.duration = msg.duration
		}
		m.refreshDetail(false)
		return m, listenTUI()

	case tuiWSMsg:
		if e := m.byID[msg.reqID]; e != nil {
			e.wsCount++
			e.wsLines = append(e.wsLines, msg.line)
			if len(e.wsLines) > maxWSLines {
				e.wsLines = e.wsLines[len(e.wsLines)-maxWSLines:]
			}
		}
		m.refreshDetail(false)
		return m, listenTUI()

	case tuiWSClosedMsg:
		if e := m.byID[msg.reqID]; e != nil {
			e.wsClosed = msg.summary
		}
		m.refreshDetail(false)
		return m, listenTUI()

	case tuiRuleMsg:
		if e := m.byID[msg.reqID]; e != nil {
			e.rule = msg.rule
		}
		m.refreshDetail(false)
		return m, listenTUI()

	case tuiFlashMsg:
		m.flash = msg.text
		return m, listenTUI()

	case tuiNoticeMsg:
		m.notice = msg.text
		m.notices++
		return m, listenTUI()

	case tuiDoneMsg:
		m.doneMsg = fmt.Sprintf(" Command exited (code %d) — press q to quit", msg.exitCode)
		return m, listenTUI()
	}

	if m.showDetail {
		m.vp, vpCmd = m.vp.Update(msg)
	}
	return m, vpCmd
}

// updateSearch handles keys while a search is being typed.
func (m tuiModel) updateSearch(msg tea.KeyMsg) tuiModel {
	switch msg.Type {
	case tea.KeyEnter:
		m.searching = false
		m.setFilter(m.input)
	case tea.KeyEsc:
		m.searching = false
		m.setFilter("")
	case tea.KeyBackspace:
		if r := []rune(m.input); len(r) > 0 {
			m.input = string(r[:len(r)-1])
		}
	case tea.KeyRunes, tea.KeySpace:
		m.input += string(msg.Runes)
	}
	return m
}

// setFilter applies a search, keeping the selected entry selected when it
// still matches.
func (m *tuiModel) setFilter(f string) {
	sel := m.selected()
	m.filter = f
	m.cursor = 0
	v := m.visible()
	for i, e := range v {
		if e == sel {
			m.cursor = i
		}
	}
	if len(v) > 0 && sel == nil {
		m.cursor = len(v) - 1
	}
	m.refreshDetail(true)
}

// trim drops the oldest entries beyond maxTUIEntries.
func (m *tuiModel) trim() {
	over := len(m.entries) - maxTUIEntries
	if over <= 0 {
		return
	}
	sel := m.selected()
	for _, e := range m.entries[:over] {
		delete(m.byID, e.id)
	}
	m.entries = append([]*tuiEntry(nil), m.entries[over:]...)
	m.cursor = 0
	for i, e := range m.visible() {
		if e == sel {
			m.cursor = i
		}
	}
}

func (m *tuiModel) listH() int {
	h := m.height - 3 // header row + col-header row + status bar
	if m.showDetail {
		h -= m.detailH() + 1 // +1 for separator line
	}
	if h < 1 {
		h = 1
	}
	return h
}

func (m *tuiModel) detailH() int {
	if m.height < 24 {
		return 8
	}
	return m.height / 3
}

func (m *tuiModel) applySize() {
	if !m.ready {
		return
	}
	m.vp.Width = m.width
	m.vp.Height = m.detailH()
	m.refreshDetail(false)
}

// refreshDetail re-renders the detail panel. resetScroll returns the viewport
// to the top, which is wanted when the selected entry changes but not when the
// current entry is merely updated in place.
func (m *tuiModel) refreshDetail(resetScroll bool) {
	e := m.selected()
	if !m.ready || e == nil {
		return
	}
	m.vp.SetContent(renderEntryDetail(e, true))
	if resetScroll {
		m.vp.GotoTop()
	}
}

// ── Actions ──────────────────────────────────────────────────────────────────

// copyAsCurl puts a curl command reproducing the selected request on the
// clipboard, using OSC 52 so it works over SSH too.
func (m *tuiModel) copyAsCurl() {
	e := m.selected()
	if e == nil {
		return
	}
	cmd := curlCommand(e)
	seq := osc52.New(cmd)
	if os.Getenv("TMUX") != "" {
		seq = seq.Tmux()
	} else if strings.HasPrefix(os.Getenv("TERM"), "screen") {
		seq = seq.Screen()
	}
	seq.WriteTo(tuiOut) //nolint:errcheck
	m.flash = fmt.Sprintf("copied #%d as curl (%d chars)", e.id, len(cmd))
	m.flashFor = e.id
}

// exportSelected writes the selected entry's detail to a file in the current
// directory.
func (m *tuiModel) exportSelected() {
	e := m.selected()
	if e == nil {
		return
	}
	name := fmt.Sprintf("httpmon-%d-%d.txt", os.Getpid(), e.id)
	err := os.WriteFile(name, []byte(renderEntryDetail(e, false)), 0o600)
	if err != nil {
		m.flash = "export failed: " + err.Error()
		return
	}
	if abs, err := filepath.Abs(name); err == nil {
		name = abs
	}
	m.flash = "exported #" + fmt.Sprint(e.id) + " to " + name
	m.flashFor = e.id
}

// curlSkipHeaders are not worth reproducing: curl sets them itself, or they
// describe the hop to httpmon rather than the request.
var curlSkipHeaders = map[string]bool{
	"Content-Length": true, "Host": true, "Connection": true, "Proxy-Connection": true,
	"Keep-Alive": true, "Transfer-Encoding": true, "Te": true, "Upgrade": true,
	"Proxy-Authorization": true,
}

// curlCommand builds a shell command that reproduces e's request.
func curlCommand(e *tuiEntry) string {
	return curlFor(e.method, e.curlURL, e.rawReqHeaders, e.reqBodyRaw, e.reqBodyWhole)
}

// curlFor builds a shell command that sends a request.
func curlFor(method, url string, headers http.Header, body []byte, whole bool) string {
	var b strings.Builder
	b.WriteString("curl")
	if method != http.MethodGet {
		b.WriteString(" -X " + shellQuote(method))
	}
	b.WriteString(" " + shellQuote(url))
	for _, k := range sortedKeys(headers) {
		if curlSkipHeaders[k] {
			continue
		}
		for _, v := range headers[k] {
			b.WriteString(" \\\n  -H " + shellQuote(k+": "+v))
		}
	}
	if len(body) > 0 {
		if whole && utf8.Valid(body) {
			b.WriteString(" \\\n  --data-binary " + shellQuote(string(body)))
		} else {
			fmt.Fprintf(&b, "\n# request body (%d+ bytes) omitted: binary or only partly captured", len(body))
		}
	}
	return b.String()
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./:=@%+-]+$`)

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	if s != "" && shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ── Detail panel renderer ─────────────────────────────────────────────────────

// renderEntryDetail renders an entry's detail. Every value came from the
// network and is sanitised; colour is our own and only added when asked.
func renderEntryDetail(e *tuiEntry, color bool) string {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return "\033[" + code + "m" + s + "\033[0m"
	}
	var b strings.Builder
	b.WriteString(c(colCyan, fmt.Sprintf("━━ REQUEST #%d ━━", e.id)) + "\n")
	fmt.Fprintf(&b, "%s %s\n", textsafe.Line(e.method), textsafe.Line(e.rawURL))
	fmt.Fprintf(&b, "Host: %s    Time: %s\n", textsafe.Line(e.host), e.startTime.Format("15:04:05"))

	writeMap := func(title string, h map[string]string) {
		if len(h) == 0 {
			return
		}
		b.WriteString("\n" + title + ":\n")
		for _, k := range sortedKeys(h) {
			fmt.Fprintf(&b, "  %s: %s\n", textsafe.Line(k), textsafe.Line(h[k]))
		}
	}
	if e.rule != "" {
		fmt.Fprintf(&b, "Rule: %s\n", textsafe.Line(e.rule))
	}
	writeMap("Request Headers", e.reqHeaders)
	if e.reqBody != "" {
		b.WriteString("\nRequest Body:\n" + textsafe.Terminal(e.reqBody) + "\n")
	}

	switch {
	case e.failed != "":
		b.WriteString("\n" + c(colRed, fmt.Sprintf("━━ FAILED (%v) ━━", e.duration.Round(time.Millisecond))) + "\n")
		b.WriteString(textsafe.Terminal(e.failed) + "\n")
		return b.String()
	case e.pending:
		b.WriteString("\n" + c(colYellow, "⏳ waiting for response…") + "\n")
		return b.String()
	}

	b.WriteString("\n" + c(colGreen, fmt.Sprintf("━━ RESPONSE: %s  (%v) ━━", textsafe.Line(e.statusText), e.duration.Round(time.Millisecond))) + "\n")
	writeMap("Response Headers", e.respHeaders)
	if e.respBody != "" {
		b.WriteString("\nResponse Body:\n" + textsafe.Terminal(e.respBody) + "\n")
	}
	writeMap("Response Trailers", e.respTrailer)
	if e.grpcLine != "" {
		b.WriteString("\n" + textsafe.Line(e.grpcLine) + "\n")
	}
	if e.ws {
		b.WriteString("\n" + c(colCyan, fmt.Sprintf("━━ WEBSOCKET: %d messages ━━", e.wsCount)) + "\n")
		if hidden := e.wsCount - len(e.wsLines); hidden > 0 {
			fmt.Fprintf(&b, "(%d earlier messages not shown)\n", hidden)
		}
		for _, l := range e.wsLines {
			b.WriteString(textsafe.Terminal(l) + "\n")
		}
		if e.wsClosed != "" {
			b.WriteString(c(colDim, "closed: "+e.wsClosed) + "\n")
		}
	}
	return b.String()
}

// truncateDisplay shortens s to at most w display cells, appending an ellipsis
// when it cuts. Width is measured in cells rather than bytes so multi-byte and
// wide characters are neither split nor misaligned.
func truncateDisplay(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		rw := lipgloss.Width(string(r))
		if used+rw > w-1 {
			break
		}
		b.WriteRune(r)
		used += rw
	}
	return b.String() + "…"
}

// ── View ─────────────────────────────────────────────────────────────────────

func (m tuiModel) View() string {
	if !m.ready {
		return "starting…\n"
	}
	var b strings.Builder
	vis := m.visible()

	// ── Header bar
	title := fmt.Sprintf("httpmon  proxy :%s", proxyPort)
	if tuiTitle != "" {
		title = tuiTitle
	}
	if filterPattern != "" {
		title += fmt.Sprintf("  filter:%q", textsafe.Line(filterPattern))
	}
	if m.filter != "" {
		title += fmt.Sprintf("  search:%q", textsafe.Line(m.filter))
	}
	right := fmt.Sprintf("%d requests ", len(m.entries))
	if m.filter != "" {
		right = fmt.Sprintf("%d of %d requests ", len(vis), len(m.entries))
	}
	pad := m.width - lipgloss.Width(title) - len(right) - 2
	if pad < 1 {
		pad = 1
	}
	hdr := title + strings.Repeat(" ", pad) + right
	b.WriteString(styleHeader.Width(m.width).Render(hdr))
	b.WriteByte('\n')

	// ── Column headers
	urlW := m.width - 32
	if urlW < 10 {
		urlW = 10
	}
	b.WriteString(styleDim.Render(fmt.Sprintf(
		" %-5s %-8s %-6s %-*s %s\n",
		"#", "Method", "Status", urlW, "URL", "Duration",
	)))

	// ── Entry list
	lh := m.listH()
	start := 0
	if m.cursor >= lh {
		start = m.cursor - lh + 1
	}
	shown := 0
	for i := start; i < len(vis) && shown < lh; i++ {
		e := vis[i]
		statusStr, durStr := "…", "pending"
		switch {
		case e.failed != "":
			statusStr, durStr = "ERR", e.duration.Round(time.Millisecond).String()
		case e.ws && e.wsClosed == "":
			statusStr, durStr = "WS", fmt.Sprintf("%d msgs", e.wsCount)
		case e.ws:
			statusStr, durStr = "101", fmt.Sprintf("%d msgs", e.wsCount)
		case !e.pending:
			statusStr = fmt.Sprintf("%d", e.status)
			durStr = e.duration.Round(time.Millisecond).String()
		}
		if t := ruleTags(e.rule); t != "" {
			durStr += " " + t
		}
		urlStr := truncateDisplay(textsafe.Line(e.host+e.path), urlW)
		pad := urlW - lipgloss.Width(urlStr)
		if pad < 0 {
			pad = 0
		}
		line := fmt.Sprintf(" %-5d %-8s %-6s %s%s %s",
			e.id, textsafe.Line(e.method), statusStr, urlStr, strings.Repeat(" ", pad), durStr)
		line = truncateDisplay(line, m.width)
		switch {
		case i == m.cursor:
			b.WriteString(styleSelected.Width(m.width).Render(line))
		case e.failed != "" || e.status >= 400:
			b.WriteString(styleErr.Render(line))
		case e.pending:
			b.WriteString(stylePending.Render(line))
		case e.ws:
			b.WriteString(styleWS.Render(line))
		default:
			b.WriteString(styleOK.Render(line))
		}
		b.WriteByte('\n')
		shown++
	}
	for shown < lh {
		b.WriteByte('\n')
		shown++
	}

	// ── Detail panel
	if m.showDetail && len(vis) > 0 {
		b.WriteString(styleSep.Render(strings.Repeat("─", m.width)))
		b.WriteByte('\n')
		b.WriteString(m.vp.View())
		b.WriteByte('\n')
	}

	// ── Status bar
	hint := " [↑↓/jk] move  [enter] detail  [/] search  [c] copy curl  [e] export  [r] replay  [q] quit"
	if tuiReadOnly {
		hint = " [↑↓/jk] move  [enter] detail  [/] search  [c] copy curl  [e] export  [q] quit"
	}
	if m.showDetail {
		hint = " [↑↓/jk] move  [pgup/pgdn] scroll  [/] search  [c] copy curl  [esc] close  [q] quit"
		if !m.vp.AtBottom() {
			hint += "  ▼"
		}
	}
	switch {
	case m.searching:
		hint = " search: " + textsafe.Line(m.input) + "█   [enter] apply  [esc] clear"
	case m.flash != "":
		hint = " " + textsafe.Line(m.flash)
	case m.doneMsg != "":
		hint = m.doneMsg
	}
	if m.notice != "" && !m.searching {
		warn := fmt.Sprintf("  ⚠ %s", textsafe.Line(m.notice))
		if m.notices > 1 {
			warn = fmt.Sprintf("  ⚠ (%d) %s", m.notices, textsafe.Line(m.notice))
		}
		hint = truncateDisplay(hint, m.width/2) + styleWarn.Render(truncateDisplay(warn, m.width-lipgloss.Width(truncateDisplay(hint, m.width/2))))
		b.WriteString(hint)
		return b.String()
	}
	b.WriteString(styleDim.Render(truncateDisplay(hint, m.width)))

	return b.String()
}
