package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// tuiEntry holds one HTTP transaction displayed in the TUI.
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
	duration    time.Duration
	pending     bool
}

// Messages exchanged with the TUI model via tuiCh.
type tuiReqMsg  struct{ entry *tuiEntry }
type tuiRespMsg struct {
	reqID      int
	status     int
	statusText string
	headers    map[string]string
	body       string
	duration   time.Duration
}
type tuiDoneMsg struct{ exitCode int }

// tuiCh is the channel the proxy handlers write events to.
// Buffered so proxy goroutines never block waiting for the TUI.
var tuiCh = make(chan tea.Msg, 512)

// ── Styles ───────────────────────────────────────────────────────────────────

var (
	styleHeader   = lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230")).Padding(0, 1)
	styleSelected = lipgloss.NewStyle().Background(lipgloss.Color("236")).Bold(true)
	stylePending  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleErr      = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleOK       = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleSep      = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
)

// ── Model ────────────────────────────────────────────────────────────────────

type tuiModel struct {
	entries    []*tuiEntry
	cursor     int
	vp         viewport.Model
	showDetail bool
	width      int
	height     int
	ready      bool
	doneMsg    string
}

func newTUIModel() tuiModel { return tuiModel{} }

func runTUI() {
	tea.NewProgram(newTUIModel(), tea.WithAltScreen()).Run() //nolint:errcheck
}

func (m tuiModel) Init() tea.Cmd { return listenTUI() }

func listenTUI() tea.Cmd {
	return func() tea.Msg { return <-tuiCh }
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var vpCmd tea.Cmd

	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.refreshDetail()
			}
		case "down", "j":
			if m.cursor < len(m.entries)-1 {
				m.cursor++
				m.refreshDetail()
			}
		case "g":
			m.cursor = 0
			m.refreshDetail()
		case "G":
			if len(m.entries) > 0 {
				m.cursor = len(m.entries) - 1
				m.refreshDetail()
			}
		case "enter", " ":
			if len(m.entries) > 0 {
				m.showDetail = !m.showDetail
				m.applySize()
			}
		case "esc":
			m.showDetail = false
			m.applySize()
		}
		return m, nil

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		if !m.ready {
			m.vp = viewport.New(msg.Width, m.detailH())
			m.ready = true
		}
		m.applySize()
		return m, nil

	case tuiReqMsg:
		m.entries = append(m.entries, msg.entry)
		// Auto-follow if cursor was already at the last entry.
		if m.cursor == len(m.entries)-2 {
			m.cursor = len(m.entries) - 1
			m.refreshDetail()
		}
		return m, listenTUI()

	case tuiRespMsg:
		for _, e := range m.entries {
			if e.id == msg.reqID {
				e.pending = false
				e.status, e.statusText = msg.status, msg.statusText
				e.respHeaders, e.respBody = msg.headers, msg.body
				e.duration = msg.duration
				break
			}
		}
		m.refreshDetail()
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
	m.refreshDetail()
}

func (m *tuiModel) refreshDetail() {
	if !m.ready || len(m.entries) == 0 {
		return
	}
	m.vp.SetContent(renderEntryDetail(m.entries[m.cursor]))
}

// ── Detail panel renderer ─────────────────────────────────────────────────────

func renderEntryDetail(e *tuiEntry) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("\033[36m━━ REQUEST #%d ━━\033[0m\n", e.id))
	b.WriteString(fmt.Sprintf("%s %s\n", e.method, e.rawURL))
	b.WriteString(fmt.Sprintf("Host: %s    Time: %s\n", e.host, e.startTime.Format("15:04:05")))

	if len(e.reqHeaders) > 0 {
		b.WriteString("\nRequest Headers:\n")
		for k, v := range e.reqHeaders {
			b.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
	}
	if e.reqBody != "" {
		b.WriteString(fmt.Sprintf("\nRequest Body:\n%s\n", e.reqBody))
	}

	if e.pending {
		b.WriteString("\n\033[33m⏳ waiting for response…\033[0m\n")
		return b.String()
	}

	b.WriteString(fmt.Sprintf(
		"\n\033[32m━━ RESPONSE: %s  (%v) ━━\033[0m\n",
		e.statusText, e.duration.Round(time.Millisecond),
	))
	if len(e.respHeaders) > 0 {
		b.WriteString("\nResponse Headers:\n")
		for k, v := range e.respHeaders {
			b.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
	}
	if e.respBody != "" {
		b.WriteString(fmt.Sprintf("\nResponse Body:\n%s\n", e.respBody))
	}
	return b.String()
}

// ── View ─────────────────────────────────────────────────────────────────────

func (m tuiModel) View() string {
	if !m.ready {
		return "starting…\n"
	}
	var b strings.Builder

	// ── Header bar
	title := fmt.Sprintf("httpmon  proxy :%s", proxyPort)
	if filterPattern != "" {
		title += fmt.Sprintf("  filter:%q", filterPattern)
	}
	right := fmt.Sprintf("%d requests ", len(m.entries))
	pad := m.width - len(title) - len(right) - 2
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
	for i := start; i < len(m.entries) && shown < lh; i++ {
		e := m.entries[i]
		statusStr, durStr := "…", "pending"
		if !e.pending {
			statusStr = fmt.Sprintf("%d", e.status)
			durStr = e.duration.Round(time.Millisecond).String()
		}
		urlStr := e.host + e.path
		if len(urlStr) > urlW {
			urlStr = urlStr[:urlW-1] + "…"
		}
		line := fmt.Sprintf(" %-5d %-8s %-6s %-*s %s",
			e.id, e.method, statusStr, urlW, urlStr, durStr)
		if len(line) > m.width {
			line = line[:m.width]
		}
		switch {
		case i == m.cursor:
			b.WriteString(styleSelected.Width(m.width).Render(line))
		case e.pending:
			b.WriteString(stylePending.Render(line))
		case e.status >= 400:
			b.WriteString(styleErr.Render(line))
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
	if m.showDetail && len(m.entries) > 0 {
		b.WriteString(styleSep.Render(strings.Repeat("─", m.width)))
		b.WriteByte('\n')
		b.WriteString(m.vp.View())
		b.WriteByte('\n')
	}

	// ── Status bar
	hint := " [↑↓/jk] navigate  [enter] detail  [g/G] top/bottom  [q] quit"
	if m.doneMsg != "" {
		hint = m.doneMsg
	}
	b.WriteString(styleDim.Render(hint))

	return b.String()
}
