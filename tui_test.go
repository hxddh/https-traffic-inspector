package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// newTestModel returns a sized, ready model, mimicking the WindowSizeMsg the
// terminal sends on startup.
func newTestModel(t *testing.T, w, h int) tuiModel {
	t.Helper()
	m, _ := newTUIModel().Update(tea.WindowSizeMsg{Width: w, Height: h})
	tm, ok := m.(tuiModel)
	if !ok {
		t.Fatalf("Update returned %T, want tuiModel", m)
	}
	return tm
}

// longEntry builds an entry whose detail rendering far exceeds the panel height.
func longEntry(id int) *tuiEntry {
	lines := make([]string, 200)
	for i := range lines {
		lines[i] = fmt.Sprintf("body line %03d", i)
	}
	return &tuiEntry{
		id:         id,
		startTime:  time.Now(),
		method:     "GET",
		host:       "api.example.com",
		path:       "/v1/things",
		rawURL:     "https://api.example.com/v1/things",
		reqHeaders: map[string]string{"Accept": "*/*"},
		reqBody:    strings.Join(lines, "\n"),
		pending:    true,
	}
}

func send(t *testing.T, m tuiModel, msg tea.Msg) tuiModel {
	t.Helper()
	next, _ := m.Update(msg)
	tm, ok := next.(tuiModel)
	if !ok {
		t.Fatalf("Update returned %T, want tuiModel", next)
	}
	return tm
}

func key(s string) tea.KeyMsg {
	switch s {
	case "pgdown":
		return tea.KeyMsg{Type: tea.KeyPgDown}
	case "pgup":
		return tea.KeyMsg{Type: tea.KeyPgUp}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

// Regression: the KeyMsg branch used to return unconditionally, so the viewport
// never saw any key event and the detail panel could not be scrolled at all.
func TestTUI_DetailScrolls(t *testing.T) {
	m := newTestModel(t, 80, 40)
	m = send(t, m, tuiReqMsg{longEntry(1)})
	m = send(t, m, key("enter"))

	if !m.showDetail {
		t.Fatal("detail panel did not open")
	}
	if m.vp.YOffset != 0 {
		t.Fatalf("YOffset = %d, want 0 before scrolling", m.vp.YOffset)
	}

	m = send(t, m, key("pgdown"))
	if m.vp.YOffset == 0 {
		t.Fatal("pgdown did not scroll the detail panel")
	}

	scrolled := m.vp.YOffset
	m = send(t, m, key("pgup"))
	if m.vp.YOffset >= scrolled {
		t.Fatalf("pgup did not scroll back: %d -> %d", scrolled, m.vp.YOffset)
	}
}

// List navigation keys must keep driving the list, not the viewport.
func TestTUI_ListKeysNotSwallowedByViewport(t *testing.T) {
	m := newTestModel(t, 80, 40)
	m = send(t, m, tuiReqMsg{longEntry(1)})
	m = send(t, m, tuiReqMsg{longEntry(2)})
	m = send(t, m, key("enter"))
	m = send(t, m, key("g")) // jump to first

	if m.cursor != 0 {
		t.Fatalf("cursor = %d, want 0", m.cursor)
	}
	before := m.vp.YOffset
	m = send(t, m, key("j"))
	if m.cursor != 1 {
		t.Fatalf("cursor = %d, want 1 after 'j'", m.cursor)
	}
	if m.vp.YOffset != before {
		t.Errorf("'j' scrolled the viewport (%d -> %d)", before, m.vp.YOffset)
	}
}

func TestTUI_CursorMoveResetsScroll(t *testing.T) {
	m := newTestModel(t, 80, 40)
	m = send(t, m, tuiReqMsg{longEntry(1)})
	m = send(t, m, tuiReqMsg{longEntry(2)})
	m = send(t, m, key("g"))
	m = send(t, m, key("enter"))
	m = send(t, m, key("pgdown"))

	if m.vp.YOffset == 0 {
		t.Fatal("setup: expected the panel to be scrolled")
	}
	m = send(t, m, key("j"))
	if m.vp.YOffset != 0 {
		t.Errorf("YOffset = %d, want 0 after selecting another entry", m.vp.YOffset)
	}
}

// A response arriving for the selected entry must not yank the user back to the
// top of a panel they are reading.
func TestTUI_ResponseDoesNotResetScroll(t *testing.T) {
	m := newTestModel(t, 80, 40)
	m = send(t, m, tuiReqMsg{longEntry(1)})
	m = send(t, m, key("enter"))
	m = send(t, m, key("pgdown"))

	scrolled := m.vp.YOffset
	if scrolled == 0 {
		t.Fatal("setup: expected the panel to be scrolled")
	}

	m = send(t, m, tuiRespMsg{
		reqID:      1,
		status:     200,
		statusText: "200 OK",
		headers:    map[string]string{"Content-Type": "application/json"},
		body:       `{"ok":true}`,
		duration:   42 * time.Millisecond,
	})

	if m.vp.YOffset != scrolled {
		t.Errorf("YOffset = %d, want %d (scroll position preserved)", m.vp.YOffset, scrolled)
	}
	if m.entries[0].pending {
		t.Error("entry still marked pending after response")
	}
}

func TestTUI_AutoFollow(t *testing.T) {
	m := newTestModel(t, 80, 40)
	m = send(t, m, tuiReqMsg{longEntry(1)})
	m = send(t, m, tuiReqMsg{longEntry(2)})
	if m.cursor != 1 {
		t.Errorf("cursor = %d, want 1 (auto-follow to newest)", m.cursor)
	}

	// With the cursor parked away from the end, new entries must not move it.
	m = send(t, m, key("g"))
	m = send(t, m, tuiReqMsg{longEntry(3)})
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0 (no auto-follow when parked)", m.cursor)
	}
}

func TestTUI_ViewRendersWithoutPanic(t *testing.T) {
	m := newTestModel(t, 80, 40)
	m = send(t, m, tuiReqMsg{longEntry(1)})
	m = send(t, m, key("enter"))
	if out := m.View(); out == "" {
		t.Error("View returned an empty string")
	}
}

func TestTruncateDisplay(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		width int
		want  string
	}{
		{"fits", "abc", 10, "abc"},
		{"exact", "abcde", 5, "abcde"},
		{"cuts ascii", "abcdefgh", 5, "abcd…"},
		{"zero width", "abc", 0, ""},
		{"multibyte not split", "日本語のホスト名", 5, "日本…"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncateDisplay(tc.in, tc.width); got != tc.want {
				t.Errorf("truncateDisplay(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
			}
		})
	}
}

// Regression: the list line was cut with len(), which split multi-byte runes.
func TestTruncateDisplay_ProducesValidUTF8(t *testing.T) {
	for w := 1; w <= 20; w++ {
		got := truncateDisplay("日本語のホスト名/パス", w)
		if strings.ToValidUTF8(got, "") != got {
			t.Errorf("width %d produced invalid UTF-8: %q", w, got)
		}
	}
}
