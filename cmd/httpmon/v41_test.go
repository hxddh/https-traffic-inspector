package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v4/internal/session"
	"github.com/hxddh/https-traffic-inspector/v4/internal/store"
)

// useSession records to a session directory, as --session-dir does.
func useSession(t *testing.T, dir string, appendMode bool) {
	t.Helper()
	savedCaptures := captures
	captures = newExchangeJoiner()
	o := &captureOptions{sessionDir: dir, appendSession: appendMode, maxSession: "0"}
	if err := o.openSession("test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeRecordWriter()
		recordMode, sessionPath, captures = false, "", savedCaptures
	})
}

// Regression: every --append run numbered its exchanges from #1, so an id
// named two exchanges and MCP's get_exchange returned the wrong one.
func TestAppend_IDsContinue(t *testing.T) {
	api := apiServer(t)
	dir := filepath.Join(t.TempDir(), "s")
	captureText(t)
	useStats(t, "")
	for run := range 2 {
		t.Run("", func(t *testing.T) {
			useSession(t, dir, run > 0)
			get(t, api.URL+"/items")
			drainInflight(2 * time.Second)
		})
	}
	st, err := store.Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var ids []int
	for _, e := range st.Entries {
		ids = append(ids, e.ID)
	}
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Errorf("ids = %v, want two different ids", ids)
	}
}

func TestQuery_IndexAndWait(t *testing.T) {
	api := apiServer(t)
	dir := filepath.Join(t.TempDir(), "s")
	captureText(t)
	useStats(t, "")
	useSession(t, dir, false)
	get(t, api.URL+"/items")
	get(t, api.URL+"/fail")
	drainInflight(2 * time.Second)

	out, code := runQuery(t, dir)
	if code != 0 || !strings.Contains(out, "/fail → 500 db_timeout") || !strings.Contains(out, "2 exchanges") {
		t.Errorf("summary from the index (exit %d):\n%s", code, out)
	}
	one, _ := runQuery(t, dir, "--id", "2", "--format", "json")
	var e exchange.Exchange
	if json.Unmarshal([]byte(strings.TrimSpace(one)), &e) != nil || e.ID != 2 || e.Status != 500 {
		t.Errorf("--id 2: %s", one)
	}

	// --wait returns an exchange that happens after it starts. (It is
	// recorded directly: a proxy in this process would share the query's
	// output.)
	go func() {
		time.Sleep(300 * time.Millisecond)
		writeRecord(&exchange.Exchange{V: exchange.Version, ID: 3, Method: "GET", Kind: "http",
			URL: api.URL + "/fail?late=1", Status: 503, Response: &exchange.Message{}})
	}()
	got, code := runQuery(t, dir, "--wait", "--status", "5xx", "--timeout", "5s")
	if code != 0 || !strings.Contains(got, "late=1 → 503") || strings.Count(got, "\n") != 1 {
		t.Errorf("--wait (exit %d):\n%q", code, got)
	}
	// --after accepts what already happened.
	if got, code := runQuery(t, dir, "--wait", "--after", "0", "--url", "/items"); code != 0 || !strings.Contains(got, "/items") {
		t.Errorf("--wait --after 0 (exit %d): %s", code, got)
	}
	if _, code := runQuery(t, dir, "--wait", "--url", "/never", "--timeout", "300ms"); code != exitWaitTimeout {
		t.Errorf("a --wait timeout exited %d, want %d", code, exitWaitTimeout)
	}
}

// Regression: --follow kept reading the file a restarted session had
// replaced, and saw nothing more.
func TestFollow_SessionStartedAgain(t *testing.T) {
	dir := t.TempDir()
	w, _ := store.OpenWriter(dir, 0)
	w.Write(&exchange.Exchange{V: exchange.Version, ID: 1, Method: "GET", URL: "http://h/old"}) //nolint:errcheck
	w.Close()                                                                                   //nolint:errcheck
	path := filepath.Join(dir, store.Current)
	fi, _ := os.Stat(path)

	got := make(chan string, 4)
	stop := make(chan os.Signal)
	go followFrom(dir, path, fi.Size(), stop, time.After(5*time.Second), func(e *exchange.Exchange) bool { //nolint:errcheck
		got <- e.URL
		return false
	})
	time.Sleep(300 * time.Millisecond)
	store.RemoveAll(dir) //nolint:errcheck
	w, _ = store.OpenWriter(dir, 0)
	w.Write(&exchange.Exchange{V: exchange.Version, ID: 1, Method: "GET", URL: "http://h/new"}) //nolint:errcheck
	w.Close()                                                                                   //nolint:errcheck
	select {
	case u := <-got:
		if u != "http://h/new" {
			t.Errorf("followed %s", u)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("follow did not move to the new file")
	}
}

func TestHeaderRules(t *testing.T) {
	var seen http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, "ok") //nolint:errcheck
	}))
	defer up.Close()
	captureText(t)
	useStats(t, "")
	useRules(t, []string{"*/mock [header X-Fail: yes*] => 503"}, nil, nil)
	if err := activeRules.Replace(nil, nil, nil, "*/* => request set X-Debug: 1", "*/* => response remove Cache-Control"); err != nil {
		t.Fatal(err)
	}
	c := proxyClient(t)
	resp, err := c.Get(up.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.Get("X-Debug") != "1" || resp.Header.Get("Cache-Control") != "" {
		t.Errorf("upstream saw X-Debug=%q; client got Cache-Control=%q", seen.Get("X-Debug"), resp.Header.Get("Cache-Control"))
	}
	// The condition: only requests carrying the header are mocked.
	for _, tc := range []struct {
		hdr  string
		want int
	}{{"", 200}, {"no", 200}, {"yes please", 503}} {
		req, _ := http.NewRequest("GET", up.URL+"/mock", nil)
		if tc.hdr != "" {
			req.Header.Set("X-Fail", tc.hdr)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("X-Fail=%q: %d, want %d", tc.hdr, resp.StatusCode, tc.want)
		}
	}
}

func TestMCP_WaitCurlReplay(t *testing.T) {
	api := apiServer(t)
	dir := filepath.Join(t.TempDir(), "s")
	captureText(t)
	useStats(t, "")
	useSession(t, dir, false)
	get(t, api.URL+"/items")
	drainInflight(2 * time.Second)

	call := func(name string, args map[string]any) string {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": name, "arguments": args}})
		return string(b)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		get(t, api.URL+"/fail")
	}()
	useColor = false
	res := mcpCall(t, mcpTools(false), call("wait_for_exchange", map[string]any{"session": dir, "status": "5xx", "timeout_sec": 5}))
	if txt, isErr := toolText(t, res[0]); isErr || !strings.Contains(txt, "/fail → 500 db_timeout") || !strings.Contains(txt, "Response: 500") {
		t.Errorf("wait_for_exchange: %s", txt)
	}
	res = mcpCall(t, mcpTools(false), call("export_curl", map[string]any{"session": dir, "id": 1}),
		call("replay_exchange", map[string]any{"session": dir, "id": 1}))
	if txt, _ := toolText(t, res[0]); !strings.Contains(txt, "curl ") || !strings.Contains(txt, "/items") {
		t.Errorf("export_curl: %s", txt)
	}
	if res[1]["error"] == nil {
		t.Error("replay_exchange was offered without --allow-mutations")
	}
	res = mcpCall(t, mcpTools(true), call("replay_exchange", map[string]any{"session": dir, "id": 1}))
	if txt, isErr := toolText(t, res[0]); isErr || !strings.Contains(txt, `"status_match": true`) {
		t.Errorf("replay_exchange: %s", txt)
	}
}

func TestSessionsRmPrune(t *testing.T) {
	t.Setenv("HTTPMON_HOME", t.TempDir())
	for _, name := range []string{"old", "live"} {
		d, _ := session.Dir(name)
		session.Create(d, false) //nolint:errcheck
		m := session.Meta{Name: name, PID: os.Getpid()}
		if name == "old" {
			m.Ended = time.Now()
		}
		session.WriteJSON(d, session.MetaFile, m) //nolint:errcheck
		past := time.Now().Add(-48 * time.Hour)
		os.Chtimes(d, past, past) //nolint:errcheck
	}
	if err := session.Remove("live"); err == nil {
		t.Error("a running session was removed")
	}
	saved := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	code := cmdSessions([]string{"prune", "--older-than", "1d"})
	os.Stdout = saved
	if code != 0 {
		t.Fatalf("prune exited %d", code)
	}
	list, _ := session.List()
	if len(list) != 1 || list[0].Name != "live" {
		t.Errorf("after prune: %+v", list)
	}
}

func TestParseSizesAndAges(t *testing.T) {
	for in, want := range map[string]int64{"0": 0, "512KB": 512 << 10, "1gb": 1 << 30, "2048": 2048} {
		if got, err := parseByteSize(in); err != nil || got != want {
			t.Errorf("parseByteSize(%q) = %d, %v", in, got, err)
		}
	}
	if _, err := parseByteSize("-1MB"); err == nil {
		t.Error("a negative size parsed")
	}
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "36h": 36 * time.Hour} {
		if got, err := parseAge(in); err != nil || got != want {
			t.Errorf("parseAge(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0d", "soon"} {
		if _, err := parseAge(bad); err == nil {
			t.Errorf("parseAge(%q) accepted", bad)
		}
	}
}

func TestTUIEntryFromRecord(t *testing.T) {
	path := recordSample(t)
	st, err := store.Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	e, _ := st.Read(st.Entries[1])
	e.Rule = "mock: */fail => 500; fault: */fail => delay 1s"
	en := tuiEntryFrom(e)
	if en.status != 500 || !strings.Contains(en.respBody, "db_timeout") || en.path != "/fail" || en.rawReqHeaders == nil {
		t.Errorf("entry = %+v", en)
	}
	if ruleTags(en.rule) != "[mock] [fault]" {
		t.Errorf("tags = %q", ruleTags(en.rule))
	}
	m := newTUIModel()
	m.filter = "[fault]"
	if !m.matches(en) {
		t.Error("search by rule tag does not match")
	}
}
