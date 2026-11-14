package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v4/internal/rules"
	"github.com/hxddh/https-traffic-inspector/v4/internal/session"
)

// useRules sets the active rules for a test.
func useRules(t *testing.T, mocks, faults, maps []string) {
	t.Helper()
	rs, err := rules.NewSet(mocks, faults, maps)
	if err != nil {
		t.Fatal(err)
	}
	saved, savedRec := activeRules, recordedMocks
	activeRules, recordedMocks = rs, nil
	t.Cleanup(func() { activeRules, recordedMocks = saved, savedRec })
}

// proxyClient is a client that uses a running httpmon proxy handler.
func proxyClient(t *testing.T) *http.Client {
	t.Helper()
	p := httptest.NewServer(http.HandlerFunc(handleHTTP))
	t.Cleanup(p.Close)
	u, _ := url.Parse(p.URL)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 10 * time.Second}
}

func TestRules_MockFaultMap(t *testing.T) {
	api := apiServer(t)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "mapped:"+r.Host+r.URL.Path) //nolint:errcheck
	}))
	defer other.Close()
	otherHost := strings.TrimPrefix(other.URL, "http://")

	recPath := filepath.Join(t.TempDir(), "rec.ndjson")
	useRecord(t, recPath)
	captureText(t)
	useStats(t, "")
	useRules(t,
		[]string{`GET */mocked => 418 {"teapot":true}`},
		[]string{"*/slow => delay 300ms", "*/reset => reset", "*/partial => reset after 4B"},
		[]string{"mapped.test => " + otherHost},
	)
	c := proxyClient(t)

	resp, err := c.Get(api.URL + "/mocked")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 418 || string(b) != `{"teapot":true}` || resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("mock = %d %q %v", resp.StatusCode, b, resp.Header)
	}

	start := time.Now()
	resp, err = c.Get(api.URL + "/slow")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if d := time.Since(start); d < 300*time.Millisecond || resp.StatusCode != 200 {
		t.Errorf("delay: %d after %v", resp.StatusCode, d)
	}

	if _, err := c.Get(api.URL + "/reset"); err == nil {
		t.Error("a reset fault returned a response")
	}

	resp, err = c.Get(api.URL + "/partial")
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if err == nil {
		t.Error("a reset-after fault delivered the whole body")
	}

	resp, err = c.Get("http://mapped.test/x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "mapped:"+otherHost+"/x" {
		t.Errorf("map = %q", b)
	}

	drainInflight(2 * time.Second)
	recs := readRecordFile(t, recPath)
	byPath := map[string]*exchange.Exchange{}
	for _, e := range recs {
		u, _ := url.Parse(e.URL)
		byPath[u.Path] = e
	}
	for path, want := range map[string]string{
		"/mocked": "mock: ", "/slow": "fault: */slow", "/reset": "fault: */reset", "/partial": "fault: */partial", "/x": "map: mapped.test",
	} {
		e := byPath[path]
		if e == nil {
			t.Errorf("%s not recorded (have %d records)", path, len(recs))
			continue
		}
		if !strings.HasPrefix(e.Rule, want) {
			t.Errorf("%s rule = %q, want prefix %q", path, e.Rule, want)
		}
	}
	if e := byPath["/reset"]; e != nil && (e.Error == nil || e.Error.Kind != exchange.KindInjected) {
		t.Errorf("reset = %+v, want an injected error", e.Error)
	}
	if e := byPath["/x"]; e != nil && e.URL != "http://mapped.test/x" {
		t.Errorf("a mapped exchange is recorded under %q, want the URL the client used", e.URL)
	}
	if e := byPath["/mocked"]; e != nil && !strings.HasSuffix(e.SummaryLine(), "[mock]") {
		t.Errorf("summary = %q, want a [mock] marker", e.SummaryLine())
	}
}

func TestRules_MockFromSession(t *testing.T) {
	path := recordSample(t)
	rec, err := rules.LoadRecorded(path, false)
	if err != nil {
		t.Fatal(err)
	}
	useRules(t, nil, nil, nil)
	recordedMocks = rec
	// The upstream is gone: the answer can only come from the session.
	u, _ := url.Parse(readRecordFile(t, path)[1].URL)
	c := proxyClient(t)
	resp, err := c.Get(u.String())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 500 || !strings.Contains(string(b), "db_timeout") {
		t.Errorf("mock-from = %d %q", resp.StatusCode, b)
	}
}

func TestMockHandler(t *testing.T) {
	path := recordSample(t)
	rec, err := rules.LoadRecorded(path, true)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mockHandler(rec))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/items")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != `{"items":[1,2,3]}` {
		t.Errorf("mock server = %d %q", resp.StatusCode, b)
	}
	resp, _ = http.Get(srv.URL + "/nope")
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 404 || !strings.Contains(string(b), "GET /items") {
		t.Errorf("unknown endpoint = %d %q, want 404 listing what is recorded", resp.StatusCode, b)
	}
}

func TestQuery_GrepCurlHAR(t *testing.T) {
	path := recordSample(t)

	out, _ := runQuery(t, path, "--grep", "db_time")
	if !strings.Contains(out, "/fail") || strings.Contains(out, "/items →") {
		t.Errorf("--grep found:\n%s", out)
	}
	if _, code := runQuery(t, path, "--grep", "("); code != 1 {
		t.Error("a bad --grep was accepted")
	}

	cur, _ := runQuery(t, path, "--format", "curl", "--url", "/items")
	if !strings.Contains(cur, "# #") || !strings.Contains(cur, "curl http://") || !strings.Contains(cur, "/items") {
		t.Errorf("--format curl:\n%s", cur)
	}

	har, code := runQuery(t, path, "--format", "har")
	var hf harFile
	if err := json.Unmarshal([]byte(har), &hf); err != nil || code != 0 {
		t.Fatalf("--format har (exit %d): %v\n%s", code, err, har)
	}
	if len(hf.Log.Entries) != 2 || hf.Log.Entries[1].Response.Status != 500 ||
		!strings.Contains(hf.Log.Entries[1].Response.Content.Text, "db_timeout") {
		t.Errorf("HAR = %+v", hf.Log.Entries)
	}
}

func TestQuery_SessionName(t *testing.T) {
	t.Setenv("HTTPMON_HOME", t.TempDir())
	src := recordSample(t)
	dir, _ := session.Dir("named")
	if err := session.Create(dir, false); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(src)
	os.WriteFile(filepath.Join(dir, session.ExchangesFile), data, 0o600) //nolint:errcheck
	out, code := runQuery(t, "named")
	if code != 0 || !strings.Contains(out, "2 exchanges") {
		t.Errorf("query named (exit %d):\n%s", code, out)
	}
	if _, code := runQuery(t, "no-such-session"); code != 1 {
		t.Error("a missing session was accepted")
	}
}

func TestExportLine(t *testing.T) {
	for _, tc := range []struct {
		shell string
		unset bool
		want  string
	}{
		{"sh", false, "export HTTPS_PROXY=http://127.0.0.1:8080"},
		{"sh", true, "unset HTTPS_PROXY"},
		{"fish", false, "set -gx HTTPS_PROXY http://127.0.0.1:8080"},
		{"powershell", false, "$env:HTTPS_PROXY = 'http://127.0.0.1:8080'"},
	} {
		if got := exportLine(tc.shell, "HTTPS_PROXY", "http://127.0.0.1:8080", tc.unset); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.shell, got, tc.want)
		}
	}
	if got := exportLine("sh", "X", "a b'c", false); got != `export X='a b'\''c'` {
		t.Errorf("quoting: %s", got)
	}
}

// ---- MCP ----

func mcpCall(t *testing.T, tools []mcpTool, lines ...string) []map[string]any {
	t.Helper()
	var out strings.Builder
	serveMCP(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, tools)
	var res []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad response %q: %v", sc.Text(), err)
		}
		res = append(res, m)
	}
	return res
}

func toolText(t *testing.T, r map[string]any) (string, bool) {
	t.Helper()
	res, _ := r["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in %v", r)
	}
	isErr, _ := res["isError"].(bool)
	return content[0].(map[string]any)["text"].(string), isErr
}

func TestMCP_ReadTools(t *testing.T) {
	path := recordSample(t)
	saved := useColor
	useColor = false
	defer func() { useColor = saved }()
	call := func(id int, name string, args map[string]any) string {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call",
			"params": map[string]any{"name": name, "arguments": args}})
		return string(b)
	}
	failID := readRecordFile(t, path)[1].ID
	res := mcpCall(t, mcpTools(false),
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		call(3, "query_exchanges", map[string]any{"session": path, "status": "5xx"}),
		call(4, "get_exchange", map[string]any{"session": path, "id": failID}),
		call(5, "get_body", map[string]any{"session": path, "id": failID, "which": "response"}),
		call(6, "add_rule", map[string]any{"session": path}),
		`{"jsonrpc":"2.0","id":7,"method":"nope"}`,
		`not json`,
	)
	if len(res) != 8 {
		t.Fatalf("%d responses (the notification gets none), want 8: %v", len(res), res)
	}
	if v := res[0]["result"].(map[string]any)["protocolVersion"]; v != mcpProtocolVersion {
		t.Errorf("protocolVersion = %v", v)
	}
	names := ""
	for _, tool := range res[1]["result"].(map[string]any)["tools"].([]any) {
		names += tool.(map[string]any)["name"].(string) + " "
	}
	if strings.Contains(names, "add_rule") || !strings.Contains(names, "query_exchanges") {
		t.Errorf("tools = %s; mutations must need --allow-mutations", names)
	}
	if txt, _ := toolText(t, res[2]); !strings.Contains(txt, "/fail → 500 db_timeout") || strings.Contains(txt, "/items →") {
		t.Errorf("query_exchanges:\n%s", txt)
	}
	if txt, _ := toolText(t, res[3]); !strings.Contains(txt, "Response: 500") {
		t.Errorf("get_exchange:\n%s", txt)
	}
	if txt, _ := toolText(t, res[4]); !strings.Contains(txt, `"db_timeout"`) {
		t.Errorf("get_body: %s", txt)
	}
	if res[5]["error"] == nil {
		t.Error("an unoffered tool was callable")
	}
	if res[6]["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Errorf("unknown method: %v", res[6])
	}
	if res[7]["error"].(map[string]any)["code"].(float64) != -32700 {
		t.Errorf("parse error: %v", res[7])
	}
}

func TestMCP_AddRuleNeedsRunningSession(t *testing.T) {
	t.Setenv("HTTPMON_HOME", t.TempDir())
	dir, _ := session.Dir("live")
	session.Create(dir, false) //nolint:errcheck
	tools := mcpTools(true)
	add := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add_rule","arguments":{"session":"live","kind":"mock","rule":"*/x => 503"}}}`

	session.WriteJSON(dir, session.MetaFile, session.Meta{Name: "live", PID: os.Getpid(), Ended: time.Now()}) //nolint:errcheck
	if txt, isErr := toolText(t, mcpCall(t, tools, add)[0]); !isErr || !strings.Contains(txt, "not running") {
		t.Errorf("ended session: %s", txt)
	}

	session.WriteJSON(dir, session.MetaFile, session.Meta{Name: "live", PID: os.Getpid()}) //nolint:errcheck
	if txt, isErr := toolText(t, mcpCall(t, tools, add)[0]); isErr {
		t.Fatalf("add_rule: %s", txt)
	}
	bad := strings.Replace(add, "*/x => 503", "nonsense", 1)
	if _, isErr := toolText(t, mcpCall(t, tools, bad)[0]); !isErr {
		t.Error("an invalid rule was added")
	}
	var r session.Rules
	if err := session.ReadJSON(dir, session.RulesFile, &r); err != nil || len(r.Mock) != 1 || r.Mock[0] != "*/x => 503" {
		t.Errorf("rules = %+v, %v", r, err)
	}
}

// Regression: a second run of a session in use replaced the first run's
// exchanges before it was refused.
func TestOpenSession_InUseKeepsExchanges(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	session.Create(dir, false) //nolint:errcheck
	ex := filepath.Join(dir, session.ExchangesFile)
	os.WriteFile(ex, []byte("{}\n"), 0o600)                                       //nolint:errcheck
	other := os.Getppid()                                                         // a running process that is not this one
	session.WriteJSON(dir, session.MetaFile, session.Meta{Name: "s", PID: other}) //nolint:errcheck
	o := &captureOptions{sessionDir: dir}
	if err := o.openSession("s"); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("openSession = %v, want in use", err)
	}
	if _, err := os.Stat(ex); err != nil {
		t.Error("the running session's exchanges were removed")
	}
}

func TestMCP_BadLimitsAreToolErrors(t *testing.T) {
	path := recordSample(t)
	id := readRecordFile(t, path)[1].ID
	call := func(args map[string]any, name string) string {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": name, "arguments": args}})
		return string(b)
	}
	res := mcpCall(t, mcpTools(false),
		call(map[string]any{"session": path, "id": id, "which": "response", "max_bytes": -1}, "get_body"),
		call(map[string]any{"session": path, "id": id, "max_body": -5}, "get_exchange"),
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
	)
	if len(res) != 3 {
		t.Fatalf("the server stopped answering: %v", res)
	}
	for i := range 2 {
		if _, isErr := toolText(t, res[i]); !isErr {
			t.Errorf("call %d: a negative limit was accepted", i)
		}
	}
}

func TestCallTool_RecoversPanic(t *testing.T) {
	_, err := callTool(mcpTool{Name: "boom", call: func(map[string]any) (string, error) { panic("x") }}, nil)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v", err)
	}
}
