package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hxddh/https-traffic-inspector/v5/internal/config"
	"github.com/hxddh/https-traffic-inspector/v5/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v5/internal/rules"
	"github.com/hxddh/https-traffic-inspector/v5/internal/session"
	"github.com/hxddh/https-traffic-inspector/v5/internal/store"
	"github.com/hxddh/https-traffic-inspector/v5/internal/textsafe"
)

// ---- httpmon mcp ----
//
// A Model Context Protocol server over stdio: an agent's client starts
// "httpmon mcp" and gets tools to list sessions, query or diagnose their
// exchanges, read one in full, wait without blocking other calls, see what is
// in flight and compare two runs. With --allow-mutations it can also add rules
// to a running session and replay recorded requests. Credentials are masked
// unless --show-secrets.

const mcpProtocolVersion = "2025-06-18"

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
	blocking    bool
	call        func(args map[string]any) (string, error)
	callCtx     func(ctx context.Context, args map[string]any) (string, error)
}

func cmdMCP(args []string) int {
	fs := flag.NewFlagSet("httpmon mcp", flag.ContinueOnError)
	allowMut := fs.Bool("allow-mutations", false, "offer tools that change something: add_rule, clear_rules (a running session's rules), replay_exchange (sends traffic)")
	show := fs.Bool("show-secrets", false, "show credentials instead of masking them")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: httpmon mcp [--allow-mutations] [--show-secrets]

Runs a Model Context Protocol server on stdin and stdout, for an agent's
MCP client. Its tools read httpmon sessions -- list_sessions,
query_exchanges, diagnose_session, get_exchange, get_body,
wait_for_exchange, export_curl, in_flight, diff_sessions -- and, with
--allow-mutations, add_rule and clear_rules change the rules of a running
session and replay_exchange sends a recorded request again.

Example client configuration:
  {"mcpServers": {"httpmon": {"command": "httpmon", "args": ["mcp"]}}}

Options:
`)
		fs.PrintDefaults()
	}
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	showSecrets = *show
	useColor = false
	return serveMCP(os.Stdin, os.Stdout, mcpTools(*allowMut))
}

func serveMCP(in io.Reader, out io.Writer, tools []mcpTool) int {
	byName := map[string]mcpTool{}
	for _, t := range tools {
		byName[t.Name] = t
	}
	var outMu sync.Mutex
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	var writeErr atomicBool
	send := func(resp mcpResponse) {
		outMu.Lock()
		defer outMu.Unlock()
		if err := enc.Encode(resp); err != nil {
			writeErr.set()
		}
	}

	var cancelMu sync.Mutex
	cancels := map[string]context.CancelFunc{}
	var wg sync.WaitGroup

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() && !writeErr.get() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req mcpRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			send(mcpResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &mcpError{-32700, "parse error"}})
			continue
		}
		if len(req.ID) == 0 {
			if req.Method == "notifications/cancelled" {
				var c struct {
					RequestID json.RawMessage `json:"requestId"`
				}
				if json.Unmarshal(req.Params, &c) == nil && len(c.RequestID) > 0 {
					key := strings.TrimSpace(string(c.RequestID))
					cancelMu.Lock()
					fn := cancels[key]
					cancelMu.Unlock()
					if fn != nil {
						fn()
					}
				}
			}
			continue // a notification: nothing to answer
		}
		resp := mcpResponse{JSONRPC: "2.0", ID: req.ID}
		switch req.Method {
		case "initialize":
			resp.Result = map[string]any{
				"protocolVersion": mcpProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "httpmon", "version": version},
				"instructions": "httpmon captures HTTP(S) traffic into sessions. Start one with `httpmon --session NAME <command>` " +
					"or `httpmon proxy`. Use diagnose_session or query_exchanges for an overview, then get_exchange or get_body for detail.",
			}
		case "ping":
			resp.Result = map[string]any{}
		case "tools/list":
			resp.Result = map[string]any{"tools": tools}
		case "tools/call":
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &p); err != nil {
				resp.Error = &mcpError{-32602, "invalid params"}
				break
			}
			t, ok := byName[p.Name]
			if !ok {
				resp.Error = &mcpError{-32602, "unknown tool " + p.Name}
				break
			}
			if t.blocking {
				reqID := append(json.RawMessage(nil), req.ID...)
				key := strings.TrimSpace(string(reqID))
				ctx, cancel := context.WithCancel(context.Background())
				cancelMu.Lock()
				cancels[key] = cancel
				cancelMu.Unlock()
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() {
						cancel()
						cancelMu.Lock()
						delete(cancels, key)
						cancelMu.Unlock()
					}()
					text, err := callToolCtx(ctx, t, p.Arguments)
					r := mcpResponse{JSONRPC: "2.0", ID: reqID}
					if err != nil {
						r.Result = map[string]any{"content": []map[string]any{{"type": "text", "text": err.Error()}}, "isError": true}
					} else {
						r.Result = map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
					}
					send(r)
				}()
				continue
			}
			text, err := callTool(t, p.Arguments)
			if err != nil {
				resp.Result = map[string]any{"content": []map[string]any{{"type": "text", "text": err.Error()}}, "isError": true}
				break
			}
			resp.Result = map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
		default:
			resp.Error = &mcpError{-32601, "method not found: " + req.Method}
		}
		send(resp)
	}
	wg.Wait()
	if writeErr.get() {
		return 1
	}
	return 0
}

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (a *atomicBool) set() {
	a.mu.Lock()
	a.v = true
	a.mu.Unlock()
}

func (a *atomicBool) get() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.v
}

// callTool runs a tool, turning a panic into a tool error: one bad call must
// not end a server the client keeps running.
func callTool(t mcpTool, args map[string]any) (text string, err error) {
	return callToolCtx(context.Background(), t, args)
}

func callToolCtx(ctx context.Context, t mcpTool, args map[string]any) (text string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("httpmon: %s failed: %v", t.Name, r)
		}
	}()
	if t.callCtx != nil {
		return t.callCtx(ctx, args)
	}
	return t.call(args)
}

func schema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
func intProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func boolProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

func argString(a map[string]any, k string) string {
	if v, ok := a[k].(string); ok {
		return v
	}
	return ""
}

func argInt(a map[string]any, k string, def int) int {
	if v, ok := a[k].(float64); ok {
		return int(v)
	}
	return def
}

func argBool(a map[string]any, k string) bool {
	if v, ok := a[k].(bool); ok {
		return v
	}
	return false
}

var sessionProp = strProp("session name (see list_sessions), session directory or exchanges file")

func mcpTools(allowMutations bool) []mcpTool {
	ro := map[string]any{"readOnlyHint": true}
	tools := []mcpTool{
		{
			Name:        "list_sessions",
			Description: "List httpmon sessions: name, whether running, size, last change, and what was captured.",
			InputSchema: schema(map[string]any{}),
			Annotations: ro,
			call:        mcpListSessions,
		},
		{
			Name: "query_exchanges",
			Description: "List a session's exchanges, one line each (\"#3 GET host/path → 500 hint (12ms, 105 B)\"), " +
				"with a digest and causal insights. Filters combine.",
			InputSchema: schema(map[string]any{
				"session": sessionProp,
				"status":  strProp("statuses: classes (5xx), codes (404), error, app_error, comma-separated"),
				"method":  strProp("HTTP method"),
				"url":     strProp("text the URL contains (case-insensitive)"),
				"grep":    strProp("regular expression searched in URL, headers and decoded bodies"),
				"rule":    boolProp("only exchanges touched by a mock, fault, map or header rule"),
				"limit":   intProp("most lines to return (default 200; the last ones)"),
			}, "session"),
			Annotations: ro,
			call:        mcpQuery,
		},
		{
			Name: "diagnose_session",
			Description: "One-call diagnosis of a session: hard failures (DNS, TLS, client CA rejections), HTTP-200 protocol soft errors " +
				"(SSE mid-stream errors, GraphQL errors, JSON-RPC, gRPC), HTTP 4xx/5xx, causal anomalies (redirect dropping Authorization, " +
				"expired JWT, CORS mismatch, retries, unpooled TLS connections, N+1 bursts), and the slowest exchanges with phase timings.",
			InputSchema: schema(map[string]any{
				"session": sessionProp,
			}, "session"),
			Annotations: ro,
			call:        mcpDiagnose,
		},
		{
			Name: "get_exchange",
			Description: "One exchange in full: phase timings (DNS/TCP/TLS/TTFB/receive), connection reuse and TLS/cert details, " +
				"auth/CORS/GraphQL metadata, headers, decoded bodies (SSE/NDJSON streams, multipart parts, JSON, gRPC), error, WebSocket messages.",
			InputSchema: schema(map[string]any{
				"session":  sessionProp,
				"id":       intProp("exchange id"),
				"max_body": intProp("approximate max bytes of each body (default 4000)"),
			}, "session", "id"),
			Annotations: ro,
			call:        mcpGetExchange,
		},
		{
			Name:        "get_body",
			Description: "One exchange's decoded request or response body.",
			InputSchema: schema(map[string]any{
				"session":   sessionProp,
				"id":        intProp("exchange id"),
				"which":     map[string]any{"type": "string", "enum": []string{"request", "response"}},
				"max_bytes": intProp("most bytes to return (default 100000)"),
			}, "session", "id", "which"),
			Annotations: ro,
			call:        mcpGetBody,
		},
		{
			Name:        "in_flight",
			Description: "A running session's exchanges still waiting for a response or with a body still open.",
			InputSchema: schema(map[string]any{"session": sessionProp}, "session"),
			Annotations: ro,
			call:        mcpInFlight,
		},
		{
			Name: "wait_for_exchange",
			Description: "Wait until an exchange matching the filters happens in a session, and return it in full. By default only exchanges " +
				"after the call count; after_id also accepts earlier ones above that id. Non-blocking for other MCP calls; honours notifications/cancelled.",
			InputSchema: schema(map[string]any{
				"session":     sessionProp,
				"status":      strProp("statuses: classes (5xx), codes (404), error, app_error, comma-separated"),
				"method":      strProp("HTTP method"),
				"url":         strProp("text the URL contains (case-insensitive)"),
				"grep":        strProp("regular expression searched in URL, headers and decoded bodies"),
				"rule":        boolProp("only exchanges touched by a rule"),
				"after_id":    intProp("also accept exchanges already recorded with an id above this"),
				"timeout_sec": intProp("how long to wait, at most 60 (default 30)"),
			}, "session"),
			Annotations: ro,
			blocking:    true,
			callCtx:     mcpWait,
		},
		{
			Name:        "export_curl",
			Description: "A curl command that sends an exchange's request again. Credentials are masked unless the server runs with --show-secrets.",
			InputSchema: schema(map[string]any{"session": sessionProp, "id": intProp("exchange id")}, "session", "id"),
			Annotations: ro,
			call:        mcpCurl,
		},
		{
			Name:        "diff_sessions",
			Description: "Compare two sessions exchange by exchange: changed outcomes, bodies, new and gone requests.",
			InputSchema: schema(map[string]any{
				"before": strProp("the earlier session"),
				"after":  strProp("the later session"),
				"ignore": strProp("JSON paths not to compare, comma-separated (e.g. .updated_at,.request_id); adds to config ignore"),
			}, "before", "after"),
			Annotations: ro,
			call:        mcpDiff,
		},
	}
	if allowMutations {
		tools = append(tools,
			mcpTool{
				Name: "add_rule",
				Description: "Add a rule to a running session. mock: '[METHOD] PATTERN => STATUS [BODY]'; " +
					"fault: '[METHOD] PATTERN => delay 2s | reset | reset after 1KB | timeout [N%]'; map: 'HOST[:PORT] => [SCHEME://]HOST[:PORT]'; " +
					"header: '[METHOD] PATTERN => request|response set NAME: VALUE | remove NAME'. " +
					"PATTERN is host/path[?query] with * wildcards; mock, fault and header rules may add conditions: [header NAME] or [header NAME: VALUE*].",
				InputSchema: schema(map[string]any{
					"session": sessionProp,
					"kind":    map[string]any{"type": "string", "enum": []string{"mock", "fault", "map", "header"}},
					"rule":    strProp("the rule"),
				}, "session", "kind", "rule"),
				Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false},
				call:        mcpAddRule,
			},
			mcpTool{
				Name: "replay_exchange",
				Description: "Send a recorded request again, byte for byte, and compare the new response with the recorded one. " +
					"target replaces the scheme and host (e.g. http://localhost:3000). This sends real traffic.",
				InputSchema: schema(map[string]any{
					"session": sessionProp,
					"id":      intProp("exchange id"),
					"target":  strProp("scheme and host to send it to instead"),
				}, "session", "id"),
				Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "openWorldHint": true},
				call:        mcpReplay,
			},
			mcpTool{
				Name:        "clear_rules",
				Description: "Remove every rule added to a running session at run time.",
				InputSchema: schema(map[string]any{"session": sessionProp}, "session"),
				Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": true},
				call:        mcpClearRules,
			},
		)
	}
	return tools
}

func mcpListSessions(map[string]any) (string, error) {
	list, err := session.List()
	if err != nil {
		return "", err
	}
	if len(list) == 0 {
		return "no sessions; capture one with `httpmon --session NAME <command>` or `httpmon proxy`", nil
	}
	var b strings.Builder
	for _, s := range list {
		state := "ended"
		if s.Running {
			state = "running"
		}
		what := s.Meta.Kind
		if len(s.Meta.Command) > 0 {
			what = clipText(strings.Join(s.Meta.Command, " "), 60)
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\n", s.Name, state, humanBytes(s.Bytes), s.Modified.Format("2006-01-02 15:04"), textsafe.Line(what))
	}
	return b.String(), nil
}

func parseMCPFilter(a map[string]any) (queryFilter, error) {
	var q queryFilter
	q.method, q.url, q.rule = argString(a, "method"), argString(a, "url"), argBool(a, "rule")
	if s := argString(a, "status"); s != "" {
		f, err := exchange.ParseFailOn(s)
		if err != nil {
			return q, err
		}
		q.status = f
	}
	if g := argString(a, "grep"); g != "" {
		re, err := regexp.Compile(g)
		if err != nil {
			return q, err
		}
		q.grep = re
	}
	return q, nil
}

func mcpQuery(a map[string]any) (string, error) {
	st, err := openStore(argString(a, "session"))
	if err != nil {
		return "", err
	}
	defer st.Close()
	q, err := parseMCPFilter(a)
	if err != nil {
		return "", err
	}
	limit := argInt(a, "limit", 200)
	var lines []string
	var d exchange.Digest
	add := func(line string, e *exchange.Exchange) {
		d.Add(e)
		lines = append(lines, textsafe.Line(line))
	}
	err = eachMatching(st, &q, q.grep == nil && !showSecrets, add, func(e *exchange.Exchange) bool {
		if q.match(e) {
			prepareForDisplayWith(e, 4000, showSecrets)
			add(e.SummaryLine(), e)
		}
		return true
	})
	if err != nil {
		return "", err
	}
	skipped := 0
	if limit > 0 && len(lines) > limit {
		skipped = len(lines) - limit
		lines = lines[skipped:]
	}
	var b strings.Builder
	if skipped > 0 {
		fmt.Fprintf(&b, "(%d earlier lines not shown)\n", skipped)
	}
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	b.WriteString(sanitizeLines(d.String()) + "\n")
	return b.String(), nil
}

func mcpDiagnose(a map[string]any) (string, error) {
	st, err := openStore(argString(a, "session"))
	if err != nil {
		return "", err
	}
	defer st.Close()
	var list []*exchange.Exchange
	if err := st.Each(func(e *exchange.Exchange) bool {
		prepareForDisplayWith(e, 2000, showSecrets)
		list = append(list, e)
		return true
	}); err != nil {
		return "", err
	}
	diag := exchange.Diagnose(list)
	return sanitizeLines(diag.String()), nil
}

// findExchange reads one exchange through the session's index.
func findExchange(a map[string]any) (*exchange.Exchange, error) {
	id := argInt(a, "id", 0)
	st, err := openStoreOnly(argString(a, "session"), func(n int) bool { return n == id })
	if err != nil {
		return nil, err
	}
	defer st.Close()
	found := st.Find(id)
	if len(found) == 0 {
		return nil, fmt.Errorf("no exchange #%d", id)
	}
	// An older session written with --append can repeat an id: the most
	// recent run's exchange is the one meant.
	return readWithHint(st, found[len(found)-1])
}

func mcpGetExchange(a map[string]any) (string, error) {
	e, err := findExchange(a)
	if err != nil {
		return "", err
	}
	maxBody := argInt(a, "max_body", 4000)
	if maxBody <= 0 {
		return "", errors.New("max_body must be greater than 0")
	}
	prepareForDisplayWith(e, maxBody, showSecrets)
	s := renderExchangeText(e)
	if e.Rule != "" {
		s += "\nRule: " + textsafe.Line(e.Rule) + "\n"
	}
	return s, nil
}

func mcpGetBody(a map[string]any) (string, error) {
	e, err := findExchange(a)
	if err != nil {
		return "", err
	}
	which := argString(a, "which")
	if which != "request" && which != "response" {
		return "", errors.New("which must be request or response")
	}
	max := argInt(a, "max_bytes", 100000)
	if max <= 0 {
		return "", errors.New("max_bytes must be greater than 0")
	}
	var sb strings.Builder
	if writeBody(&sb, e, which) != 0 {
		return "", fmt.Errorf("exchange #%d has no %s body", e.ID, which)
	}
	s := textsafe.Terminal(sb.String())
	if clipped, cut := textsafe.ClipUTF8(s, max); cut {
		s = clipped + truncationMarker
	}
	return s, nil
}

func mcpInFlight(a map[string]any) (string, error) {
	dir, err := session.ResolveDir(argString(a, "session"))
	if err != nil {
		return "", err
	}
	var m session.Meta
	_ = session.ReadJSON(dir, session.MetaFile, &m)
	var l session.Live
	if !m.RunningIn(dir) || session.ReadJSON(dir, session.LiveFile, &l) != nil {
		return "session not running; nothing in flight", nil
	}
	var b strings.Builder
	for _, p := range l.InFlight {
		p.URL = displayURL(p.URL)
		b.WriteString(textsafe.Line(p.SummaryLine()) + "\n")
	}
	fmt.Fprintf(&b, "%d in flight as of %s\n", len(l.InFlight), l.Updated.Format("15:04:05"))
	return b.String(), nil
}

func mcpDiff(a map[string]any) (string, error) {
	var ignore []string
	if cfg, err := config.Load(); err == nil {
		ignore = append(ignore, cfg.Ignore...)
	}
	for _, p := range strings.Split(argString(a, "ignore"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			ignore = append(ignore, p)
		}
	}
	before, after, load, closeAll, err := readForDiff(argString(a, "before"), argString(a, "after"))
	if err != nil {
		return "", err
	}
	defer closeAll()
	opt := exchange.DefaultDiffOptions
	opt.Ignore = ignore
	opt.Load = load
	changes, counts := exchange.Diff(before, after, opt)
	var b strings.Builder
	for _, c := range changes {
		c.URL = displayURL(c.URL)
		b.WriteString(textsafe.Line(c.Line()) + "\n")
	}
	b.WriteString(counts.String() + "\n")
	return b.String(), nil
}

func runningSessionDir(name string) (string, error) {
	dir, err := session.ResolveDir(name)
	if err != nil {
		return "", err
	}
	var m session.Meta
	if err := session.ReadJSON(dir, session.MetaFile, &m); err != nil || !m.RunningIn(dir) {
		return "", fmt.Errorf("session %q is not running; rules apply to a running session", name)
	}
	return dir, nil
}

func mcpAddRule(a map[string]any) (string, error) {
	dir, err := runningSessionDir(argString(a, "session"))
	if err != nil {
		return "", err
	}
	kind, text := argString(a, "kind"), argString(a, "rule")
	if _, err := rules.Parse(kind, text); err != nil {
		return "", err
	}
	var r session.Rules
	_ = session.ReadJSON(dir, session.RulesFile, &r)
	switch kind {
	case rules.KindMock:
		r.Mock = append(r.Mock, text)
	case rules.KindFault:
		r.Fault = append(r.Fault, text)
	case rules.KindMap:
		r.Map = append(r.Map, text)
	case rules.KindHeader:
		r.Header = append(r.Header, text)
	}
	if err := session.WriteJSON(dir, session.RulesFile, r); err != nil {
		return "", err
	}
	return fmt.Sprintf("added %s rule %q; it applies within a second. Exchanges it touches are marked [%s].", kind, text, kind), nil
}

func mcpClearRules(a map[string]any) (string, error) {
	dir, err := runningSessionDir(argString(a, "session"))
	if err != nil {
		return "", err
	}
	if err := session.WriteJSON(dir, session.RulesFile, session.Rules{}); err != nil {
		return "", err
	}
	return "cleared the rules added at run time; rules given on the command line stay", nil
}

func mcpWait(ctx context.Context, a map[string]any) (string, error) {
	st, err := openStore(argString(a, "session"))
	if err != nil {
		return "", err
	}
	defer st.Close()
	q, err := parseMCPFilter(a)
	if err != nil {
		return "", err
	}
	q.after = argInt(a, "after_id", -1)
	if q.after < 0 {
		q.after = st.MaxID()
	}
	timeout := time.Duration(min(max(argInt(a, "timeout_sec", 30), 1), 60)) * time.Second
	stop := make(chan os.Signal)
	doneWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			close(stop)
		case <-doneWatch:
		}
	}()
	defer close(doneWatch)

	var found *exchange.Exchange
	timedOut, err := waitFor(st, &q, timeout, stop, func(e *exchange.Exchange) bool {
		if !q.match(e) {
			return true
		}
		found = e
		return false
	})
	if err != nil {
		return "", err
	}
	if ctx.Err() != nil {
		return "", errors.New("wait cancelled")
	}
	if timedOut || found == nil {
		return "", fmt.Errorf("no matching exchange within %s (latest id was %d)", timeout, q.after)
	}
	if found.Status >= 400 && found.Response != nil {
		found.Hint = store.HintOf(found.Response)
	}
	prepareForDisplayWith(found, 4000, showSecrets)
	return textsafe.Line(found.SummaryLine()) + "\n" + renderExchangeText(found), nil
}

func mcpCurl(a map[string]any) (string, error) {
	e, err := findExchange(a)
	if err != nil {
		return "", err
	}
	return textsafe.Terminal(curlForExchange(e)), nil
}

func mcpReplay(a map[string]any) (string, error) {
	e, err := findExchange(a)
	if err != nil {
		return "", err
	}
	res := replayExchangeQuiet(newUpstreamClient(insecureUpstream), e, argString(a, "target"))
	b, _ := json.MarshalIndent(res, "", "  ")
	return textsafe.Terminal(string(b)), nil
}
