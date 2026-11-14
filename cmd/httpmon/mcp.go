package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v4/internal/rules"
	"github.com/hxddh/https-traffic-inspector/v4/internal/session"
	"github.com/hxddh/https-traffic-inspector/v4/internal/textsafe"
)

// ---- httpmon mcp ----
//
// A Model Context Protocol server over stdio: an agent's client starts
// "httpmon mcp" and gets tools to list sessions, query their exchanges, read
// one in full, see what is in flight and compare two runs. With
// --allow-mutations it can also add mock and fault rules to a running
// session. Credentials are masked unless --show-secrets.

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
	call        func(args map[string]any) (string, error)
}

func cmdMCP(args []string) int {
	fs := flag.NewFlagSet("httpmon mcp", flag.ContinueOnError)
	allowMut := fs.Bool("allow-mutations", false, "offer tools that change a running session: add_rule, clear_rules")
	show := fs.Bool("show-secrets", false, "show credentials instead of masking them")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: httpmon mcp [--allow-mutations] [--show-secrets]

Runs a Model Context Protocol server on stdin and stdout, for an agent's
MCP client. Its tools read httpmon sessions -- list_sessions,
query_exchanges, get_exchange, get_body, in_flight, diff_sessions -- and,
with --allow-mutations, add_rule and clear_rules change the rules of a
running session.

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
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req mcpRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			enc.Encode(mcpResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &mcpError{-32700, "parse error"}}) //nolint:errcheck
			continue
		}
		if len(req.ID) == 0 {
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
					"or `httpmon proxy`. Use query_exchanges for an overview (one line per exchange), then get_exchange or get_body for detail.",
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
			text, err := callTool(t, p.Arguments)
			if err != nil {
				resp.Result = map[string]any{"content": []map[string]any{{"type": "text", "text": err.Error()}}, "isError": true}
				break
			}
			resp.Result = map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
		default:
			resp.Error = &mcpError{-32601, "method not found: " + req.Method}
		}
		if err := enc.Encode(resp); err != nil {
			return 1
		}
	}
	return 0
}

// callTool runs a tool, turning a panic into a tool error: one bad call must
// not end a server the client keeps running.
func callTool(t mcpTool, args map[string]any) (text string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("httpmon: %s failed: %v", t.Name, r)
		}
	}()
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
				"with a digest. Filters combine.",
			InputSchema: schema(map[string]any{
				"session": sessionProp,
				"status":  strProp("statuses: classes (5xx), codes (404), error, comma-separated"),
				"method":  strProp("HTTP method"),
				"url":     strProp("text the URL contains (case-insensitive)"),
				"grep":    strProp("regular expression searched in URL, headers and decoded bodies"),
				"limit":   intProp("most lines to return (default 200; the last ones)"),
			}, "session"),
			Annotations: ro,
			call:        mcpQuery,
		},
		{
			Name:        "get_exchange",
			Description: "One exchange in full: request and response headers, decoded bodies (cut to max_body), error, gRPC status, WebSocket messages.",
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
			Name:        "diff_sessions",
			Description: "Compare two sessions exchange by exchange: changed outcomes, bodies, new and gone requests.",
			InputSchema: schema(map[string]any{
				"before": strProp("the earlier session"),
				"after":  strProp("the later session"),
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
					"fault: '[METHOD] PATTERN => delay 2s | reset | reset after 1KB | timeout [N%]'; map: 'HOST[:PORT] => [SCHEME://]HOST[:PORT]'. " +
					"PATTERN is host/path with * wildcards.",
				InputSchema: schema(map[string]any{
					"session": sessionProp,
					"kind":    map[string]any{"type": "string", "enum": []string{"mock", "fault", "map"}},
					"rule":    strProp("the rule"),
				}, "session", "kind", "rule"),
				Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false},
				call:        mcpAddRule,
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
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\n", s.Name, state, humanBytes(s.Exchanges), s.Modified.Format("2006-01-02 15:04"), textsafe.Line(what))
	}
	return b.String(), nil
}

func mcpQuery(a map[string]any) (string, error) {
	list, err := readExchanges(argString(a, "session"))
	if err != nil {
		return "", err
	}
	var q queryFilter
	q.method, q.url = argString(a, "method"), argString(a, "url")
	if s := argString(a, "status"); s != "" {
		f, err := exchange.ParseFailOn(s)
		if err != nil {
			return "", err
		}
		q.status = f
	}
	if g := argString(a, "grep"); g != "" {
		re, err := regexp.Compile(g)
		if err != nil {
			return "", err
		}
		q.grep = re
	}
	limit := argInt(a, "limit", 200)
	var lines []string
	var d exchange.Digest
	for _, e := range list {
		if !q.match(e) {
			continue
		}
		e.URL = displayURL(e.URL)
		d.Add(e)
		lines = append(lines, textsafe.Line(e.SummaryLine()))
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
	b.WriteString(textsafe.Line(d.String()) + "\n")
	return b.String(), nil
}

func findExchange(a map[string]any) (*exchange.Exchange, error) {
	id := argInt(a, "id", 0)
	list, err := readExchanges(argString(a, "session"))
	if err != nil {
		return nil, err
	}
	for _, e := range list {
		if e.ID == id {
			return e, nil
		}
	}
	return nil, fmt.Errorf("no exchange #%d", id)
}

func mcpGetExchange(a map[string]any) (string, error) {
	e, err := findExchange(a)
	if err != nil {
		return "", err
	}
	displayMaxBody = argInt(a, "max_body", 4000)
	if displayMaxBody <= 0 {
		return "", errors.New("max_body must be greater than 0")
	}
	prepareForDisplay(e)
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
	var sb strings.Builder
	if writeBody(&sb, e, which) != 0 {
		return "", fmt.Errorf("exchange #%d has no %s body", e.ID, which)
	}
	s := textsafe.Terminal(sb.String())
	max := argInt(a, "max_bytes", 100000)
	if max <= 0 {
		return "", errors.New("max_bytes must be greater than 0")
	}
	if len(s) > max {
		s = s[:max] + truncationMarker
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
	if !m.Running() || session.ReadJSON(dir, session.LiveFile, &l) != nil {
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
	before, err := readExchanges(argString(a, "before"))
	if err != nil {
		return "", err
	}
	after, err := readExchanges(argString(a, "after"))
	if err != nil {
		return "", err
	}
	changes, counts := exchange.Diff(before, after, exchange.DefaultDiffOptions)
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
	if err := session.ReadJSON(dir, session.MetaFile, &m); err != nil || !m.Running() {
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
