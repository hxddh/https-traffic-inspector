// Package rules parses and matches httpmon's declarative traffic rules:
//
//	mock   [METHOD] PATTERN [CONDITION…] => STATUS [BODY | @FILE]
//	fault  [METHOD] PATTERN [CONDITION…] => delay 2s | reset | reset after 1KB | timeout  [N%]
//	header [METHOD] PATTERN [CONDITION…] => request|response set NAME: VALUE | remove NAME
//	map    HOST[:PORT] => [SCHEME://]HOST[:PORT]
//
// A PATTERN is a host and path, with * matching any run of characters:
// "api.example.com/v1/orders", "*/upload", "api.example.com/*". A pattern
// without a path matches every path of the host. A CONDITION requires a
// request header: "[header X-Test]" that it is present, "[header
// Authorization: Bearer expired*]" that a value matches; several must all
// hold.
package rules

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kinds of rule.
const (
	KindMock   = "mock"
	KindFault  = "fault"
	KindMap    = "map"
	KindHeader = "header"
)

// Fault actions.
const (
	FaultDelay   = "delay"
	FaultReset   = "reset"
	FaultTimeout = "timeout"
)

// Rule is one parsed rule.
type Rule struct {
	Kind   string
	Source string // as written
	method string // "" matches any
	match  *regexp.Regexp

	// mock
	Status      int
	Body        []byte
	ContentType string

	// fault
	Action string
	Delay  time.Duration
	After  int64   // reset after this many response body bytes; 0 resets before the response
	Prob   float64 // 0 < Prob <= 1

	// map
	From string // host[:port], lower case
	To   *url.URL

	// header
	Dir   string // "request" or "response"
	Op    string // "set" or "remove"
	Name  string // canonical
	Value string

	conds []headerCond
}

// headerCond requires a request header, and a value when val is set.
type headerCond struct {
	name string
	val  *regexp.Regexp
}

var condRE = regexp.MustCompile(`\[header\s+([^\]:]+?)\s*(?::\s*([^\]]*))?\]`)

// Label is how an exchange touched by the rule is marked in output.
func (r *Rule) Label() string { return r.Kind + ": " + r.Source }

// Parse parses one rule of the given kind.
func Parse(kind, text string) (*Rule, error) {
	text = strings.TrimSpace(text)
	lhs, rhs, ok := strings.Cut(text, "=>")
	if !ok {
		return nil, fmt.Errorf("%s rule %q: want \"PATTERN => ACTION\"", kind, text)
	}
	lhs, rhs = strings.TrimSpace(lhs), strings.TrimSpace(rhs)
	r := &Rule{Kind: kind, Source: text, Prob: 1}
	switch kind {
	case KindMap:
		return r, r.parseMap(lhs, rhs)
	case KindMock, KindFault, KindHeader:
		var err error
		if lhs, err = r.parseConds(lhs); err != nil {
			return nil, fmt.Errorf("%s rule %q: %w", kind, text, err)
		}
		if err := r.parseMatch(lhs); err != nil {
			return nil, fmt.Errorf("%s rule %q: %w", kind, text, err)
		}
		switch kind {
		case KindMock:
			err = r.parseMock(rhs)
		case KindFault:
			err = r.parseFault(rhs)
		default:
			err = r.parseHeader(rhs)
		}
		if err != nil {
			return nil, fmt.Errorf("%s rule %q: %w", kind, text, err)
		}
		return r, nil
	}
	return nil, fmt.Errorf("unknown rule kind %q", kind)
}

// parseConds takes the header conditions out of a rule's left side.
func (r *Rule) parseConds(lhs string) (string, error) {
	for _, m := range condRE.FindAllStringSubmatch(lhs, -1) {
		c := headerCond{name: http.CanonicalHeaderKey(strings.TrimSpace(m[1]))}
		if strings.ContainsAny(c.name, " \t") {
			return "", fmt.Errorf("bad header name %q", m[1])
		}
		if v := strings.TrimSpace(m[2]); v != "" {
			re, err := regexp.Compile("^" + glob(v) + "$")
			if err != nil {
				return "", err
			}
			c.val = re
		}
		r.conds = append(r.conds, c)
	}
	rest := strings.TrimSpace(condRE.ReplaceAllString(lhs, ""))
	if strings.ContainsAny(rest, "[]") {
		return "", errors.New(`want "[header NAME]" or "[header NAME: VALUE]"`)
	}
	return rest, nil
}

// parseHeader parses "request|response set NAME: VALUE" or "… remove NAME".
func (r *Rule) parseHeader(rhs string) error {
	dir, rest, _ := strings.Cut(rhs, " ")
	op, rest, _ := strings.Cut(strings.TrimSpace(rest), " ")
	r.Dir, r.Op = strings.ToLower(dir), strings.ToLower(op)
	if r.Dir != "request" && r.Dir != "response" {
		return errors.New(`want "request" or "response" after =>`)
	}
	rest = strings.TrimSpace(rest)
	switch r.Op {
	case "set":
		name, val, ok := strings.Cut(rest, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return errors.New(`want "set NAME: VALUE"`)
		}
		r.Name, r.Value = http.CanonicalHeaderKey(strings.TrimSpace(name)), strings.TrimSpace(val)
	case "remove":
		if rest == "" || strings.ContainsAny(rest, " :") {
			return errors.New(`want "remove NAME"`)
		}
		r.Name = http.CanonicalHeaderKey(rest)
	default:
		return errors.New(`want "set" or "remove"`)
	}
	if strings.ContainsAny(r.Name+r.Value, "\r\n") || strings.ContainsAny(r.Name, " \t") {
		return errors.New("bad header")
	}
	return nil
}

// Apply makes a header rule's change to h.
func (r *Rule) Apply(h http.Header) {
	if r.Op == "set" {
		h.Set(r.Name, r.Value)
	} else {
		h.Del(r.Name)
	}
}

func (r *Rule) parseMatch(lhs string) error {
	fields := strings.Fields(lhs)
	switch len(fields) {
	case 1:
	case 2:
		if fields[0] != "*" {
			r.method = strings.ToUpper(fields[0])
		}
		fields = fields[1:]
	default:
		return errors.New("want \"[METHOD] PATTERN\" before =>")
	}
	pat := fields[0]
	if i := strings.Index(pat, "://"); i >= 0 {
		pat = pat[i+3:]
	}
	if !strings.Contains(pat, "/") {
		pat += "/*"
	}
	host, path, _ := strings.Cut(pat, "/")
	re := "^" + glob(strings.ToLower(host)) + "/" + glob(path) + "$"
	m, err := regexp.Compile(re)
	if err != nil {
		return err
	}
	r.match = m
	return nil
}

// glob turns a * pattern into a regular expression.
func glob(s string) string {
	parts := strings.Split(s, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return strings.Join(parts, ".*")
}

func (r *Rule) parseMock(rhs string) error {
	code, rest, _ := strings.Cut(rhs, " ")
	status, err := strconv.Atoi(code)
	if err != nil || status < 100 || status > 599 {
		return fmt.Errorf("want a status code after =>, got %q", code)
	}
	r.Status = status
	rest = strings.TrimSpace(rest)
	switch {
	case strings.HasPrefix(rest, "@"):
		b, err := os.ReadFile(rest[1:])
		if err != nil {
			return err
		}
		r.Body = b
		r.ContentType = mime.TypeByExtension(filepath.Ext(rest[1:]))
	case rest != "":
		r.Body = []byte(rest)
	}
	if r.ContentType == "" && len(r.Body) > 0 {
		r.ContentType = "text/plain; charset=utf-8"
		if t := strings.TrimSpace(string(r.Body)); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
			r.ContentType = "application/json"
		}
	}
	return nil
}

func (r *Rule) parseFault(rhs string) error {
	fields := strings.Fields(rhs)
	if n := len(fields); n > 0 && strings.HasSuffix(fields[n-1], "%") {
		p, err := strconv.ParseFloat(strings.TrimSuffix(fields[n-1], "%"), 64)
		if err != nil || p <= 0 || p > 100 {
			return fmt.Errorf("bad percentage %q", fields[n-1])
		}
		r.Prob = p / 100
		fields = fields[:n-1]
	}
	if len(fields) == 0 {
		return errors.New("want an action after =>: delay, reset or timeout")
	}
	r.Action = strings.ToLower(fields[0])
	switch {
	case r.Action == FaultDelay && len(fields) == 2:
		d, err := time.ParseDuration(fields[1])
		if err != nil || d <= 0 {
			return fmt.Errorf("bad delay %q", fields[1])
		}
		r.Delay = d
	case r.Action == FaultReset && len(fields) == 1:
	case r.Action == FaultReset && len(fields) == 3 && fields[1] == "after":
		n, err := parseSize(fields[2])
		if err != nil {
			return err
		}
		r.After = n
	case r.Action == FaultTimeout && len(fields) == 1:
	default:
		return fmt.Errorf("unknown fault %q (want delay DURATION, reset, reset after SIZE, or timeout)", strings.Join(fields, " "))
	}
	return nil
}

func parseSize(s string) (int64, error) {
	u := strings.ToUpper(s)
	mult := int64(1)
	for _, suf := range []struct {
		s string
		m int64
	}{{"KB", 1 << 10}, {"MB", 1 << 20}, {"B", 1}} {
		if strings.HasSuffix(u, suf.s) {
			mult, u = suf.m, strings.TrimSuffix(u, suf.s)
			break
		}
	}
	n, err := strconv.ParseInt(u, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("bad size %q (e.g. 512B, 1KB, 2MB)", s)
	}
	return n * mult, nil
}

func (r *Rule) parseMap(lhs, rhs string) error {
	if lhs == "" || strings.ContainsAny(lhs, "/* ") {
		return fmt.Errorf("map rule %q: want \"HOST[:PORT] => [SCHEME://]HOST[:PORT]\"", r.Source)
	}
	r.From = strings.ToLower(lhs)
	to := rhs
	if !strings.Contains(to, "://") {
		to = "http://" + to
	}
	u, err := url.Parse(to)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("map rule %q: bad target %q", r.Source, rhs)
	}
	r.To = u
	return nil
}

// matches reports whether the rule's method, pattern and conditions match a
// request. host has no default port; target is host + path.
func (r *Rule) matches(method, target string, h http.Header) bool {
	if r.method != "" && r.method != method {
		return false
	}
	if !r.match.MatchString(target) {
		return false
	}
	for _, c := range r.conds {
		vals := h.Values(c.name)
		if len(vals) == 0 {
			return false
		}
		if c.val == nil {
			continue
		}
		ok := false
		for _, v := range vals {
			ok = ok || c.val.MatchString(v)
		}
		if !ok {
			return false
		}
	}
	return true
}

// fires decides, for a rule applied to a share of requests, whether this
// request is one of them.
func (r *Rule) fires() bool {
	return r.Prob >= 1 || rand.Float64() < r.Prob //nolint:gosec // not security sensitive
}

// Set is the active rules. It is safe for concurrent use; Replace swaps the
// rules added at run time without disturbing the fixed ones.
type Set struct {
	mu      sync.RWMutex
	fixed   []*Rule
	dynamic []*Rule
}

// NewSet parses the given rules.
func NewSet(mocks, faults, maps []string, headers ...string) (*Set, error) {
	rs, err := parseAll(mocks, faults, maps, headers)
	if err != nil {
		return nil, err
	}
	return &Set{fixed: rs}, nil
}

func parseAll(mocks, faults, maps, headers []string) ([]*Rule, error) {
	var out []*Rule
	for _, l := range []struct {
		kind  string
		rules []string
	}{{KindMock, mocks}, {KindFault, faults}, {KindMap, maps}, {KindHeader, headers}} {
		for _, t := range l.rules {
			r, err := Parse(l.kind, t)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// Replace sets the rules added at run time.
func (s *Set) Replace(mocks, faults, maps []string, headers ...string) error {
	rs, err := parseAll(mocks, faults, maps, headers)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.dynamic = rs
	s.mu.Unlock()
	return nil
}

// Empty reports whether there are no rules at all.
func (s *Set) Empty() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.fixed)+len(s.dynamic) == 0
}

func (s *Set) all() []*Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Rules added at run time come first, so they can override fixed ones.
	return append(append([]*Rule(nil), s.dynamic...), s.fixed...)
}

// Decision is what the rules say to do with one request.
type Decision struct {
	Mock  *Rule // answer with this instead of forwarding
	Fault *Rule // apply this fault
	Map   *Rule // send the request here instead
	// Headers are every header rule that matches, in order.
	Headers []*Rule
}

// Decide matches a request. host is the request's host without a default
// port, path its path, h its headers (for rules with conditions).
func (s *Set) Decide(method, host, path string, h ...http.Header) Decision {
	var hdr http.Header
	if len(h) > 0 {
		hdr = h[0]
	}
	var d Decision
	if s == nil {
		return d
	}
	host = strings.ToLower(host)
	target := host + path
	if !strings.HasPrefix(path, "/") {
		target = host + "/" + path
	}
	for _, r := range s.all() {
		switch r.Kind {
		case KindMock:
			if d.Mock == nil && r.matches(method, target, hdr) && r.fires() {
				d.Mock = r
			}
		case KindFault:
			if d.Fault == nil && r.matches(method, target, hdr) && r.fires() {
				d.Fault = r
			}
		case KindHeader:
			if r.matches(method, target, hdr) {
				d.Headers = append(d.Headers, r)
			}
		case KindMap:
			if d.Map == nil && (r.From == host || r.From == hostOnly(host)) {
				d.Map = r
			}
		}
	}
	return d
}

func hostOnly(h string) string {
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		return h[:i]
	}
	return h
}
