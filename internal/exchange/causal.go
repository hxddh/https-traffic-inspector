package exchange

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// CausalLink connects an exchange to an earlier one in the same session: a
// redirect it followed, or a failed request it retried.
type CausalLink struct {
	RedirectFrom int  `json:"redirect_from,omitempty"`
	AuthStripped bool `json:"auth_stripped,omitempty"`
	RetryOf      int  `json:"retry_of,omitempty"`
	Attempt      int  `json:"attempt,omitempty"`
}

type pendingRedirect struct {
	id       int
	fromHost string
	hadAuth  bool
}

type retryState struct {
	firstID  int
	attempts int
	lastAt   time.Time
}

type hostConnStats struct {
	total  int
	reused int
}

// CausalTracker observes exchanges in order, annotates per-exchange CausalLinks,
// and summarises cross-request anomalies for the end-of-run Digest or query --diagnose.
type CausalTracker struct {
	redirects map[string]pendingRedirect // target URL -> 30x source
	retries   map[string]retryState      // METHOD + URL -> retry state
	conns     map[string]*hostConnStats  // host -> HTTPS conn reuse

	authDrops   []string
	corsIssues  []string
	expiredJWTs []int
	retryCount  int
	retryWaitMs float64

	// N+1 sequential burst detection
	curTemplate string
	curRunCount int
	curRunMs    float64
	nPlusOnes   []string
	seenNPlus   map[string]bool
}

// NewCausalTracker creates an empty tracker.
func NewCausalTracker() *CausalTracker {
	return &CausalTracker{
		redirects: map[string]pendingRedirect{},
		retries:   map[string]retryState{},
		conns:     map[string]*hostConnStats{},
		seenNPlus: map[string]bool{},
	}
}

var (
	intSegRE  = regexp.MustCompile(`^\d+$`)
	uuidSegRE = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexSegRE  = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
)

func pathTemplate(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", false
	}
	segs := strings.Split(u.Path, "/")
	parameterised := false
	for i, s := range segs {
		if s == "" {
			continue
		}
		if intSegRE.MatchString(s) || uuidSegRE.MatchString(s) || hexSegRE.MatchString(s) {
			segs[i] = "{id}"
			parameterised = true
		}
	}
	if !parameterised {
		return "", false
	}
	return u.Host + strings.Join(segs, "/"), true
}

// Observe inspects e (using unmasked hasAuth and response Location when known),
// sets e.Cause when a causal link applies, and updates session-wide statistics.
func (ct *CausalTracker) Observe(e *Exchange, hasAuth bool, location string) {
	if ct == nil || e == nil {
		return
	}
	t, _ := parseTime(e.Time)
	if t.IsZero() {
		t = time.Now()
	}

	// 1. Redirect link check.
	normURL := stripDefaultPortURL(e.URL)
	if pr, ok := ct.redirects[normURL]; ok {
		delete(ct.redirects, normURL)
		if e.Cause == nil {
			e.Cause = &CausalLink{}
		}
		e.Cause.RedirectFrom = pr.id
		if pr.hadAuth && !hasAuth {
			e.Cause.AuthStripped = true
			ct.authDrops = append(ct.authDrops, fmt.Sprintf("#%d → #%d redirect dropped Authorization header", pr.id, e.ID))
		}
	}
	if isRedirectStatus(e.Status) && location != "" {
		if target := resolveRedirect(e.URL, location); target != "" {
			u, _ := url.Parse(e.URL)
			host := ""
			if u != nil {
				host = u.Host
			}
			ct.redirects[stripDefaultPortURL(target)] = pendingRedirect{id: e.ID, fromHost: host, hadAuth: hasAuth}
		}
	}

	// 2. Retry chain check.
	if e.Kind == "http" || e.Kind == "" {
		rKey := e.Method + " " + normURL
		if st, ok := ct.retries[rKey]; ok && t.Sub(st.lastAt) <= 30*time.Second {
			st.attempts++
			st.lastAt = t
			if e.Cause == nil {
				e.Cause = &CausalLink{}
			}
			e.Cause.RetryOf = st.firstID
			e.Cause.Attempt = st.attempts
			ct.retryCount++
			ct.retryWaitMs += e.DurationMs
			if isRetryableOutcome(e) {
				ct.retries[rKey] = st
			} else {
				delete(ct.retries, rKey)
			}
		} else if isRetryableOutcome(e) {
			ct.retries[rKey] = retryState{firstID: e.ID, attempts: 1, lastAt: t}
		}
	}

	// 3. HTTPS connection reuse tracking.
	if strings.HasPrefix(e.URL, "https://") && e.Conn != nil && e.Error == nil && e.Rule == "" {
		if u, err := url.Parse(e.URL); err == nil && u.Host != "" {
			cs := ct.conns[u.Host]
			if cs == nil {
				cs = &hostConnStats{}
				ct.conns[u.Host] = cs
			}
			cs.total++
			if e.Conn.Reused {
				cs.reused++
			}
		}
	}

	// 4. N+1 sequential burst detection.
	if e.Method == "GET" {
		if tpl, ok := pathTemplate(e.URL); ok {
			if tpl == ct.curTemplate {
				ct.curRunCount++
				ct.curRunMs += e.DurationMs
			} else {
				ct.flushBurst()
				ct.curTemplate, ct.curRunCount, ct.curRunMs = tpl, 1, e.DurationMs
			}
		} else {
			ct.flushBurst()
		}
	} else {
		ct.flushBurst()
	}

	// 5. Semantic Auth & CORS anomalies.
	if e.Meta != nil {
		if e.Meta.Auth != nil && e.Meta.Auth.Expired && len(ct.expiredJWTs) < 5 {
			ct.expiredJWTs = append(ct.expiredJWTs, e.ID)
		}
		if e.Meta.CORS != nil && e.Meta.CORS.Problem != "" && len(ct.corsIssues) < 3 {
			ct.corsIssues = append(ct.corsIssues, fmt.Sprintf("#%d %s: CORS %s", e.ID, ShortURL(e.URL), e.Meta.CORS.Problem))
		}
	}
}

func (ct *CausalTracker) flushBurst() {
	if ct.curRunCount >= 8 && !ct.seenNPlus[ct.curTemplate] {
		ct.seenNPlus[ct.curTemplate] = true
		ct.nPlusOnes = append(ct.nPlusOnes, fmt.Sprintf("%d sequential GET %s (%s) — likely N+1 pattern",
			ct.curRunCount, ct.curTemplate, formatMs(ct.curRunMs)))
	}
	ct.curTemplate, ct.curRunCount, ct.curRunMs = "", 0, 0
}

// Insights returns concise, high-confidence causal findings, or nil when none occurred.
func (ct *CausalTracker) Insights() []string {
	if ct == nil {
		return nil
	}
	ct.flushBurst()
	var out []string
	out = append(out, ct.authDrops...)
	if len(ct.expiredJWTs) > 0 {
		ids := make([]string, len(ct.expiredJWTs))
		for i, id := range ct.expiredJWTs {
			ids[i] = fmt.Sprintf("#%d", id)
		}
		out = append(out, "expired JWT sent in "+strings.Join(ids, ", "))
	}
	out = append(out, ct.corsIssues...)
	if ct.retryCount > 0 {
		noun := "retries"
		if ct.retryCount == 1 {
			noun = "retry"
		}
		out = append(out, fmt.Sprintf("%d %s (%s spent retrying)", ct.retryCount, noun, formatMs(ct.retryWaitMs)))
	}
	var hosts []string
	for h, cs := range ct.conns {
		if cs.total >= 5 && cs.reused == 0 {
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		cs := ct.conns[h]
		out = append(out, fmt.Sprintf("%d HTTPS requests to %s opened %d new TLS connections (0 reused)", cs.total, h, cs.total))
	}
	out = append(out, ct.nPlusOnes...)
	return out
}

func isRedirectStatus(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

func isRetryableOutcome(e *Exchange) bool {
	return e.Error != nil || e.Status == 429 || e.Status >= 500
}

func resolveRedirect(baseURL, loc string) string {
	b, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	return b.ResolveReference(ref).String()
}

func stripDefaultPortURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	switch {
	case u.Scheme == "https" && strings.HasSuffix(u.Host, ":443"):
		u.Host = strings.TrimSuffix(u.Host, ":443")
	case u.Scheme == "http" && strings.HasSuffix(u.Host, ":80"):
		u.Host = strings.TrimSuffix(u.Host, ":80")
	}
	return u.String()
}

// Diagnosis is a one-shot structured health report of a session, returned by
// "httpmon query --diagnose" and MCP's "diagnose_session".
type Diagnosis struct {
	Exchanges  int            `json:"exchanges"`
	ByStatus   map[string]int `json:"by_status"`
	HardErrors []string       `json:"hard_errors,omitempty"`
	SoftErrors []string       `json:"soft_errors,omitempty"`
	HTTP4xx5xx []string       `json:"http_errors,omitempty"`
	Tunnels    []string       `json:"tunnels,omitempty"`
	Slowest    []string       `json:"slowest,omitempty"`
	Insights   []string       `json:"insights,omitempty"`
}

// Diagnose analyses a session's exchanges into a single compact report.
func Diagnose(list []*Exchange) Diagnosis {
	d := Diagnosis{ByStatus: map[string]int{}}
	ct := NewCausalTracker()
	var httpList []*Exchange
	for _, e := range list {
		d.Exchanges++
		hasAuth := len(e.Request.Headers.HTTP().Values("Authorization")) > 0
		loc := ""
		if e.Response != nil {
			loc = e.Response.Headers.HTTP().Get("Location")
		}
		if e.Cause == nil {
			ct.Observe(e, hasAuth, loc)
		} else {
			// Preserve existing Cause while collecting session-level stats.
			saved := *e.Cause
			ct.Observe(e, hasAuth, loc)
			*e.Cause = saved
		}
		switch {
		case e.Kind == "tunnel":
			d.ByStatus["tunnel"]++
			if len(d.Tunnels) < 10 {
				d.Tunnels = append(d.Tunnels, e.SummaryLine())
			}
		case e.Error != nil:
			d.ByStatus["failed"]++
			if len(d.HardErrors) < 15 {
				d.HardErrors = append(d.HardErrors, e.SummaryLine())
			}
		default:
			if e.Status > 0 {
				d.ByStatus[fmt.Sprintf("%dxx", e.Status/100)]++
			}
			if e.AppError != nil || (e.GRPC != nil && e.GRPC.Code != 0) {
				if len(d.SoftErrors) < 15 {
					d.SoftErrors = append(d.SoftErrors, e.SummaryLine())
				}
			} else if e.Status >= 400 && len(d.HTTP4xx5xx) < 15 {
				d.HTTP4xx5xx = append(d.HTTP4xx5xx, e.SummaryLine())
			}
			if e.WebSocket == nil {
				httpList = append(httpList, e)
			}
		}
	}
	d.Insights = ct.Insights()
	sort.Slice(httpList, func(i, j int) bool { return httpList[i].DurationMs > httpList[j].DurationMs })
	for i := 0; i < len(httpList) && i < 3; i++ {
		e := httpList[i]
		line := fmt.Sprintf("#%d %s %s — %s", e.ID, e.Method, ShortURL(e.URL), formatMs(e.DurationMs))
		if t := e.Timings; t != nil {
			line += fmt.Sprintf(" (dns %s, tcp %s, tls %s, ttfb %s, recv %s)",
				formatMs(t.DNSMs), formatMs(t.TCPMs), formatMs(t.TLSMs), formatMs(t.WaitMs), formatMs(t.RecvMs))
		}
		d.Slowest = append(d.Slowest, line)
	}
	return d
}

// String renders a Diagnosis as a concise human- and agent-readable summary.
func (d Diagnosis) String() string {
	var b strings.Builder
	var parts []string
	keys := make([]string, 0, len(d.ByStatus))
	for k := range d.ByStatus {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d×%s", d.ByStatus[k], k))
	}
	fmt.Fprintf(&b, "Session diagnosis: %d exchange(s)", d.Exchanges)
	if len(parts) > 0 {
		b.WriteString(" (" + strings.Join(parts, ", ") + ")")
	}
	b.WriteByte('\n')

	writeSection := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s:\n", title)
		for _, it := range items {
			fmt.Fprintf(&b, "  %s\n", it)
		}
	}
	writeSection("Causal insights", d.Insights)
	writeSection("Hard failures (network / TLS / tunnel)", d.HardErrors)
	writeSection("Protocol soft errors (HTTP 200 with error)", d.SoftErrors)
	writeSection("HTTP 4xx/5xx responses", d.HTTP4xx5xx)
	writeSection("Relayed non-HTTP tunnels", d.Tunnels)
	writeSection("Slowest exchanges", d.Slowest)
	if len(d.Insights) == 0 && len(d.HardErrors) == 0 && len(d.SoftErrors) == 0 && len(d.HTTP4xx5xx) == 0 {
		b.WriteString("\nNo errors or causal anomalies detected.\n")
	}
	return b.String()
}
