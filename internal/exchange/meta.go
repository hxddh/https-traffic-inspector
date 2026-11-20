package exchange

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SemanticMeta holds non-sensitive protocol and diagnostic metadata derived
// automatically from headers and structured bodies. Secret values are never
// stored here, so it is safe to display without --show-secrets.
type SemanticMeta struct {
	Auth      *AuthMeta      `json:"auth,omitempty"`
	RateLimit *RateLimitMeta `json:"rate_limit,omitempty"`
	Cache     string         `json:"cache,omitempty"`
	CORS      *CORSMeta      `json:"cors,omitempty"`
	GraphQLOp string         `json:"graphql_op,omitempty"`
}

// AuthMeta describes the authentication mechanism and non-secret token metadata.
type AuthMeta struct {
	Scheme       string `json:"scheme"`
	Alg          string `json:"alg,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	Subject      string `json:"subject,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	ExpiresInSec *int64 `json:"expires_in_sec,omitempty"`
	Expired      bool   `json:"expired,omitempty"`
	Region       string `json:"region,omitempty"`
	Service      string `json:"service,omitempty"`
}

// RateLimitMeta normalises common rate-limit response headers.
type RateLimitMeta struct {
	Limit      string `json:"limit,omitempty"`
	Remaining  string `json:"remaining,omitempty"`
	Reset      string `json:"reset,omitempty"`
	RetryAfter string `json:"retry_after,omitempty"`
}

// CORSMeta summarises Cross-Origin Resource Sharing headers and any mismatch
// that would make a browser block the response.
type CORSMeta struct {
	Origin      string `json:"origin"`
	AllowOrigin string `json:"allow_origin,omitempty"`
	Credentials bool   `json:"credentials,omitempty"`
	Problem     string `json:"problem,omitempty"`
}

// ExtractMeta derives non-secret semantic metadata for an exchange.
func ExtractMeta(method string, reqH, respH http.Header, status int, refTime time.Time, gqlOp string) *SemanticMeta {
	var m SemanticMeta
	m.Auth = inspectAuth(reqH, refTime)
	if respH != nil {
		m.RateLimit = inspectRateLimit(respH)
		m.Cache = inspectCache(respH, status)
		m.CORS = inspectCORS(method, reqH, respH)
	}
	m.GraphQLOp = gqlOp
	if m.Auth == nil && m.RateLimit == nil && m.Cache == "" && m.CORS == nil && m.GraphQLOp == "" {
		return nil
	}
	return &m
}

func inspectAuth(h http.Header, refTime time.Time) *AuthMeta {
	if h == nil {
		return nil
	}
	auth := strings.TrimSpace(h.Get("Authorization"))
	if auth == "" {
		for _, k := range []string{"X-Api-Key", "Api-Key", "X-Goog-Api-Key", "X-Auth-Token"} {
			if h.Get(k) != "" {
				return &AuthMeta{Scheme: k}
			}
		}
		return nil
	}
	scheme, rest, hasSpace := strings.Cut(auth, " ")
	if !hasSpace {
		return &AuthMeta{Scheme: "custom"}
	}
	rest = strings.TrimSpace(rest)
	switch strings.ToLower(scheme) {
	case "bearer":
		if jwt := inspectJWT(rest, refTime); jwt != nil {
			return jwt
		}
		return &AuthMeta{Scheme: "Bearer"}
	case "basic":
		return &AuthMeta{Scheme: "Basic"}
	case "aws4-hmac-sha256":
		am := &AuthMeta{Scheme: "AWS4-HMAC-SHA256"}
		if _, after, ok := strings.Cut(rest, "Credential="); ok {
			cred, _, _ := strings.Cut(after, ",")
			parts := strings.Split(strings.TrimSpace(cred), "/")
			// AKID / YYYYMMDD / region / service / aws4_request
			if len(parts) >= 5 {
				am.Region = safeClaim(parts[2])
				am.Service = safeClaim(parts[3])
			}
		}
		return am
	default:
		return &AuthMeta{Scheme: safeClaim(scheme)}
	}
}

func inspectJWT(tok string, refTime time.Time) *AuthMeta {
	// Skip masked tokens ("eyJh…(812 chars)").
	if strings.Contains(tok, "…(") {
		return nil
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return nil
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return nil
	}
	var hdr, pay map[string]any
	if json.Unmarshal(hb, &hdr) != nil || json.Unmarshal(pb, &pay) != nil {
		return nil
	}
	alg, _ := hdr["alg"].(string)
	if alg == "" {
		return nil
	}
	am := &AuthMeta{Scheme: "Bearer (JWT)", Alg: safeClaim(alg)}
	if iss, ok := pay["iss"].(string); ok {
		am.Issuer = safeClaim(iss)
	}
	if sub, ok := pay["sub"].(string); ok {
		am.Subject = safeClaim(sub)
	}
	if exp, ok := claimInt64(pay["exp"]); ok && exp > 0 {
		expTime := time.Unix(exp, 0).UTC()
		am.ExpiresAt = expTime.Format(time.RFC3339)
		if !refTime.IsZero() {
			sec := int64(expTime.Sub(refTime).Seconds())
			am.ExpiresInSec = &sec
			am.Expired = sec < 0
		}
	}
	return am
}

func claimInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func safeClaim(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 48 {
		return string(r[:48]) + "…"
	}
	return s
}

func inspectRateLimit(h http.Header) *RateLimitMeta {
	first := func(keys ...string) string {
		for _, k := range keys {
			if v := strings.TrimSpace(h.Get(k)); v != "" {
				return safeClaim(v)
			}
		}
		return ""
	}
	rl := &RateLimitMeta{
		Limit:      first("RateLimit-Limit", "X-RateLimit-Limit", "X-Rate-Limit-Limit"),
		Remaining:  first("RateLimit-Remaining", "X-RateLimit-Remaining", "X-Rate-Limit-Remaining"),
		Reset:      first("RateLimit-Reset", "X-RateLimit-Reset", "X-Rate-Limit-Reset"),
		RetryAfter: first("Retry-After"),
	}
	if rl.Limit == "" && rl.Remaining == "" && rl.Reset == "" && rl.RetryAfter == "" {
		return nil
	}
	return rl
}

func inspectCache(h http.Header, status int) string {
	if status == http.StatusNotModified {
		return "REVALIDATED"
	}
	for _, k := range []string{"CF-Cache-Status", "X-Vercel-Cache", "X-Cache", "X-Cache-Status"} {
		v := strings.ToUpper(strings.TrimSpace(h.Get(k)))
		switch {
		case v == "":
		case strings.Contains(v, "HIT"):
			return "HIT"
		case strings.Contains(v, "MISS"):
			return "MISS"
		case strings.Contains(v, "BYPASS"):
			return "BYPASS"
		case strings.Contains(v, "STALE"), strings.Contains(v, "REVALIDATED"):
			return "REVALIDATED"
		case v == "DYNAMIC":
			return "DYNAMIC"
		}
	}
	if age := strings.TrimSpace(h.Get("Age")); age != "" {
		if n, err := strconv.Atoi(age); err == nil && n > 0 {
			return "HIT"
		}
	}
	return ""
}

func inspectCORS(method string, reqH, respH http.Header) *CORSMeta {
	if reqH == nil || respH == nil {
		return nil
	}
	origin := strings.TrimSpace(reqH.Get("Origin"))
	if origin == "" {
		return nil
	}
	allowOrigin := strings.TrimSpace(respH.Get("Access-Control-Allow-Origin"))
	creds := strings.EqualFold(strings.TrimSpace(respH.Get("Access-Control-Allow-Credentials")), "true")
	c := &CORSMeta{Origin: safeClaim(origin), AllowOrigin: safeClaim(allowOrigin), Credentials: creds}
	switch {
	case allowOrigin == "":
		c.Problem = "missing Access-Control-Allow-Origin"
	case allowOrigin == "*" && creds:
		c.Problem = "wildcard Allow-Origin cannot be combined with Allow-Credentials: true"
	case allowOrigin != "*" && !strings.EqualFold(allowOrigin, origin):
		c.Problem = "Allow-Origin does not match Origin"
	case strings.EqualFold(method, http.MethodOptions) && reqH.Get("Access-Control-Request-Method") != "":
		wantM := strings.ToUpper(strings.TrimSpace(reqH.Get("Access-Control-Request-Method")))
		allowM := strings.ToUpper(respH.Get("Access-Control-Allow-Methods"))
		if allowM != "*" && !headerListContains(allowM, wantM) {
			c.Problem = "preflight method " + wantM + " not in Access-Control-Allow-Methods"
		}
	}
	return c
}

func headerListContains(list, item string) bool {
	for _, f := range strings.Split(list, ",") {
		if strings.TrimSpace(f) == item {
			return true
		}
	}
	return false
}
