package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/hxddh/https-traffic-inspector/v4/internal/body"
	"github.com/hxddh/https-traffic-inspector/v4/internal/config"
	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v4/internal/store"
	"github.com/hxddh/https-traffic-inspector/v4/internal/textsafe"
)

// ---- httpmon diff ----
//
// Compares two records -- a run before a change and one after -- and lists
// what is different: exchanges that appeared or disappeared, outcomes that
// changed, bodies that differ (by JSON path), and exchanges that became much
// slower. It answers the question an agent asks after editing code: what did
// that change do to the program's requests?

// Exit codes: no difference, a difference, a record that could not be read.
const (
	exitDiffSame    = 0
	exitDiffChanged = 1
	exitDiffTrouble = 2
)

func cmdDiff(args []string) int {
	fs := flag.NewFlagSet("httpmon diff", flag.ContinueOnError)
	var out outputFlags
	out.register(fs)
	// Paths ignored in every comparison can be set in the settings files.
	var ignore []string
	if cfg, err := config.Load(); err == nil {
		ignore = append(ignore, cfg.Ignore...)
	}
	fs.Func("ignore", "JSON paths not to compare, comma-separated; a path matches any path ending in it (e.g. .updated_at,.request_id)", func(s string) error {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				ignore = append(ignore, p)
			}
		}
		return nil
	})
	format := fs.String("format", "summary", "output format: summary | json")
	noTiming := fs.Bool("no-timing", false, "do not report exchanges that became slower")
	show := fs.Bool("show-secrets", false, "show credentials in URLs instead of masking them")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: httpmon diff <before> <after> [options]

Compares two sessions (names, directories or exchanges files) exchange by exchange. Exchanges are paired by
method, path and query parameter names, in order. Reported:

  +  an exchange only in <after>        -  an exchange only in <before>
  ~  a changed outcome, a request or response body that differs (the first
     differing JSON path is named), or an exchange at least twice as slow
     and 200 ms slower (timing alone does not count as a difference)

Exit status: 0 no difference, 1 differences, 2 a record could not be read.

Options:
`)
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return exitDiffTrouble
	}
	if len(pos) != 2 {
		fs.Usage()
		return exitDiffTrouble
	}
	switch *format {
	case "summary":
	case "json":
		jsonMode = true
	default:
		fmt.Fprintf(os.Stderr, "httpmon diff: unknown --format %q (want summary or json)\n", *format)
		return exitDiffTrouble
	}
	showSecrets = *show

	// Two large sessions' light forms are the whole of what diff holds; a
	// tighter collection target keeps the heap near that.
	debug.SetGCPercent(30)
	before, after, load, closeAll, err := readForDiff(pos[0], pos[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon diff: %v\n", err)
		return exitDiffTrouble
	}
	defer closeAll()
	if _, err := out.open(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "httpmon diff: %v\n", err)
		return exitDiffTrouble
	}

	opt := exchange.DefaultDiffOptions
	opt.Ignore = ignore
	opt.Load = load
	if *noTiming {
		opt.SlowerFactor = 0
	}
	changes, counts := exchange.Diff(before, after, opt)
	for _, c := range changes {
		c.URL = displayURL(c.URL)
		if jsonMode {
			emitJSON(c)
		} else {
			emitText(textsafe.Line(c.Line()) + "\n")
		}
	}
	if jsonMode {
		emitJSON(struct {
			Event  string          `json:"event"`
			Counts exchange.Counts `json:"counts"`
		}{"end", counts})
	} else {
		emitText(counts.String() + "\n")
	}
	if counts.Differs() {
		return exitDiffChanged
	}
	return exitDiffSame
}

// readForDiff reads two sessions in their light form (exchange.Slim) and
// returns how to load an exchange back in full: a diff of large sessions
// then holds little more than their summaries.
func readForDiff(a, b string) (before, after []*exchange.Exchange, load func(*exchange.Exchange) (*exchange.Exchange, error), closeAll func(), err error) {
	sa, err := openStore(a)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sb, err := openStore(b)
	if err != nil {
		sa.Close()
		return nil, nil, nil, nil, err
	}
	sa.Lean()
	sb.Lean()
	stores := []*store.Store{sa, sb}
	closeAll = func() { sa.Close(); sb.Close() }
	read := func(which int) ([]*exchange.Exchange, error) {
		st := stores[which]
		out := make([]*exchange.Exchange, 0, len(st.Entries))
		for i, en := range st.Entries {
			e, err := readWithHint(st, en)
			if err != nil {
				return nil, err
			}
			e.Ref = i*2 + which
			exchange.Slim(e)
			e.Session = intern(e.Session)
			out = append(out, e)
		}
		return out, nil
	}
	if before, err = read(0); err == nil {
		after, err = read(1)
	}
	if err != nil {
		closeAll()
		return nil, nil, nil, nil, err
	}
	load = func(e *exchange.Exchange) (*exchange.Exchange, error) {
		st := stores[e.Ref%2]
		return readWithHint(st, st.Entries[e.Ref/2])
	}
	return before, after, load, closeAll, nil
}

// readWithHint reads one exchange, recovering its error response's hint:
// the hint is not stored, and an outcome such as "500 db_timeout" is more
// telling than "500".
func readWithHint(st *store.Store, en store.Entry) (*exchange.Exchange, error) {
	e, err := st.Read(en)
	if err != nil {
		return nil, err
	}
	if e.Status >= 400 && e.Response != nil {
		e.Hint = hintOf(e.Response)
	}
	return e, nil
}

func hintOf(m *exchange.Message) string {
	b := m.Body
	if b == nil {
		return ""
	}
	if b.Raw != nil {
		raw, err := b.Raw.Bytes()
		if err != nil {
			return ""
		}
		_, hint := body.Render(m.Headers.HTTP(), raw, b.Raw.Truncated, b.Size, 1)
		return hint
	}
	if b.JSON != nil {
		return body.ErrorHint(b.JSON)
	}
	return ""
}

var interned = map[string]string{}

// intern shares one copy of a string repeated across a session's exchanges.
func intern(s string) string {
	if v, ok := interned[s]; ok {
		return v
	}
	interned[s] = s
	return s
}
