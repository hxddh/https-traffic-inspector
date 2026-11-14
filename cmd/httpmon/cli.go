package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
)

// subcommands are reserved first arguments. Anything else is a command to
// wrap; "httpmon -- query …" wraps a command that is named like one.
func subcommand(name string) func([]string) int {
	switch name {
	case "replay":
		return cmdReplay
	case "query":
		return cmdQuery
	case "diff":
		return cmdDiff
	case "ca":
		return cmdCA
	case "schema":
		return cmdSchema
	case "help":
		return cmdHelp
	case "proxy":
		return cmdProxy
	case "env":
		return cmdEnv
	case "mock":
		return cmdMock
	case "sessions":
		return cmdSessions
	case "mcp":
		return cmdMCP
	case "ui":
		return cmdUI
	}
	return nil
}

// run holds the whole program body so that every exit path returns a code
// instead of calling os.Exit directly, which would skip cleanup.
func run() int {
	defer runCleanups()
	args := os.Args[1:]
	if len(args) > 0 {
		if cmd := subcommand(args[0]); cmd != nil {
			return cmd(args[1:])
		}
	}
	return cmdWrap(args)
}

// stringFlag registers one string flag under several names, such as -o and
// --output.
func stringFlag(fs *flag.FlagSet, p *string, names []string, value, usage string) {
	for _, n := range names {
		fs.StringVar(p, n, value, usage)
	}
}

// parseInterspersed parses fs from args, allowing flags after positional
// arguments ("httpmon query trace.ndjson --id 3"), and returns the positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// outputFlags are shared by every subcommand that writes results.
type outputFlags struct {
	path    string
	noColor bool
}

func (o *outputFlags) register(fs *flag.FlagSet) {
	stringFlag(fs, &o.path, []string{"o", "output"}, "", "write output to this file instead of the default stream; \"-\" for stdout")
	fs.BoolVar(&o.noColor, "no-color", false, "disable coloured output")
}

// open directs httpmon's output, and returns where it went.
func (o *outputFlags) open(def *os.File) (io.Writer, error) {
	out, closeOut, err := openOutput(o.path, def)
	if err != nil {
		return nil, err
	}
	addCleanup(closeOut)
	setOutput(out)
	useColor = !o.noColor && os.Getenv("NO_COLOR") == "" && isTerminal(out)
	return out, nil
}

// exitFailOn is the exit code when the command succeeded but an exchange
// matched --fail-on.
const exitFailOn = 3

// finishRun reports the end of the run and settles the exit code: the
// command's own failure first, then --fail-on.
func finishRun(exitCode int) int {
	pending := unfinishedExchanges()
	for _, p := range pending {
		currentSink().incomplete(p)
	}
	d := runStats.final(pending)
	currentSink().end(d)
	finishSession()
	if exitCode == 0 && len(d.Matched) > 0 {
		return exitFailOn
	}
	return exitCode
}

// dashDashBefore reports whether the n trailing arguments of args were
// introduced by "--".
func dashDashBefore(args []string, n int) bool {
	i := len(args) - n - 1
	return i >= 0 && args[i] == "--"
}

func applyLimits(maxBody, maxCapture int) error {
	if maxBody <= 0 || maxCapture <= 0 {
		return errors.New("--max-body and --max-capture must be greater than 0")
	}
	if maxCapture < maxBody {
		return errors.New("--max-capture must not be smaller than --max-body")
	}
	displayMaxBody, captureMaxBody = maxBody, maxCapture
	return nil
}

func applyUpstream(insecure bool, proxy string) error {
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid --upstream-proxy %q", proxy)
		}
		upstreamProxy = u
	}
	insecureUpstream = insecure
	upstreamClient = newUpstreamClient(insecureUpstream)
	h2cClient = newH2CClient()
	return nil
}

// ---- replay ----

func cmdReplay(args []string) int {
	fs := flag.NewFlagSet("httpmon replay", flag.ContinueOnError)
	var out outputFlags
	out.register(fs)
	target := fs.String("target", "", "replace the scheme and host of every URL (e.g. https://staging.example.com)")
	delay := fs.Duration("delay", 0, "pause between replayed requests")
	failOnDiff := fs.Bool("fail-on-diff", false, "exit 2 if any response differs from the recording")
	format := fs.String("format", "text", "output format: text | json")
	insecure := fs.Bool("insecure-upstream", false, "skip TLS certificate verification")
	proxy := fs.String("upstream-proxy", "", "proxy for replayed requests (default: HTTP(S)_PROXY)")
	maxCapture := fs.Int("max-capture", 1<<20, "max bytes of each response read for comparison")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: httpmon replay <session> [options]")
		fmt.Fprintln(os.Stderr, "\nRe-sends each exchange of a session and compares the responses.\n\nOptions:")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return flagErr(err)
	}
	if len(pos) != 1 {
		fs.Usage()
		return 1
	}
	if err := applyLimits(1, *maxCapture); err != nil {
		fmt.Fprintf(os.Stderr, "httpmon replay: %v\n", err)
		return 1
	}
	if err := applyUpstream(*insecure, *proxy); err != nil {
		fmt.Fprintf(os.Stderr, "httpmon replay: %v\n", err)
		return 1
	}
	switch *format {
	case "text":
	case "json":
		jsonMode = true
	default:
		fmt.Fprintf(os.Stderr, "httpmon replay: unknown --format %q (want text or json)\n", *format)
		return 1
	}
	if _, err := out.open(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "httpmon replay: %v\n", err)
		return 1
	}
	return replayFile(pos[0], *target, *delay, *failOnDiff)
}

// ---- ca ----

func cmdCA(args []string) int {
	fs := flag.NewFlagSet("httpmon ca", flag.ContinueOnError)
	dir := fs.String("dir", defaultCADir(), "directory that keeps the CA ($HTTPMON_CA_DIR; default: ca in httpmon's home)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: httpmon ca [--dir <dir>]")
		fmt.Fprintln(os.Stderr, "\nCreates the persistent CA, or shows the one already there. \"httpmon proxy\"")
		fmt.Fprintln(os.Stderr, "uses it automatically; trust its certificate once on each device.\n\nOptions:")
		fs.PrintDefaults()
	}
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	if *dir == "" {
		fs.Usage()
		return 1
	}
	certPath, created, err := loadOrCreateCA(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon ca: %v\n", err)
		return 1
	}
	verb := "Using"
	if created {
		verb = "Created"
	}
	fmt.Printf("%s httpmon CA: %s\n", verb, certPath)
	fmt.Printf("  %s\n  valid until %s\n", caCert.Subject.CommonName, caCert.NotAfter.Format("2006-01-02"))
	fmt.Println("Import this certificate into a device or trust store to let it trust httpmon.")
	fmt.Println("Keep the directory private: its key can intercept every connection that trusts this CA.")
	return 0
}

func flagErr(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 1
}

// ---- usage ----

func usage(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage:
  httpmon [options] <command> [args...]   run a command and show its HTTP(S) traffic
  httpmon proxy  [options]                run as a proxy for browsers, devices and services
  httpmon env    [--session NAME]         shell exports that route commands through a running proxy
  httpmon query  <session> [filters]      list, search, expand or export exchanges; --wait for one
  httpmon ui     <session>                interactive UI on a session, live while it runs
  httpmon diff   <before> <after>         compare two sessions: what changed between runs
  httpmon replay <session> [options]      re-send recorded requests and compare responses
  httpmon mock   <session> [--port N]     serve recorded responses as an offline mock server
  httpmon sessions [rm NAME | prune]      list or remove sessions
  httpmon mcp    [--allow-mutations]      MCP server over stdio, for AI agents
  httpmon ca     [--dir DIR]              create or show the persistent CA
  httpmon schema                          print the JSON Schema of an exchange
  httpmon help   [agents]                 this help, or a guide for AI agents

httpmon's output goes to stderr (or -o <file>); the command's stdout is left untouched.
On a terminal it shows full text; anywhere else, a one-line summary per exchange.
Settings can also come from ~/.config/httpmon/config.toml and a project's .httpmon.toml.

Options:
`)
	fs.PrintDefaults()
	fmt.Fprint(os.Stderr, `
Examples:
  httpmon curl https://api.github.com
  httpmon --fail-on 5xx,error --session test npm test
  httpmon query test --status 5xx
  httpmon --mock 'GET api.example.com/v1/orders => 503 {"error":"maintenance"}' npm test
  httpmon --fault '* api.example.com/* => delay 2s 30%' pytest
  httpmon --header '*/api/* => response remove Cache-Control' npm start
  httpmon query test --wait --status 5xx --timeout 30s
  httpmon diff before after --ignore .updated_at
  httpmon proxy --ui
  httpmon proxy --listen 0.0.0.0 --port 8080
  httpmon --ui curl https://api.github.com
`)
}
