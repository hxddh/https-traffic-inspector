package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hxddh/https-traffic-inspector/v2/internal/exchange"
)

// subcommands are reserved first arguments. Anything else is a command to
// wrap; "httpmon -- query …" wraps a command that is named like one.
func subcommand(name string) func([]string) int {
	switch name {
	case "replay":
		return cmdReplay
	case "query":
		return cmdQuery
	case "ca":
		return cmdCA
	case "schema":
		return cmdSchema
	case "help":
		return cmdHelp
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

// ---- wrap ----

func cmdWrap(args []string) int {
	fs := flag.NewFlagSet("httpmon", flag.ContinueOnError)
	var out outputFlags
	out.register(fs)
	portFlag := fs.String("port", "0", "proxy listen port; 0 picks a random free port")
	listenFlag := fs.String("listen", "127.0.0.1", "address the proxy listens on; anything other than loopback exposes it to the network")
	filterFlag := fs.String("filter", "", "only log requests whose URL or host contains this string (case-insensitive)")
	formatFlag := fs.String("format", os.Getenv("HTTPMON_FORMAT"), "output format: text | summary | json (default: text on a terminal, summary otherwise; $HTTPMON_FORMAT)")
	failOnFlag := fs.String("fail-on", os.Getenv("HTTPMON_FAIL_ON"), "exit 3 if any exchange matches: status classes (5xx), codes (404) or error, comma-separated ($HTTPMON_FAIL_ON)")
	certTTLFlag := fs.Duration("cert-ttl", time.Hour, "how long to cache per-host TLS certificates; 0 disables caching")
	uiFlag := fs.Bool("ui", false, "launch the interactive terminal UI")
	recordFlag := fs.String("record", "", "append each exchange, with its raw bytes, to this NDJSON file")
	harFlag := fs.String("har", "", "write captured traffic as HAR 1.2 JSON")
	insecureFlag := fs.Bool("insecure-upstream", false, "skip TLS certificate verification for upstream servers")
	upstreamProxyFlag := fs.String("upstream-proxy", "", "proxy for httpmon's own upstream requests (default: HTTP(S)_PROXY from the environment)")
	maxBodyFlag := fs.Int("max-body", 1000, "approximate max bytes of each body shown in output")
	maxCaptureFlag := fs.Int("max-capture", 1<<20, "max bytes of each body kept for --record/--har and decoding")
	showSecretsFlag := fs.Bool("show-secrets", false, "show credentials (Authorization, cookies, API keys, signed URLs) in output instead of masking them")
	redactFlag := fs.Bool("redact", false, "mask credentials in --record and --har files too")
	caDirFlag := fs.String("ca-dir", os.Getenv("HTTPMON_CA_DIR"), "use the persistent CA kept in this directory (see: httpmon ca) ($HTTPMON_CA_DIR)")
	versionFlag := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() { usage(fs) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	if *versionFlag {
		fmt.Printf("httpmon %s (%s, %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	}

	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		usage(fs)
		return 1
	}
	// A reserved name after options is ambiguous: say how to mean each.
	if subcommand(cmdArgs[0]) != nil && !dashDashBefore(args, len(cmdArgs)) {
		fmt.Fprintf(os.Stderr, "httpmon: %q is a subcommand; put it first (httpmon %s …), or run a command of that name with: httpmon [options] -- %s …\n",
			cmdArgs[0], cmdArgs[0], cmdArgs[0])
		return 1
	}

	if err := applyLimits(*maxBodyFlag, *maxCaptureFlag); err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: %v\n", err)
		return 1
	}
	showSecrets = *showSecretsFlag
	redactCaptures = *redactFlag
	if err := applyUpstream(*insecureFlag, *upstreamProxyFlag); err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: %v\n", err)
		return 1
	}
	if *failOnFlag != "" {
		f, err := exchange.ParseFailOn(*failOnFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "httpmon: %v\n", err)
			return 1
		}
		runStats.failOn = f
	}

	w, err := out.open(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: cannot open output %s: %v\n", out.path, err)
		return 1
	}
	format := *formatFlag
	if format == "" {
		// The full text is for a person at a terminal. Anything else -- a
		// pipe, a file, an agent's non-interactive shell -- gets the summary,
		// a small fraction of the size; details are a query away.
		format = "summary"
		if isTerminal(w) {
			format = "text"
		}
	}
	switch format {
	case "text":
	case "summary":
		summaryMode = true
	case "json":
		jsonMode = true
	default:
		fmt.Fprintf(os.Stderr, "httpmon: unknown --format %q (want text, summary or json)\n", format)
		return 1
	}

	if *caDirFlag != "" {
		if _, _, err := loadOrCreateCA(*caDirFlag); err != nil {
			fmt.Fprintf(os.Stderr, "httpmon: --ca-dir: %v\n", err)
			return 1
		}
	}

	filterPattern = *filterFlag
	tuiMode = *uiFlag
	recordMode = *recordFlag != ""
	harMode = *harFlag != ""
	harPath = *harFlag
	certTTL = *certTTLFlag

	if recordMode {
		if err := openRecordFile(*recordFlag); err != nil {
			fmt.Fprintf(os.Stderr, "httpmon: cannot open record file %s: %v\n", *recordFlag, err)
			return 1
		}
		addCleanup(func() { recordFile.Close() }) //nolint:errcheck
	}
	if harMode {
		if err := openHARFile(harPath); err != nil {
			fmt.Fprintf(os.Stderr, "httpmon: cannot create HAR file %s: %v\n", harPath, err)
			return 1
		}
		// finishHAR normally closes it; this covers the early exits.
		addCleanup(func() { closeHAR() }) //nolint:errcheck
	}
	if certTTL > 0 {
		// Sweep expired entries at 1/6 of the TTL interval, minimum every minute.
		sweep := certTTL / 6
		if sweep < time.Minute {
			sweep = time.Minute
		}
		startCertJanitor(sweep)
	}

	caCertPath, err := buildCABundle(caPEM())
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: failed to build CA bundle: %v\n", err)
		return 1
	}
	addCleanup(func() { os.Remove(caCertPath) }) //nolint:errcheck

	trustStore, err := buildJavaTrustStore(caCertPath)
	if err != nil {
		// Only Java needs it; everything else can still be inspected.
		fmt.Fprintf(os.Stderr, "httpmon: Java truststore not created, JVM tools will not be configured: %v\n", err)
	} else {
		addCleanup(func() { os.Remove(trustStore) }) //nolint:errcheck
	}

	listenAddr := net.JoinHostPort(*listenFlag, *portFlag)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: failed to bind proxy on %s: %v\n", listenAddr, err)
		return 1
	}
	proxyPort = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	if !isLoopbackHost(*listenFlag) {
		fmt.Fprintf(os.Stderr,
			"httpmon: WARNING: proxy listening on %s is reachable from the network; anyone who can reach it can use it, including to reach services bound to this machine's loopback\n",
			ln.Addr())
	}
	// What the wrapped command dials. A wildcard bind is reached via loopback.
	dialHost := proxyDialHost(*listenFlag)
	proxyURL := "http://" + net.JoinHostPort(dialHost, proxyPort)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleConnect(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		// Bounds how long a connection may sit mid-header. Request bodies and
		// hijacked CONNECT tunnels are unaffected, so long-lived streams and
		// WebSocket splices still work.
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			// Print rather than exit: the subprocess is already running and
			// os.Exit here would skip cleanup of the CA bundle.
			fmt.Fprintf(os.Stderr, "httpmon: proxy error: %v\n", err)
		}
	}()

	if strings.EqualFold(strings.TrimSuffix(filepath.Base(cmdArgs[0]), ".exe"), "curl") {
		cmdArgs, err = curlArgs(cmdArgs, proxyURL, caCertPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "httpmon: %v\n", err)
			return 1
		}
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = subprocessEnv(os.Environ(), proxyURL, caCertPath)
	if trustStore != "" {
		cmd.Env = append(cmd.Env, "JAVA_TOOL_OPTIONS="+
			javaToolOptions(lookupEnv(os.Environ(), "JAVA_TOOL_OPTIONS"), dialHost, proxyPort, trustStore))
	}

	currentSink().start(runInfo{
		Version: version, Proxy: ln.Addr().String(), Command: cmdArgs,
		Filter: filterPattern, CA: caCertPath,
	})

	if tuiMode {
		return runWithTUI(cmd)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		if cmd.Process != nil {
			cmd.Process.Signal(sig) //nolint:errcheck
		}
	}()

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "httpmon: %v\n", err)
			exitCode = 1
		}
	}

	drainInflight(exitDrainTimeout)
	return finishRun(exitCode)
}

// exitFailOn is the exit code when the command succeeded but an exchange
// matched --fail-on.
const exitFailOn = 3

// finishRun reports the end of the run and settles the exit code: the
// command's own failure first, then a HAR that could not be written, then
// --fail-on.
func finishRun(exitCode int) int {
	d := runStats.final()
	currentSink().end(d)
	exitCode = finishHAR(exitCode)
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
		fmt.Fprintln(os.Stderr, "Usage: httpmon replay <record> [options]")
		fmt.Fprintln(os.Stderr, "\nRe-sends each exchange of a --record file and compares the responses.\n\nOptions:")
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
	dir := fs.String("dir", os.Getenv("HTTPMON_CA_DIR"), "directory that keeps the CA ($HTTPMON_CA_DIR)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: httpmon ca --dir <dir>")
		fmt.Fprintln(os.Stderr, "\nCreates a persistent CA in <dir>, or shows the one already there.")
		fmt.Fprintln(os.Stderr, "Use it with: httpmon --ca-dir <dir> <command>\n\nOptions:")
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
  httpmon query  <record> [filters]       list or expand exchanges from a --record file
  httpmon replay <record> [options]       re-send recorded requests and compare responses
  httpmon ca     --dir <dir>              create or show a persistent CA
  httpmon schema                          print the JSON Schema of an exchange record
  httpmon help   [agents]                 this help, or a guide for AI agents

httpmon's output goes to stderr (or -o <file>); the command's stdout is left untouched.
On a terminal it shows full text; anywhere else, a one-line summary per exchange.

Options:
`)
	fs.PrintDefaults()
	fmt.Fprint(os.Stderr, `
Examples:
  httpmon curl https://api.github.com
  httpmon --fail-on 5xx,error --record trace.ndjson npm test
  httpmon query trace.ndjson --status 5xx
  httpmon --format json -o trace.ndjson curl https://api.github.com
  httpmon --ui curl https://api.github.com
  httpmon replay trace.ndjson --target https://staging.example.com
`)
}
