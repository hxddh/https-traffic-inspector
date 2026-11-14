package main

import (
	"bytes"
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
	"sync"
	"syscall"
	"time"

	"github.com/mattn/go-isatty"
)

var (
	proxyPort string

	// set by flags
	filterPattern    string
	jsonMode         bool
	tuiMode          bool
	recordMode       bool
	harMode          bool
	harPath          string
	insecureUpstream bool
	upstreamProxy    *url.URL  // --upstream-proxy; nil means use the environment
	displayMaxBody   = 1000    // --max-body: bytes of body shown in text/JSON/TUI output
	captureMaxBody   = 1 << 20 // --max-capture: bytes of body kept for --record/--har/decompression
)

// version is the released build identifier, injected at link time with
// -ldflags "-X main.version=<tag>".
var version = "dev"

func init() {
	var err error
	caCert, caKey, err = generateCA()
	if err != nil {
		log.Fatal("Failed to generate CA:", err)
	}

	// Verified by default; run() replaces this once --insecure-upstream is parsed.
	upstreamClient = newUpstreamClient(false)
	h2cClient = newH2CClient()
}

// ---- cleanup ----

var (
	cleanups   []func()
	cleanupsMu sync.Mutex
)

// addCleanup registers a function to run before run() returns. An explicit list
// is used instead of defer because run() has several exit points and because it
// lets tests trigger cleanup directly.
func addCleanup(f func()) {
	cleanupsMu.Lock()
	cleanups = append(cleanups, f)
	cleanupsMu.Unlock()
}

// runCleanups executes registered cleanups in reverse registration order.
func runCleanups() {
	cleanupsMu.Lock()
	fs := cleanups
	cleanups = nil
	cleanupsMu.Unlock()
	for i := len(fs) - 1; i >= 0; i-- {
		fs[i]()
	}
}

// matchesFilter reports whether the request URL or host contains filterPattern.
// When filterPattern is empty every request matches.
func matchesFilter(req *http.Request) bool {
	if filterPattern == "" {
		return true
	}
	p := strings.ToLower(filterPattern)
	return strings.Contains(strings.ToLower(req.URL.String()), p) ||
		strings.Contains(strings.ToLower(req.Host), p) ||
		strings.Contains(strings.ToLower(req.URL.Path), p)
}

// isLoopbackHost reports whether a listen address only accepts local
// connections. "localhost" counts: it resolves to loopback addresses.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// proxyDialHost returns the host the wrapped command should dial to reach a
// proxy listening on listenHost. An unspecified (wildcard) address accepts
// connections but cannot be dialled, so loopback stands in for it. A literal
// IP is used rather than "localhost", which may resolve to ::1 while the
// listener is IPv4-only.
func proxyDialHost(listenHost string) string {
	if listenHost == "" || strings.EqualFold(listenHost, "localhost") {
		return "127.0.0.1"
	}
	if ip := net.ParseIP(listenHost); ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			return "127.0.0.1"
		}
		return "::1"
	}
	return listenHost
}

func main() { os.Exit(run()) }

// stringFlag registers one string flag under several names, such as -o and
// --output.
func stringFlag(p *string, names []string, value, usage string) {
	for _, n := range names {
		flag.StringVar(p, n, value, usage)
	}
}

// run holds the whole program body so that every exit path returns a code
// instead of calling os.Exit directly, which would skip cleanup.
func run() int {
	defer runCleanups()

	var outputPath string
	portFlag := flag.String("port", "0", "proxy listen port; 0 picks a random free port")
	listenFlag := flag.String("listen", "127.0.0.1", "address the proxy listens on; anything other than loopback exposes it to the network")
	filterFlag := flag.String("filter", "", "only log requests whose URL or host contains this string (case-insensitive)")
	formatFlag := flag.String("format", "text", "output format: text | json")
	stringFlag(&outputPath, []string{"o", "output"}, "", "write httpmon's output to this file instead of stderr; \"-\" for stdout")
	certTTLFlag := flag.Duration("cert-ttl", time.Hour, "how long to cache per-host TLS certificates; 0 disables caching")
	uiFlag := flag.Bool("ui", false, "launch interactive terminal UI (TUI)")
	recordFlag := flag.String("record", "", "path to write recorded traffic as NDJSON (appends if file exists)")
	harFlag := flag.String("har", "", "write captured traffic as HAR 1.2 JSON")
	replayFlag := flag.String("replay", "", "path of a recorded NDJSON file to replay (skips proxy, no <command> needed)")
	replayTargetFlag := flag.String("replay-target", "", "override base URL for replay (e.g. https://staging.example.com)")
	replayDelayFlag := flag.Duration("replay-delay", 0, "pause between replayed requests")
	replayFailFlag := flag.Bool("replay-fail-on-diff", false, "exit with code 2 if any replayed response differs from the recording")
	insecureFlag := flag.Bool("insecure-upstream", false, "skip TLS certificate verification for upstream servers")
	upstreamProxyFlag := flag.String("upstream-proxy", "", "proxy for httpmon's own upstream requests (default: HTTP(S)_PROXY from the environment)")
	maxBodyFlag := flag.Int("max-body", 1000, "max bytes of each body shown in output")
	maxCaptureFlag := flag.Int("max-capture", 1<<20, "max bytes of each body kept for --record/--har and decompression")
	showSecretsFlag := flag.Bool("show-secrets", false, "show credentials (Authorization, cookies, API keys, signed URLs) in output instead of masking them")
	redactFlag := flag.Bool("redact", false, "mask credentials in --record and --har files too")
	caDirFlag := flag.String("ca-dir", os.Getenv("HTTPMON_CA_DIR"), "keep the CA in this directory across runs, creating it on first use (default $HTTPMON_CA_DIR)")
	noColorFlag := flag.Bool("no-color", false, "disable coloured output")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: httpmon [options] <command> [args...]")
		fmt.Fprintln(os.Stderr, "       httpmon --replay <file> [--replay-target <url>]")
		fmt.Fprintln(os.Stderr, "       httpmon --ca-dir <dir>        (create or show a persistent CA)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "httpmon's output goes to stderr (or -o <file>); the command's stdout is left untouched.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  httpmon curl https://api.github.com")
		fmt.Fprintln(os.Stderr, "  httpmon curl -s https://api.github.com | jq .   # jq gets curl's output")
		fmt.Fprintln(os.Stderr, "  httpmon --filter /api curl https://example.com/api/v1/users")
		fmt.Fprintln(os.Stderr, "  httpmon --format json -o trace.ndjson curl https://api.github.com")
		fmt.Fprintln(os.Stderr, "  httpmon --ui curl https://api.github.com")
		fmt.Fprintln(os.Stderr, "  httpmon --record traffic.ndjson curl https://api.github.com")
		fmt.Fprintln(os.Stderr, "  httpmon --har traffic.har curl https://api.github.com")
		fmt.Fprintln(os.Stderr, "  httpmon --replay traffic.ndjson --replay-target https://staging.example.com")
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("httpmon %s (%s, %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	}

	if *maxBodyFlag <= 0 || *maxCaptureFlag <= 0 {
		fmt.Fprintln(os.Stderr, "httpmon: --max-body and --max-capture must be greater than 0")
		return 1
	}
	if *maxCaptureFlag < *maxBodyFlag {
		fmt.Fprintln(os.Stderr, "httpmon: --max-capture must not be smaller than --max-body")
		return 1
	}
	displayMaxBody = *maxBodyFlag
	captureMaxBody = *maxCaptureFlag
	showSecrets = *showSecretsFlag
	redactCaptures = *redactFlag

	if *upstreamProxyFlag != "" {
		u, err := url.Parse(*upstreamProxyFlag)
		if err != nil || u.Host == "" {
			fmt.Fprintf(os.Stderr, "httpmon: invalid --upstream-proxy %q\n", *upstreamProxyFlag)
			return 1
		}
		upstreamProxy = u
	}

	switch *formatFlag {
	case "text", "json":
	default:
		fmt.Fprintf(os.Stderr, "httpmon: unknown --format %q (want text or json)\n", *formatFlag)
		return 1
	}
	jsonMode = *formatFlag == "json"
	// Assigned before the replay branch so replay honours it too: a recording
	// captured from a self-signed or internal-CA host must be replayable.
	insecureUpstream = *insecureFlag
	upstreamClient = newUpstreamClient(insecureUpstream)
	h2cClient = newH2CClient()

	// ── Output channel ───────────────────────────────────────────────────────
	// Replay has no wrapped command, so its results are its stdout.
	defaultOut := os.Stderr
	if *replayFlag != "" {
		defaultOut = os.Stdout
	}
	out, closeOut, err := openOutput(outputPath, defaultOut)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: cannot open output %s: %v\n", outputPath, err)
		return 1
	}
	addCleanup(closeOut)
	setOutput(out)
	useColor = !*noColorFlag && os.Getenv("NO_COLOR") == "" && isTerminal(out)

	// ── Replay mode: no proxy, no subprocess ─────────────────────────────────
	if *replayFlag != "" {
		return replayFile(*replayFlag, *replayTargetFlag, *replayDelayFlag, *replayFailFlag)
	}

	// ── CA ───────────────────────────────────────────────────────────────────
	cmdArgs := flag.Args()
	if *caDirFlag != "" {
		certPath, created, err := loadOrCreateCA(*caDirFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "httpmon: --ca-dir: %v\n", err)
			return 1
		}
		if len(cmdArgs) == 0 {
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
	}

	filterPattern = *filterFlag
	tuiMode = *uiFlag
	recordMode = *recordFlag != ""
	harMode = *harFlag != ""
	harPath = *harFlag
	certTTL = *certTTLFlag

	if len(cmdArgs) < 1 {
		flag.Usage()
		return 1
	}

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

	// The banner is diagnostic, so it goes to stderr whatever -o says.
	if !tuiMode {
		var b strings.Builder
		fmt.Fprintf(&b, "httpmon %s: proxy on %s, CA bundle %s\n", version, ln.Addr(), caCertPath)
		if filterPattern != "" {
			fmt.Fprintf(&b, "httpmon: filter %q\n", filterPattern)
		}
		if insecureUpstream {
			b.WriteString("httpmon: upstream TLS verification DISABLED (--insecure-upstream)\n")
		}
		if outputPath != "" && outputPath != "-" {
			fmt.Fprintf(&b, "httpmon: writing output to %s\n", outputPath)
		}
		fmt.Fprintf(&b, "httpmon: running %s\n", strings.Join(cmdArgs, " "))
		fmt.Fprint(os.Stderr, b.String())
	}

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
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "httpmon: %v\n", err)
			exitCode = 1
		}
	}

	drainInflight(exitDrainTimeout)
	return finishHAR(exitCode)
}

// runWithTUI runs cmd behind the interactive UI. The command's output is held
// back while the UI owns the terminal and replayed afterwards, stdout to
// stdout and stderr to stderr. It gets no stdin: the UI reads the keyboard.
func runWithTUI(cmd *exec.Cmd) int {
	var subOut, subErr bytes.Buffer
	cmd.Stdout = &subOut
	cmd.Stderr = &subErr
	cmd.Stdin = nil

	// Draw on the terminal. When stdout is redirected it is the command's
	// output, so draw on stderr.
	if !isTerminal(os.Stdout) {
		tuiOut = os.Stderr
	}

	exitCh := make(chan int, 1)
	go func() {
		code := 0
		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			} else {
				noticef("%v", err)
				code = 1
			}
		}
		tuiSend(tuiDoneMsg{code})
		exitCh <- code
	}()

	runTUI()

	// Kill subprocess if user quit the TUI before it finished.
	if cmd.Process != nil {
		cmd.Process.Kill() //nolint:errcheck
	}
	code := <-exitCh
	drainInflight(exitDrainTimeout)

	printTUINotices(os.Stderr)
	os.Stdout.Write(subOut.Bytes()) //nolint:errcheck
	os.Stderr.Write(subErr.Bytes()) //nolint:errcheck
	return finishHAR(code)
}

// openOutput opens httpmon's output destination: def when path is empty,
// stdout for "-", otherwise the named file.
func openOutput(path string, def *os.File) (io.Writer, func(), error) {
	switch path {
	case "":
		return def, func() {}, nil
	case "-":
		return os.Stdout, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil //nolint:errcheck
}

// isTerminal reports whether w is a terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && (isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()))
}

// curlArgs points a curl command line at httpmon: -x for the proxy and a CA
// bundle that includes httpmon's CA. Options the user already gave are
// respected -- their own -x means they chose another route, -k means no
// verification is wanted -- but their own --cacert is merged with httpmon's CA
// rather than left to fail against httpmon's certificates.
func curlArgs(args []string, proxyURL, caBundle string) ([]string, error) {
	hasProxy, hasInsecure := false, false
	caIdx, caInline := -1, false // position of the user's --cacert value
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		switch {
		case a == "--proxy" || a == "-x" || strings.HasPrefix(a, "--proxy="):
			hasProxy = true
			if !strings.Contains(a, "=") {
				i++
			}
		case a == "--insecure":
			hasInsecure = true
		case a == "--cacert":
			caIdx = i + 1
			i++
		case strings.HasPrefix(a, "--cacert="):
			caIdx, caInline = i, true
		case strings.HasPrefix(a, "--"):
			if curlLongTakesValue[strings.SplitN(a[2:], "=", 2)[0]] && !strings.Contains(a, "=") {
				i++
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			// A cluster of short options; the first one that takes a value
			// consumes the rest of the cluster, or the next argument.
			for j := 1; j < len(a); j++ {
				c := a[j]
				if c == 'k' {
					hasInsecure = true
				}
				if strings.IndexByte(curlShortTakesValue, c) >= 0 {
					if c == 'x' {
						hasProxy = true
					}
					if j == len(a)-1 {
						i++
					}
					break
				}
			}
		}
	}

	out := []string{args[0]}
	if !hasProxy {
		out = append(out, "-x", proxyURL)
	}
	rest := append([]string(nil), args[1:]...)
	if caIdx > 0 && caIdx < len(args) && !hasInsecure {
		userCA := args[caIdx]
		if caInline {
			userCA = strings.TrimPrefix(args[caIdx], "--cacert=")
		}
		merged, err := mergeCABundle(userCA, caBundle)
		if err != nil {
			return nil, fmt.Errorf("cannot read --cacert %s: %w", userCA, err)
		}
		addCleanup(func() { os.Remove(merged) }) //nolint:errcheck
		if caInline {
			rest[caIdx-1] = "--cacert=" + merged
		} else {
			rest[caIdx-1] = merged
		}
	} else if caIdx < 0 && !hasInsecure {
		out = append(out, "--cacert", caBundle)
	}
	return append(out, rest...), nil
}

// curlShortTakesValue lists curl's short options that take an argument.
const curlShortTakesValue = "AbcCdDeEFHKmoPQrtTuUwxXyYz"

// curlLongTakesValue lists common long options that take an argument, so
// their value is not mistaken for an option.
var curlLongTakesValue = map[string]bool{
	"data": true, "data-binary": true, "data-raw": true, "data-urlencode": true, "data-ascii": true,
	"header": true, "output": true, "user": true, "user-agent": true, "referer": true,
	"request": true, "form": true, "upload-file": true, "write-out": true, "max-time": true,
	"connect-timeout": true, "cookie": true, "cookie-jar": true, "cert": true, "key": true,
	"resolve": true, "connect-to": true, "proxy-user": true, "json": true, "url": true,
	"capath": true, "config": true, "range": true, "retry": true, "limit-rate": true,
	"noproxy": true, "proxy-header": true, "variable": true, "aws-sigv4": true, "oauth2-bearer": true,
}

// mergeCABundle writes a bundle holding the user's CA file and httpmon's.
func mergeCABundle(userCA, ours string) (string, error) {
	a, err := os.ReadFile(userCA)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(ours)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "httpmon-curl-ca-*.crt")
	if err != nil {
		return "", err
	}
	data := append(append(a, '\n'), b...)
	if _, err := f.Write(data); err != nil {
		f.Close() //nolint:errcheck
		return "", err
	}
	return f.Name(), f.Close()
}

// exitDrainTimeout bounds how long httpmon waits, once the wrapped command
// has exited, for exchanges still in flight to be logged and recorded.
const exitDrainTimeout = 3 * time.Second

// finishHAR completes the HAR file when --har is active, promoting a write
// failure to a non-zero exit code so a silent loss of captured traffic is
// impossible.
func finishHAR(exitCode int) int {
	if !harMode {
		return exitCode
	}
	if err := closeHAR(); err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: failed to write HAR file %s: %v\n", harPath, err)
		if exitCode == 0 {
			return 1
		}
	}
	return exitCode
}
