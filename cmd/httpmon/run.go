package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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

	"github.com/hxddh/https-traffic-inspector/v4/internal/config"
	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v4/internal/rules"
	"github.com/hxddh/https-traffic-inspector/v4/internal/session"
	"github.com/hxddh/https-traffic-inspector/v4/internal/store"
)

// listFlag collects a repeatable flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ", ") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// captureOptions are the flags shared by wrapping a command and running as a
// proxy. Their defaults come from the settings files, then the environment.
type captureOptions struct {
	out           outputFlags
	port, listen  string
	filter        string
	format        string
	failOn        string
	certTTL       time.Duration
	session       string
	sessionDir    string
	appendSession bool
	insecure      bool
	upstream      string
	maxBody       int
	maxCapture    int
	showSecrets   bool
	redact        bool
	caDir         string
	mock          listFlag
	fault         listFlag
	mapRules      listFlag
	mockFrom      string
	maxSession    string
	cfg           config.Config
}

func (o *captureOptions) register(fs *flag.FlagSet, cfg config.Config, proxyMode bool) {
	o.cfg = cfg
	o.out.register(fs)
	defPort, defSession := "0", ""
	if proxyMode {
		// A device is configured once with a fixed address.
		defPort, defSession = "8080", "proxy"
	}
	fs.StringVar(&o.port, "port", defPort, "proxy listen port; 0 picks a random free port")
	fs.StringVar(&o.listen, "listen", "127.0.0.1", "address the proxy listens on; anything other than loopback exposes it to the network")
	fs.StringVar(&o.filter, "filter", "", "only log requests whose URL or host contains this string (case-insensitive)")
	fs.StringVar(&o.format, "format", config.String(cfg.Format, os.Getenv("HTTPMON_FORMAT")), "output format: text | summary | json (default: text on a terminal, summary otherwise)")
	fs.StringVar(&o.failOn, "fail-on", config.String(cfg.FailOn, os.Getenv("HTTPMON_FAIL_ON")), "exit 3 if any exchange matches: status classes (5xx), codes (404), error or incomplete, comma-separated")
	fs.DurationVar(&o.certTTL, "cert-ttl", time.Hour, "how long to cache per-host TLS certificates; 0 disables caching")
	fs.StringVar(&o.session, "session", defSession, "save exchanges to this named session (read them with: httpmon query NAME)")
	fs.StringVar(&o.sessionDir, "session-dir", "", "save exchanges to a session in this directory")
	fs.BoolVar(&o.appendSession, "append", false, "add to the session's earlier exchanges instead of replacing them")
	defMax := "0"
	if proxyMode {
		defMax = "1GB"
	}
	fs.StringVar(&o.maxSession, "max-session-size", defMax, "keep the session under this size (e.g. 500MB, 2GB), dropping its oldest exchanges; 0 keeps everything")
	fs.BoolVar(&o.insecure, "insecure-upstream", config.Bool(cfg.InsecureUpstream, false), "skip TLS certificate verification for upstream servers")
	fs.StringVar(&o.upstream, "upstream-proxy", cfg.UpstreamProxy, "proxy for httpmon's own upstream requests (default: HTTP(S)_PROXY from the environment)")
	fs.IntVar(&o.maxBody, "max-body", config.Int(cfg.MaxBody, 1000), "approximate max bytes of each body shown in output")
	fs.IntVar(&o.maxCapture, "max-capture", config.Int(cfg.MaxCapture, 1<<20), "max bytes of each body kept in a session and for decoding")
	fs.BoolVar(&o.showSecrets, "show-secrets", config.Bool(cfg.ShowSecrets, false), "show credentials (Authorization, cookies, API keys, signed URLs) in output instead of masking them")
	fs.BoolVar(&o.redact, "redact", config.Bool(cfg.Redact, false), "mask credentials in the session too")
	fs.StringVar(&o.caDir, "ca-dir", config.String(cfg.CADir, os.Getenv("HTTPMON_CA_DIR")), "use the persistent CA in this directory (httpmon proxy uses the default one)")
	fs.Var(&o.mock, "mock", "answer matching requests: '[METHOD] PATTERN => STATUS [BODY|@FILE]' (repeatable)")
	fs.Var(&o.fault, "fault", "inject a fault: '[METHOD] PATTERN => delay 2s|reset|reset after 1KB|timeout [N%]' (repeatable)")
	fs.Var(&o.mapRules, "map", "send a host's requests elsewhere: 'HOST[:PORT] => [SCHEME://]HOST[:PORT]' (repeatable)")
	fs.StringVar(&o.mockFrom, "mock-from", cfg.MockFrom, "answer requests from a recorded session where it has a matching response")
}

// globals for the running capture
var (
	activeRules   *rules.Set
	recordedMocks *rules.Recorded
	sessionPath   string // the running session's directory, or ""
	sessionMeta   session.Meta
)

// apply sets up everything the flags describe except the listener.
func (o *captureOptions) apply(name string) error {
	if err := applyLimits(o.maxBody, o.maxCapture); err != nil {
		return err
	}
	showSecrets, redactCaptures = o.showSecrets, o.redact
	if err := applyUpstream(o.insecure, o.upstream); err != nil {
		return err
	}
	if o.failOn != "" {
		f, err := exchange.ParseFailOn(o.failOn)
		if err != nil {
			return err
		}
		runStats.failOn = f
	}
	w, err := o.out.open(os.Stderr)
	if err != nil {
		return fmt.Errorf("cannot open output %s: %w", o.out.path, err)
	}
	format := o.format
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
		return fmt.Errorf("unknown --format %q (want text, summary or json)", format)
	}
	if o.caDir != "" {
		if _, _, err := loadOrCreateCA(o.caDir); err != nil {
			return fmt.Errorf("--ca-dir: %w", err)
		}
	}
	rs, err := rules.NewSet(append(append([]string(nil), o.cfg.Mock...), o.mock...),
		append(append([]string(nil), o.cfg.Fault...), o.fault...),
		append(append([]string(nil), o.cfg.Map...), o.mapRules...))
	if err != nil {
		return err
	}
	activeRules = rs
	if o.mockFrom != "" {
		files, err := sessionFiles(o.mockFrom)
		if err != nil {
			return fmt.Errorf("--mock-from: %w", err)
		}
		if recordedMocks, err = rules.LoadRecordedFiles(files, false); err != nil {
			return fmt.Errorf("--mock-from: %w", err)
		}
	}
	filterPattern = o.filter
	certTTL = o.certTTL
	if certTTL > 0 {
		// Sweep expired entries at 1/6 of the TTL interval, minimum every minute.
		sweep := certTTL / 6
		if sweep < time.Minute {
			sweep = time.Minute
		}
		startCertJanitor(sweep)
	}
	return o.openSession(name)
}

// openSession creates the session the flags name, if any.
func (o *captureOptions) openSession(name string) error {
	dir := o.sessionDir
	if dir == "" && o.session != "" {
		d, err := session.Dir(o.session)
		if err != nil {
			return err
		}
		dir = d
	}
	if dir == "" {
		return nil
	}
	// Check before Create, which replaces the exchanges: a session another
	// process is writing must not lose them to a run that is then refused.
	var m session.Meta
	if session.ReadJSON(dir, session.MetaFile, &m) == nil && m.Running() && m.PID != os.Getpid() {
		return fmt.Errorf("session %s is in use by process %d; choose another with --session", dir, m.PID)
	}
	if err := session.Create(dir, o.appendSession); err != nil {
		return fmt.Errorf("session %s: %w", dir, err)
	}
	maxSize, err := parseByteSize(o.maxSession)
	if err != nil {
		return fmt.Errorf("--max-session-size: %w", err)
	}
	w, err := store.OpenWriter(dir, maxSize)
	if err != nil {
		return fmt.Errorf("session %s: %w", dir, err)
	}
	recordWriter = w
	addCleanup(func() {
		recordMu.Lock()
		w.Close() //nolint:errcheck
		recordWriter = nil
		recordMu.Unlock()
	})
	// Ids continue from an earlier run of the session (--append), so each
	// names one exchange.
	counterMu.Lock()
	requestCounter = w.NextID() - 1
	counterMu.Unlock()
	recordMode = true
	sessionPath = dir
	if name == "" {
		name = filepath.Base(dir)
	}
	sessionMeta = session.Meta{Name: name, PID: os.Getpid(), Started: time.Now(), Version: version}
	return nil
}

// proxyRuntime is a listening proxy and what clients need to use it.
type proxyRuntime struct {
	ln         net.Listener
	proxyURL   string
	dialHost   string
	caBundle   string
	trustStore string
}

// startProxy builds the CA files, listens and serves. In a session the CA
// files are kept in the session directory, so that "httpmon env" can point
// other shells at them for as long as the proxy runs.
func startProxy(listen, port string) (*proxyRuntime, error) {
	rt := &proxyRuntime{}
	var err error
	if sessionPath != "" {
		rt.caBundle = filepath.Join(sessionPath, session.CABundleFile)
		err = writeCABundle(rt.caBundle, caPEM())
	} else {
		rt.caBundle, err = buildCABundle(caPEM())
		if err == nil {
			p := rt.caBundle
			addCleanup(func() { os.Remove(p) }) //nolint:errcheck
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to build CA bundle: %w", err)
	}
	if ts, err := buildJavaTrustStore(rt.caBundle); err != nil {
		// Only Java needs it; everything else can still be inspected.
		fmt.Fprintf(os.Stderr, "httpmon: Java truststore not created, JVM tools will not be configured: %v\n", err)
	} else {
		rt.trustStore = ts
		if sessionPath != "" {
			dst := filepath.Join(sessionPath, session.TrustStore)
			if err := os.Rename(ts, dst); err == nil {
				rt.trustStore = dst
			}
		} else {
			addCleanup(func() { os.Remove(ts) }) //nolint:errcheck
		}
	}

	addr := net.JoinHostPort(listen, port)
	rt.ln, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind proxy on %s: %w", addr, err)
	}
	proxyPort = strconv.Itoa(rt.ln.Addr().(*net.TCPAddr).Port)
	if !isLoopbackHost(listen) {
		fmt.Fprintf(os.Stderr,
			"httpmon: WARNING: proxy listening on %s is reachable from the network; anyone who can reach it can use it, including to reach services bound to this machine's loopback\n",
			rt.ln.Addr())
	}
	// What clients dial. A wildcard bind is reached via loopback.
	rt.dialHost = proxyDialHost(listen)
	rt.proxyURL = "http://" + net.JoinHostPort(rt.dialHost, proxyPort)

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
		if err := server.Serve(rt.ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "httpmon: proxy error: %v\n", err)
		}
	}()
	startSessionWatchers()
	return rt, nil
}

// clientEnv is the environment that points a client at the proxy.
func (rt *proxyRuntime) clientEnv(base []string) []string {
	env := subprocessEnv(base, rt.proxyURL, rt.caBundle)
	if rt.trustStore != "" {
		env = append(env, "JAVA_TOOL_OPTIONS="+
			javaToolOptions(lookupEnv(os.Environ(), "JAVA_TOOL_OPTIONS"), rt.dialHost, proxyPort, rt.trustStore))
	}
	return env
}

// ---- session upkeep ----

var sessionStop = make(chan struct{})

// startSessionWatchers keeps a session's live view current and reloads the
// rules added to it while it runs.
func startSessionWatchers() {
	if sessionPath == "" {
		return
	}
	if err := session.WriteJSON(sessionPath, session.MetaFile, sessionMeta); err != nil {
		noticef("session: %v", err)
	}
	go func() {
		// The live view is rewritten soon after the in-flight set changes,
		// and every few seconds regardless, so a reader can tell a running
		// session from one whose process died. Rules are polled.
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		var lastRules time.Time
		lastLive := time.Time{}
		dirty := true
		for {
			select {
			case <-sessionStop:
				return
			case <-liveChanged:
				dirty = true
				// Coalesce a burst of changes into one write.
				time.Sleep(50 * time.Millisecond)
			case <-t.C:
			}
			if dirty || time.Since(lastLive) > 3*time.Second {
				dirty = false
				lastLive = time.Now()
				session.WriteJSON(sessionPath, session.LiveFile, session.Live{ //nolint:errcheck
					PID: os.Getpid(), Updated: lastLive, InFlight: unfinishedExchanges(),
				})
			}
			if fi, err := os.Stat(filepath.Join(sessionPath, session.RulesFile)); err == nil && fi.ModTime() != lastRules {
				lastRules = fi.ModTime()
				reloadSessionRules()
			}
		}
	}()
}

func reloadSessionRules() {
	var r session.Rules
	if err := session.ReadJSON(sessionPath, session.RulesFile, &r); err != nil {
		noticef("session rules: %v", err)
		return
	}
	if err := activeRules.Replace(r.Mock, r.Fault, r.Map); err != nil {
		noticef("session rules: %v", err)
		return
	}
	noticef("session rules reloaded: %d mock, %d fault, %d map", len(r.Mock), len(r.Fault), len(r.Map))
}

var finishOnce sync.Once

// finishSession marks the session ended.
func finishSession() {
	if sessionPath == "" {
		return
	}
	finishOnce.Do(func() {
		close(sessionStop)
		sessionMeta.Ended = time.Now()
		session.WriteJSON(sessionPath, session.MetaFile, sessionMeta)                       //nolint:errcheck
		session.WriteJSON(sessionPath, session.LiveFile, session.Live{Updated: time.Now()}) //nolint:errcheck
	})
}

// ---- wrap ----

func cmdWrap(args []string) int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: %v\n", err)
		return 1
	}
	fs := flag.NewFlagSet("httpmon", flag.ContinueOnError)
	var o captureOptions
	o.register(fs, cfg, false)
	uiFlag := fs.Bool("ui", false, "launch the interactive terminal UI")
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
	if err := o.apply(""); err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: %v\n", err)
		return 1
	}
	tuiMode = *uiFlag

	rt, err := startProxy(o.listen, o.port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon: %v\n", err)
		return 1
	}
	if strings.EqualFold(strings.TrimSuffix(filepath.Base(cmdArgs[0]), ".exe"), "curl") {
		cmdArgs, err = curlArgs(cmdArgs, rt.proxyURL, rt.caBundle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "httpmon: %v\n", err)
			return 1
		}
	}
	if sessionPath != "" {
		sessionMeta.Kind, sessionMeta.Command, sessionMeta.Proxy = "command", cmdArgs, rt.proxyURL
		sessionMeta.CABundle, sessionMeta.Store = rt.caBundle, rt.trustStore
		session.WriteJSON(sessionPath, session.MetaFile, sessionMeta) //nolint:errcheck
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = rt.clientEnv(os.Environ())
	currentSink().start(runInfo{
		Version: version, Proxy: rt.ln.Addr().String(), Command: cmdArgs,
		Filter: filterPattern, CA: rt.caBundle, Session: sessionPath,
	})

	if tuiMode {
		return runWithTUI(cmd)
	}
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin

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

// ---- proxy ----

func cmdProxy(args []string) int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon proxy: %v\n", err)
		return 1
	}
	fs := flag.NewFlagSet("httpmon proxy", flag.ContinueOnError)
	var o captureOptions
	o.register(fs, cfg, true)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: httpmon proxy [options]

Runs httpmon as a standalone HTTP and HTTPS proxy until interrupted, for
clients it does not start: browsers, phones, emulators, containers, services
already running. Exchanges go to a session ("proxy" unless --session is
given), which "httpmon query", "httpmon mcp" and "httpmon env" read.

It uses the persistent CA (see "httpmon ca"): trust its certificate once on
each device.

Options:
`)
		fs.PrintDefaults()
	}
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	if o.session == "" && o.sessionDir == "" {
		o.session = "proxy"
	}
	if o.caDir == "" {
		o.caDir = defaultCADir()
	}
	if err := o.apply(o.session); err != nil {
		fmt.Fprintf(os.Stderr, "httpmon proxy: %v\n", err)
		return 1
	}
	rt, err := startProxy(o.listen, o.port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon proxy: %v\n", err)
		if strings.Contains(err.Error(), "address already in use") {
			fmt.Fprintln(os.Stderr, "httpmon proxy: choose another port with --port, or --port 0 for any free port")
		}
		return 1
	}
	certPath := filepath.Join(o.caDir, caCertFile)
	sessionMeta.Kind, sessionMeta.Proxy = "proxy", rt.proxyURL
	sessionMeta.CABundle, sessionMeta.Store = rt.caBundle, rt.trustStore
	session.WriteJSON(sessionPath, session.MetaFile, sessionMeta) //nolint:errcheck

	envHint := "eval \"$(httpmon env)\""
	if sessionMeta.Name != "proxy" {
		envHint = fmt.Sprintf("eval \"$(httpmon env --session %s)\"", sessionMeta.Name)
	}
	fmt.Fprintf(os.Stderr, `httpmon %s: proxy listening on %s (session %q)
  Proxy for HTTP and HTTPS:  %s
  CA certificate:            %s
                             trust it once on each device or browser
  Use it from a shell:       %s
  Query the traffic:         httpmon query %s [--live]
Press Ctrl-C to stop.
`, version, rt.ln.Addr(), sessionMeta.Name, rt.proxyURL, certPath, envHint, sessionMeta.Name)
	currentSink().start(runInfo{Version: version, Proxy: rt.ln.Addr().String(), CA: rt.caBundle, Session: sessionPath})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	drainInflight(exitDrainTimeout)
	finishRun(0)
	return 0
}

// defaultCADir is the persistent CA's directory.
func defaultCADir() string {
	if d := os.Getenv("HTTPMON_CA_DIR"); d != "" {
		return d
	}
	d, err := session.CADir()
	if err != nil {
		return ""
	}
	return d
}

// ---- env ----

func cmdEnv(args []string) int {
	fs := flag.NewFlagSet("httpmon env", flag.ContinueOnError)
	name := fs.String("session", "proxy", "the running proxy's session")
	shell := fs.String("shell", defaultShell(), "output syntax: sh | fish | powershell")
	unset := fs.Bool("unset", false, "print commands that undo the exports")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: eval "$(httpmon env [--session NAME])"

Prints the environment that routes a shell's commands through a running
"httpmon proxy" -- proxy variables, CA bundle variables, JAVA_TOOL_OPTIONS --
the same environment httpmon gives a command it wraps.

Options:
`)
		fs.PrintDefaults()
	}
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	dir, err := session.ResolveDir(*name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon env: %v; start one with: httpmon proxy\n", err)
		return 1
	}
	var m session.Meta
	if err := session.ReadJSON(dir, session.MetaFile, &m); err != nil {
		fmt.Fprintf(os.Stderr, "httpmon env: session %q has no metadata: %v\n", *name, err)
		return 1
	}
	if !m.Running() {
		fmt.Fprintf(os.Stderr, "httpmon env: session %q is not running; start it with: httpmon proxy --session %s\n", *name, *name)
		return 1
	}
	vars := subprocessEnv(nil, m.Proxy, m.CABundle)
	if m.Store != "" {
		u := strings.TrimPrefix(m.Proxy, "http://")
		host, port, _ := net.SplitHostPort(u)
		vars = append(vars, "JAVA_TOOL_OPTIONS="+javaToolOptions(os.Getenv("JAVA_TOOL_OPTIONS"), host, port, m.Store))
	}
	for _, kv := range vars {
		k, v, _ := strings.Cut(kv, "=")
		fmt.Println(exportLine(*shell, k, v, *unset))
	}
	return 0
}

func defaultShell() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	if strings.HasSuffix(os.Getenv("SHELL"), "fish") {
		return "fish"
	}
	return "sh"
}

func exportLine(shell, k, v string, unset bool) string {
	switch shell {
	case "fish":
		if unset {
			return "set -e " + k
		}
		return fmt.Sprintf("set -gx %s %s", k, shellQuote(v))
	case "powershell":
		if unset {
			return fmt.Sprintf("Remove-Item Env:%s -ErrorAction SilentlyContinue", k)
		}
		return fmt.Sprintf("$env:%s = '%s'", k, strings.ReplaceAll(v, "'", "''"))
	}
	if unset {
		return "unset " + k
	}
	return fmt.Sprintf("export %s=%s", k, shellQuote(v))
}

// ---- sessions ----

func cmdSessions(args []string) int {
	fs := flag.NewFlagSet("httpmon sessions", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	list, err := session.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpmon sessions: %v\n", err)
		return 1
	}
	if *asJSON {
		setOutput(os.Stdout)
		emitJSON(list)
		return 0
	}
	if len(list) == 0 {
		fmt.Println("no sessions (create one with --session NAME, or run httpmon proxy)")
		return 0
	}
	for _, s := range list {
		state := "ended"
		if s.Running {
			state = "running"
		}
		what := s.Meta.Kind
		if len(s.Meta.Command) > 0 {
			what = clipText(strings.Join(s.Meta.Command, " "), 60)
		}
		fmt.Printf("%-20s %-8s %8s  %s  %s\n", s.Name, state, humanBytes(s.Exchanges), s.Modified.Format("2006-01-02 15:04"), what)
	}
	return 0
}

func humanBytes(n int64) string {
	switch {
	case n >= 10<<20:
		return fmt.Sprintf("%d MB", n>>20)
	case n >= 10<<10:
		return fmt.Sprintf("%d KB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}

func clipText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// parseByteSize parses "0", "1048576", "512KB", "500MB" or "2GB".
func parseByteSize(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	for _, u := range []struct {
		suf string
		m   int64
	}{{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(t, u.suf) {
			mult, t = u.m, strings.TrimSuffix(t, u.suf)
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad size %q (e.g. 0, 500MB, 2GB)", s)
	}
	return n * mult, nil
}
