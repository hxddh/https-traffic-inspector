package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-isatty"
)

var (
	proxyPort string

	// set by flags
	filterPattern    string
	jsonMode         bool
	summaryMode      bool
	tuiMode          bool
	recordMode       bool
	insecureUpstream bool
	upstreamProxy    *url.URL  // --upstream-proxy; nil means use the environment
	displayMaxBody   = 1000    // --max-body: bytes of body shown in text/JSON/TUI output
	captureMaxBody   = 1 << 20 // --max-capture: bytes of body kept in sessions and for decoding
)

// version is the released build identifier, injected at link time with
// -ldflags "-X main.version=<tag>".
var version = "dev"

// buildVersion returns the version a binary was built as: the release tag
// injected by the release workflow, or else the module version Go records
// for "go install …@v3.1.0", which runs no link-time injection.
func buildVersion(injected string, info *debug.BuildInfo, ok bool) string {
	if injected != "dev" || !ok || info == nil {
		return injected
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	return injected
}

func init() {
	info, ok := debug.ReadBuildInfo()
	version = buildVersion(version, info, ok)

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
	return finishRun(code)
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
