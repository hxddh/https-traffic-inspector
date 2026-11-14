// Package session keeps httpmon's captures on disk. A session is a directory
// holding the exchanges of a run (or of a long-running proxy), its metadata,
// the exchanges still in flight, and rules added while it runs. Every command
// that reads captures -- query, diff, replay, mcp -- takes a session name.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/hxddh/https-traffic-inspector/v4/internal/exchange"
)

// File names inside a session directory.
const (
	ExchangesFile = "exchanges.ndjson"
	MetaFile      = "meta.json"
	LiveFile      = "live.json"
	RulesFile     = "rules.json"
	CABundleFile  = "ca-bundle.pem"
	TrustStore    = "truststore.p12"
)

// Home is httpmon's directory: $HTTPMON_HOME, or httpmon under the user's
// configuration directory. It holds config.toml, the persistent CA and the
// sessions.
func Home() (string, error) {
	if h := os.Getenv("HTTPMON_HOME"); h != "" {
		return h, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot find a home for httpmon (set HTTPMON_HOME): %w", err)
	}
	return filepath.Join(base, "httpmon"), nil
}

// CADir is where the persistent CA lives.
func CADir() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "ca"), nil
}

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidName reports whether name can name a session.
func ValidName(name string) bool { return validName.MatchString(name) }

// Dir is the directory of the named session.
func Dir(name string) (string, error) {
	if !ValidName(name) {
		return "", fmt.Errorf("invalid session name %q (letters, digits, '.', '_' and '-', up to 64)", name)
	}
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "sessions", name), nil
}

// Resolve turns what a user typed into the exchanges file to read: an
// existing file, a session directory, or a session name.
func Resolve(arg string) (string, error) {
	if arg == "-" {
		return arg, nil
	}
	if fi, err := os.Stat(arg); err == nil {
		if fi.IsDir() {
			return filepath.Join(arg, ExchangesFile), nil
		}
		return arg, nil
	}
	if !ValidName(arg) {
		return "", fmt.Errorf("%s: no such file or session", arg)
	}
	d, err := Dir(arg)
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, ExchangesFile)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("no session %q (looked in %s)", arg, d)
	}
	return p, nil
}

// ResolveDir turns a session name or directory into the session directory.
func ResolveDir(arg string) (string, error) {
	if fi, err := os.Stat(arg); err == nil && fi.IsDir() {
		return arg, nil
	}
	d, err := Dir(arg)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(d); err != nil {
		return "", fmt.Errorf("no session %q (looked in %s)", arg, d)
	}
	return d, nil
}

// Create makes a session directory, readable by its owner only: it holds
// whole requests, credentials included. Unless keep is set, the exchanges of
// an earlier run under the same name are discarded.
func Create(dir string, keep bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs x
		return err
	}
	// Rules added at run time belong to the run that added them.
	if err := os.Remove(filepath.Join(dir, RulesFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if !keep {
		for _, f := range []string{ExchangesFile, LiveFile} {
			if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// Meta describes a session's run.
type Meta struct {
	Name     string    `json:"name"`
	Kind     string    `json:"kind"` // "command" or "proxy"
	Command  []string  `json:"command,omitempty"`
	Proxy    string    `json:"proxy"` // the URL clients use
	CABundle string    `json:"ca_bundle,omitempty"`
	Store    string    `json:"java_truststore,omitempty"`
	PID      int       `json:"pid"`
	Started  time.Time `json:"started"`
	Ended    time.Time `json:"ended,omitzero"`
	Version  string    `json:"httpmon_version"`
}

// Running reports whether the session's process is still running.
func (m Meta) Running() bool {
	return m.Ended.IsZero() && m.PID > 0 && processAlive(m.PID)
}

// WriteJSON writes v to dir/name atomically, so a reader never sees half a file.
func WriteJSON(dir, name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()           //nolint:errcheck
		os.Remove(tmp.Name()) //nolint:errcheck
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name()) //nolint:errcheck
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

// ReadJSON reads dir/name into v.
func ReadJSON(dir, name string, v any) error {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Live is a running session's exchanges still in flight.
type Live struct {
	PID      int                `json:"pid"`
	Updated  time.Time          `json:"updated"`
	InFlight []exchange.Pending `json:"in_flight"`
}

// Rules are mock, fault and map rules added to a running session -- by
// "httpmon mcp" or by hand -- which the session's process reloads.
type Rules struct {
	Mock  []string `json:"mock,omitempty"`
	Fault []string `json:"fault,omitempty"`
	Map   []string `json:"map,omitempty"`
}

// Info summarises a session for listing.
type Info struct {
	Name      string    `json:"name"`
	Meta      Meta      `json:"meta"`
	Running   bool      `json:"running"`
	Exchanges int64     `json:"bytes"`
	Modified  time.Time `json:"modified"`
}

// List returns the sessions under Home, most recently modified first.
func List() ([]Info, error) {
	h, err := Home()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(h, "sessions"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, e := range entries {
		if !e.IsDir() || !ValidName(e.Name()) {
			continue
		}
		dir := filepath.Join(h, "sessions", e.Name())
		info := Info{Name: e.Name()}
		_ = ReadJSON(dir, MetaFile, &info.Meta) // a session without meta is still listed
		info.Running = info.Meta.Running()
		if fi, err := os.Stat(filepath.Join(dir, ExchangesFile)); err == nil {
			info.Exchanges = fi.Size()
			info.Modified = fi.ModTime()
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Modified.After(out[j].Modified) })
	return out, nil
}
