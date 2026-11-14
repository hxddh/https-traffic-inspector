// Package config loads httpmon's settings files: the user's config.toml in
// httpmon's home, and a project's .httpmon.toml in the working directory or
// the nearest parent. A project file overrides the user file; command-line
// flags override both, and both override environment variables.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/hxddh/https-traffic-inspector/v4/internal/session"
)

// ProjectFile is the name of a project's settings file.
const ProjectFile = ".httpmon.toml"

// Config holds the settings a file may set. Unset fields leave the
// lower-priority value in place.
type Config struct {
	Format           string   `toml:"format"`
	FailOn           string   `toml:"fail_on"`
	MaxBody          int      `toml:"max_body"`
	MaxCapture       int      `toml:"max_capture"`
	UpstreamProxy    string   `toml:"upstream_proxy"`
	InsecureUpstream *bool    `toml:"insecure_upstream"`
	ShowSecrets      *bool    `toml:"show_secrets"`
	Redact           *bool    `toml:"redact"`
	CADir            string   `toml:"ca_dir"`
	Mock             []string `toml:"mock"`
	Fault            []string `toml:"fault"`
	Map              []string `toml:"map"`
	MockFrom         string   `toml:"mock_from"`
	Ignore           []string `toml:"ignore"` // httpmon diff

	// Files lists the files the settings came from.
	Files []string `toml:"-"`
}

// Load reads the user and project files that exist.
func Load() (Config, error) {
	var c Config
	if h, err := session.Home(); err == nil {
		if err := c.merge(filepath.Join(h, "config.toml"), false); err != nil {
			return c, err
		}
	}
	if p := findProject(); p != "" {
		if err := c.merge(p, true); err != nil {
			return c, err
		}
	}
	return c, nil
}

// findProject looks for ProjectFile in the working directory and its parents.
func findProject() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 32; i++ {
		p := filepath.Join(dir, ProjectFile)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}

// A project file comes with whatever repository is checked out, so it may not
// change where traffic goes or how it is verified: no upstream proxy, no
// skipped verification, no other CA, no unmasked credentials, and map rules
// only to this machine.
func checkProject(f *Config) error {
	switch {
	case f.UpstreamProxy != "":
		return errors.New("upstream_proxy may only be set in the user config")
	case f.InsecureUpstream != nil:
		return errors.New("insecure_upstream may only be set in the user config")
	case f.CADir != "":
		return errors.New("ca_dir may only be set in the user config")
	case f.ShowSecrets != nil:
		return errors.New("show_secrets may only be set in the user config")
	}
	for _, m := range f.Map {
		_, to, _ := strings.Cut(m, "=>")
		to = strings.TrimSpace(to)
		if i := strings.Index(to, "://"); i >= 0 {
			to = to[i+3:]
		}
		host := to
		if h, _, err := net.SplitHostPort(to); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("map %q: a project file may only map to this machine (localhost, 127.0.0.1, ::1)", m)
		}
	}
	return nil
}

func (c *Config) merge(path string, project bool) error {
	var f Config
	md, err := toml.DecodeFile(path, &f)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return fmt.Errorf("%s: unknown setting %q", path, und[0].String())
	}
	if project {
		if err := checkProject(&f); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	c.Files = append(c.Files, path)
	if f.Format != "" {
		c.Format = f.Format
	}
	if f.FailOn != "" {
		c.FailOn = f.FailOn
	}
	if f.MaxBody != 0 {
		c.MaxBody = f.MaxBody
	}
	if f.MaxCapture != 0 {
		c.MaxCapture = f.MaxCapture
	}
	if f.UpstreamProxy != "" {
		c.UpstreamProxy = f.UpstreamProxy
	}
	if f.InsecureUpstream != nil {
		c.InsecureUpstream = f.InsecureUpstream
	}
	if f.ShowSecrets != nil {
		c.ShowSecrets = f.ShowSecrets
	}
	if f.Redact != nil {
		c.Redact = f.Redact
	}
	if f.CADir != "" {
		c.CADir = f.CADir
	}
	if f.MockFrom != "" {
		c.MockFrom = f.MockFrom
	}
	// Rules accumulate: a project's mocks add to the user's.
	c.Mock = append(c.Mock, f.Mock...)
	c.Fault = append(c.Fault, f.Fault...)
	c.Map = append(c.Map, f.Map...)
	c.Ignore = append(c.Ignore, f.Ignore...)
	return nil
}

// String returns the first non-empty value.
func String(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Bool returns the file's value if set, else def.
func Bool(v *bool, def bool) bool {
	if v != nil {
		return *v
	}
	return def
}

// Int returns v if set, else def.
func Int(v, def int) int {
	if v != 0 {
		return v
	}
	return def
}
