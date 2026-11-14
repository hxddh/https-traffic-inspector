package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setup(t *testing.T, user, project string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HTTPMON_HOME", home)
	if user != "" {
		os.WriteFile(filepath.Join(home, "config.toml"), []byte(user), 0o600) //nolint:errcheck
	}
	proj := t.TempDir()
	sub := filepath.Join(proj, "a", "b")
	os.MkdirAll(sub, 0o700) //nolint:errcheck
	if project != "" {
		os.WriteFile(filepath.Join(proj, ProjectFile), []byte(project), 0o600) //nolint:errcheck
	}
	t.Chdir(sub)
	return proj
}

func TestLoad_ProjectOverridesUser(t *testing.T) {
	setup(t, `
format = "json"
max_body = 500
upstream_proxy = "http://corp:3128"
mock = ["*/a => 200"]
`, `
format = "summary"
fail_on = "5xx"
mock = ["*/b => 500"]
map = ["api.example.com => localhost:3000"]
ignore = [".updated_at"]
`)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Format != "summary" || c.MaxBody != 500 || c.FailOn != "5xx" || c.UpstreamProxy != "http://corp:3128" {
		t.Errorf("config = %+v", c)
	}
	if len(c.Mock) != 2 || len(c.Map) != 1 || len(c.Ignore) != 1 || len(c.Files) != 2 {
		t.Errorf("lists = %+v", c)
	}
}

func TestLoad_UnknownKey(t *testing.T) {
	setup(t, `formt = "json"`, "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "formt") {
		t.Errorf("err = %v", err)
	}
}

// A project file arrives with a checked-out repository: it may not send
// traffic, credentials included, anywhere else.
func TestLoad_ProjectCannotRedirectTraffic(t *testing.T) {
	for _, bad := range []string{
		`upstream_proxy = "http://evil:8080"`,
		`insecure_upstream = true`,
		`show_secrets = true`,
		`ca_dir = "/tmp/x"`,
		`map = ["api.stripe.com => evil.example.com"]`,
		`map = ["api.stripe.com => https://10.0.0.5:443"]`,
		// userinfo: url.Parse routes to attacker.example, not localhost
		`map = ["api.example.com => http://localhost:80@attacker.example"]`,
		`map = ["api.example.com => localhost:80@attacker.example"]`,
	} {
		setup(t, "", bad)
		if _, err := Load(); err == nil {
			t.Errorf("project file accepted %s", bad)
		}
	}
	for _, ok := range []string{`map = ["api.example.com => localhost:3000"]`, `map = ["a => http://127.0.0.1:8080"]`, `map = ["a => [::1]:80"]`} {
		setup(t, "", ok)
		if _, err := Load(); err != nil {
			t.Errorf("project file rejected %s: %v", ok, err)
		}
	}
}

func TestHelpers(t *testing.T) {
	yes := true
	if String("", "b", "c") != "b" || Bool(nil, true) != true || Bool(&yes, false) != true || Int(0, 7) != 7 || Int(3, 7) != 3 {
		t.Error("helpers")
	}
}
