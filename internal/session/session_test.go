package session

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestResolve(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HTTPMON_HOME", home)
	d, err := Dir("api-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := Create(d, false); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(d); fi.Mode().Perm() != 0o700 {
			t.Errorf("session dir mode = %v, want 0700", fi.Mode().Perm())
		}
	}
	ex := filepath.Join(d, ExchangesFile)
	os.WriteFile(ex, []byte("{}\n"), 0o600) //nolint:errcheck

	for _, arg := range []string{"api-test", d, ex} {
		got, err := Resolve(arg)
		if err != nil || got != ex {
			t.Errorf("Resolve(%q) = %q, %v; want %q", arg, got, err, ex)
		}
	}
	if got, _ := Resolve("-"); got != "-" {
		t.Errorf("Resolve(-) = %q", got)
	}
	if _, err := Resolve("missing"); err == nil {
		t.Error("Resolve of a missing session succeeded")
	}
	if _, err := Resolve("../etc"); err == nil {
		t.Error("Resolve accepted a path-like name")
	}
	if got, err := ResolveDir("api-test"); err != nil || got != d {
		t.Errorf("ResolveDir = %q, %v", got, err)
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"a", "proxy", "test-1.run_2"} {
		if !ValidName(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", ".hidden", "a/b", "..", "a b", string(make([]byte, 65))} {
		if ValidName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCreate_ReplacesOrKeeps(t *testing.T) {
	d := filepath.Join(t.TempDir(), "s")
	if err := Create(d, false); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{ExchangesFile, LiveFile, RulesFile} {
		os.WriteFile(filepath.Join(d, f), []byte("x"), 0o600) //nolint:errcheck
	}
	if err := Create(d, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(d, ExchangesFile)); err != nil {
		t.Error("--append removed the exchanges")
	}
	if _, err := os.Stat(filepath.Join(d, RulesFile)); err == nil {
		t.Error("rules added at run time survived into a new run")
	}
	if err := Create(d, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(d, ExchangesFile)); err == nil {
		t.Error("a new run kept the old exchanges")
	}
}

func TestMetaAndList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HTTPMON_HOME", home)
	for i, name := range []string{"old", "new"} {
		d, _ := Dir(name)
		Create(d, false) //nolint:errcheck
		m := Meta{Name: name, Kind: "command", PID: os.Getpid(), Started: time.Now()}
		if name == "old" {
			m.Ended = time.Now()
		}
		if err := WriteJSON(d, MetaFile, m); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, ExchangesFile)
		os.WriteFile(p, []byte("{}\n"), 0o600)                                  //nolint:errcheck
		os.Chtimes(p, time.Now(), time.Now().Add(time.Duration(i)*time.Minute)) //nolint:errcheck
	}
	list, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "new" || !list[0].Running || list[1].Running {
		t.Errorf("List = %+v", list)
	}
	var m Meta
	if err := ReadJSON(list[1].Meta.Name, "nope", &m); err == nil {
		t.Error("ReadJSON of a missing file succeeded")
	}
}

func TestMeta_DeadProcessIsNotRunning(t *testing.T) {
	m := Meta{PID: 1 << 30}
	if m.Running() {
		t.Error("a process that does not exist is running")
	}
}
