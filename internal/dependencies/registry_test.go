package dependencies

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMissingDependencyIsReportedWithoutNetwork(t *testing.T) {
	registry := Registry{definitions: []Definition{{ID: "fake", DisplayName: "Fake", Executable: "definitely-not-installed-pwnflow", Required: true}}}
	status := registry.Check(context.Background())[0]
	if status.Available || status.State != "missing" {
		t.Fatalf("unexpected status: %#v", status)
	}
}

func TestDependencyRegistryDetectsExecutableAndVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell test helper uses Unix permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nif [ \"$1\" = \"--help\" ]; then echo help; exit 0; fi\necho fake-1.0\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	registry := Registry{definitions: []Definition{{ID: "fake", DisplayName: "Fake", Executable: "fake-tool", ProbeArgs: []string{"--help"}, VersionArgs: []string{"--version"}}}}
	status := registry.Check(context.Background())[0]
	if !status.Available || status.Version != "fake-1.0" {
		t.Fatalf("unexpected status: %#v", status)
	}
}

func TestDependencyRegistryDistinguishesBrokenProbe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken-tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho startup-failure >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	status := (Registry{definitions: []Definition{{ID: "broken", DisplayName: "Broken", Executable: "broken-tool", ProbeArgs: []string{"--help"}}}}).Check(context.Background())[0]
	if status.Available || status.State != "broken" || status.Detail == "" {
		t.Fatalf("unexpected broken status: %#v", status)
	}
}

func TestOptionalBloodHoundDependenciesAreRegisteredSeparately(t *testing.T) {
	definitions := DefaultRegistry().All()
	seen := map[ID]bool{}
	for _, definition := range definitions {
		seen[definition.ID] = true
		if definition.ID != NetExec && definition.Required {
			t.Fatalf("optional dependency %s was marked required", definition.ID)
		}
	}
	if !seen[BloodHoundCE] || !seen[BloodHoundPy] || !seen[RustHoundCE] {
		t.Fatalf("BloodHound components were not independently registered: %#v", seen)
	}
	definitions = DefaultRegistry().All()
	for _, definition := range definitions {
		switch definition.ID {
		case NetExec:
			if definition.InstallMethod != InstallAPT {
				t.Fatal("NetExec must preserve its APT installation method")
			}
		case BloodHoundCE:
			if definition.InstallMethod != InstallOfficialApplication {
				t.Fatal("BloodHound CE must use its official application method")
			}
		case BloodHoundPy:
			if definition.InstallMethod != InstallPipx || definition.Package != "bloodhound-ce" {
				t.Fatal("BloodHound CE Python must use pipx")
			}
		case RustHoundCE:
			if definition.InstallMethod != InstallCargo || definition.Executable != "rusthound-ce" {
				t.Fatal("RustHound-CE must use Cargo")
			}
		}
	}
}

func TestPipxExecutableDiscoveryUsesUserBinWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, ".local", "bin")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(bin, "bloodhound-ce-python")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\ncase \"$1\" in --help) exit 0;; --version) echo test-version;; esac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", dir)
	t.Setenv("PATH", "/usr/bin")
	status := DefaultRegistry().CheckOne(context.Background(), BloodHoundPy)
	if !status.Available || status.FoundExecutable != "bloodhound-ce-python" || !strings.Contains(status.Detail, bin) {
		t.Fatalf("unexpected pipx discovery status: %#v", status)
	}
}

func TestRefreshExecutablePathAddsUserBinOnce(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("PATH", "/usr/bin")
	if err := RefreshExecutablePath(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := RefreshExecutablePath(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".local", "bin")
	if count := strings.Count(os.Getenv("PATH"), path); count != 1 {
		t.Fatalf("user bin appears %d times in PATH: %q", count, os.Getenv("PATH"))
	}
}

func TestParseDebianPackageStatus(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		version string
		valid   bool
	}{
		{name: "installed", value: "ii  9.8.0~rc3-0kali1\n", version: "9.8.0~rc3-0kali1", valid: true},
		{name: "unpacked", value: "iU  9.8.0~rc3-0kali1\n", valid: false},
		{name: "half configured", value: "iF  9.8.0~rc3-0kali1\n", valid: false},
		{name: "error flag", value: "iiE  9.8.0~rc3-0kali1\n", valid: false},
		{name: "missing version", value: "ii  \n", valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			version, valid := parseDebianPackageStatus(test.value)
			if valid != test.valid || version != test.version {
				t.Fatalf("parseDebianPackageStatus(%q)=(%q,%t), want (%q,%t)", test.value, version, valid, test.version, test.valid)
			}
		})
	}
}

func TestBloodHoundPackageDetectionDoesNotInvokeDeprecatedCLI(t *testing.T) {
	dir := t.TempDir()
	dpkg := filepath.Join(dir, "dpkg-query")
	bloodhound := filepath.Join(dir, "bloodhound")
	if err := os.WriteFile(dpkg, []byte("#!/bin/sh\nprintf '%s\\n' 'ii  9.8.0~rc3-0kali1'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bloodhound, []byte("#!/bin/sh\necho deprecated-wrapper-should-not-run >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	status := DefaultRegistry().CheckOne(context.Background(), BloodHoundCE)
	if !status.Available || status.State != "installed" || status.Version != "9.8.0~rc3-0kali1" {
		t.Fatalf("unexpected BloodHound package status: %#v", status)
	}
}

func TestBloodHoundPackageDetectionDistinguishesMissingAndBrokenQueries(t *testing.T) {
	dir := t.TempDir()
	dpkg := filepath.Join(dir, "dpkg-query")
	if err := os.WriteFile(dpkg, []byte("#!/bin/sh\ncase \"$DPKG_TEST_STATE\" in\nmissing) echo 'dpkg-query: no packages found matching bloodhound' >&2; exit 1;; failed) echo 'dpkg database unavailable' >&2; exit 2;; half) printf '%s\\n' 'iF  9.8.0~rc3-0kali1';; esac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	for _, test := range []struct {
		state string
		want  string
	}{
		{state: "missing", want: "missing"},
		{state: "failed", want: "check failed"},
		{state: "half", want: "broken"},
	} {
		t.Run(test.state, func(t *testing.T) {
			t.Setenv("DPKG_TEST_STATE", test.state)
			status := DefaultRegistry().CheckOne(context.Background(), BloodHoundCE)
			if status.Available || status.State != test.want {
				t.Fatalf("state=%s status=%#v", test.state, status)
			}
		})
	}
}
