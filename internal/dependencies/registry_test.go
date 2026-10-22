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

// Detection is read-only: PwnFlow never installs, upgrades, or removes a
// dependency on the operator's behalf. Trap the package managers so any attempt
// to run one is recorded.
func TestDependencyDetectionNeverInvokesAPackageManager(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "package-manager-ran")
	for _, name := range []string{"sudo", "apt", "apt-get", "dpkg"} {
		script := "#!/bin/sh\necho " + name + " >> " + marker + "\nexit 99\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	for _, status := range DefaultRegistry().Check(context.Background()) {
		if status.ID == "" {
			t.Fatalf("unexpected status: %#v", status)
		}
	}
	if data, err := os.ReadFile(marker); err == nil {
		t.Fatalf("dependency detection invoked a package manager: %s", string(data))
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
	if !status.Available || status.FoundExecutable != executable || !strings.Contains(status.Detail, bin) {
		t.Fatalf("unexpected pipx discovery status: %#v", status)
	}
}

// Cargo installs into $CARGO_HOME/bin, which Kali does not add to PATH, so the
// collector has to be discovered from the managed Cargo location.
func TestCargoBinDiscoveryFindsRustHoundWithoutPathEntry(t *testing.T) {
	dir := t.TempDir()
	cargoHome := filepath.Join(dir, "cargo-home")
	cargoBin := filepath.Join(cargoHome, "bin")
	if err := os.MkdirAll(cargoBin, 0700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(cargoBin, "rusthound-ce")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\ncase \"$1\" in --help) exit 0;; --version) echo 'rusthound-ce 2.5.25';; esac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("CARGO_HOME", cargoHome)
	t.Setenv("PIPX_BIN_DIR", filepath.Join(dir, "pipx-bin"))
	t.Setenv("PATH", filepath.Join(dir, "empty-path"))
	status := DefaultRegistry().CheckOne(context.Background(), RustHoundCE)
	if !status.Available || status.State != "installed" || status.FoundExecutable != executable {
		t.Fatalf("unexpected Cargo discovery status: %#v", status)
	}
	if status.Version != "rusthound-ce 2.5.25" || !strings.Contains(status.Detail, cargoBin) {
		t.Fatalf("unexpected Cargo discovery detail: %#v", status)
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

// certipyADCSHelp is the identifying part of Certipy's own help output.
const certipyADCSHelp = "Active Directory Certificate Services enumeration and abuse\n    find                Enumerate AD CS"

func writeFakeCertipy(t *testing.T, directory, name, help string) {
	t.Helper()
	body := "#!/bin/sh\ncase \"$1\" in\n--help) printf '%s\\n' \"" + help + "\" ;;\n--version) echo 'Certipy v5.1.0' ;;\n*) exit 1 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
}

// Kali packages Certipy's AD CS tool as certipy-ad; the pipx distribution
// exposes it as certipy. Both names are detected, and the capability probe has to
// show the AD CS tool itself.
func TestCertipyIsDetectedUnderEitherCommandName(t *testing.T) {
	for _, name := range []string{"certipy-ad", "certipy"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFakeCertipy(t, dir, name, certipyADCSHelp)
			t.Setenv("PATH", dir)
			status := DefaultRegistry().CheckOne(context.Background(), Certipy)
			if !status.Available || status.State != "installed" {
				t.Fatalf("Certipy was not detected as %s: %#v", name, status)
			}
			if status.FoundExecutable != filepath.Join(dir, name) {
				t.Fatalf("unexpected executable: %q", status.FoundExecutable)
			}
		})
	}
}

// A different program that happens to be called certipy must not be reported as
// installed: detection is read-only and never installs or replaces anything.
func TestUnrelatedCertipyIsNotAccepted(t *testing.T) {
	dir := t.TempDir()
	writeFakeCertipy(t, dir, "certipy", "certificate helper: no AD CS support")
	t.Setenv("PATH", dir)
	status := DefaultRegistry().CheckOne(context.Background(), Certipy)
	if status.Available {
		t.Fatalf("an unrelated certipy was accepted: %#v", status)
	}
	if status.State != "broken" || !strings.Contains(status.Detail, "Active Directory Certificate Services") {
		t.Fatalf("the mismatch was not explained: %#v", status)
	}
}
