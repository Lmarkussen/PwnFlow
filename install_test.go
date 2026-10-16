package pwnflow

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The standalone installer is a repository-root file: that is the documented,
// single location operators run, and it must stay executable.
func TestInstallerLivesAtRepositoryRoot(t *testing.T) {
	info, err := os.Stat("install.sh")
	if err != nil {
		t.Fatalf("install.sh is missing from the repository root: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("install.sh is not executable: %v", info.Mode())
	}
	if _, err := os.Stat(filepath.Join("scripts", "install.sh")); err == nil {
		t.Fatal("a second installer copy still exists under scripts/")
	}
}

// No source, documentation, or build file may still point at the old location.
func TestNoObsoleteInstallerReferences(t *testing.T) {
	needle := "scripts" + "/install.sh"
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "bin", "results":
				return fs.SkipDir
			}
			return nil
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(contents), needle) {
			t.Errorf("%s still references the old installer location", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

const (
	ampleFreeSpaceKB        = 2147483648 // 2 TiB
	insufficientFreeSpaceKB = 102400     // 100 MiB
)

func runInstaller(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := runInstallerSplit(t, bin, args...)
	return stdout + stderr, err
}

// runInstallerSplit captures stdout and stderr separately. The installer's own
// narration (progress lines and the final summary) must be readable on stdout
// alone, because that is the stream operators and logs keep; captured output that
// merges the streams cannot detect narration that was stranded on stderr.
func runInstallerSplit(t *testing.T, bin string, args ...string) (string, string, error) {
	t.Helper()
	command := exec.Command("bash", append([]string{"install.sh"}, args...)...)
	command.Dir = filepath.Dir("install.sh")
	env := os.Environ()
	pathSet := false
	for index, value := range env {
		if strings.HasPrefix(value, "PATH=") {
			env[index] = "PATH=" + bin
			command.Env = env
			pathSet = true
			break
		}
	}
	if !pathSet {
		command.Env = append(env, "PATH="+bin)
	}
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

func writeExecutable(t *testing.T, directory, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
}

// writeAvailableSpaceMock replaces df so a test decides how much free space the
// installer observes for a Cargo build directory.
func writeAvailableSpaceMock(t *testing.T, bin string, availableKB int) {
	t.Helper()
	writeExecutable(t, bin, "df", fmt.Sprintf("printf '%%s\\n' '    Avail' '%d'", availableKB))
}

// writeCargoPrerequisiteMocks satisfies every native prerequisite and filesystem
// helper the installer uses before and around the Cargo call.
func writeCargoPrerequisiteMocks(t *testing.T, bin string) {
	t.Helper()
	for _, name := range []string{"cc", "clang", "pkg-config", "gcc"} {
		writeExecutable(t, bin, name, `exit 0`)
	}
	writeExecutable(t, bin, "dpkg-query", `printf '%s\n' 'install ok installed'`)
	writeExecutable(t, bin, "grep", `exec /usr/bin/grep "$@"`)
	writeExecutable(t, bin, "mkdir", `exec /usr/bin/mkdir "$@"`)
	writeAvailableSpaceMock(t, bin, ampleFreeSpaceKB)
}

func writeFailingPackageManagerMocks(t *testing.T, bin string) {
	t.Helper()
	writeExecutable(t, bin, "apt-get", `echo apt-should-not-run >&2; exit 99`)
	writeExecutable(t, bin, "apt-cache", `echo apt-cache-should-not-run >&2; exit 99`)
	writeExecutable(t, bin, "sudo", `echo sudo-should-not-run >&2; exit 99`)
	writeExecutable(t, bin, "pipx", `echo pipx-should-not-run >&2; exit 99`)
}

// writeCertipyADCSMock writes a stand-in for Certipy's AD CS tool under the
// command name the installer is expected to find. It answers the capability
// probes the installer performs: the AD CS banner, the find action, and the find
// arguments PwnFlow's modules pass.
func writeCertipyADCSMock(t *testing.T, directory, name string) {
	t.Helper()
	writeExecutable(t, directory, name, `case "$1" in
--version) echo 'Certipy v5.1.0 - by Oliver Lyak (ly4k)' >&2 ;;
--help) echo 'Active Directory Certificate Services enumeration and abuse'; echo '    find                Enumerate AD CS' ;;
find) echo 'Discover and analyze Active Directory Certificate Services components.'; echo '-dc-only -dc-ip -u -p -ldap-scheme -ldap-port -json -text -output -enabled -vulnerable' ;;
*) exit 1 ;;
esac`)
}

// writeUnrelatedCertipyMock writes a different program that happens to be called
// certipy. It must never be mistaken for the AD CS tool.
func writeUnrelatedCertipyMock(t *testing.T, directory, name string) {
	t.Helper()
	writeExecutable(t, directory, name, `case "$1" in
--version) echo 'certipy 0.1 - certificate helper' ;;
*) echo 'certificate helper: no AD CS support'; exit 0 ;;
esac`)
}

func readLoggedTMPDIR(t *testing.T, logPath string) string {
	t.Helper()
	contents, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("cargo recorded no TMPDIR: %v", err)
	}
	return strings.TrimSpace(string(contents))
}

// The default invocation manages supported dependencies without reaching for
// APT, sudo, or retired BloodHound components when all fixtures are present.

// installSCCMToolLayouts puts a functional SCCMhunter and PXEThief layout in the
// tools root, so a default installer run reuses them instead of installing.
func installSCCMToolLayouts(t *testing.T, bin string) {
	t.Helper()
	// A verified checkout reports its recorded revision through git.
	writeExecutable(t, bin, "git", `case "$*" in *"rev-parse HEAD"*) echo "8ca8a7905c3aec98b9b1e610c03688cbd361ddb0" ;; esac; exit 0`)
	toolsRoot := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", toolsRoot)
	for _, tool := range []struct{ root, script string }{{"sccmhunter", "sccmhunter.py"}, {"PXEThief", "pxethief.py"}} {
		if err := os.MkdirAll(filepath.Join(toolsRoot, tool.root, ".venv", "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(toolsRoot, tool.root, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeExecutable(t, filepath.Join(toolsRoot, tool.root, ".venv", "bin"), "python3", `case "$2" in
--help) echo "Commands:"; echo "  find  Enumerate LDAP for SCCM assets."; echo "  show  Show and/or recon table results."; exit 0 ;;
find) if [ "$3" = "--help" ]; then echo "-u -p -d -dc-ip -ldaps"; exit 0; fi; exit 0 ;;
esac
exit 0`)
		files := map[string]string{tool.script: "# entry\n", "requirements.txt": "scapy\n", "settings.ini": "auto_exploit_blank_password = 0\n", ".pwnflow-pr11": "8ca8a7905c3aec98b9b1e610c03688cbd361ddb0\n"}
		for name, contents := range files {
			if err := os.WriteFile(filepath.Join(toolsRoot, tool.root, name), []byte(contents), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	installNetworkToolLayouts(t, bin, toolsRoot)
}

// installNetworkToolLayouts adds the NetworkHound and RelayKing checkouts the way
// their upstream entry points behave: the help text documents the options PwnFlow
// builds, and RelayKing prints its usage and then exits non-zero, which the
// installer has to accept.
func installNetworkToolLayouts(t *testing.T, bin, toolsRoot string) {
	t.Helper()
	tools := []struct {
		root, script, help string
	}{
		{
			root: "NetworkHound", script: "NetworkHound.py",
			help: "--dc --domain --user --password --networks --output --port-scan --ports --scan-timeout --scan-threads",
		},
		{
			root: "RelayKing", script: "relayking.py",
			help: "--audit --protocols --dc-ip --output-file --proto-portscan --ntlmv1 --gen-relay-list --threads -o",
		},
	}
	for _, tool := range tools {
		root := filepath.Join(toolsRoot, tool.root)
		if err := os.MkdirAll(filepath.Join(root, ".venv", "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		help := tool.help
		// The usage text is printed for any invocation, and the exit status is
		// non-zero like RelayKing's own help: the installer judges the text, not
		// the status.
		writeExecutable(t, filepath.Join(root, ".venv", "bin"), "python3", "printf '%s\\n' '"+help+"'\nexit 1")
		// A checkout that has to be prepared goes through pip; providing it keeps
		// the fixture honest about what the installer needs.
		writeExecutable(t, filepath.Join(root, ".venv", "bin"), "pip3", "exit 0")
		files := map[string]string{tool.script: "# entry\n", "requirements.txt": "impacket\n", ".pwnflow-revision": "47ea549\n"}
		for name, contents := range files {
			if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The specialist integrations are also preinstalled fixtures: the default
	// installer must check them without invoking package managers or the network.
	sccmSecrets := filepath.Join(toolsRoot, "SCCMSecrets", ".venv", "bin")
	if err := os.MkdirAll(sccmSecrets, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsRoot, "SCCMSecrets", "SCCMSecrets.py"), []byte("# entry\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, sccmSecrets, "python3", `echo SCCMSecrets; exit 0`)
	for name, banner := range map[string]string{"mssqlrelay": "Microsoft SQL Relaying Tool", "mssqlpwner": "MSSQL Pwner", "gpoParser": "GPO Analysis Tool", "ghostspn": "ghostSPN"} {
		writeExecutable(t, bin, name, fmt.Sprintf("echo %q; exit 0", banner))
	}
}

func TestInstallerDefaultChecksAllSupportedDependencies(t *testing.T) {
	bin := t.TempDir()
	installSCCMToolLayouts(t, bin)
	writeExecutable(t, bin, "nxc", `if [ "$1" = "--help" ]; then exit 0; fi; if [ "$1" = "--version" ]; then echo fake-nxc; exit 0; fi; exit 1`)
	writeExecutable(t, bin, "rusthound-ce", `if [ "$1" = "--help" ]; then exit 0; fi`)
	writeCertipyADCSMock(t, bin, "certipy-ad")
	writeExecutable(t, bin, "dpkg-query", `printf '%s\n' 'ii  9.8.0~rc3-0kali1'`)
	writeFailingPackageManagerMocks(t, bin)

	output, err := runInstaller(t, bin)
	if err != nil {
		t.Fatalf("default installer check failed: %v\n%s", err, output)
	}
	for _, want := range []string{
		"NetExec already installed and functional",
		"RustHound-CE already installed and functional",
		"Certipy already installed and functional",
		"NetworkHound already installed and functional",
		"RelayKing already installed and functional",
		"NetExec: Already installed",
		"RustHound-CE: Already installed",
		"Certipy: Already installed",
		"NetworkHound: Already installed",
		"RelayKing: Already installed",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q: %s", want, output)
		}
	}
	for _, unwanted := range []string{
		"apt-should-not-run",
		"apt-cache-should-not-run",
		"sudo-should-not-run",
		"pipx-should-not-run",
		"BloodHound CE:",
		"BloodHound CE Python",
	} {
		if strings.Contains(output, unwanted) {
			t.Errorf("default installer referenced %q: %s", unwanted, output)
		}
	}
}

func TestInstallerSkipsExistingNetExecWithoutAPT(t *testing.T) {
	bin := t.TempDir()
	writeExecutable(t, bin, "nxc", `if [ "$1" = "--help" ]; then echo working; exit 0; fi`)
	writeExecutable(t, bin, "apt-get", `echo apt-should-not-run >&2; exit 99`)
	output, err := runInstaller(t, bin, "--with-netexec")
	if err != nil || !strings.Contains(output, "NetExec: Already installed") {
		t.Fatalf("existing tool was not skipped: err=%v\n%s", err, output)
	}
	if strings.Contains(output, "apt-should-not-run") {
		t.Fatal("installer invoked APT for a functional existing tool")
	}
}

// BloodHound CE is the separate graph application for importing and viewing
// collected data. The installer must not install it, and the retired flags must
// fail loudly instead of silently doing nothing.
func TestInstallerRefusesRetiredBloodHoundFlagsWithoutInstalling(t *testing.T) {
	bin := t.TempDir()
	writeFailingPackageManagerMocks(t, bin)
	for _, flag := range []string{"--with-bloodhound-ce", "--with-bloodhound-python", "--with-bloodhound"} {
		t.Run(flag, func(t *testing.T) {
			stdout, stderr, err := runInstallerSplit(t, bin, flag)
			if err == nil {
				t.Fatalf("%s unexpectedly succeeded:\n%s", flag, stdout)
			}
			combined := stdout + stderr
			if !strings.Contains(combined, "no longer installs BloodHound CE") {
				t.Errorf("%s did not explain the retirement: %s", flag, combined)
			}
			for _, unwanted := range []string{"apt-should-not-run", "apt-cache-should-not-run", "pipx-should-not-run", "sudo-should-not-run"} {
				if strings.Contains(combined, unwanted) {
					t.Errorf("%s performed installation work: %s", flag, combined)
				}
			}
		})
	}
}

func TestInstallerNeverInstallsOrStartsBloodHound(t *testing.T) {
	bin := t.TempDir()
	installSCCMToolLayouts(t, bin)
	writeExecutable(t, bin, "nxc", `if [ "$1" = "--help" ]; then exit 0; fi`)
	writeExecutable(t, bin, "rusthound-ce", `if [ "$1" = "--help" ]; then exit 0; fi`)
	writeCertipyADCSMock(t, bin, "certipy-ad")
	writeExecutable(t, bin, "systemctl", `echo systemctl-should-not-run >&2; exit 99`)
	writeExecutable(t, bin, "apt-cache", `echo apt-cache-should-not-run >&2; exit 99`)
	writeFailingPackageManagerMocks(t, bin)

	stdout, _, err := runInstallerSplit(t, bin)
	if err != nil {
		t.Fatalf("default installer run failed: %v\n%s", err, stdout)
	}
	for _, unwanted := range []string{
		"systemctl-should-not-run",
		"apt-cache-should-not-run",
		"apt-should-not-run",
		"pipx-should-not-run",
	} {
		if strings.Contains(stdout, unwanted) {
			t.Errorf("installer performed unrelated work: %s", stdout)
		}
	}
	// The installer no longer narrates BloodHound at all: no application
	// messaging, no retired installer rows, and no summary entry. The mock
	// directory is named after this test, so it is normalised away first.
	narrated := strings.ReplaceAll(stdout, bin, "<mock>")
	narrated = strings.ReplaceAll(narrated, os.Getenv("PWNFLOW_TOOLS_DIR"), "<tools>")
	if strings.Contains(narrated, "BloodHound") {
		t.Errorf("installer still displays obsolete BloodHound messaging: %s", narrated)
	}
	for _, unwanted := range []string{"BloodHound CE:", "BloodHound CE Python", "bloodhound-ce"} {
		if strings.Contains(narrated, unwanted) {
			t.Errorf("installer still displays %q: %s", unwanted, narrated)
		}
	}
}

func TestInstallerAPTUsesScopedNoninteractiveEnvironmentAndLockTimeout(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "apt.log")
	writeExecutable(t, bin, "sudo", `if [ "$1" = "-n" ]; then shift; fi; if [ "$1" = "-v" ]; then exit 0; fi; if [ "$1" = "env" ]; then shift; exec /usr/bin/env "$@"; fi; exec "$@"`)
	writeExecutable(t, bin, "apt-get", "printf '%s\\n' \"$DEBIAN_FRONTEND|$NEEDRESTART_MODE|$*\" >> \""+log+"\"; case \" $* \" in *install*) printf '%s\\n' '#!/bin/sh' 'if [ \"$1\" = \"--help\" ]; then exit 0; fi' > \""+filepath.Join(bin, "nxc")+"\"; /bin/chmod 700 \""+filepath.Join(bin, "nxc")+"\"; ;; esac; exit 0")
	writeExecutable(t, bin, "apt-cache", `exit 0`)
	oldPath := os.Getenv("PATH")
	t.Setenv("PWNFlow_ASSUME_YES", "1")
	os.Setenv("APT_LOG", log)
	os.Setenv("FAKE_BIN", bin)
	defer os.Setenv("PATH", oldPath)
	output, err := runInstaller(t, bin, "--with-netexec")
	if err != nil {
		t.Fatalf("mock APT install failed: %v\n%s", err, output)
	}
	contents, readErr := os.ReadFile(log)
	if readErr != nil {
		t.Fatalf("%v\ninstaller output: %s", readErr, output)
	}
	logText := string(contents)
	if !strings.Contains(logText, "noninteractive|l|") || !strings.Contains(logText, "DPkg::Lock::Timeout=30") {
		t.Fatalf("APT safety settings missing: %s", logText)
	}
}

func TestInstallerCargoOnlyDoesNotRequireSudo(t *testing.T) {
	bin := t.TempDir()
	writeExecutable(t, bin, "rusthound-ce", `if [ "$1" = "--help" ]; then exit 0; fi`)
	writeExecutable(t, bin, "sudo", `echo sudo-should-not-run >&2; exit 99`)
	output, err := runInstaller(t, bin, "--with-rusthound-ce")
	if err != nil || !strings.Contains(output, "RustHound-CE: Already installed") {
		t.Fatalf("Cargo-only existing dependency failed: err=%v\n%s", err, output)
	}
	if strings.Contains(output, "sudo-should-not-run") {
		t.Fatal("sudo was invoked for an already-installed user-level collector")
	}
}

// Kali does not put ~/.cargo/bin on PATH, so an existing RustHound-CE install
// must still be detected through CARGO_HOME/bin instead of being reinstalled.
func TestInstallerDetectsRustHoundInCargoBinWithoutRunningCargo(t *testing.T) {
	bin := t.TempDir()
	cargoHome := t.TempDir()
	marker := filepath.Join(t.TempDir(), "cargo-ran")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CARGO_HOME", cargoHome)
	t.Setenv("TMPDIR", "")
	t.Setenv("CARGO_RAN_MARKER", marker)
	writeExecutable(t, bin, "cargo", `case "$1" in
--version) echo 'cargo 1.95.0';;
install) : > "$CARGO_RAN_MARKER";;
esac`)
	if err := os.MkdirAll(filepath.Join(cargoHome, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(cargoHome, "bin"), "rusthound-ce", `case "$1" in --help) exit 0;; --version) echo 'rusthound-ce 2.5.25';; esac`)

	output, err := runInstaller(t, bin, "--with-rusthound-ce")
	if err != nil {
		t.Fatalf("existing RustHound-CE was not accepted: %v\n%s", err, output)
	}
	if !strings.Contains(output, "RustHound-CE already installed and functional") {
		t.Errorf("installer did not report the existing installation: %s", output)
	}
	if !strings.Contains(output, "RustHound-CE: Already installed") {
		t.Errorf("summary did not record the existing installation: %s", output)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Error("installer ran cargo install for a functional existing RustHound-CE")
	}
}

func TestInstallerHelpDocumentsStandaloneDefaultAndFlags(t *testing.T) {
	output, err := runInstaller(t, t.TempDir(), "--help")
	if err != nil {
		t.Fatalf("help failed: %v", err)
	}
	for _, want := range []string{"--with-netexec", "--with-rusthound-ce", "--with-certipy"} {
		if !strings.Contains(output, want) {
			t.Errorf("help missing %s", want)
		}
	}
	for _, unwanted := range []string{"--with-bloodhound", "pipx"} {
		if strings.Contains(output, unwanted) {
			t.Errorf("help still advertises %s: %s", unwanted, output)
		}
	}
}

// Cargo installs build under TMPDIR. Kali's /tmp is a small tmpfs, so the
// installer must use a disk-backed cache directory when the operator has not
// chosen one, and must hand that directory to Cargo.
func TestInstallerUsesDiskBackedCargoBuildDirectory(t *testing.T) {
	bin := t.TempDir()
	cargoHome := t.TempDir()
	home := t.TempDir()
	tmpLog := filepath.Join(t.TempDir(), "tmpdir.log")
	t.Setenv("HOME", home)
	t.Setenv("CARGO_HOME", cargoHome)
	t.Setenv("TMPDIR", "")
	t.Setenv("CARGO_TMP_LOG", tmpLog)
	writeExecutable(t, bin, "cargo", `case "$1" in
--version) echo 'cargo 1.95.0';;
install) printf '%s\n' "$TMPDIR" > "$CARGO_TMP_LOG"; /bin/mkdir -p "$CARGO_HOME/bin"; printf '%s\n' '#!/bin/sh' 'case "$1" in --help) echo rusthound-help;; --version) echo rusthound-ce 2.5.25;; esac' > "$CARGO_HOME/bin/rusthound-ce"; /bin/chmod 700 "$CARGO_HOME/bin/rusthound-ce";;
esac`)
	writeCargoPrerequisiteMocks(t, bin)
	writeFailingPackageManagerMocks(t, bin)

	output, err := runInstaller(t, bin, "--with-rusthound-ce")
	if err != nil {
		t.Fatalf("RustHound mock installation failed: %v\n%s", err, output)
	}
	wantDirectory := filepath.Join(home, ".cache", "pwnflow", "cargo-tmp")
	if recorded := readLoggedTMPDIR(t, tmpLog); recorded != wantDirectory {
		t.Errorf("Cargo ran with TMPDIR=%q, want %q", recorded, wantDirectory)
	}
	for _, want := range []string{
		"Cargo build directory: " + wantDirectory,
		"Installing missing RustHound-CE with Cargo.",
		"RustHound-CE installed and functional at " + filepath.Join(cargoHome, "bin", "rusthound-ce"),
		"RustHound-CE: Installed",
		"Cargo: Already installed",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q: %s", want, output)
		}
	}
	if strings.Contains(output, "apt-should-not-run") {
		t.Errorf("installer ran APT although every prerequisite was present: %s", output)
	}
}

func TestInstallerRespectsExplicitTMPDIR(t *testing.T) {
	bin := t.TempDir()
	cargoHome := t.TempDir()
	chosen := t.TempDir()
	tmpLog := filepath.Join(t.TempDir(), "tmpdir.log")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CARGO_HOME", cargoHome)
	t.Setenv("TMPDIR", chosen)
	t.Setenv("CARGO_TMP_LOG", tmpLog)
	writeExecutable(t, bin, "cargo", `case "$1" in
--version) echo 'cargo 1.95.0';;
install) printf '%s\n' "$TMPDIR" > "$CARGO_TMP_LOG"; /bin/mkdir -p "$CARGO_HOME/bin"; printf '%s\n' '#!/bin/sh' 'case "$1" in --help) exit 0;; esac' > "$CARGO_HOME/bin/rusthound-ce"; /bin/chmod 700 "$CARGO_HOME/bin/rusthound-ce";;
esac`)
	writeCargoPrerequisiteMocks(t, bin)

	output, err := runInstaller(t, bin, "--with-rusthound-ce")
	if err != nil {
		t.Fatalf("RustHound mock installation failed: %v\n%s", err, output)
	}
	if recorded := readLoggedTMPDIR(t, tmpLog); recorded != chosen {
		t.Errorf("operator TMPDIR was replaced: Cargo saw %q, want %q", recorded, chosen)
	}
	if !strings.Contains(output, "Cargo build directory: "+chosen) {
		t.Errorf("output did not report the operator TMPDIR: %s", output)
	}
}

func TestInstallerReportsInsufficientCargoBuildSpaceWithoutRunningCargo(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "cargo-ran")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CARGO_HOME", t.TempDir())
	t.Setenv("TMPDIR", "")
	t.Setenv("CARGO_RAN_MARKER", marker)
	writeExecutable(t, bin, "cargo", `case "$1" in
--version) echo 'cargo 1.95.0';;
install) : > "$CARGO_RAN_MARKER";;
esac`)
	for _, name := range []string{"cc", "clang", "pkg-config", "gcc"} {
		writeExecutable(t, bin, name, `exit 0`)
	}
	writeExecutable(t, bin, "dpkg-query", `printf '%s\n' 'install ok installed'`)
	writeExecutable(t, bin, "grep", `exec /usr/bin/grep "$@"`)
	writeExecutable(t, bin, "mkdir", `exec /usr/bin/mkdir "$@"`)
	writeAvailableSpaceMock(t, bin, insufficientFreeSpaceKB)

	stdout, _, err := runInstallerSplit(t, bin, "--with-rusthound-ce")
	if err == nil {
		t.Fatalf("installer ran with an undersized build directory:\n%s", stdout)
	}
	for _, want := range []string{
		"needs at least 2048 MiB",
		"RustHound-CE: Failed (no usable Cargo build directory)",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout must explain the build directory problem; missing %q\n%s", want, stdout)
		}
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Error("installer invoked cargo without a usable build directory")
	}
}

// Regression test: the installer reported "RustHound-CE: Failed" in its summary
// (stdout) while every diagnostic, including cargo's own error and the exit
// status, went to stderr. Any stdout-only view - a log, a pipe, a captured run -
// therefore showed a failure with no explanation, which is exactly what the
// operator observed on Kali.
func TestInstallerRustHoundCargoFailureIsExplainedOnStdout(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CARGO_HOME", t.TempDir())
	t.Setenv("TMPDIR", "")
	writeExecutable(t, bin, "cargo", `case "$1" in
--version) echo 'cargo 1.95.0';;
install) echo 'error: No space left on device (os error 28)' >&2; exit 101;;
esac`)
	writeCargoPrerequisiteMocks(t, bin)

	stdout, stderr, err := runInstallerSplit(t, bin, "--with-rusthound-ce")
	if err == nil {
		t.Fatalf("failed Cargo install unexpectedly succeeded:\n%s", stdout)
	}
	for _, want := range []string{
		"Installing missing RustHound-CE with Cargo.",
		"RustHound-CE Cargo installation failed (exit 101)",
		"RustHound-CE: Failed (cargo install exit 101)",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout must explain the failure on its own; missing %q\nstdout:\n%s\nstderr:\n%s", want, stdout, stderr)
		}
	}
	if !strings.Contains(stderr, "error: No space left on device (os error 28)") {
		t.Errorf("raw Cargo output must be preserved on stderr, got:\n%s", stderr)
	}
	if strings.Contains(stdout, "No space left on device") {
		t.Errorf("installer narration must not duplicate raw Cargo output on stdout:\n%s", stdout)
	}
}

func TestInstallerRustHoundCargoFailureShowsExitStatus(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CARGO_HOME", t.TempDir())
	t.Setenv("TMPDIR", "")
	writeExecutable(t, bin, "cargo", `case "$1" in
--version) echo 'cargo 1.95.0';;
install) echo 'error: libclang development files not found' >&2; exit 42;;
esac`)
	writeCargoPrerequisiteMocks(t, bin)

	output, err := runInstaller(t, bin, "--with-rusthound-ce")
	if err == nil {
		t.Fatalf("failed Cargo install unexpectedly succeeded: %s", output)
	}
	for _, want := range []string{
		"error: libclang development files not found",
		"RustHound-CE Cargo installation failed (exit 42)",
		"RustHound-CE: Failed",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("failure output missing %q: %s", want, output)
		}
	}
}

// The summary must let an operator tell a Cargo failure apart from a
// post-install verification failure, and the explanation must be on stdout.
func TestInstallerRustHoundVerificationFailureDiffersFromCargoFailure(t *testing.T) {
	bin := t.TempDir()
	cargoHome := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CARGO_HOME", cargoHome)
	t.Setenv("TMPDIR", "")
	writeExecutable(t, bin, "cargo", `case "$1" in
--version) echo 'cargo 1.95.0';;
install) echo 'Installed rusthound-ce';;
esac`)
	writeCargoPrerequisiteMocks(t, bin)

	stdout, _, err := runInstallerSplit(t, bin, "--with-rusthound-ce")
	if err == nil {
		t.Fatalf("unverified Cargo install unexpectedly succeeded:\n%s", stdout)
	}
	want := "RustHound-CE: Failed (cargo succeeded but rusthound-ce was not found in " + filepath.Join(cargoHome, "bin") + ")"
	if !strings.Contains(stdout, want) {
		t.Errorf("stdout missing %q:\n%s", want, stdout)
	}
	if strings.Contains(stdout, "cargo install exit") {
		t.Errorf("post-install verification failure must not be reported as a Cargo failure:\n%s", stdout)
	}
}

func TestInstallerRustHoundAddsOnlyMissingDocumentedPrerequisites(t *testing.T) {
	bin := t.TempDir()
	cargoHome := t.TempDir()
	log := filepath.Join(t.TempDir(), "apt.log")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CARGO_HOME", cargoHome)
	t.Setenv("TMPDIR", "")
	t.Setenv("PWNFlow_ASSUME_YES", "1")
	writeExecutable(t, bin, "cargo", `case "$1" in
--version) echo 'cargo 1.95.0';;
install) /bin/mkdir -p "$CARGO_HOME/bin"; printf '%s\n' '#!/bin/sh' 'exit 0' > "$CARGO_HOME/bin/rusthound-ce"; /bin/chmod 700 "$CARGO_HOME/bin/rusthound-ce";;
esac`)
	for _, name := range []string{"cc", "clang", "pkg-config", "gcc"} {
		writeExecutable(t, bin, name, `exit 0`)
	}
	writeExecutable(t, bin, "grep", `exec /usr/bin/grep "$@"`)
	writeExecutable(t, bin, "mkdir", `exec /usr/bin/mkdir "$@"`)
	writeAvailableSpaceMock(t, bin, ampleFreeSpaceKB)
	writeExecutable(t, bin, "dpkg-query", `case "$3" in libclang-dev|libkrb5-dev) exit 1;; *) printf '%s\n' 'install ok installed';; esac`)
	writeExecutable(t, bin, "sudo", `if [ "$1" = "-n" ]; then shift; fi; if [ "$1" = "-v" ]; then exit 0; fi; if [ "$1" = "env" ]; then shift; exec /usr/bin/env "$@"; fi; exec "$@"`)
	writeExecutable(t, bin, "apt-get", "printf '%s\\n' \"$*\" >> \""+log+"\"; exit 0")

	output, err := runInstaller(t, bin, "--with-rusthound-ce")
	if err != nil {
		t.Fatalf("prerequisite mock failed: %v\n%s", err, output)
	}
	contents, readErr := os.ReadFile(log)
	if readErr != nil {
		t.Fatal(readErr)
	}
	logText := string(contents)
	for _, want := range []string{"libclang-dev", "libkrb5-dev"} {
		if !strings.Contains(logText, want) {
			t.Errorf("missing prerequisite %q was not sent to APT: %s", want, logText)
		}
	}
	if strings.Contains(logText, "libssl-dev") || strings.Contains(logText, "libgssapi-krb5-2") || strings.Contains(logText, "libsasl2-modules-gssapi-mit") {
		t.Errorf("already installed prerequisites were unnecessarily selected: %s", logText)
	}
	if strings.Contains(logText, "bloodhound") || strings.Contains(logText, "pipx") {
		t.Errorf("BloodHound components must never be installed: %s", logText)
	}
}

// A functional AD CS Certipy, whatever name it is exposed as, must be reused
// instead of sending APT after a package that is already configured.
func TestInstallerReusesExistingCertipyWithoutAPT(t *testing.T) {
	for _, name := range []string{"certipy-ad", "certipy"} {
		t.Run(name, func(t *testing.T) {
			bin := t.TempDir()
			writeCertipyADCSMock(t, bin, name)
			writeFailingPackageManagerMocks(t, bin)

			output, err := runInstaller(t, bin, "--with-certipy")
			if err != nil {
				t.Fatalf("existing Certipy was not accepted: %v\n%s", err, output)
			}
			if !strings.Contains(output, "Certipy already installed and functional") {
				t.Errorf("existing Certipy was not reported: %s", output)
			}
			// Certipy reports its banner on stderr, so the installer has to read
			// both streams to name the version it accepted.
			if !strings.Contains(output, "Certipy v5.1.0") {
				t.Errorf("the accepted Certipy version was not reported: %s", output)
			}
			if !strings.Contains(output, "Certipy: Already installed") {
				t.Errorf("summary did not record the existing installation: %s", output)
			}
			for _, unwanted := range []string{"apt-should-not-run", "sudo-should-not-run", "pipx-should-not-run"} {
				if strings.Contains(output, unwanted) {
					t.Errorf("installer performed installation work for an existing Certipy: %s", output)
				}
			}
		})
	}
}

// A different program that happens to be called certipy must not be treated as
// the AD CS tool, and must not stop the supported package from being installed.
func TestInstallerRejectsUnrelatedCertipyAndInstallsTheADCSPackage(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "apt.log")
	writeUnrelatedCertipyMock(t, bin, "certipy")
	writeExecutable(t, bin, "sudo", `if [ "$1" = "-n" ]; then shift; fi; if [ "$1" = "-v" ]; then exit 0; fi; if [ "$1" = "env" ]; then shift; exec /usr/bin/env "$@"; fi; exec "$@"`)
	writeExecutable(t, bin, "apt-get", `printf '%s\n' "$*" >> "$APT_LOG"; case " $* " in
*" install "*) `+certipyPackageBody+` ;;
esac; exit 0`)
	t.Setenv("PWNFlow_ASSUME_YES", "1")
	t.Setenv("APT_LOG", log)
	t.Setenv("FAKE_BIN", bin)

	output, err := runInstaller(t, bin, "--with-certipy")
	if err != nil {
		t.Fatalf("Certipy installation failed: %v\n%s", err, output)
	}
	contents, readErr := os.ReadFile(log)
	if readErr != nil {
		t.Fatalf("%v\ninstaller output: %s", readErr, output)
	}
	logText := string(contents)
	if !strings.Contains(logText, "certipy-ad") {
		t.Errorf("the certipy-ad package was not requested: %s", logText)
	}
	if strings.Contains(output, "certipy 0.1") {
		t.Errorf("the unrelated certipy was accepted as AD CS Certipy: %s", output)
	}
	if !strings.Contains(output, "Installing missing Certipy (AD CS) from the Kali APT repository.") {
		t.Errorf("installer did not explain the installation: %s", output)
	}
	if !strings.Contains(output, "Certipy: Installed") {
		t.Errorf("summary did not record the installation: %s", output)
	}
}

// certipyPackageBody stands in for the package manager installing the Certipy
// package: it places the expected executable next to the mocks.
const certipyPackageBody = `printf '%s\n' \
'#!/bin/sh' \
'case "$1" in' \
'--version) echo "Certipy v5.1.0 - by Oliver Lyak (ly4k)" >&2 ;;' \
'--help) echo "Active Directory Certificate Services enumeration and abuse"; echo "    find                Enumerate AD CS" ;;' \
'find) echo "Discover and analyze Active Directory Certificate Services components."; echo "-dc-only -dc-ip -u -p -ldap-scheme -ldap-port -json -text -output -enabled -vulnerable" ;;' \
'*) exit 1 ;;' \
'esac' > "$FAKE_BIN/certipy-ad"
/bin/chmod 700 "$FAKE_BIN/certipy-ad"`

// An APT transaction still needs the operator's explicit approval: without it the
// simulation runs, the installation does not.
func TestInstallerCertipyInstallRequiresApproval(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "apt.log")
	writeExecutable(t, bin, "sudo", `if [ "$1" = "-n" ]; then shift; fi; if [ "$1" = "-v" ]; then exit 0; fi; if [ "$1" = "env" ]; then shift; exec /usr/bin/env "$@"; fi; exec "$@"`)
	writeExecutable(t, bin, "apt-get", `printf '%s\n' "$*" >> "$APT_LOG"; exit 0`)
	t.Setenv("PWNFlow_ASSUME_YES", "")
	t.Setenv("APT_LOG", log)

	stdout, stderr, err := runInstallerSplit(t, bin, "--with-certipy")
	if err == nil {
		t.Fatalf("the installer applied an unapproved transaction:\n%s", stdout)
	}
	if !strings.Contains(stdout+stderr, "APT transaction cancelled") {
		t.Errorf("the cancellation was not reported: %s%s", stdout, stderr)
	}
	contents, readErr := os.ReadFile(log)
	if readErr != nil {
		t.Fatalf("%v\ninstaller output: %s", readErr, stdout)
	}
	if strings.Contains(string(contents), "install -y") {
		t.Errorf("an installation ran without operator approval: %s", contents)
	}
	if !strings.Contains(stdout, "APT simulation for: certipy-ad") {
		t.Errorf("the transaction was not simulated before approval: %s", contents)
	}
	if !strings.Contains(stdout, "Certipy: Failed") {
		t.Errorf("summary did not record the cancelled installation: %s", stdout)
	}
}

// Selective installation stays selective: a tool that was not requested is
// reported as skipped and is not touched.
func TestInstallerSkipsCertipyUnlessRequested(t *testing.T) {
	bin := t.TempDir()
	writeExecutable(t, bin, "nxc", `if [ "$1" = "--help" ]; then exit 0; fi`)
	writeFailingPackageManagerMocks(t, bin)
	output, err := runInstaller(t, bin, "--with-netexec")
	if err != nil {
		t.Fatalf("selective installation failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "Certipy: Skipped") {
		t.Errorf("unselected Certipy was not reported as skipped: %s", output)
	}
	for _, unwanted := range []string{"apt-should-not-run", "sudo-should-not-run"} {
		if strings.Contains(output, unwanted) {
			t.Errorf("unselected Certipy still performed installation work: %s", output)
		}
	}
}

// pr11Head is the pull/11 revision the installer fixtures record. It is the commit
// upstream published for that pull request.
const pr11Head = "8ca8a7905c3aec98b9b1e610c03688cbd361ddb0"

// writeSCCMToolMocks provides the git, python3, mkdir, and chmod stand-ins the SCCM
// installation paths use, and records every call so a test can assert both what was
// run and what was deliberately not run. Nothing contacts a network.
func writeSCCMToolMocks(t *testing.T, bin, log string) {
	t.Helper()
	writeExecutable(t, bin, "mkdir", `exec /usr/bin/mkdir "$@"`)
	writeExecutable(t, bin, "chmod", `exec /bin/chmod "$@"`)
	writeExecutable(t, bin, "dirname", `exec /usr/bin/dirname "$@"`)
	writeExecutable(t, bin, "git", `printf '%s\n' "git $*" >> "`+log+`"
case "$1" in
clone)
  /usr/bin/mkdir -p "$3/.git"
  printf '%s\n' 'requirements' > "$3/requirements.txt"
  printf '%s\n' '# entry script' > "$3/sccmhunter.py"
  printf '%s\n' '# entry script' > "$3/pxethief.py"
  printf '%s\n' '[GENERAL SETTINGS]' > "$3/settings.ini"
  ;;
esac
case "$*" in
*"rev-parse HEAD"*) echo "$FAKE_PR_HEAD" ;;
esac
exit 0`)
	writeExecutable(t, bin, "python3", `printf '%s\n' "python3 $*" >> "`+log+`"
if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
  # $3 is the environment directory itself: <root>/.venv
  /usr/bin/mkdir -p "$3/bin"
  printf '%s\n' '#!/bin/sh' 'case "$2" in' '--help) echo "Commands:"; echo "  find  Enumerate LDAP for SCCM assets."; echo "  show  Show and/or recon table results."; exit 0 ;;' 'find) if [ "$3" = "--help" ]; then echo "-u -p -d -dc-ip -ldaps"; exit 0; fi; exit 0 ;;' 'esac' 'exit 0' > "$3/bin/python3"
  printf '%s\n' '#!/bin/sh' 'echo "pip3 $*" >> "`+log+`"' 'exit 0' > "$3/bin/pip3"
  /bin/chmod 700 "$3/bin/python3" "$3/bin/pip3"
fi
exit 0`)
}

// createCheckoutLayout lays out a checkout exactly as the installer leaves it: a
// git checkout, its entry script and requirements, and a working environment.
func createCheckoutLayout(t *testing.T, root, script, recordedRevision string) {
	t.Helper()
	for _, directory := range []string{filepath.Join(root, ".venv", "bin"), filepath.Join(root, ".git")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable(t, filepath.Join(root, ".venv", "bin"), "python3", `case "$2" in
--help) echo "Commands:"; echo "  find  Enumerate LDAP for SCCM assets."; echo "  show  Show and/or recon table results."; exit 0 ;;
find) if [ "$3" = "--help" ]; then echo "-u -p -d -dc-ip -ldaps"; exit 0; fi; exit 0 ;;
esac
exit 0`)
	files := map[string]string{script: "# entry script\n", "requirements.txt": "scapy\n", "settings.ini": "auto_exploit_blank_password = 0\n"}
	if recordedRevision != "" {
		files[".pwnflow-pr11"] = recordedRevision + "\n"
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A fresh installation clones both tools into their own checkouts, builds each
// virtual environment, and pins PXEThief to the pull/11 revision rather than the
// default branch.
func TestInstallerInstallsSCCMToolsFromTheirExactSources(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "calls.log")
	toolsRoot := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", toolsRoot)
	t.Setenv("FAKE_PR_HEAD", pr11Head)
	writeSCCMToolMocks(t, bin, log)
	writeFailingPackageManagerMocks(t, bin)

	output, err := runInstaller(t, bin, "--with-sccmhunter", "--with-pxethief")
	if err != nil {
		t.Fatalf("SCCM tool installation failed: %v\n%s", err, output)
	}
	sccmRoot := filepath.Join(toolsRoot, "sccmhunter")
	pxeRoot := filepath.Join(toolsRoot, "PXEThief")
	calls, readErr := os.ReadFile(log)
	if readErr != nil {
		t.Fatalf("no tool calls were recorded: %v", readErr)
	}
	recorded := string(calls)
	for _, want := range []string{
		"clone https://github.com/garrettfoster13/sccmhunter.git " + sccmRoot,
		"clone https://github.com/MWR-CyberSec/PXEThief.git " + pxeRoot,
		"-C " + pxeRoot + " fetch origin pull/11/head:pr-11",
		"-C " + pxeRoot + " checkout pr-11",
		"python3 -m venv " + filepath.Join(sccmRoot, ".venv"),
		"python3 -m venv " + filepath.Join(pxeRoot, ".venv"),
		"pip3 install -r " + filepath.Join(sccmRoot, "requirements.txt"),
		"pip3 install -r " + filepath.Join(pxeRoot, "requirements.txt"),
	} {
		if !strings.Contains(recorded, want) {
			t.Errorf("expected call %q is missing:\n%s", want, recorded)
		}
	}
	for _, forbidden := range []string{"checkout main", "checkout master", "checkout origin/HEAD"} {
		if strings.Contains(recorded, forbidden) {
			t.Errorf("a default branch was made the operational version (%q):\n%s", forbidden, recorded)
		}
	}
	marker, markerErr := os.ReadFile(filepath.Join(pxeRoot, ".pwnflow-pr11"))
	if markerErr != nil || strings.TrimSpace(string(marker)) != pr11Head {
		t.Errorf("the verified pull/11 revision was not recorded: %q %v", string(marker), markerErr)
	}
	for _, want := range []string{"SCCMhunter: Installed", "PXEThief: Installed"} {
		if !strings.Contains(output, want) {
			t.Errorf("the summary is missing %q: %s", want, output)
		}
	}
	for _, unwanted := range []string{"apt-should-not-run", "sudo-should-not-run"} {
		if strings.Contains(output, unwanted) {
			t.Errorf("the SCCM tools were installed through the system package manager: %s", output)
		}
	}
}

// A verified installation is reused: nothing is cloned, fetched, or installed
// again, and the environment is left alone.
func TestInstallerReusesVerifiedSCCMInstallations(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "calls.log")
	toolsRoot := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", toolsRoot)
	t.Setenv("FAKE_PR_HEAD", pr11Head)
	writeSCCMToolMocks(t, bin, log)
	writeFailingPackageManagerMocks(t, bin)
	createCheckoutLayout(t, filepath.Join(toolsRoot, "sccmhunter"), "sccmhunter.py", pr11Head)
	createCheckoutLayout(t, filepath.Join(toolsRoot, "PXEThief"), "pxethief.py", pr11Head)

	output, err := runInstaller(t, bin, "--with-sccmhunter", "--with-pxethief")
	if err != nil {
		t.Fatalf("existing SCCM tools were not reused: %v\n%s", err, output)
	}
	for _, want := range []string{"SCCMhunter already installed and functional", "PXEThief already installed at the required revision", "SCCMhunter: Already installed", "PXEThief: Already installed"} {
		if !strings.Contains(output, want) {
			t.Errorf("output is missing %q: %s", want, output)
		}
	}
	calls, _ := os.ReadFile(log)
	for _, forbidden := range []string{"clone", "fetch", "checkout", "venv", "pip3 install"} {
		if strings.Contains(string(calls), forbidden) {
			t.Errorf("a working installation was touched (%q):\n%s", forbidden, calls)
		}
	}
}

// When the pull request cannot be fetched the installer reports the git error and
// leaves the working SCCMhunter installation alone.
func TestInstallerKeepsWorkingSCCMHunterWhenPullRequestFetchFails(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "calls.log")
	toolsRoot := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", toolsRoot)
	writeExecutable(t, bin, "mkdir", `exec /usr/bin/mkdir "$@"`)
	writeExecutable(t, bin, "chmod", `exec /bin/chmod "$@"`)
	writeExecutable(t, bin, "dirname", `exec /usr/bin/dirname "$@"`)
	writeExecutable(t, bin, "git", `printf '%s\n' "git $*" >> "`+log+`"
case "$*" in
*" fetch "*) echo "fatal: couldn't find remote ref pull/11/head" >&2; exit 128 ;;
esac
exit 0`)
	writeFailingPackageManagerMocks(t, bin)
	createCheckoutLayout(t, filepath.Join(toolsRoot, "sccmhunter"), "sccmhunter.py", "")
	// The PXEThief checkout exists but is on another revision, so the installer has
	// to fetch pull/11 to make it operational.
	createCheckoutLayout(t, filepath.Join(toolsRoot, "PXEThief"), "pxethief.py", "0123456789abcdef0123456789abcdef01234567")

	stdout, stderr, err := runInstallerSplit(t, bin, "--with-sccmhunter", "--with-pxethief")
	if err == nil {
		t.Fatalf("a failed pull/11 fetch was reported as success:\n%s", stdout)
	}
	if !strings.Contains(stderr, "couldn't find remote ref") {
		t.Errorf("the actual git error was not reported: %s", stderr)
	}
	if !strings.Contains(stdout, "SCCMhunter: Already installed") {
		t.Errorf("a working SCCMhunter installation was not preserved: %s", stdout)
	}
	if !strings.Contains(stdout, "PXEThief: Failed (pull/11 could not be fetched)") {
		t.Errorf("the failure was not recorded accurately: %s", stdout)
	}
	calls, _ := os.ReadFile(log)
	if strings.Contains(string(calls), "pip3 install") || strings.Contains(string(calls), "checkout ") {
		t.Errorf("the installer substituted another revision or reinstalled a working tool:\n%s", calls)
	}
}

// A checkout on another revision, or one whose environment is damaged, is
// diagnosed rather than assumed to work.
func TestInstallerDiagnosesDamagedPXEThiefCheckout(t *testing.T) {
	bin := t.TempDir()
	toolsRoot := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", toolsRoot)
	writeExecutable(t, bin, "chmod", `exec /bin/chmod "$@"`)
	writeExecutable(t, bin, "dirname", `exec /usr/bin/dirname "$@"`)
	writeExecutable(t, bin, "git", `case "$*" in
*"rev-parse HEAD"*) echo "0123456789abcdef0123456789abcdef01234567" ;;
*fetch*) echo "fatal: couldn't find remote ref pull/11/head" >&2; exit 128 ;;
esac
exit 0`)
	writeFailingPackageManagerMocks(t, bin)
	if err := os.MkdirAll(filepath.Join(toolsRoot, "PXEThief", ".venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(toolsRoot, "PXEThief", ".venv", "bin"), "python3", `exit 0`)
	if err := os.WriteFile(filepath.Join(toolsRoot, "PXEThief", "pxethief.py"), []byte("# entry\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(toolsRoot, "PXEThief", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsRoot, "PXEThief", ".pwnflow-pr11"), []byte("8ca8a7905c3aec98b9b1e610c03688cbd361ddb0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := runInstallerSplit(t, bin, "--with-pxethief")
	if err == nil {
		t.Fatalf("a checkout on another revision was accepted:\n%s", stdout)
	}
	if !strings.Contains(stderr, "couldn't find remote ref") {
		t.Errorf("the actual git error was not reported: %s", stderr)
	}
	if !strings.Contains(stdout, "PXEThief: Failed (pull/11 could not be fetched)") {
		t.Errorf("the failure was not recorded accurately: %s", stdout)
	}
}

// The default invocation manages the SCCM tools too, and an unselected tool is
// reported as skipped without installation work.
func TestInstallerSCCMToolSelection(t *testing.T) {
	bin := t.TempDir()
	installSCCMToolLayouts(t, bin)
	writeFailingPackageManagerMocks(t, bin)
	output, err := runInstaller(t, bin, "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--with-sccmhunter", "--with-pxethief"} {
		if !strings.Contains(output, want) {
			t.Errorf("help missing %s: %s", want, output)
		}
	}
	skipped, err := runInstaller(t, bin, "--with-netexec")
	if err == nil {
		// nxc is absent in this mock set, so a failure is expected; what matters is
		// that the SCCM tools were not touched.
		_ = skipped
	}
	if strings.Contains(skipped, "SCCMhunter: Installed") || strings.Contains(skipped, "PXEThief: Installed") {
		t.Errorf("unselected SCCM tools were installed: %s", skipped)
	}
	if !strings.Contains(skipped, "SCCMhunter: Skipped") || !strings.Contains(skipped, "PXEThief: Skipped") {
		t.Errorf("unselected SCCM tools were not reported as skipped: %s", skipped)
	}
}

// The installer and the runtime validate the same thing: a checkout that runs but
// does not document the find options is reported, not called functional.
func TestInstallerRejectsSCCMHunterWithoutTheFindWorkflow(t *testing.T) {
	bin := t.TempDir()
	toolsRoot := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", toolsRoot)
	writeExecutable(t, bin, "chmod", `exec /bin/chmod "$@"`)
	writeExecutable(t, bin, "dirname", `exec /usr/bin/dirname "$@"`)
	writeFailingPackageManagerMocks(t, bin)
	root := filepath.Join(toolsRoot, "sccmhunter")
	if err := os.MkdirAll(filepath.Join(root, ".venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The tool runs, but its find subcommand no longer documents -ldaps.
	writeExecutable(t, filepath.Join(root, ".venv", "bin"), "python3", `case "$2" in
--help) echo "Commands:"; echo "  find"; echo "  show"; exit 0 ;;
find) if [ "$3" = "--help" ]; then echo "-u -p -d -dc-ip"; exit 0; fi; exit 0 ;;
esac
exit 0`)
	if err := os.WriteFile(filepath.Join(root, "sccmhunter.py"), []byte("# entry\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := runInstallerSplit(t, bin, "--with-sccmhunter")
	if err == nil {
		t.Fatalf("a checkout without the find workflow was called functional:\n%s", stdout)
	}
	if !strings.Contains(stdout+stderr, "does not document the find options") {
		t.Errorf("the mismatch was not explained: %s%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "SCCMhunter: Failed") {
		t.Errorf("the summary does not record the failure: %s", stdout)
	}
}
