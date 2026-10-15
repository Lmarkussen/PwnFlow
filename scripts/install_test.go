package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

// writeCargoPrerequisiteMocks satisfies every native prerequisite the installer
// checks before invoking Cargo, so the RustHound paths reach the Cargo call.
func writeCargoPrerequisiteMocks(t *testing.T, bin string) {
	t.Helper()
	for _, name := range []string{"cc", "clang", "pkg-config", "gcc"} {
		writeExecutable(t, bin, name, `exit 0`)
	}
	writeExecutable(t, bin, "dpkg-query", `printf '%s\n' 'install ok installed'`)
	writeExecutable(t, bin, "grep", `exec /usr/bin/grep "$@"`)
}

func TestInstallerDefaultChecksAllSupportedDependencies(t *testing.T) {
	bin := t.TempDir()
	writeExecutable(t, bin, "nxc", `if [ "$1" = "--help" ]; then exit 0; fi; if [ "$1" = "--version" ]; then echo fake-nxc; exit 0; fi; exit 1`)
	writeExecutable(t, bin, "bloodhound", `exit 1`)
	writeExecutable(t, bin, "bloodhound-ce-python", `if [ "$1" = "--help" ]; then exit 0; fi`)
	writeExecutable(t, bin, "rusthound-ce", `if [ "$1" = "--help" ]; then exit 0; fi`)
	writeExecutable(t, bin, "dpkg-query", `printf '%s\n' 'ii  9.8.0~rc3-0kali1'`)
	output, err := runInstaller(t, bin)
	if err != nil {
		t.Fatalf("default installer check failed: %v\n%s", err, output)
	}
	for _, want := range []string{
		"NetExec already installed and functional",
		"BloodHound CE package already installed and configured",
		"BloodHound CE Python ingestor already installed and functional",
		"RustHound-CE already installed and functional",
		"NetExec: Already installed",
		"BloodHound CE: Already installed",
		"BloodHound CE Python: Already installed",
		"RustHound-CE: Already installed",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q: %s", want, output)
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

func TestInstallerBloodHoundUsesPackageStateNotDeprecatedCLI(t *testing.T) {
	bin := t.TempDir()
	writeExecutable(t, bin, "dpkg-query", `printf '%s\n' 'ii  9.8.0~rc3-0kali1'`)
	writeExecutable(t, bin, "bloodhound", `echo deprecated >&2; exit 1`)
	output, err := runInstaller(t, bin, "--with-bloodhound-ce")
	if err != nil || !strings.Contains(output, "BloodHound CE: Already installed") {
		t.Fatalf("package-aware detection failed: err=%v\n%s", err, output)
	}
	if strings.Contains(output, "deprecated") {
		t.Fatal("deprecated BloodHound wrapper was executed")
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

func TestInstallerHelpDocumentsStandaloneDefaultAndFlags(t *testing.T) {
	output, err := runInstaller(t, t.TempDir(), "--help")
	if err != nil {
		t.Fatalf("help failed: %v", err)
	}
	for _, want := range []string{"--with-netexec", "--with-bloodhound-ce", "--with-bloodhound-python", "--with-rusthound-ce"} {
		if !strings.Contains(output, want) {
			t.Errorf("help missing %s", want)
		}
	}
}

func TestInstallerRustHoundCargoSuccessRefreshesPath(t *testing.T) {
	bin := t.TempDir()
	cargoHome := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CARGO_HOME", cargoHome)
	writeExecutable(t, bin, "cargo", `case "$1" in
--version) echo 'cargo 1.95.0';;
install) /bin/mkdir -p "$CARGO_HOME/bin"; printf '%s\n' '#!/bin/sh' 'case "$1" in --help) echo rusthound-help;; --version) echo rusthound-ce 2.5.25;; esac' > "$CARGO_HOME/bin/rusthound-ce"; /bin/chmod 700 "$CARGO_HOME/bin/rusthound-ce";;
esac`)
	writeExecutable(t, bin, "cc", `exit 0`)
	writeExecutable(t, bin, "clang", `exit 0`)
	writeExecutable(t, bin, "pkg-config", `exit 0`)
	writeExecutable(t, bin, "gcc", `exit 0`)
	writeExecutable(t, bin, "dpkg-query", `printf '%s\n' 'install ok installed'`)
	writeExecutable(t, bin, "grep", `exec /usr/bin/grep "$@"`)

	output, err := runInstaller(t, bin, "--with-rusthound-ce")
	if err != nil {
		t.Fatalf("RustHound mock installation failed: %v\n%s", err, output)
	}
	for _, want := range []string{
		"Installing missing RustHound-CE with Cargo.",
		"RustHound-CE installed and functional at " + filepath.Join(cargoHome, "bin", "rusthound-ce"),
		"RustHound-CE: Installed",
		"Cargo: Already installed",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q: %s", want, output)
		}
	}
}

func TestInstallerRustHoundCargoFailureShowsStderrAndExitStatus(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CARGO_HOME", t.TempDir())
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

// Regression test: the installer reported "RustHound-CE: Failed" in its summary
// (stdout) while every diagnostic, including cargo's own error and the exit
// status, went to stderr. Any stdout-only view - a log, a pipe, a captured run -
// therefore showed a failure with no explanation, which is exactly what the
// operator observed on Kali.
func TestInstallerRustHoundCargoFailureIsExplainedOnStdout(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CARGO_HOME", t.TempDir())
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

// The summary must let an operator tell a Cargo failure apart from a
// post-install verification failure, and the explanation must be on stdout.
func TestInstallerRustHoundVerificationFailureDiffersFromCargoFailure(t *testing.T) {
	bin := t.TempDir()
	cargoHome := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CARGO_HOME", cargoHome)
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
	t.Setenv("PWNFlow_ASSUME_YES", "1")
	writeExecutable(t, bin, "cargo", `case "$1" in
--version) echo 'cargo 1.95.0';;
install) /bin/mkdir -p "$CARGO_HOME/bin"; printf '%s\n' '#!/bin/sh' 'exit 0' > "$CARGO_HOME/bin/rusthound-ce"; /bin/chmod 700 "$CARGO_HOME/bin/rusthound-ce";;
esac`)
	for _, name := range []string{"cc", "clang", "pkg-config", "gcc"} {
		writeExecutable(t, bin, name, `exit 0`)
	}
	writeExecutable(t, bin, "grep", `exec /usr/bin/grep "$@"`)
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
}
