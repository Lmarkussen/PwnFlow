package dependencies

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type ID string

type InstallMethod string
type DetectionMethod string

const (
	InstallAPT                 InstallMethod = "apt"
	InstallPipx                InstallMethod = "pipx"
	InstallOfficialBinary      InstallMethod = "official binary/release"
	InstallOfficialApplication InstallMethod = "official application"
	InstallCargo               InstallMethod = "cargo"
	InstallVenv                InstallMethod = "python virtual environment"
)

const (
	DetectExecutable    DetectionMethod = "executable"
	DetectDebianPackage DetectionMethod = "debian-package"
	// DetectToolLayout finds a tool shipped as a source checkout with its own
	// interpreter, such as a Python virtual environment created inside the
	// checkout. The interpreter is invoked by path, so no shell activation is
	// involved.
	DetectToolLayout DetectionMethod = "tool-layout"
)

const (
	NetExec      ID = "netexec"
	BloodHoundCE ID = "bloodhound-ce"
	BloodHoundPy ID = "bloodhound-ce-python"
	RustHoundCE  ID = "rusthound-ce"
	Certipy      ID = "certipy"
	SCCMHunter   ID = "sccmhunter"
	PXEThief     ID = "pxethief"
	NetworkHound ID = "networkhound"
	RelayKing    ID = "relayking"
)

// Layout locates a tool that is a source checkout with its own interpreter.
type Layout struct {
	// Roots are candidate checkout directories, in order.
	Roots []string
	// Script is the entry script inside a root.
	Script string
	// Interpreters are candidate interpreter paths inside a root, in order.
	Interpreters []string
}

type Definition struct {
	ID                   ID
	DisplayName          string
	Executable           string
	ExecutableCandidates []string
	Install              string
	// InstallHint, when set, is the operator-facing remedy verbatim.
	InstallHint   string
	InstallMethod InstallMethod
	Package       string
	Required      bool
	ProbeArgs     []string
	VersionArgs   []string
	Detection     DetectionMethod
	// ProbeMustContain lists text the capability probe must report. It exists so
	// a definition can require the tool to identify itself, which keeps an
	// unrelated program that happens to share a command name from counting as
	// installed.
	ProbeMustContain []string
	// ProbeAcceptsNonZeroExit marks a tool that prints its usage and then exits
	// non-zero, which RelayKing does for every help invocation. Such a probe is
	// judged by the output that identifies the tool - ProbeMustContain is then
	// required - rather than by the exit status.
	ProbeAcceptsNonZeroExit bool
	// Layout is used when Detection is DetectToolLayout.
	Layout *Layout
}

type Status struct {
	Definition
	Available       bool
	State           string
	Detail          string
	Version         string
	FoundExecutable string
	// Root, Interpreter, and Script describe a tool found through a Layout.
	Root        string
	Interpreter string
	Script      string
}

type Registry struct{ definitions []Definition }

func DefaultRegistry() Registry {
	return Registry{definitions: []Definition{
		{ID: NetExec, DisplayName: "NetExec (nxc)", Executable: "nxc", Install: "install.sh", InstallMethod: InstallAPT, Package: "netexec", Required: true, ProbeArgs: []string{"--help"}, VersionArgs: []string{"--version"}},
		// BloodHound CE is the separate graph application for importing and viewing
		// collected data; the standalone installer deliberately does not install it,
		// so these hints never name an installer operation.
		{ID: BloodHoundCE, DisplayName: "BloodHound CE", Executable: "bloodhound", Install: "the official BloodHound CE application", InstallMethod: InstallOfficialApplication, Package: "bloodhound", Required: false, Detection: DetectDebianPackage},
		{ID: BloodHoundPy, DisplayName: "BloodHound CE Python ingestor", Executable: "bloodhound-ce-python", ExecutableCandidates: []string{"bloodhound-ce-python", "bloodhound-python"}, Install: "the bloodhound-ce package", InstallMethod: InstallPipx, Package: "bloodhound-ce", Required: false, ProbeArgs: []string{"--help"}},
		{ID: RustHoundCE, DisplayName: "RustHound-CE", Executable: "rusthound-ce", Install: "install.sh --with-rusthound-ce", InstallMethod: InstallCargo, Package: "rusthound-ce", Required: false, ProbeArgs: []string{"--help"}, VersionArgs: []string{"--version"}},
		// Kali's package installs Certipy's AD CS tool as certipy-ad; the
		// pipx/PyPI distribution exposes the same tool as certipy. Both names are
		// tried, and the probe has to show the AD CS tool's own banner so an
		// unrelated command named certipy is never mistaken for it.
		{ID: Certipy, DisplayName: "Certipy (AD CS)", Executable: "certipy-ad", ExecutableCandidates: []string{"certipy"}, Install: "install.sh --with-certipy", InstallMethod: InstallAPT, Package: "certipy-ad", Required: false, ProbeArgs: []string{"--help"}, VersionArgs: []string{"--version"}, ProbeMustContain: []string{"Active Directory Certificate Services"}},
		// SCCMhunter and PXEThief are installed as source checkouts with their own
		// virtual environment, so the interpreter is invoked by path. SCCMhunter
		// also accepts an existing console script, such as a pipx installation.
		{ID: SCCMHunter, DisplayName: "SCCMhunter", Executable: "sccmhunter", Install: "install.sh --with-sccmhunter", InstallHint: "./install.sh --with-sccmhunter", InstallMethod: InstallVenv, Package: "sccmhunter", Required: false, Detection: DetectToolLayout, ProbeArgs: []string{"--help"}, Layout: &Layout{Roots: ToolRoots("sccmhunter"), Script: "sccmhunter.py", Interpreters: []string{".venv/bin/python3"}}},
		{ID: PXEThief, DisplayName: "PXEThief", Install: "install.sh --with-pxethief", InstallHint: "./install.sh --with-pxethief", InstallMethod: InstallVenv, Package: "PXEThief", Required: false, Detection: DetectToolLayout, ProbeArgs: []string{"-h"}, Layout: &Layout{Roots: ToolRoots("PXEThief"), Script: "pxethief.py", Interpreters: []string{".venv/bin/python3"}}},
		// NetworkHound and RelayKing are upstream checkouts with their own virtual
		// environments, exactly like the SCCM tooling. They are not pinned to a
		// revision: the installer and the runtime check that the installed checkout
		// documents the options the registrations use.
		{ID: NetworkHound, DisplayName: "NetworkHound", Install: "install.sh --with-networkhound", InstallHint: "./install.sh --with-networkhound", InstallMethod: InstallVenv, Package: "NetworkHound", Required: false, Detection: DetectToolLayout, ProbeArgs: []string{"--help"}, Layout: &Layout{Roots: ToolRoots("NetworkHound"), Script: "NetworkHound.py", Interpreters: []string{".venv/bin/python3"}}},
		{ID: RelayKing, DisplayName: "RelayKing", Install: "install.sh --with-relayking", InstallHint: "./install.sh --with-relayking", InstallMethod: InstallVenv, Package: "RelayKing", Required: false, Detection: DetectToolLayout, ProbeArgs: []string{"-h"}, ProbeMustContain: []string{"RelayKing"}, ProbeAcceptsNonZeroExit: true, Layout: &Layout{Roots: ToolRoots("RelayKing"), Script: "relayking.py", Interpreters: []string{".venv/bin/python3"}}},
	}}
}

// ToolRoots returns the candidate checkout directories for a PwnFlow-managed
// tool, in order: an explicitly configured tools directory, then the user's data
// directory. install.sh resolves the same roots.
func ToolRoots(name string) []string {
	if configured := strings.TrimSpace(os.Getenv("PWNFLOW_TOOLS_DIR")); configured != "" {
		return []string{filepath.Join(configured, name)}
	}
	if dataHome := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); dataHome != "" {
		return []string{filepath.Join(dataHome, "pwnflow", "tools", name)}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{filepath.Join(home, ".local", "share", "pwnflow", "tools", name)}
}

func (r Registry) All() []Definition { return append([]Definition(nil), r.definitions...) }

func (r Registry) Check(ctx context.Context) []Status {
	statuses := make([]Status, 0, len(r.definitions))
	for _, definition := range r.definitions {
		statuses = append(statuses, check(ctx, definition))
	}
	return statuses
}

func (r Registry) CheckOne(ctx context.Context, id ID) Status {
	for _, definition := range r.definitions {
		if definition.ID == id {
			return check(ctx, definition)
		}
	}
	return Status{Definition: Definition{ID: id}, State: "unknown", Detail: "dependency is not registered"}
}

func check(ctx context.Context, definition Definition) Status {
	if definition.Detection == DetectDebianPackage {
		return checkDebianPackage(ctx, definition)
	}
	if definition.Detection == DetectToolLayout {
		return checkToolLayout(ctx, definition)
	}
	status := Status{Definition: definition, State: "missing"}
	path, executable, err := findExecutable(ctx, definition)
	if err != nil {
		status.Detail = fmt.Sprintf("binary is not installed; install with %s", installationDescription(definition))
		return status
	}
	status.FoundExecutable = executable
	probeArgs := definition.ProbeArgs
	if len(probeArgs) == 0 {
		probeArgs = []string{"--help"}
	}
	var probeStdout, probeStderr bytes.Buffer
	probe := exec.CommandContext(ctx, path, probeArgs...)
	probe.Stdout, probe.Stderr = &probeStdout, &probeStderr
	if err := probe.Run(); err != nil {
		state := "broken"
		if ctx.Err() != nil {
			state = "check failed"
		}
		status.State = state
		status.Detail = fmt.Sprintf("%s capability probe %q failed: %s", definition.DisplayName, strings.Join(probeArgs, " "), diagnostic(probeStdout.String(), probeStderr.String(), err))
		return status
	}
	for _, required := range definition.ProbeMustContain {
		if !strings.Contains(probeStdout.String(), required) && !strings.Contains(probeStderr.String(), required) {
			status.State = "broken"
			status.Detail = fmt.Sprintf("%s at %s did not identify itself during the capability probe (expected %q); install %s", definition.DisplayName, path, required, installationDescription(definition))
			return status
		}
	}
	status.Available = true
	status.State = "installed"
	versionArgs := definition.VersionArgs
	if len(versionArgs) == 0 {
		versionArgs = []string{"--version"}
	}
	versionStdout, versionStderr := new(bytes.Buffer), new(bytes.Buffer)
	version := exec.CommandContext(ctx, path, versionArgs...)
	version.Stdout, version.Stderr = versionStdout, versionStderr
	_ = version.Run()
	status.Version = strings.TrimSpace(versionStdout.String())
	if status.Version == "" {
		status.Version = strings.TrimSpace(versionStderr.String())
	}
	if status.Version == "" {
		status.Version = "version unavailable"
	}
	status.Detail = path
	return status
}

// toolCommand is the resolved invocation of a tool found through a Layout.
func (s Status) toolCommand() (string, []string, bool) {
	if s.Interpreter == "" || s.Script == "" {
		return "", nil, false
	}
	return s.Interpreter, []string{s.Script}, true
}

// checkToolLayout detects a tool that lives in a source checkout with its own
// interpreter. An existing console script on PATH is accepted first, so a tool the
// operator installed another way is reused instead of reinstalled.
func checkToolLayout(ctx context.Context, definition Definition) Status {
	status := Status{Definition: definition, State: "missing"}
	if definition.Layout == nil {
		status.State = "broken"
		status.Detail = fmt.Sprintf("%s has no tool layout to search", definition.DisplayName)
		return status
	}
	if definition.Executable != "" {
		if path, _, err := findExecutable(ctx, definition); err == nil {
			status.FoundExecutable = path
			status.Root = filepath.Dir(path)
			if !probeSucceeds(ctx, path, definition.ProbeArgs, &status) {
				return status
			}
			status.Detail = path
			return status
		}
	}
	probeArgs := definition.ProbeArgs
	if len(probeArgs) == 0 {
		probeArgs = []string{"--help"}
	}
	reasons := make([]string, 0, len(definition.Layout.Roots))
	for _, root := range definition.Layout.Roots {
		script := filepath.Join(root, definition.Layout.Script)
		if !isRegularFile(script) {
			reasons = append(reasons, fmt.Sprintf("%s is missing", script))
			continue
		}
		interpreterPath := ""
		for _, candidate := range definition.Layout.Interpreters {
			if isExecutableFile(filepath.Join(root, candidate)) {
				interpreterPath = filepath.Join(root, candidate)
				break
			}
		}
		if interpreterPath == "" {
			reasons = append(reasons, fmt.Sprintf("%s has no usable interpreter (%s); re-run %s", root, strings.Join(definition.Layout.Interpreters, ", "), installationDescription(definition)))
			continue
		}
		status.Root, status.Interpreter, status.Script = root, interpreterPath, script
		if !probeSucceeds(ctx, interpreterPath, append([]string{script}, probeArgs...), &status) {
			return status
		}
		status.Detail = interpreterPath + " " + script
		return status
	}
	status.Detail = fmt.Sprintf("%s is not installed; install with %s", definition.DisplayName, installationDescription(definition))
	if len(reasons) > 0 {
		status.Detail = status.Detail + " (" + strings.Join(reasons, "; ") + ")"
	}
	return status
}

// probeSucceeds runs the capability probe and records a broken state when the
// installed tool cannot run.
func probeSucceeds(ctx context.Context, program string, arguments []string, status *Status) bool {
	var stdout, stderr bytes.Buffer
	probe := exec.CommandContext(ctx, program, arguments...)
	probe.Stdout, probe.Stderr = &stdout, &stderr
	if err := probe.Run(); err != nil {
		// A tool that prints its usage and exits non-zero is judged by the text
		// below, not by the status: there is no invocation of it that exits zero.
		if !status.ProbeAcceptsNonZeroExit || (stdout.Len() == 0 && stderr.Len() == 0) {
			status.State = "broken"
			if ctx.Err() != nil {
				status.State = "check failed"
			}
			status.Detail = fmt.Sprintf("%s capability probe %q failed: %s", status.DisplayName, strings.Join(append([]string{program}, arguments...), " "), diagnostic(stdout.String(), stderr.String(), err))
			status.Available = false
			return false
		}
	}
	for _, required := range status.ProbeMustContain {
		if !strings.Contains(stdout.String(), required) && !strings.Contains(stderr.String(), required) {
			status.State = "broken"
			status.Detail = fmt.Sprintf("%s at %s did not identify itself during the capability probe (expected %q)", status.DisplayName, program, required)
			status.Available = false
			return false
		}
	}
	status.Available = true
	status.State = "installed"
	return true
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
}

func checkDebianPackage(ctx context.Context, definition Definition) Status {
	status := Status{Definition: definition, State: "missing"}
	dpkg, err := exec.LookPath("dpkg-query")
	if err != nil {
		status.State = "broken"
		status.Detail = "dpkg-query is unavailable; cannot verify the installed package"
		return status
	}
	command := exec.CommandContext(ctx, dpkg, "-W", "-f=${db:Status-Abbrev} ${Version}\n", definition.Package)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		if strings.Contains(strings.ToLower(stderr.String()), "no packages found matching") {
			status.Detail = fmt.Sprintf("Debian package %s is not installed", definition.Package)
			return status
		}
		status.State = "check failed"
		status.Detail = fmt.Sprintf("dpkg-query failed for %s: %s", definition.Package, diagnostic(stdout.String(), stderr.String(), err))
		return status
	}
	version, valid := parseDebianPackageStatus(stdout.String())
	if !valid {
		status.State = "broken"
		status.Detail = fmt.Sprintf("Debian package %s is not fully installed/configured", definition.Package)
		return status
	}
	status.Available = true
	status.State = "installed"
	status.Version = version
	if path, lookErr := exec.LookPath(definition.Executable); lookErr == nil {
		status.FoundExecutable = path
	}
	status.Detail = fmt.Sprintf("Debian package %s (%s)", definition.Package, version)
	return status
}

func parseDebianPackageStatus(value string) (string, bool) {
	value = strings.TrimRight(value, "\r\n")
	fields := strings.Fields(value)
	if len(fields) < 2 || fields[0] != "ii" || fields[1] == "" {
		return "", false
	}
	// dpkg's status abbreviation must be exactly "ii " so an error flag or
	// transitional state such as iU/iF is never reported as installed.
	if len(value) < 3 || value[:3] != "ii " {
		return "", false
	}
	return fields[1], true
}

func findExecutable(ctx context.Context, definition Definition) (string, string, error) {
	candidates := append([]string{definition.Executable}, definition.ExecutableCandidates...)
	seen := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		if path, err := exec.LookPath(candidate); err == nil {
			return path, candidate, nil
		}
		for _, directory := range executableDirectories(ctx) {
			path := filepath.Join(directory, candidate)
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				return path, candidate, nil
			}
		}
	}
	return "", "", fmt.Errorf("no executable candidate found")
}

func executableDirectories(ctx context.Context) []string {
	seen := map[string]bool{}
	result := make([]string, 0, 3)
	add := func(directory string) {
		if directory != "" && !seen[directory] {
			seen[directory] = true
			result = append(result, directory)
		}
	}
	add(os.Getenv("PIPX_BIN_DIR"))
	if cargoHome := os.Getenv("CARGO_HOME"); cargoHome != "" {
		add(filepath.Join(cargoHome, "bin"))
	}
	if path, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(path, ".local", "bin"))
		add(filepath.Join(path, ".cargo", "bin"))
	}
	if pipx, err := exec.LookPath("pipx"); err == nil {
		output, err := exec.CommandContext(ctx, pipx, "environment", "--value", "PIPX_BIN_DIR").Output()
		if err == nil {
			add(strings.TrimSpace(string(output)))
		}
	}
	return result
}

// RefreshExecutablePath makes a newly installed user-scoped pipx application
// visible to this running process without editing shell startup files.
func RefreshExecutablePath(ctx context.Context) error {
	directories := executableDirectories(ctx)
	if len(directories) == 0 {
		return nil
	}
	pathValue := os.Getenv("PATH")
	parts := strings.Split(pathValue, string(os.PathListSeparator))
	seen := make(map[string]bool, len(parts)+len(directories))
	for _, part := range parts {
		seen[part] = true
	}
	prefix := make([]string, 0, len(directories))
	for _, directory := range directories {
		if !seen[directory] {
			prefix = append(prefix, directory)
		}
	}
	if len(prefix) == 0 {
		return nil
	}
	return os.Setenv("PATH", strings.Join(append(prefix, parts...), string(os.PathListSeparator)))
}

func installationDescription(definition Definition) string {
	if definition.InstallHint != "" {
		return definition.InstallHint
	}
	if definition.InstallMethod == "" {
		return definition.Install
	}
	return string(definition.InstallMethod) + " via " + definition.Install
}

func diagnostic(stdout, stderr string, err error) string {
	if value := strings.TrimSpace(stderr); value != "" {
		return value
	}
	if value := strings.TrimSpace(stdout); value != "" {
		return value
	}
	return err.Error()
}
