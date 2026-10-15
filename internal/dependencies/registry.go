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
)

const (
	DetectExecutable    DetectionMethod = "executable"
	DetectDebianPackage DetectionMethod = "debian-package"
)

const (
	NetExec      ID = "netexec"
	BloodHoundCE ID = "bloodhound-ce"
	BloodHoundPy ID = "bloodhound-ce-python"
	RustHoundCE  ID = "rusthound-ce"
)

type Definition struct {
	ID                   ID
	DisplayName          string
	Executable           string
	ExecutableCandidates []string
	Install              string
	InstallMethod        InstallMethod
	Package              string
	Required             bool
	ProbeArgs            []string
	VersionArgs          []string
	Detection            DetectionMethod
}

type Status struct {
	Definition
	Available       bool
	State           string
	Detail          string
	Version         string
	FoundExecutable string
}

type Registry struct{ definitions []Definition }

func DefaultRegistry() Registry {
	return Registry{definitions: []Definition{
		{ID: NetExec, DisplayName: "NetExec (nxc)", Executable: "nxc", Install: "scripts/install.sh", InstallMethod: InstallAPT, Package: "netexec", Required: true, ProbeArgs: []string{"--help"}, VersionArgs: []string{"--version"}},
		// BloodHound CE is the separate graph application for importing and viewing
		// collected data; the standalone installer deliberately does not install it,
		// so these hints never name an installer operation.
		{ID: BloodHoundCE, DisplayName: "BloodHound CE", Executable: "bloodhound", Install: "the official BloodHound CE application", InstallMethod: InstallOfficialApplication, Package: "bloodhound", Required: false, Detection: DetectDebianPackage},
		{ID: BloodHoundPy, DisplayName: "BloodHound CE Python ingestor", Executable: "bloodhound-ce-python", ExecutableCandidates: []string{"bloodhound-ce-python", "bloodhound-python"}, Install: "the bloodhound-ce package", InstallMethod: InstallPipx, Package: "bloodhound-ce", Required: false, ProbeArgs: []string{"--help"}},
		{ID: RustHoundCE, DisplayName: "RustHound-CE", Executable: "rusthound-ce", Install: "scripts/install.sh --with-rusthound-ce", InstallMethod: InstallCargo, Package: "rusthound-ce", Required: false, ProbeArgs: []string{"--help"}, VersionArgs: []string{"--version"}},
	}}
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
