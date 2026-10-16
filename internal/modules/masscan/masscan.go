package masscan

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/process"
)

const (
	moduleID        = "masscan"
	outputFile      = "Enumeration/Masscan/masscan.log"
	defaultRate     = 4000
	defaultPorts    = "21,22,23,25,53,80,110,111,135,139,389,443,445,593,623,636,993,995,1433,1521,1723,2049,2083,2086,3306,3389,5000,5432,5601,5985,5986,6379,8000,8008,8080-8090,8181,8443,8444,8888,9000,9090,9200,9443,10000,27017"
	artifactFolder  = "Enumeration/Masscan/artifacts"
	runTimeLayout   = "20060102-150405.000000000"
	optionTarget    = "TARGET"
	optionPorts     = "PORTS"
	optionScope     = "AUTHORIZED_SCOPE"
	optionExclusion = "EXCLUDE"
)

type Module struct{}

func (Module) ID() string                     { return moduleID }
func (Module) Name() string                   { return "Masscan" }
func (Module) ToolFamily() modules.ToolFamily { return modules.ToolFamilyNetwork }
func (Module) Category() modules.Category     { return modules.CategoryServiceEnumeration }
func (Module) Tool() string                   { return "Masscan" }
func (Module) Protocol() modules.Protocol     { return modules.ProtocolNA }
func (Module) Description() string {
	return "Runs an explicitly scoped Masscan TCP port scan at 4000 packets per second. The scan always requires operator approval and local sudo; it reports open ports as network observations, not vulnerabilities."
}
func (Module) Prerequisites() []string {
	return []string{"Masscan installed from the supported system package", "explicit authorized IPv4 scope", "local sudo for raw packets"}
}
func (Module) RequiredPrivileges() []string {
	return []string{"local raw-packet privileges via the existing sudo approval flow (not remote ADMIN-REQ)"}
}
func (Module) OutputFile() string               { return outputFile }
func (Module) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (Module) ReadOnly() bool                   { return false }
func (Module) SecondaryConnections() []string {
	return []string{"contacts only the operator-supplied authorized IPv4 target range"}
}
func (Module) OptionKeys() []string {
	return []string{optionTarget, optionPorts, optionScope, optionExclusion}
}

func (Module) Status(runtime *modules.Runtime) modules.Status {
	if runtime == nil || strings.TrimSpace(optionValue(runtime, optionTarget)) == "" || strings.TrimSpace(optionValue(runtime, optionPorts)) == "" {
		return modules.StatusInputRequired
	}
	return modules.StatusSudoRequired
}

func (Module) StatusReason(runtime *modules.Runtime) string {
	if runtime == nil || strings.TrimSpace(optionValue(runtime, optionTarget)) == "" {
		return "enter the IPv4 address, CIDR, or explicit IPv4 range to scan"
	}
	if strings.TrimSpace(optionValue(runtime, optionPorts)) == "" {
		return "accept or edit the default TCP port list"
	}
	return "Masscan needs local raw-packet privileges; approve sudo before the active scan"
}

func (Module) MissingInputs(runtime *modules.Runtime) []modules.InputField {
	missing := make([]modules.InputField, 0, 2)
	if strings.TrimSpace(optionValue(runtime, optionTarget)) == "" {
		missing = append(missing, modules.InputField{Key: optionTarget, Prompt: "IP-Range to scan", Example: "198.51.100.0/24"})
	}
	if strings.TrimSpace(optionValue(runtime, optionPorts)) == "" {
		missing = append(missing, modules.InputField{Key: optionPorts, Prompt: "Ports to scan (Enter accepts defaults)", Example: "443,445,8080-8090", Default: defaultPorts})
	}
	return missing
}

func (Module) ValidateInput(key, value string) error {
	switch key {
	case optionTarget:
		_, err := parseTarget(value)
		return err
	case optionPorts:
		_, err := normalizePorts(value)
		return err
	default:
		return nil
	}
}

func (Module) PlanApproval(runtime *modules.Runtime) (bool, string) {
	target := optionValue(runtime, optionTarget)
	ports := optionValue(runtime, optionPorts)
	return true, fmt.Sprintf("active Masscan scan of %s on ports %s at %d packets per second; only the explicitly authorized scope may be contacted", target, ports, defaultRate)
}

func (Module) IncludeInGlobalPlan() (bool, string) {
	return false, "manual active scan only; excluded from Default Enumeration"
}

func (m Module) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil {
		return fmt.Errorf("runtime configuration is required")
	}
	status := dependencies.DefaultRegistry().CheckOne(ctx, dependencies.Masscan)
	if !status.Available {
		return fmt.Errorf("%s: %s", status.DisplayName, status.Detail)
	}
	target := strings.TrimSpace(optionValue(runtime, optionTarget))
	if target == "" {
		return fmt.Errorf("Masscan target is required")
	}
	if _, err := parseTarget(target); err != nil {
		return err
	}
	ports := strings.TrimSpace(optionValue(runtime, optionPorts))
	if ports == "" {
		ports = defaultPorts
	}
	if _, err := normalizePorts(ports); err != nil {
		return err
	}
	scope := strings.TrimSpace(optionValue(runtime, optionScope))
	if scope == "" {
		scope = strings.TrimSpace(runtime.Target)
	}
	if scope == "" {
		return fmt.Errorf("an explicit AUTHORIZED_SCOPE is required for Masscan; the assessment target is not a usable IPv4 scope")
	}
	if err := targetWithinScope(target, scope); err != nil {
		return err
	}
	if exclusion := strings.TrimSpace(optionValue(runtime, optionExclusion)); exclusion != "" {
		if _, err := parseTargetList(exclusion); err != nil {
			return fmt.Errorf("invalid Masscan exclusion: %w", err)
		}
	}
	if runtime.Elevation == nil || !runtime.Elevation.ElevationApproved(moduleID) {
		return fmt.Errorf("Masscan requires local sudo approval for raw-packet access")
	}
	// The TUI performs the shared sudo preflight before this module enters the
	// runner. The actual sudo -n process below remains the authoritative launch;
	// if its timestamp is gone, the runner records a failed execution rather than
	// misclassifying it as an unavailable dependency.
	return nil
}

func (m Module) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if err := m.Check(ctx, runtime); err != nil {
		return err
	}
	status := dependencies.DefaultRegistry().CheckOne(ctx, dependencies.Masscan)
	ports := optionValue(runtime, optionPorts)
	if ports == "" {
		ports = defaultPorts
	}
	normalizedPorts, _ := normalizePorts(ports)
	target := optionValue(runtime, optionTarget)
	runDirectory := filepath.Join(runtime.ResultsRoot, artifactFolder, time.Now().UTC().Format(runTimeLayout))
	if err := os.MkdirAll(runDirectory, 0o700); err != nil {
		return err
	}
	artifact := filepath.Join(runDirectory, "masscan.log")
	args := []string{"-n", status.FoundExecutable, "--rate", strconv.Itoa(defaultRate), target, "-p", normalizedPorts, "-oG", artifact}
	if exclusion := strings.TrimSpace(optionValue(runtime, optionExclusion)); exclusion != "" {
		args = append(args, "--exclude", exclusion)
	}
	fmt.Fprintf(sink, "[i] Masscan target=%s ports=%s rate=%d artifact=%s\n", target, normalizedPorts, defaultRate, artifact)
	command := process.Command(ctx, "sudo", args...)
	command.Dir = runDirectory
	command.Stdout, command.Stderr = sink, sink
	err := process.Wait(ctx, command)
	if _, statErr := os.Stat(artifact); os.IsNotExist(statErr) && err == nil {
		if writeErr := os.WriteFile(artifact, nil, 0o600); writeErr != nil {
			return writeErr
		}
	}
	if data, readErr := os.ReadFile(artifact); readErr == nil && len(data) > 0 {
		fmt.Fprintln(sink, "[i] Masscan grepable artifact:")
		if _, writeErr := sink.Write(data); writeErr != nil {
			return writeErr
		}
	}
	if err != nil {
		return err
	}
	return nil
}

func (Module) CommandPreview(runtime *modules.Runtime) string {
	target := optionValue(runtime, optionTarget)
	ports := optionValue(runtime, optionPorts)
	if ports == "" {
		ports = defaultPorts
	}
	return fmt.Sprintf("sudo masscan --rate %d %s -p %s -oG <per-run-artifact>/masscan.log", defaultRate, target, ports)
}

func optionValue(runtime *modules.Runtime, key string) string {
	if runtime == nil {
		return ""
	}
	value, _ := runtime.ModuleOption(moduleID, key)
	return value
}

type ipRange struct{ first, last uint32 }

func parseTarget(value string) (ipRange, error) {
	if strings.TrimSpace(value) == "" || strings.HasPrefix(strings.TrimSpace(value), "-") || strings.ContainsAny(value, " \t\r\n;,\x00") {
		return ipRange{}, fmt.Errorf("invalid Masscan target: enter one IPv4 address, CIDR, or explicit IPv4 range")
	}
	if strings.Contains(value, "/") {
		ip, network, err := net.ParseCIDR(value)
		if err != nil || ip.To4() == nil || network.IP.To4() == nil || ip.To4().String() != network.IP.To4().String() {
			return ipRange{}, fmt.Errorf("invalid Masscan CIDR target: %s", value)
		}
		first := ipv4Number(network.IP.To4())
		mask := uint32(network.Mask[0])<<24 | uint32(network.Mask[1])<<16 | uint32(network.Mask[2])<<8 | uint32(network.Mask[3])
		last := first | ^mask
		return validateRange(ipRange{first, last})
	}
	if strings.Contains(value, "-") {
		parts := strings.Split(value, "-")
		if len(parts) != 2 {
			return ipRange{}, fmt.Errorf("invalid Masscan IPv4 range: %s", value)
		}
		first, err1 := parseIPv4(parts[0])
		last, err2 := parseIPv4(parts[1])
		if err1 != nil || err2 != nil {
			return ipRange{}, fmt.Errorf("invalid Masscan IPv4 range: %s", value)
		}
		return validateRange(ipRange{first, last})
	}
	valueNumber, err := parseIPv4(value)
	if err != nil {
		return ipRange{}, err
	}
	return validateRange(ipRange{valueNumber, valueNumber})
}

func parseTargetList(value string) ([]ipRange, error) {
	parts := strings.Split(value, ",")
	result := make([]ipRange, 0, len(parts))
	for _, part := range parts {
		rangeValue, err := parseTarget(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		result = append(result, rangeValue)
	}
	return result, nil
}

func targetWithinScope(target, scope string) error {
	targetRanges, err := parseTargetList(target)
	if err != nil {
		return err
	}
	scopeRanges, err := parseTargetList(scope)
	if err != nil {
		return fmt.Errorf("invalid authorized IPv4 scope: %w", err)
	}
	for _, requested := range targetRanges {
		contained := false
		for _, authorized := range scopeRanges {
			if requested.first >= authorized.first && requested.last <= authorized.last {
				contained = true
				break
			}
		}
		if !contained {
			return fmt.Errorf("Masscan target %s is outside the explicitly authorized scope", target)
		}
	}
	return nil
}

func parseIPv4(value string) (uint32, error) {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", value)
	}
	valueNumber := ipv4Number(ip.To4())
	if _, err := validateRange(ipRange{valueNumber, valueNumber}); err != nil {
		return 0, err
	}
	return valueNumber, nil
}

func validateRange(value ipRange) (ipRange, error) {
	if value.first > value.last {
		return ipRange{}, fmt.Errorf("Masscan target range is reversed")
	}
	if value.first>>24 == 127 || value.first>>28 == 0xe || value.first == 0 || value.last == ^uint32(0) {
		return ipRange{}, fmt.Errorf("loopback, multicast, unspecified, and broadcast ranges are not valid Masscan targets")
	}
	if uint64(value.last)-uint64(value.first)+1 > 1<<20 {
		return ipRange{}, fmt.Errorf("Masscan target range exceeds the one-million-address safety limit")
	}
	return value, nil
}

func ipv4Number(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

type portRange struct{ first, last int }

func normalizePorts(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("Masscan ports are required")
	}
	parts := strings.Split(value, ",")
	cleaned := make([]string, 0, len(parts))
	for _, raw := range parts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return "", fmt.Errorf("Masscan ports contain an empty entry")
		}
		pieces := strings.Split(raw, "-")
		if len(pieces) > 2 {
			return "", fmt.Errorf("invalid Masscan port range %q", raw)
		}
		first, err := parsePort(pieces[0])
		if err != nil {
			return "", err
		}
		last := first
		if len(pieces) == 2 {
			last, err = parsePort(pieces[1])
			if err != nil || last < first {
				return "", fmt.Errorf("invalid Masscan port range %q", raw)
			}
		}
		if len(pieces) == 1 {
			cleaned = append(cleaned, strconv.Itoa(first))
		} else {
			cleaned = append(cleaned, fmt.Sprintf("%d-%d", first, last))
		}
	}
	return strings.Join(cleaned, ","), nil
}

func parsePort(value string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("Masscan ports contain an empty value")
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid Masscan port %q; ports must be between 1 and 65535", value)
	}
	return port, nil
}

var _ modules.Module = Module{}
var _ modules.StatusProvider = Module{}
var _ modules.InputRequester = Module{}
var _ modules.InputValidator = Module{}
var _ modules.ApprovalRequester = Module{}
var _ modules.GlobalExecutionPolicy = Module{}
var _ modules.ElevationRequester = Module{}
var _ modules.OptionDeclarer = Module{}

func (Module) ElevationRequired() (bool, string) {
	return true, "Masscan needs local raw-packet privileges; approve sudo before the active scan"
}
