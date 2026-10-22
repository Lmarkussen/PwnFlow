// Package networkhound integrates NetworkHound, the AD network topology
// collector.
//
// Upstream: https://github.com/MorDavid/NetworkHound (Mor David). NetworkHound is
// distributed under a non-commercial license, so PwnFlow does not vendor or
// redistribute it: install.sh fetches the upstream checkout into the managed tools
// root, and this package drives the installed copy.
//
// Two capabilities are registered, and the difference between them is the whole
// point of the integration:
//
//   - AD Network Topology reads the directory through the configured domain
//     controller - computer objects, then DNS resolution through the same server -
//     and writes BloodHound-compatible OpenGraph JSON. It never connects to a
//     discovered computer.
//   - Scoped Network & Service Validation runs the port and service validation
//     NetworkHound normally applies to every discovered computer, but only against
//     a network scope the operator types for that run. Nothing is derived from
//     Active Directory, and no credential is passed: NetworkHound's manual mode
//     ignores the LDAP options entirely.
//
// The upstream features that sweep without an operator-supplied scope - the
// shadow-IT subnet sweep, automatic port scanning of AD-discovered hosts, and
// validation against every resolved address - are deliberately not registered.
package networkhound

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/artifacts"
	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/process"
)

const (
	// toolFolder is the checkout directory install.sh creates under the managed
	// tools root, and script is the upstream entry point inside it.
	toolFolder = "NetworkHound"
	script     = "NetworkHound.py"

	outputFolder                = "Enumeration/NetworkHound"
	artifactRel                 = "Enumeration/NetworkHound/artifacts"
	runTimeLayout               = "20060102-150405"
	automaticServiceArtifactKey = "networkhound-ad-host-services"
	automaticServiceOutput      = "ad_host_service.json"

	// redactedValue replaces the credential in anything PwnFlow displays.
	redactedValue = "[REDACTED]"

	// topologyOutput and scopeOutput are the OpenGraph JSON file names inside one
	// run directory.
	topologyOutput = "network_opengraph.json"
	scopeOutput    = "network_scope.json"

	// defaultPorts is NetworkHound's own default set of common ports; naming it
	// keeps the scan bounded to what the module documents.
	defaultPorts = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,5985,8080,8443"
)

const AutomaticServiceArtifactKey = automaticServiceArtifactKey

// options are the upstream options this package relies on. They are matched
// against the installed checkout's own help output, so a revision that renames or
// drops one is reported as unsupported instead of producing a different command
// than the module advertises.
var (
	topologyOptions = []string{"--dc", "--domain", "--user", "--password", "--output"}
	scopeOptions    = []string{"--networks", "-Pn", "--port-scan", "--ports", "--scan-timeout", "--scan-threads", "--output"}
)

// scopePattern accepts a comma-separated list of CIDR blocks, address ranges and
// single addresses - the three forms NetworkHound documents. A host name is
// refused, because a name would resolve to addresses the operator has not named.
var scopePattern = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2}|-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?)(,\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2}|-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?)*$`)

// Definition describes one registration.
type Definition struct {
	IDValue          string
	NameValue        string
	DescriptionValue string
	SlugValue        string
	CategoryValue    modules.Category
}

type Module struct{ definition Definition }

// EnumerationModules returns the NetworkHound registrations under
// Network → Enumeration.
func EnumerationModules() []Module {
	return []Module{
		{definition: Definition{
			IDValue:   "networkhound-topology",
			NameValue: "AD Network Topology",
			SlugValue: "topology",
			// Host Discovery: this is the collection that discovers the domain's
			// computers and the addresses they answer on.
			CategoryValue: modules.CategoryHostDiscovery,
			DescriptionValue: "Collects the Active Directory network topology with NetworkHound and writes BloodHound-compatible " +
				"OpenGraph JSON: computer objects, their operating systems, and the addresses they resolve to. The collection is " +
				"LDAP against the configured domain controller plus DNS resolution through the same server; NetworkHound's port scan, " +
				"service validation and shadow-IT sweep are not requested, so no discovered computer is contacted.",
		}},
		{definition: Definition{
			IDValue:   "networkhound-scope-validation",
			NameValue: "NetworkHound",
			SlugValue: "scope-validation",
			// Service Enumeration: it validates the services on the scope the
			// operator names.
			CategoryValue: modules.CategoryServiceEnumeration,
			DescriptionValue: "Runs NetworkHound's port and service validation against a network scope the operator supplies for this " +
				"run: CIDR blocks, address ranges and single addresses. Nothing is derived from Active Directory and no credential is " +
				"passed - NetworkHound's manual mode ignores the LDAP options - so the scan reaches exactly the addresses the operator " +
				"names, and PwnFlow asks for approval before it starts.",
		}},
	}
}

func (m Module) ID() string                       { return m.definition.IDValue }
func (m Module) Name() string                     { return m.definition.NameValue }
func (m Module) ToolFamily() modules.ToolFamily   { return modules.ToolFamilyNetwork }
func (m Module) Category() modules.Category       { return m.definition.CategoryValue }
func (m Module) Tool() string                     { return "NetworkHound" }
func (m Module) Protocol() modules.Protocol       { return modules.ProtocolNA }
func (m Module) Description() string              { return m.definition.DescriptionValue }
func (m Module) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (m Module) ReadOnly() bool                   { return true }
func (m Module) RequiredPrivileges() []string     { return nil }
func (m Module) SecondaryConnections() []string   { return m.secondaryConnections() }
func (m Module) DependencyKey() string            { return string(dependencies.NetworkHound) }

func (m Module) Prerequisites() []string {
	return []string{"NetworkHound checkout with its own virtual environment (install.sh)"}
}

func (m Module) OutputFile() string {
	return filepath.Join(outputFolder, m.definition.SlugValue+".log")
}

// scoped reports whether this registration is the operator-scoped validation.
func (m Module) scoped() bool { return m.definition.SlugValue == "scope-validation" }

// secondaryConnections states what the module may contact, so the operator does not
// have to infer it from the description.
func (m Module) secondaryConnections() []string {
	if !m.scoped() {
		return []string{
			"queries the configured domain controller over LDAP",
			"resolves computer names through DNS on the configured domain controller",
			"does not connect to the computers it discovers",
		}
	}
	if m.scoped() {
		return []string{
			"connects only to the addresses in the network scope supplied for this run",
			"does not query Active Directory and does not follow AD-discovered computers",
		}
	}
	return nil
}

// MissingInputs implements modules.InputRequester: the scoped registration cannot
// run without a scope, and PwnFlow asks for it before the batch starts.
func (m Module) MissingInputs(runtime *modules.Runtime) []modules.InputField {
	if !m.scoped() || (runtime != nil && runtime.AutomaticBatch) {
		return nil
	}
	if _, ok := runtime.ModuleOption(m.ID(), "NETWORKS"); ok {
		return nil
	}
	return []modules.InputField{{
		Key:     "NETWORKS",
		Prompt:  "which network scope should be validated? PwnFlow scans exactly these addresses.",
		Example: "198.51.100.0/29 or 198.51.100.10-198.51.100.20",
	}}
}

// Status implements modules.StatusProvider, with the same vocabulary the NetExec
// registrations use: a module waiting for a value the operator has to supply is
// configurable, not unavailable, and the family view says so instead of looking
// ready and then asking a question.
func (m Module) Status(runtime *modules.Runtime) modules.Status {
	if !m.scoped() {
		return modules.StatusAvailable
	}
	if _, ok := runtime.ModuleOption(m.ID(), "NETWORKS"); !ok {
		return modules.StatusInputRequired
	}
	return modules.StatusAvailable
}

// StatusReason explains the status, so Module Information names the value.
func (m Module) StatusReason(runtime *modules.Runtime) string {
	if status := m.Status(runtime); status == modules.StatusInputRequired {
		return "needs NETWORKS - the network scope this run may scan"
	}
	return ""
}

// PlanApproval implements modules.ApprovalRequester: a network scan is not
// something a global run may start on its own, so it is named in the plan.
func (m Module) PlanApproval(runtime *modules.Runtime) (bool, string) {
	if !m.scoped() || (runtime != nil && runtime.AutomaticBatch) {
		return false, ""
	}
	scope, ok := runtime.ModuleOption(m.ID(), "NETWORKS")
	if !ok {
		return true, "no network scope has been supplied yet"
	}
	return true, fmt.Sprintf("scans the operator-supplied scope %s", scope)
}

// DetailLines implements modules.DetailProvider: the pinned configuration and the
// scope statement, cheap enough to compute while drawing and free of secrets.
func (m Module) DetailLines(runtime *modules.Runtime) []string {
	lines := []string{"Transport: NetworkHound over the installed checkout (no shell)"}
	if m.scoped() {
		scope, ok := runtime.ModuleOption(m.ID(), "NETWORKS")
		if !ok {
			scope = "not supplied yet"
		}
		lines = append(lines,
			"Network scope: "+scope,
			"Ports: "+m.portList(runtime),
			fmt.Sprintf("Concurrency and timeout: %s thread(s), %s second(s) per port", m.value(runtime, "SCAN_THREADS", "10"), m.value(runtime, "SCAN_TIMEOUT", "10")),
			"Service validation: "+m.validationList(runtime),
			"Not requested: shadow-IT sweep, AD-derived targets, full-domain sweeps",
		)
		return lines
	}
	lines = append(lines,
		"Collection: LDAP and DNS against the configured domain controller",
		"Not requested: --port-scan, --valid-http, --valid-smb, --ssl, --shadow-it, --networks",
		"Output: BloodHound-compatible OpenGraph JSON",
	)
	return lines
}

func (m Module) value(runtime *modules.Runtime, key, fallback string) string {
	if value, ok := runtime.ModuleOption(m.ID(), key); ok {
		return value
	}
	return fallback
}

func (m Module) portList(runtime *modules.Runtime) string {
	return m.value(runtime, "PORTS", defaultPorts)
}

// validationList names the service checks this run will perform.
func (m Module) validationList(runtime *modules.Runtime) string {
	checks := make([]string, 0, 3)
	if enabled(runtime, m.ID(), "VALIDATE_HTTP") {
		checks = append(checks, "HTTP/HTTPS")
	}
	if enabled(runtime, m.ID(), "VALIDATE_SMB") {
		checks = append(checks, "SMB")
	}
	if enabled(runtime, m.ID(), "SSL_CERTIFICATES") {
		checks = append(checks, "certificate detail")
	}
	if len(checks) == 0 {
		return "port scan only (no HTTP, SMB or certificate validation requested)"
	}
	return strings.Join(checks, ", ")
}

func enabled(runtime *modules.Runtime, moduleID, key string) bool {
	value, ok := runtime.ModuleOption(moduleID, key)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// status resolves the installed checkout.
func status(ctx context.Context) (dependencies.Status, error) {
	return dependencies.DefaultRegistry().CheckOne(ctx, dependencies.NetworkHound), nil
}

// command resolves how the tool is invoked: the checkout's own interpreter, run
// against the entry script by path, so nothing depends on shell activation.
func command(status dependencies.Status) (string, []string, error) {
	if status.Interpreter != "" && status.Script != "" {
		return status.Interpreter, []string{status.Script}, nil
	}
	if status.FoundExecutable != "" {
		return status.FoundExecutable, nil, nil
	}
	return "", nil, fmt.Errorf("%s: installed location could not be resolved", status.DisplayName)
}

// Check validates the registration against the installed checkout before anything
// runs.
func (m Module) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil || strings.TrimSpace(runtime.Target) == "" {
		return fmt.Errorf("runtime target is required")
	}
	found, err := status(ctx)
	if err != nil {
		return err
	}
	if !found.Available {
		return fmt.Errorf("%s: %s", found.DisplayName, found.Detail)
	}
	help, err := installedHelp(ctx, found)
	if err != nil {
		return err
	}
	required := topologyOptions
	if m.scoped() {
		required = scopeOptions
	}
	for _, option := range required {
		if !strings.Contains(help, option) {
			return fmt.Errorf("the installed NetworkHound does not document %s, which this registration uses", option)
		}
	}
	if !m.scoped() {
		if strings.TrimSpace(runtime.Domain) == "" || strings.TrimSpace(runtime.Username) == "" {
			return fmt.Errorf("runtime domain and username are required for the directory collection")
		}
		return nil
	}
	if runtime.AutomaticBatch {
		addresses, err := topologyHostAddresses(runtime.BatchArtifacts["networkhound-topology"])
		if err != nil {
			return modules.SkipError{Reason: "AD-host service validation unavailable: " + err.Error()}
		}
		if len(addresses) == 0 {
			return modules.SkipError{Reason: "AD-host service validation skipped: topology contained no valid host IPs"}
		}
		if _, err := strconv.Atoi(m.value(runtime, "SCAN_THREADS", "10")); err != nil {
			return fmt.Errorf("SCAN_THREADS must be a number")
		}
		return nil
	}
	scope, ok := runtime.ModuleOption(m.ID(), "NETWORKS")
	if !ok {
		return fmt.Errorf("this registration scans a network scope and none has been supplied; set it with --module-options %s.NETWORKS=<scope>", m.ID())
	}
	if err := validateScope(scope); err != nil {
		return err
	}
	if _, err := strconv.Atoi(m.value(runtime, "SCAN_THREADS", "10")); err != nil {
		return fmt.Errorf("SCAN_THREADS must be a number")
	}
	if _, err := strconv.Atoi(m.value(runtime, "SCAN_TIMEOUT", "10")); err != nil {
		return fmt.Errorf("SCAN_TIMEOUT must be a number of seconds")
	}
	return nil
}

// validateScope refuses anything that is not a literal address, CIDR block or
// range: a name would resolve to addresses the operator did not name.
func validateScope(scope string) error {
	trimmed := strings.TrimSpace(scope)
	if trimmed == "" {
		return fmt.Errorf("the network scope is empty")
	}
	if !scopePattern.MatchString(trimmed) {
		return fmt.Errorf("the network scope %q is not a list of addresses, CIDR blocks or ranges", scope)
	}
	// Every network and range endpoint has to parse as an address as well: the
	// pattern alone would accept 999.1.1.1.
	for _, item := range strings.Split(trimmed, ",") {
		item = strings.TrimSpace(item)
		base := item
		if index := strings.IndexAny(item, "/"); index >= 0 {
			base = item[:index]
			prefix, err := strconv.Atoi(item[index+1:])
			if err != nil {
				return fmt.Errorf("the network scope %q has an invalid prefix length", item)
			}
			// Only IPv4 literals reach this point, so the prefix has to fit in a
			// 32-bit address: /33 would be a range nobody asked for.
			if prefix < 0 || prefix > 32 {
				return fmt.Errorf("the network scope %q has a prefix length outside 0-32", item)
			}
		}
		if index := strings.Index(item, "-"); index >= 0 {
			base = item[:index]
			if net.ParseIP(item[index+1:]) == nil {
				return fmt.Errorf("the network scope %q has an invalid range end", item)
			}
		}
		if net.ParseIP(base) == nil {
			return fmt.Errorf("the network scope %q is not an IP address", base)
		}
	}
	return nil
}

// installedHelp reads the checkout's own usage text.
func installedHelp(ctx context.Context, found dependencies.Status) (string, error) {
	program, base, err := command(found)
	if err != nil {
		return "", err
	}
	probeContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	output, _ := exec.CommandContext(probeContext, program, append(base, "--help")...).CombinedOutput()
	if len(output) == 0 {
		return "", fmt.Errorf("%s did not produce usage output", found.DisplayName)
	}
	return string(output), nil
}

// RunArtifactDirectory is the per-run directory: one directory per run, so no run
// overwrites another's JSON.
func (m Module) RunArtifactDirectory(runtime *modules.Runtime, started time.Time) string {
	if m.scoped() && runtime != nil && runtime.AutomaticBatch {
		return filepath.Join(runtime.ResultsRoot, artifactRel, "ad-host-service-"+started.Format(runTimeLayout))
	}
	return filepath.Join(runtime.ResultsRoot, artifactRel, m.definition.SlugValue+"-"+started.Format(runTimeLayout))
}

// CommandArgs builds the argument vector, which is also what the preview shows.
func (m Module) CommandArgs(runtime *modules.Runtime) []string {
	started := time.Now()
	return m.commandArgs(runtime, m.RunArtifactDirectory(runtime, started))
}

func (m Module) commandArgs(runtime *modules.Runtime, runDirectory string) []string {
	if m.scoped() {
		scope, _ := runtime.ModuleOption(m.ID(), "NETWORKS")
		ports := m.portList(runtime)
		scanTimeout := m.value(runtime, "SCAN_TIMEOUT", "10")
		scanThreads := m.value(runtime, "SCAN_THREADS", "10")
		if runtime.AutomaticBatch {
			targets, _ := topologyHostAddresses(runtime.BatchArtifacts["networkhound-topology"])
			scope = strings.Join(targets, ",")
			ports, scanTimeout, scanThreads = "21,445", "3", "10"
		}
		args := []string{
			"--networks", scope,
			"-Pn",
			"--port-scan",
			"--ports", ports,
			"--scan-timeout", scanTimeout,
			"--scan-threads", scanThreads,
			"--output", filepath.Join(runDirectory, automaticServiceOutput),
		}
		if !runtime.AutomaticBatch {
			args[len(args)-1] = filepath.Join(runDirectory, scopeOutput)
		}
		if enabled(runtime, m.ID(), "VALIDATE_HTTP") {
			args = append(args, "--valid-http")
		}
		if enabled(runtime, m.ID(), "VALIDATE_SMB") {
			args = append(args, "--valid-smb")
		}
		if enabled(runtime, m.ID(), "SSL_CERTIFICATES") {
			args = append(args, "--ssl")
		}
		return args
	}
	return []string{
		"--dc", runtime.Target,
		"--domain", runtime.Domain,
		"--user", runtime.Username,
		"--password", runtime.Password,
		"--output", filepath.Join(runDirectory, topologyOutput),
		"--verbose",
	}
}

// CommandPreview implements modules.CommandPreviewProvider: the operator's
// credential is never part of a preview, and the scope is always visible.
func (m Module) CommandPreview(runtime *modules.Runtime) string {
	args := m.CommandArgs(runtime)
	for index := range args {
		if index > 0 && args[index-1] == "--password" {
			args[index] = redactedValue
		}
	}
	return "NetworkHound.py " + strings.Join(args, " ")
}

// Run executes the collection in its own per-run directory. The tool writes its
// JSON there; the same output is what the runner records as the module's artifact.
func (m Module) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	found, err := status(ctx)
	if err != nil {
		return err
	}
	if !found.Available {
		return fmt.Errorf("%s: %s", found.DisplayName, found.Detail)
	}
	program, base, err := command(found)
	if err != nil {
		return err
	}
	started := time.Now()
	runDirectory := m.RunArtifactDirectory(runtime, started)
	if err := artifacts.EnsureDirectory(runDirectory, 0750); err != nil {
		return fmt.Errorf("create NetworkHound run directory: %w", err)
	}
	// The run directory is named in the transcript, so the operator can find this
	// run's JSON without guessing which timestamp belongs to it.
	outputName := topologyOutput
	if m.scoped() {
		outputName = scopeOutput
		if runtime.AutomaticBatch {
			outputName = automaticServiceOutput
		}
	}
	fmt.Fprintf(sink, "[i] NetworkHound %s: writing %s\n", m.definition.SlugValue, filepath.Join(runDirectory, outputName))
	args := append(append([]string(nil), base...), m.commandArgs(runtime, runDirectory)...)
	command := process.Command(ctx, program, args...)
	command.Dir = runDirectory
	command.Stdout, command.Stderr = sink, sink
	command.WaitDelay = 2 * time.Second
	runErr := process.Wait(ctx, command)
	// Whatever the tool produced is assessment data: an AD topology, not a public
	// document. The tool writes with the process umask, so the run directory is
	// tightened to owner-only afterwards, on the failure path as well, because a
	// partial collection is still a finding.
	if err := hardenRunDirectory(runDirectory); err != nil {
		fmt.Fprintf(sink, "[i] NetworkHound artifacts could not be restricted to your account: %v\n", err)
	}
	if runErr != nil {
		return fmt.Errorf("NetworkHound %s failed after %s: %w", m.definition.SlugValue, time.Since(started).Round(time.Millisecond), runErr)
	}
	if !m.scoped() {
		artifact := filepath.Join(runDirectory, topologyOutput)
		if _, err := os.Stat(artifact); err != nil {
			return fmt.Errorf("NetworkHound topology did not produce %s: %w", topologyOutput, err)
		}
		if runtime.BatchArtifacts == nil {
			runtime.BatchArtifacts = make(map[string]string)
		}
		runtime.BatchArtifacts[m.ID()] = artifact
	}
	if m.scoped() {
		artifact := filepath.Join(runDirectory, scopeOutput)
		if runtime.AutomaticBatch {
			artifact = filepath.Join(runDirectory, automaticServiceOutput)
		}
		if _, err := os.Stat(artifact); err != nil {
			return fmt.Errorf("NetworkHound scope validation did not produce %s: %w", filepath.Base(artifact), err)
		}
		addresses := []string(nil)
		if runtime.AutomaticBatch {
			data, err := os.ReadFile(artifact)
			if err != nil || !json.Valid(data) {
				return fmt.Errorf("NetworkHound AD-host service output is not valid JSON")
			}
			addresses, _ = topologyHostAddresses(runtime.BatchArtifacts["networkhound-topology"])
			metadata := map[string]any{
				"source_topology_artifact": runtime.BatchArtifacts["networkhound-topology"],
				"hosts_scanned":            addresses,
				"ports":                    []int{21, 445},
				"complete":                 true,
			}
			metadataBytes, _ := json.MarshalIndent(metadata, "", "  ")
			if err := os.WriteFile(filepath.Join(runDirectory, "ad_host_service_metadata.json"), metadataBytes, 0o600); err != nil {
				return fmt.Errorf("write NetworkHound service metadata: %w", err)
			}
		}
		if runtime.BatchArtifacts == nil {
			runtime.BatchArtifacts = make(map[string]string)
		}
		if runtime.AutomaticBatch {
			runtime.BatchArtifacts[AutomaticServiceArtifactKey] = artifact
			scope := strings.Join(addresses, ",")
			smb, _ := OpenPortEndpoints(artifact, scope, 445)
			ftp, _ := OpenPortEndpoints(artifact, scope, 21)
			fmt.Fprintf(sink, "[i] AD-host service validation: %d scoped hosts; TCP/21, TCP/445; %d SMB endpoints, %d FTP endpoints\n", len(addresses), len(smb), len(ftp))
		} else {
			runtime.BatchArtifacts[m.ID()] = artifact
		}
	}
	return nil
}

// OpenFTPEndpoints reads the current NetworkHound OpenGraph artifact and returns
// only literal, in-scope addresses whose reported open port is TCP/21. The
// artifact is intentionally supplied by the current batch; this function never
// searches historical results or performs a network request.
func OpenFTPEndpoints(path, scope string) ([]string, error) {
	return OpenPortEndpoints(path, scope, 21)
}

// OpenSMBEndpoints reads only current-batch NetworkHound evidence reporting
// TCP/445 as open. It never probes a host or consults historical results.
func OpenSMBEndpoints(path, scope string) ([]string, error) {
	return OpenPortEndpoints(path, scope, 445)
}

// topologyHostAddresses returns only valid IPv4 addresses attached to current
// topology Computer nodes. It never expands a network or resolves a hostname.
func topologyHostAddresses(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("current-batch NetworkHound topology artifact is missing")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("NetworkHound topology is invalid JSON: %w", err)
	}
	seen := make(map[string]bool)
	var addresses []string
	var walk func(any)
	walk = func(value any) {
		object, ok := value.(map[string]any)
		if !ok {
			if list, ok := value.([]any); ok {
				for _, child := range list {
					walk(child)
				}
			}
			return
		}
		computer := false
		if kinds, ok := object["kinds"].([]any); ok {
			for _, kind := range kinds {
				if text, ok := kind.(string); ok && text == "Computer" {
					computer = true
				}
			}
		}
		if computer {
			if properties, ok := object["properties"].(map[string]any); ok {
				collectTopologyIPs(properties["ip_addresses"], seen, &addresses)
			}
		}
		for _, child := range object {
			walk(child)
		}
	}
	walk(document)
	sort.Strings(addresses)
	return addresses, nil
}

// TopologyHostAddresses exposes the current-batch topology allowlist to
// consumers that need to reapply it while reading a derived artifact.
func TopologyHostAddresses(path string) ([]string, error) {
	return topologyHostAddresses(path)
}

func collectTopologyIPs(value any, seen map[string]bool, addresses *[]string) {
	switch value := value.(type) {
	case string:
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return
		}
		address := ip.To4().String()
		if !seen[address] {
			seen[address] = true
			*addresses = append(*addresses, address)
		}
	case []any:
		for _, child := range value {
			collectTopologyIPs(child, seen, addresses)
		}
	}
}

// OpenPortEndpoints returns literal, in-scope addresses whose open_ports list
// contains the requested TCP port.
func OpenPortEndpoints(path, scope string, wantedPort int) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("NetworkHound artifact path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("NetworkHound artifact is invalid JSON: %w", err)
	}
	if err := validateScope(scope); err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var endpoints []string
	var walk func(any)
	walk = func(value any) {
		switch item := value.(type) {
		case []any:
			for _, child := range item {
				walk(child)
			}
		case map[string]any:
			ports, ok := item["open_ports"].([]any)
			if ok {
				addresses := literalAddresses(item)
				for _, address := range addresses {
					if !addressInScope(address, scope) {
						continue
					}
					for _, port := range ports {
						if openPortValue(port, wantedPort) {
							endpoint := net.JoinHostPort(address, strconv.Itoa(wantedPort))
							if !seen[endpoint] {
								seen[endpoint] = true
								endpoints = append(endpoints, endpoint)
							}
						}
					}
				}
			}
			for _, child := range item {
				walk(child)
			}
		}
	}
	walk(document)
	return endpoints, nil
}

func openPortValue(value any, wanted int) bool {
	switch value := value.(type) {
	case float64:
		return int(value) == wanted
	case string:
		number, err := strconv.Atoi(strings.TrimSpace(value))
		return err == nil && number == wanted
	case map[string]any:
		for _, key := range []string{"port", "number", "port_number"} {
			if candidate, ok := value[key]; ok && openPortValue(candidate, wanted) {
				state, hasState := value["state"]
				if !hasState {
					state, hasState = value["status"]
				}
				if !hasState {
					return true
				}
				text, ok := state.(string)
				return ok && strings.EqualFold(strings.TrimSpace(text), "open")
			}
		}
	}
	return false
}

func literalAddresses(item map[string]any) []string {
	var addresses []string
	var add func(any)
	add = func(value any) {
		switch value := value.(type) {
		case string:
			if net.ParseIP(value) != nil {
				addresses = append(addresses, value)
			}
		case []any:
			for _, child := range value {
				add(child)
			}
		}
	}
	for _, key := range []string{"ip_addresses", "ip", "address", "addresses"} {
		add(item[key])
	}
	return addresses
}

func addressInScope(address, scope string) bool {
	ip := net.ParseIP(address)
	for _, item := range strings.Split(scope, ",") {
		item = strings.TrimSpace(item)
		if strings.Contains(item, "/") {
			if _, network, err := net.ParseCIDR(item); err == nil && network.Contains(ip) {
				return true
			}
			continue
		}
		if strings.Contains(item, "-") {
			parts := strings.SplitN(item, "-", 2)
			start, end := net.ParseIP(parts[0]), net.ParseIP(parts[1])
			if start != nil && end != nil && bytesCompare(start, ip) <= 0 && bytesCompare(ip, end) <= 0 {
				return true
			}
			continue
		}
		if item == address {
			return true
		}
	}
	return false
}

// AddressInScope exposes the same literal scope policy to dependent modules.
func AddressInScope(address, scope string) bool { return addressInScope(address, scope) }

// ValidateScope exposes NetworkHound's explicit operator scope validation to
// dependent modules without creating a second scope parser.
func ValidateScope(scope string) error { return validateScope(scope) }

func bytesCompare(left, right net.IP) int {
	left, right = left.To4(), right.To4()
	return strings.Compare(string(left), string(right))
}

// hardenRunDirectory makes one run's artifacts owner-only: directories 0750, files
// 0600. The assessment tree already has restrictive permissions, and this closes
// the gap the external tool leaves when it creates its own output files.
func hardenRunDirectory(directory string) error {
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o750)
		}
		return os.Chmod(path, 0o600)
	})
	if err != nil {
		return err
	}
	return artifacts.NormalizeTree(directory)
}

// ValidateOptionValue reports whether an operator-supplied option value is
// acceptable for this registration, so the interface can refuse a bad scope before
// a batch starts.
func (m Module) ValidateOptionValue(key, value string) error {
	if key != "NETWORKS" {
		return nil
	}
	return validateScope(value)
}
