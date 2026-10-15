// Package sccm integrates Microsoft Configuration Manager (SCCM/MECM) assessment
// tooling: SCCMhunter discovers SCCM infrastructure through Active Directory, and
// PXEThief operates against the discovered PXE endpoints.
//
// The two modules share one assessment-scoped endpoint list. SCCMhunter records
// what it discovered - address, host name, SCCM role, and provenance - and
// PXEThief reads that list when it runs, so a batch that selects both discovers
// first and probes afterwards without either module reaching for the other's
// internals. Endpoints are scoped to the assessment domain and never carry
// credentials.
package sccm

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/process"
)

// detailSnapshotTTL bounds how long a module's Module Information is reused. The work
// behind it is expensive - a Python capability probe measured 625 ms on the reference
// Kali host - so it is computed off the render path and reused afterwards.
const detailSnapshotTTL = 15 * time.Second

// detailStore keeps the last computed Module Information of every module in this
// package. Rendering reads it; only a refresh writes it.
type detailStore struct {
	mutex   sync.Mutex
	entries map[string]detailSnapshot
}

type detailSnapshot struct {
	lines []string
	at    time.Time
}

var details = detailStore{entries: map[string]detailSnapshot{}}

// key scopes a snapshot to the environment and assessment whose information it
// describes, so reinstalling a tool, switching tools directory or starting a different
// assessment never shows another context's information.
func detailKey(moduleID string, runtime *modules.Runtime) string {
	domain := ""
	if runtime != nil {
		domain = runtime.Domain
	}
	return strings.Join([]string{
		moduleID, domain,
		os.Getenv("PWNFLOW_TOOLS_DIR"), os.Getenv("XDG_DATA_HOME"), os.Getenv("HOME"), os.Getenv("PATH"),
	}, "|")
}

// snapshot returns the stored lines and how old they are. A module that has not been
// refreshed yet says so rather than probing on the spot.
func (s *detailStore) snapshot(moduleID string) ([]string, time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	entry, ok := s.entries[moduleID]
	if !ok {
		return []string{"Module information is being collected."}, detailSnapshotTTL
	}
	return append([]string(nil), entry.lines...), time.Since(entry.at)
}

// store records freshly computed lines.
func (s *detailStore) store(moduleID string, lines []string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.entries[moduleID] = detailSnapshot{lines: append([]string(nil), lines...), at: time.Now()}
}

// refreshDetail runs one module's expensive work unless its snapshot is still fresh,
// so a refresh issued on a timer does nothing until it is worth doing.
func refreshDetail(moduleID string, runtime *modules.Runtime, compute func(context.Context, *modules.Runtime) []string) {
	key := detailKey(moduleID, runtime)
	if _, age := details.snapshot(key); age < detailSnapshotTTL {
		return
	}
	details.store(key, compute(context.Background(), runtime))
}

const (
	moduleIDSCCMHunter = "sccmhunter"
	moduleIDPXEThief   = "pxethief"

	sccmHunterFolder = "Enumeration/SCCMHunter"
	pxeThiefFolder   = "Enumeration/PXEThief"

	sccmHunterLog = "Enumeration/SCCMHunter/sccmhunter.log"
	pxeThiefLog   = "Enumeration/PXEThief/pxethief.log"

	runTimeLayout = "20060102-150405"
	redactedValue = "[REDACTED]"

	// discoveryFileName is the SCCMhunter database inside its isolated home.
	discoveryDBRelative = ".sccmhunter/logs/db/find.db"
	// discoveryShowFile keeps the original `show -all` output of one run.
	discoveryShowFile = "show-all.txt"
	// discoveryHomeDirectory isolates SCCMhunter's data directory per run: the tool
	// writes to $HOME/.sccmhunter and has no output-directory option, so the run
	// gets its own home instead of sharing the operator's accumulated database.
	discoveryHomeDirectory = "home"

	// Roles reported for discovered endpoints, in the order PXEThief prefers them.
	rolePXEDistributionPoint = "PXE-enabled distribution point"
	roleManagementPoint      = "management point"
	roleSiteServer           = "site server"
	roleSiteDatabase         = "site database"
	roleSCCMComputer         = "SCCM-related computer"
)

// secretOptions carry a value that must never reach a display, a log, or the
// execution history. Only -p is emitted by these modules; the remaining entries are
// the credential-bearing options the tools document, so no preview or log line can
// carry one of their values either.
var secretOptions = map[string]bool{
	"-p":         true,
	"--password": true,
	"-hashes":    true,
	"-aes":       true,
}

func redactArguments(args []string) []string {
	redacted := append([]string(nil), args...)
	for index, argument := range redacted {
		if secretOptions[argument] && index+1 < len(redacted) {
			redacted[index+1] = redactedValue
		}
	}
	return redacted
}

// dependencyCacheTTL bounds how long a detection result is reused. Detection runs a
// capability probe in a subprocess, and Module Information is rendered every frame,
// so the result is cached briefly. Tests set this to zero to observe every probe.
var dependencyCacheTTL = 30 * time.Second

var (
	dependencyCacheMu      sync.Mutex
	dependencyCacheResults = map[string]dependencyCacheEntry{}
)

// dependencyCacheKey includes the environment the lookup resolution depends on, so
// a change to the tools directory or PATH is observed instead of served from a
// stale entry.
func dependencyCacheKey(id dependencies.ID) string {
	return strings.Join([]string{
		string(id),
		os.Getenv("PWNFLOW_TOOLS_DIR"),
		os.Getenv("XDG_DATA_HOME"),
		os.Getenv("HOME"),
		os.Getenv("PATH"),
	}, "|")
}

type dependencyCacheEntry struct {
	status dependencies.Status
	err    error
	at     time.Time
}

// dependency resolves the installed tool for a module, reusing a recent detection
// result so rendering does not run a probe on every frame.
func dependency(ctx context.Context, id dependencies.ID) (dependencies.Status, error) {
	key := dependencyCacheKey(id)
	dependencyCacheMu.Lock()
	if entry, ok := dependencyCacheResults[key]; ok && time.Since(entry.at) < dependencyCacheTTL {
		dependencyCacheMu.Unlock()
		return entry.status, entry.err
	}
	dependencyCacheMu.Unlock()
	status := dependencies.DefaultRegistry().CheckOne(ctx, id)
	var err error
	if !status.Available {
		err = fmt.Errorf("%s: %s", status.DisplayName, status.Detail)
	}
	dependencyCacheMu.Lock()
	dependencyCacheResults[key] = dependencyCacheEntry{status: status, err: err, at: time.Now()}
	dependencyCacheMu.Unlock()
	return status, err
}

// dependencyLine describes a tool's installation state for Module Information. It
// reads the same short-lived cache as execution, so rendering never blocks on a
// probe, and it names the remedy when the tool is missing or unusable.
func dependencyLine(ctx context.Context, id dependencies.ID, displayName, remedy string) string {
	status, err := dependency(ctx, id)
	if err != nil {
		return fmt.Sprintf("%s: not usable - %v", displayName, err)
	}
	location := status.Detail
	if location == "" {
		location = status.FoundExecutable
	}
	if location == "" {
		return fmt.Sprintf("%s: installed (%s)", displayName, remedy)
	}
	return fmt.Sprintf("%s: installed at %s", displayName, location)
}

// interpreterCommand is the resolved invocation of a tool: its private
// interpreter, the entry script, and the arguments that follow.
func interpreterCommand(status dependencies.Status) (string, []string, error) {
	if status.Interpreter != "" && status.Script != "" {
		return status.Interpreter, []string{status.Script}, nil
	}
	if status.FoundExecutable != "" {
		return status.FoundExecutable, nil, nil
	}
	return "", nil, fmt.Errorf("%s: installed location could not be resolved", status.DisplayName)
}

// rolePriority orders endpoints so the systems most likely to answer a PXE
// request are probed first, deterministically.
func rolePriority(role string) int {
	switch role {
	case rolePXEDistributionPoint:
		return 0
	case roleManagementPoint:
		return 1
	case roleSiteServer:
		return 2
	case roleSiteDatabase:
		return 3
	default:
		return 4
	}
}

// sortEndpoints puts endpoints in the deterministic order PXEThief executes them:
// by role, then by address, then by host name.
func sortEndpoints(endpoints []modules.Endpoint) {
	sort.SliceStable(endpoints, func(first, second int) bool {
		left, right := endpoints[first], endpoints[second]
		if rolePriority(left.Role) != rolePriority(right.Role) {
			return rolePriority(left.Role) < rolePriority(right.Role)
		}
		if left.Address != right.Address {
			return left.Address < right.Address
		}
		return left.Hostname < right.Hostname
	})
}

// validAddress normalises an address discovered for an endpoint. Only addresses a
// packet can actually be sent to are accepted, so a placeholder or a broadcast
// address can never become a target.
func validAddress(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", false
	}
	address := net.ParseIP(trimmed)
	if address == nil {
		return "", false
	}
	if address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return "", false
	}
	if address.Equal(net.IPv4bcast) {
		return "", false
	}
	return address.String(), true
}

// inAssessmentDomain reports whether a discovered name belongs to the assessment
// domain. A name outside it was discovered from somewhere this assessment did not
// authorize, so it is never resolved into a target address.
func inAssessmentDomain(hostname, domain string) bool {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	scope := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if name == "" {
		return true
	}
	if scope == "" {
		return false
	}
	return name == scope || strings.HasSuffix(name, "."+scope)
}

// usableEndpoints returns the stored endpoints PXEThief may act on: those with a
// validated address that belong to the assessment domain, in execution order.
func usableEndpoints(stored []modules.Endpoint, domain string) []modules.Endpoint {
	usable := make([]modules.Endpoint, 0, len(stored))
	seen := make(map[string]bool, len(stored))
	for _, endpoint := range stored {
		address, ok := validAddress(endpoint.Address)
		if !ok || !inAssessmentDomain(endpoint.Hostname, domain) {
			continue
		}
		if endpoint.Domain != "" && !strings.EqualFold(endpoint.Domain, domain) {
			continue
		}
		if seen[address] {
			continue
		}
		seen[address] = true
		endpoint.Address = address
		usable = append(usable, endpoint)
	}
	sortEndpoints(usable)
	return usable
}

// discoveredEndpoints reports how many stored records belong to this assessment,
// which is what the Module Information pane shows.
func discoveredEndpoints(ctx context.Context, runtime *modules.Runtime) ([]modules.Endpoint, error) {
	if runtime == nil || runtime.Endpoints == nil || strings.TrimSpace(runtime.Domain) == "" {
		return nil, nil
	}
	return runtime.Endpoints.Endpoints(ctx, strings.TrimSpace(runtime.Domain))
}

// Resolver resolves discovered host names to addresses. It is an interface so
// discovery can be exercised without touching a network.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// SystemResolver performs bounded lookups with the host resolver.
type SystemResolver struct{ Timeout time.Duration }

func (r SystemResolver) lookupTimeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 3 * time.Second
}

// LookupHost resolves a name with a bounded context so discovery can never stall.
func (r SystemResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	bounded, cancel := context.WithTimeout(ctx, r.lookupTimeout())
	defer cancel()
	return net.DefaultResolver.LookupHost(bounded, host)
}

// resolveAddresses turns one discovered name into the addresses this assessment
// may use. A name that is already an address is used directly, and a name outside
// the assessment domain is never resolved.
func resolveAddresses(ctx context.Context, resolver Resolver, hostname, domain string) []string {
	if address, ok := validAddress(hostname); ok {
		return []string{address}
	}
	if !inAssessmentDomain(hostname, domain) {
		return nil
	}
	if resolver == nil {
		resolver = SystemResolver{}
	}
	addresses, err := resolver.LookupHost(ctx, strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if err != nil {
		return nil
	}
	valid := make([]string, 0, len(addresses))
	seen := make(map[string]bool, len(addresses))
	for _, address := range addresses {
		normalized, ok := validAddress(address)
		if !ok || seen[normalized] {
			continue
		}
		seen[normalized] = true
		valid = append(valid, normalized)
	}
	sort.Strings(valid)
	return valid
}

// pruneArtifacts removes empty run directories, so a failed run does not leave a
// misleading artifact tree behind.
func pruneArtifacts(directory string) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	if len(entries) == 0 {
		_ = os.Remove(directory)
	}
}

// runEnvironment is the process environment for a tool run: the inherited
// environment with HOME pointed at the run's own directory, which is what isolates
// SCCMhunter's data directory per assessment run.
func runEnvironment(home string) []string {
	if home == "" {
		return os.Environ()
	}
	allowed := make([]string, 0, 32)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "HOME=") {
			continue
		}
		allowed = append(allowed, entry)
	}
	if home == "" {
		return allowed
	}
	return append(allowed, "HOME="+home)
}

// prepareDirectory creates a directory with owner-only permissions.
func prepareDirectory(path string) error {
	return os.MkdirAll(path, 0750)
}

// capNetRawBit is CAP_NET_RAW's position in a Linux capability set. Both PXEThief
// modes craft DHCP packets with Scapy, which needs that capability.
const capNetRawBit = 13

// rawSocketHint is the short diagnostic shown when the kernel refuses a raw socket.
const rawSocketHint = "PXEThief discovery requires Linux raw-socket privileges (CAP_NET_RAW), which this process does not have"

// rawSocketPrivileges reports whether this process may open a Linux raw socket. It
// reads the process's own effective capability set, so it changes nothing and needs
// no network access: a capability is only ever removed by the kernel, and only the
// operator can grant one.
func rawSocketPrivileges() (available bool, known bool, detail string) {
	contents, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, false, "raw-socket privileges could not be determined on this host"
	}
	for _, line := range strings.Split(string(contents), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		bits, parseErr := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if parseErr != nil {
			return false, false, "the effective capability set could not be read"
		}
		if bits&(1<<capNetRawBit) != 0 {
			return true, true, "available (CAP_NET_RAW is in this process's effective set)"
		}
		return false, true, "missing (CAP_NET_RAW is not in this process's effective set)"
	}
	return false, false, "the effective capability set could not be read"
}

// rawSocketFailure reports whether tool output shows the kernel refusing a raw
// socket, which is the failure an operator can actually act on.
func rawSocketFailure(output string) bool {
	for _, pattern := range []string{"AF_PACKET", "PermissionError", "Operation not permitted"} {
		if strings.Contains(output, pattern) {
			return true
		}
	}
	return false
}

// tailBuffer keeps the most recent output of a tool so a failure can be classified
// without holding the whole stream in memory.
type tailBuffer struct {
	limit int
	data  []byte
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	if b.limit > 0 && len(b.data) > b.limit {
		b.data = append([]byte(nil), b.data[len(b.data)-b.limit:]...)
	}
	return len(p), nil
}

func (b *tailBuffer) String() string { return string(b.data) }

// multiSink forwards output to every sink in order.
type multiSink []modules.OutputSink

func (s multiSink) Write(p []byte) (int, error) {
	for _, sink := range s {
		if _, err := sink.Write(p); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// artifactLog persists a tool's output next to its artifacts. Everything written
// to it is redacted twice: the operator's password by value, and the values of any
// label that names secret material, because these tools can recover credentials.
type artifactLog struct {
	file *os.File
}

func newArtifactLog(path string) (*artifactLog, error) {
	if err := prepareDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	return &artifactLog{file: file}, nil
}

func (l *artifactLog) Write(p []byte) (int, error) { return l.file.Write(p) }

// Close closes the artifact file.
func (l *artifactLog) Close() error { return l.file.Close() }

// endpointCounts summarises the stored discovery state for Module Information.
func endpointCounts(ctx context.Context, runtime *modules.Runtime) (total int, usable int, detail string) {
	stored, err := discoveredEndpoints(ctx, runtime)
	if err != nil {
		return 0, 0, fmt.Sprintf("discovery store unreadable: %v", err)
	}
	if runtime == nil || runtime.Endpoints == nil {
		return 0, 0, "no assessment discovery store is available"
	}
	usableList := usableEndpoints(stored, runtime.Domain)
	roles := map[string]int{}
	for _, endpoint := range stored {
		roles[endpoint.Role]++
	}
	parts := make([]string, 0, len(roles))
	for _, role := range []string{rolePXEDistributionPoint, roleManagementPoint, roleSiteServer, roleSiteDatabase, roleSCCMComputer} {
		if roles[role] > 0 {
			parts = append(parts, strconv.Itoa(roles[role])+" "+role)
		}
	}
	if len(parts) == 0 {
		return len(stored), len(usableList), "no SCCM endpoints discovered for this assessment yet"
	}
	return len(stored), len(usableList), strings.Join(parts, ", ")
}

// artifactDirectory is the per-run artifact root of one module.
func artifactDirectory(runtime *modules.Runtime, folder string, started time.Time) string {
	if runtime == nil || runtime.ResultsRoot == "" {
		return filepath.Join(folder, "artifacts", started.Format(runTimeLayout))
	}
	return filepath.Join(runtime.ResultsRoot, folder, "artifacts", started.Format(runTimeLayout))
}

// outputDirectory is the per-domain module directory.
func outputDirectory(runtime *modules.Runtime, folder string) string {
	if runtime == nil || runtime.ResultsRoot == "" {
		return folder
	}
	return filepath.Join(runtime.ResultsRoot, folder)
}

// runCommand executes a tool with a controlled working directory and environment.
func runCommand(ctx context.Context, program string, args []string, directory, home string, sink modules.OutputSink) error {
	command := process.Command(ctx, program, args...)
	command.Dir = directory
	command.Env = runEnvironment(home)
	command.Stdout, command.Stderr = sink, sink
	// The tool runs in its own process group, so stopping one module reaches the
	// children it started and never PwnFlow's own group.
	return process.Wait(ctx, command)
}

// commandContext builds a tool invocation with a controlled working directory.
func commandContext(ctx context.Context, program string, args []string, directory string) *exec.Cmd {
	command := exec.CommandContext(ctx, program, args...)
	if directory != "" {
		command.Dir = directory
	}
	command.WaitDelay = 2 * time.Second
	return command
}
