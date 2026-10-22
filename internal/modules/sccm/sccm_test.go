package sccm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
)

// Fixtures for arbitrary operator-supplied assessment configuration.
const (
	// prTestHead is the pull/11 revision the fixtures record.
	prTestHead = "8ca8a7905c3aec98b9b1e610c03688cbd361ddb0"
	testTarget = "198.51.100.10"
	testDomain = "corp.example"
	testDC     = "dc01.corp.example"
)

// fakeStore is an in-memory endpoint store, so discovery persists exactly as it
// would through the assessment database without touching SQLite.
type fakeStore struct {
	mutex   sync.Mutex
	records []modules.Endpoint
	writes  int
}

func (s *fakeStore) RecordEndpoints(_ context.Context, endpoints []modules.Endpoint) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.writes++
	s.records = append(s.records, endpoints...)
	return nil
}

func (s *fakeStore) Endpoints(_ context.Context, domain string) ([]modules.Endpoint, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	selected := make([]modules.Endpoint, 0, len(s.records))
	for _, record := range s.records {
		if record.Domain == domain {
			selected = append(selected, record)
		}
	}
	return selected, nil
}

// fakeResolver resolves names from a table, so discovery never touches a network.
type fakeResolver map[string][]string

func (r fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if addresses, ok := r[host]; ok {
		return addresses, nil
	}
	return nil, fmt.Errorf("no such host %s", host)
}

// toolLayout installs a fake checkout with a private interpreter, which is the
// layout both tools are installed in. The interpreter records every invocation and
// runs the shell body provided for the entry script.
func toolLayout(t *testing.T, rootName, scriptName, body string) (root string, recordPath string) {
	t.Helper()
	toolsDirectory := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", toolsDirectory)
	t.Setenv("XDG_DATA_HOME", "")
	root = filepath.Join(toolsDirectory, rootName)
	if err := os.MkdirAll(filepath.Join(root, ".venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	recordPath = filepath.Join(t.TempDir(), "invocations.log")
	t.Setenv("PWNFLOW_FAKE_RECORD", recordPath)
	interpreter := `#!/bin/sh
script="$1"; shift
printf '%s %s\n' "$(basename "$script")" "$*" >> "$PWNFLOW_FAKE_RECORD"
exec /bin/sh -c "$PWNFLOW_FAKE_BODY" "$0" "$@"
`
	if err := os.WriteFile(filepath.Join(root, ".venv", "bin", "python3"), []byte(interpreter), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, scriptName), []byte("# fake entry script\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// PXEThief reads its settings from the working directory, and the installer
	// preserves the operator's file in the checkout.
	if err := os.WriteFile(filepath.Join(root, "settings.ini"), []byte("[GENERAL SETTINGS]\nauto_exploit_blank_password = 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNFLOW_FAKE_BODY", body)
	return root, recordPath
}

// moduleInvocations drops the capability probes so a test can assert the workflow
// invocations in order.
func moduleInvocations(invocations []string) []string {
	filtered := make([]string, 0, len(invocations))
	for _, invocation := range invocations {
		if strings.HasSuffix(invocation, " --help") || strings.HasSuffix(invocation, " -h") {
			continue
		}
		filtered = append(filtered, invocation)
	}
	return filtered
}

func readInvocations(t *testing.T, path string) []string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

// withRawSocketPrivileges stubs the capability probe so a test can exercise the
// privileged and unprivileged paths without touching the host's capabilities.
func withRawSocketPrivileges(t *testing.T, available bool) {
	t.Helper()
	previous := rawSocketPrivilegesFunc
	rawSocketPrivilegesFunc = func() (bool, bool, string) {
		if available {
			return true, true, "available (test stub)"
		}
		return false, true, "missing (test stub)"
	}
	t.Cleanup(func() { rawSocketPrivilegesFunc = previous })
}

// approvingPolicy is the operator's approval for one run. A renewal asks the same
// question again, so a module the operator approved is approved for the renewal
// unless the test says otherwise.
type approvingPolicy map[string]bool

func (p approvingPolicy) ElevationApproved(moduleID string) bool { return p[moduleID] }

func (p approvingPolicy) RenewElevation(_ context.Context, moduleID, _ string) bool {
	return p[moduleID]
}

// sudoCache makes the noninteractive sudo check report a valid or an expired
// timestamp. It stands in for sudo's own cached authorization, which a test cannot
// produce without authenticating.
func sudoCache(t *testing.T, valid bool) *bool {
	t.Helper()
	state := new(bool)
	*state = valid
	previous := sudoCheckFunc
	sudoCheckFunc = func(context.Context, string, ...string) error {
		if *state {
			return nil
		}
		return errors.New("sudo: a password is required")
	}
	t.Cleanup(func() { sudoCheckFunc = previous })
	return state
}

// sudoMock puts a stand-in sudo on PATH that records its arguments and then runs the
// command it was given, so a test can see exactly what would have been elevated.
// Nothing authenticates and nothing is privileged. When failWith is not empty the
// mock prints it to standard error and exits like a refused authorisation.
func sudoMock(t *testing.T, failWith string) string {
	t.Helper()
	bin := t.TempDir()
	record := filepath.Join(t.TempDir(), "sudo.log")
	body := "printf '%s\\n' \"sudo $*\" >> \"" + record + "\"\n"
	if failWith != "" {
		body += "printf '%s\\n' \"" + failWith + "\" >&2\nexit 1\n"
	} else {
		body += "while [ \"${1#-}\" != \"$1\" ]; do shift; done\nexec \"$@\"\n"
	}
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return record
}

func testRuntime(t *testing.T, store modules.EndpointStore) *modules.Runtime {
	t.Helper()
	return &modules.Runtime{
		Target:      testTarget,
		Domain:      testDomain,
		Username:    "audituser",
		Password:    "Sup3rSecret",
		ResultsRoot: filepath.Join(t.TempDir(), "results", testDomain),
		Endpoints:   store,
	}
}

// The discovery database is the structured source: the tool's own tables decide
// which records are endpoints and what role each one has.
func TestDiscoveryDatabaseIsReadByTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "find.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE PXEDistributionPoints(Hostname, SigningStatus, SCCM, WDS)`,
		`CREATE TABLE ManagementPoints(Hostname, SiteCode, SigningStatus)`,
		`CREATE TABLE SiteServers(Hostname, SiteCode, CAS, SigningStatus, SiteServer, SMSProvider, Config, MSSQL)`,
		`INSERT INTO PXEDistributionPoints VALUES('pxe01.corp.example','','','')`,
		`INSERT INTO PXEDistributionPoints VALUES('Unknown','','','')`,
		`INSERT INTO ManagementPoints VALUES('mp01.corp.example','PS1','')`,
		`INSERT INTO SiteServers VALUES('site01.corp.example','PS1','','','','','','')`,
	}
	for _, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	database.Close()

	records, err := readDiscoveryDatabase(path)
	if err != nil {
		t.Fatalf("reading the discovery database failed: %v", err)
	}
	roles := map[string]string{}
	for _, record := range records {
		roles[record.Hostname] = record.Role
	}
	if roles["pxe01.corp.example"] != rolePXEDistributionPoint {
		t.Fatalf("PXE distribution point role missing: %#v", roles)
	}
	if roles["mp01.corp.example"] != roleManagementPoint {
		t.Fatalf("management point role missing: %#v", roles)
	}
	if roles["site01.corp.example"] != roleSiteServer {
		t.Fatalf("site server role missing: %#v", roles)
	}
	if _, ok := roles["Unknown"]; !ok {
		t.Fatalf("the placeholder row should still be read as a record: %#v", roles)
	}
}

// The tool's printed tables are parsed as a structured fallback: the header row
// names the columns, so the host name is read from the Hostname column of each
// table the tool labels.
func TestDiscoveryTablesFallbackParsesRoles(t *testing.T) {
	output := `
Site Servers Table
+-------------+----------+
| Hostname    | SiteCode |
+-------------+----------+
| site01.corp.example | PS1      |
+-------------+----------+

Management Points Table
+-------------+----------+
| Hostname    | SiteCode |
+-------------+----------+
| mp01.corp.example   | PS1      |
+-------------+----------+

Potential PXE Distribution Points
+-------------+----------+------+------+
| Hostname    | SigningStatus | SCCM | WDS  |
+-------------+----------+------+------+
| pxe01.corp.example  |          |      |      |
| pxe01.corp.example  |          |      |      |
+-------------+----------+------+------+
`
	records := dedupeRecords(parseDiscoveryTables(output))
	roles := map[string]string{}
	for _, record := range records {
		roles[record.Hostname] = record.Role
	}
	if len(records) != 3 {
		t.Fatalf("expected one record per distinct host and role, got %#v", records)
	}
	if roles["pxe01.corp.example"] != rolePXEDistributionPoint || roles["mp01.corp.example"] != roleManagementPoint || roles["site01.corp.example"] != roleSiteServer {
		t.Fatalf("roles were not preserved: %#v", roles)
	}
}

// The discovery workflow runs find, then show -all, with LDAPS and the runtime
// credentials, and records what it found.
func TestSCCMHunterRunDiscoversThenShows(t *testing.T) {
	body := `case "$1" in
--help) echo "Commands: find show"; echo "-u -p -d -dc-ip -ldaps"; exit 0 ;;
find) echo "Potential PXE Distribution Points"; echo "+----------+"; echo "| Hostname |"; echo "+----------+"; echo "| pxe01.corp.example |"; exit 0 ;;
show) echo "Management Points Table"; echo "+----------+"; echo "| Hostname |"; echo "+----------+"; echo "| mp01.corp.example |"; echo "Potential PXE Distribution Points"; echo "+----------+"; echo "| Hostname |"; echo "+----------+"; echo "| pxe01.corp.example |"; exit 0 ;;
esac
exit 1`
	_, recordPath := toolLayout(t, "sccmhunter", "sccmhunter.py", body)
	dependencyCacheTTL = 0
	store := &fakeStore{}
	runtime := testRuntime(t, store)
	module := SCCMHunter{Resolver: fakeResolver{"pxe01.corp.example": {"198.51.100.41"}, "mp01.corp.example": {"198.51.100.42"}}}

	var output strings.Builder
	if err := module.Run(context.Background(), runtime, &output); err != nil {
		t.Fatalf("discovery failed: %v", err)
	}
	invocations := moduleInvocations(readInvocations(t, recordPath))
	if len(invocations) < 2 || !strings.HasPrefix(invocations[0], "sccmhunter.py find ") || !strings.HasPrefix(invocations[1], "sccmhunter.py show -all") {
		t.Fatalf("find must complete before show -all: %#v", invocations)
	}
	find := invocations[0]
	for _, want := range []string{"-u audituser", "-p Sup3rSecret", "-d " + testDomain, "-dc-ip " + testTarget, "-ldaps"} {
		if !strings.Contains(find, want) {
			t.Fatalf("find invocation is missing %q: %s", want, find)
		}
	}
	for _, forbidden := range []string{"admin", "http", "dpapi", "smb"} {
		for _, invocation := range invocations {
			if strings.Contains(invocation, " "+forbidden) {
				t.Fatalf("an unrelated subcommand was invoked: %s", invocation)
			}
		}
	}
	store.mutex.Lock()
	records := append([]modules.Endpoint(nil), store.records...)
	store.mutex.Unlock()
	if len(records) != 2 {
		t.Fatalf("expected two discovered endpoints, got %#v", records)
	}
	addresses := map[string]string{}
	for _, record := range records {
		addresses[record.Address] = record.Role
		if record.Domain != testDomain {
			t.Fatalf("endpoint was not scoped to the assessment: %#v", record)
		}
		if strings.Contains(record.Role+record.Source+record.Hostname, "Sup3rSecret") {
			t.Fatalf("a credential reached the endpoint record: %#v", record)
		}
	}
	if addresses["198.51.100.41"] != rolePXEDistributionPoint || addresses["198.51.100.42"] != roleManagementPoint {
		t.Fatalf("roles were not recorded per endpoint: %#v", addresses)
	}
	// The original output is preserved as an artifact, with the password removed.
	artifacts, err := filepath.Glob(filepath.Join(runtime.ResultsRoot, sccmHunterFolder, "artifacts", "*", discoveryShowFile))
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("expected one preserved show -all artifact, got %v (%v)", artifacts, err)
	}
	preserved, err := os.ReadFile(artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(preserved), "Sup3rSecret") {
		t.Fatal("the preserved output contains the password")
	}
}

// A failed discovery is not a zero-result discovery.
func TestSCCMHunterDistinguishesFailureFromZeroResults(t *testing.T) {
	failureBody := `case "$1" in
--help) echo "Commands: find show"; echo "-u -p -d -dc-ip -ldaps"; exit 0 ;;
find) echo "[-] bind failed"; exit 3 ;;
esac
exit 1`
	toolLayout(t, "sccmhunter", "sccmhunter.py", failureBody)
	dependencyCacheTTL = 0
	store := &fakeStore{}
	module := SCCMHunter{Resolver: fakeResolver{}}
	if err := module.Run(context.Background(), testRuntime(t, store), &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "find failed") {
		t.Fatalf("a failed discovery was not reported as a failure: %v", err)
	}
	if store.writes != 0 {
		t.Fatal("a failed discovery recorded endpoints")
	}

	zeroBody := `case "$1" in
--help) echo "Commands: find show"; echo "-u -p -d -dc-ip -ldaps"; exit 0 ;;
find) echo "[+] No SCCM found"; exit 0 ;;
show) echo "Management Points Table"; echo "+----------+"; echo "| Hostname |"; echo "+----------+"; exit 0 ;;
esac
exit 1`
	toolLayout(t, "sccmhunter", "sccmhunter.py", zeroBody)
	emptyStore := &fakeStore{}
	var output strings.Builder
	if err := module.Run(context.Background(), testRuntime(t, emptyStore), &output); err != nil {
		t.Fatalf("a zero-result discovery must succeed: %v", err)
	}
	if emptyStore.writes != 1 || len(emptyStore.records) != 0 {
		t.Fatalf("zero-result discovery recorded unexpected endpoints: %#v", emptyStore.records)
	}
	if !strings.Contains(output.String(), "mode 1") {
		t.Fatalf("the zero-result outcome was not explained: %s", output.String())
	}
}

func TestSCCMHunterCommandArguments(t *testing.T) {
	module := SCCMHunter{}
	args := module.CommandArgs(&modules.Runtime{Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret"})
	joined := strings.Join(args, " ")
	for _, want := range []string{"find", "-u audituser", "-p Sup3rSecret", "-d " + testDomain, "-dc-ip " + testTarget, "-ldaps"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("arguments are missing %q: %s", want, joined)
		}
	}
	for _, forbidden := range []string{"admin", "http", "dpapi", "smb", "-k"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("arguments contain %q: %s", forbidden, joined)
		}
	}
	preview := module.CommandPreview(&modules.Runtime{Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret"})
	if strings.Contains(preview, "Sup3rSecret") || !strings.Contains(preview, "-p "+redactedValue) {
		t.Fatalf("the preview does not redact the password: %s", preview)
	}
}

// PXEThief selects its mode from the assessment's stored endpoints at run time.
func TestPXEThiefModesFromStoredEndpoints(t *testing.T) {
	withRawSocketPrivileges(t, true)
	body := `case "$1" in
-h) echo "pxethief.py 1 - discover"; echo "pxethief.py 2 <ip>"; exit 0 ;;
1) echo "[+] mode 1 broadcast"; exit 0 ;;
2) echo "[+] mode 2 against $2"; exit 0 ;;
esac
exit 1`
	_, recordPath := toolLayout(t, "PXEThief", "pxethief.py", body)
	if err := os.WriteFile(filepath.Join(os.Getenv("PWNFLOW_TOOLS_DIR"), "PXEThief", pxeThiefMarker), []byte("8ca8a7905c3aec98b9b1e610c03688cbd361ddb0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencyCacheTTL = 0
	module := PXEThief{}

	cases := []struct {
		name      string
		endpoints []modules.Endpoint
		want      []string
	}{
		{name: "one endpoint", endpoints: []modules.Endpoint{{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain}}, want: []string{"pxethief.py 2 198.51.100.41"}},
		{name: "three endpoints", endpoints: []modules.Endpoint{
			{Address: "198.51.100.43", Hostname: "pxe03.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
			{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
			{Address: "198.51.100.42", Hostname: "mp01.corp.example", Role: roleManagementPoint, Domain: testDomain},
		}, want: []string{"pxethief.py 2 198.51.100.41", "pxethief.py 2 198.51.100.43", "pxethief.py 2 198.51.100.42"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Remove(recordPath); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			store := &fakeStore{}
			runtime := testRuntime(t, store)
			store.records = test.endpoints
			var output strings.Builder
			if err := module.Run(context.Background(), runtime, &output); err != nil {
				t.Fatalf("PXEThief failed: %v", err)
			}
			invocations := moduleInvocations(readInvocations(t, recordPath))
			if strings.Join(invocations, ",") != strings.Join(test.want, ",") {
				t.Fatalf("unexpected invocations:\ngot  %v\nwant %v", invocations, test.want)
			}
			for _, invocation := range invocations {
				if strings.Count(invocation, "198.51.100") > 1 {
					t.Fatalf("endpoints were combined into one argument: %s", invocation)
				}
			}
			// Every endpoint gets its own directory and its own log.
			for _, endpoint := range test.endpoints {
				directory := filepath.Join(runtime.ResultsRoot, pxeThiefFolder, "artifacts")
				matches, err := filepath.Glob(filepath.Join(directory, "*", endpoint.Address, "pxethief.log"))
				if err != nil || len(matches) != 1 {
					t.Fatalf("expected one log for %s, got %v (%v)", endpoint.Address, matches, err)
				}
			}
		})
	}
}

// One failing endpoint must not stop the others.
func TestPXEThiefContinuesAfterAnEndpointFails(t *testing.T) {
	withRawSocketPrivileges(t, true)
	body := `case "$1" in
-h) exit 0 ;;
1) exit 0 ;;
2) case "$2" in 198.51.100.42) echo "[-] no answer"; exit 4 ;; *) echo "[+] ok"; exit 0 ;; esac ;;
esac
exit 1`
	_, recordPath := toolLayout(t, "PXEThief", "pxethief.py", body)
	if err := os.WriteFile(filepath.Join(os.Getenv("PWNFLOW_TOOLS_DIR"), "PXEThief", pxeThiefMarker), []byte("8ca8a79\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencyCacheTTL = 0
	store := &fakeStore{records: []modules.Endpoint{
		{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
		{Address: "198.51.100.42", Hostname: "mp01.corp.example", Role: roleManagementPoint, Domain: testDomain},
		{Address: "198.51.100.43", Hostname: "pxe03.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
	}}
	var output strings.Builder
	err := (&PXEThief{}).Run(context.Background(), testRuntime(t, store), &output)
	if err == nil || !strings.Contains(err.Error(), "198.51.100.42") {
		t.Fatalf("the failing endpoint was not reported: %v", err)
	}
	invocations := moduleInvocations(readInvocations(t, recordPath))
	if len(invocations) != 3 {
		t.Fatalf("every endpoint must be attempted: %#v", invocations)
	}
}

// A cancelled run stops before the next endpoint.
func TestPXEThiefStopsOnCancellation(t *testing.T) {
	withRawSocketPrivileges(t, true)
	body := `case "$1" in
-h) exit 0 ;;
2) echo "[+] $2"; sleep 5; exit 0 ;;
esac
exit 0`
	_, _ = toolLayout(t, "PXEThief", "pxethief.py", body)
	if err := os.WriteFile(filepath.Join(os.Getenv("PWNFLOW_TOOLS_DIR"), "PXEThief", pxeThiefMarker), []byte("8ca8a79\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencyCacheTTL = 0
	store := &fakeStore{records: []modules.Endpoint{
		{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
		{Address: "198.51.100.42", Hostname: "pxe02.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	started := time.Now()
	err := (&PXEThief{}).Run(ctx, testRuntime(t, store), &strings.Builder{})
	if err == nil {
		t.Fatal("a cancelled run reported success")
	}
	if time.Since(started) > 4*time.Second {
		t.Fatal("cancellation did not stop the run promptly")
	}
}

// Endpoints outside the assessment domain, or without a usable address, are never
// turned into targets, and credentials recovered by the tool never reach the logs.
func TestPXEThiefScopeAndSecretHandling(t *testing.T) {
	withRawSocketPrivileges(t, true)
	body := `case "$1" in
-h) exit 0 ;;
2) echo "[+] Password provided: Sup3rSecret"; echo "[!] Network Access Account Password: 'recovered-secret'"; echo "[!] Collection Variable Secret: 'another-secret'"; exit 0 ;;
esac
exit 0`
	_, _ = toolLayout(t, "PXEThief", "pxethief.py", body)
	if err := os.WriteFile(filepath.Join(os.Getenv("PWNFLOW_TOOLS_DIR"), "PXEThief", pxeThiefMarker), []byte("8ca8a79\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencyCacheTTL = 0
	store := &fakeStore{records: []modules.Endpoint{
		{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
		{Address: "203.0.113.9", Hostname: "pxe01.other.example", Role: rolePXEDistributionPoint, Domain: testDomain},
		{Address: "0.0.0.0", Hostname: "unset.corp.example", Role: roleSCCMComputer, Domain: testDomain},
		{Address: "198.51.100.44", Hostname: "foreign.corp.example", Role: roleSCCMComputer, Domain: "other.example"},
	}}
	var output strings.Builder
	runtime := testRuntime(t, store)
	if err := (&PXEThief{}).Run(context.Background(), runtime, &output); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	// Only the endpoint that is both in the assessment domain and addressed is used.
	if !strings.Contains(output.String(), "198.51.100.41") {
		t.Fatalf("the in-scope endpoint was not used: %s", output.String())
	}
	for _, forbidden := range []string{"203.0.113.9", "0.0.0.0", "198.51.100.44"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("an out-of-scope endpoint was targeted (%s): %s", forbidden, output.String())
		}
	}
	logs, err := filepath.Glob(filepath.Join(runtime.ResultsRoot, pxeThiefFolder, "artifacts", "*", "198.51.100.41", "pxethief.log"))
	if err != nil || len(logs) != 1 {
		t.Fatalf("expected one per-endpoint log, got %v (%v)", logs, err)
	}
	// Findings are evidence: complete, and readable only by their owner.
	if info, statErr := os.Stat(logs[0]); statErr != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact permissions are not owner-only: %v %v", info.Mode().Perm(), statErr)
	}
	persisted, err := os.ReadFile(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	// Findings reach the operator exactly as the tool produced them: recovered
	// credentials are never rewritten, and neither is a value that happens to match the
	// authentication input.
	for _, finding := range []string{"recovered-secret", "another-secret"} {
		if !strings.Contains(string(persisted), finding) {
			t.Fatalf("a recovered finding was rewritten (%s):\n%s", finding, persisted)
		}
		if !strings.Contains(output.String(), finding) {
			t.Fatalf("a recovered finding was withheld from the pane (%s):\n%s", finding, output.String())
		}
	}
	// PwnFlow's own command preview keeps protecting the authentication input.
	if preview := (&PXEThief{}).CommandPreview(runtime); strings.Contains(preview, runtime.Password) {
		t.Fatalf("the preview exposed the authentication password: %s", preview)
	}
	// The labels survive, so the operator still sees what the tool reported.
	if !strings.Contains(string(persisted), "Network Access Account Password") {
		t.Fatalf("the redacted log lost the meaning of the finding:\n%s", persisted)
	}
}

func TestUsableEndpointsDeduplicatesAndOrders(t *testing.T) {
	stored := []modules.Endpoint{
		{Address: "198.51.100.42", Hostname: "mp01.corp.example", Role: roleManagementPoint, Domain: testDomain},
		{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
		{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: roleSCCMComputer, Domain: testDomain},
		{Address: "", Hostname: "unresolved.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
		{Address: "203.0.113.9", Hostname: "pxe01.other.example", Role: rolePXEDistributionPoint, Domain: testDomain},
	}
	usable := usableEndpoints(stored, testDomain)
	if len(usable) != 2 {
		t.Fatalf("unexpected usable set: %#v", usable)
	}
	if usable[0].Role != rolePXEDistributionPoint || usable[0].Address != "198.51.100.41" {
		t.Fatalf("PXE endpoints must come first: %#v", usable)
	}
	if usable[1].Role != roleManagementPoint {
		t.Fatalf("unexpected order: %#v", usable)
	}
}

func TestPXEThiefDeclaresItsDiscoveryPrerequisite(t *testing.T) {
	prerequisites := (PXEThief{}).BatchPrerequisites()
	if len(prerequisites) != 1 || prerequisites[0] != moduleIDSCCMHunter {
		t.Fatalf("PXEThief must declare its discovery prerequisite: %#v", prerequisites)
	}
}

func TestPXEThiefRequiresApprovalWhenRawSocketCapabilityIsUnknown(t *testing.T) {
	previous := rawSocketPrivilegesFunc
	rawSocketPrivilegesFunc = func() (bool, bool, string) {
		return false, false, "capability probe unavailable"
	}
	t.Cleanup(func() { rawSocketPrivilegesFunc = previous })

	required, reason := (PXEThief{}).ElevationRequired()
	if !required || !strings.Contains(reason, "CAP_NET_RAW") {
		t.Fatalf("unknown raw-socket capability did not require approval: required=%v reason=%q", required, reason)
	}
}

func TestPXEThiefRequiresTheVerifiedRevision(t *testing.T) {
	_, _ = toolLayout(t, "PXEThief", "pxethief.py", `case "$1" in -h) exit 0 ;; esac; exit 0`)
	dependencyCacheTTL = 0
	module := PXEThief{}
	if err := module.Check(context.Background(), testRuntime(t, &fakeStore{})); err == nil {
		t.Fatal("a checkout without the pull/11 marker was accepted")
	}
	marker := filepath.Join(os.Getenv("PWNFLOW_TOOLS_DIR"), "PXEThief", pxeThiefMarker)
	if err := os.WriteFile(marker, []byte("8ca8a7905c3aec98b9b1e610c03688cbd361ddb0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The checkout is not a git repository, so the revision cannot be confirmed
	// against HEAD and the module must say so rather than assume it.
	err := module.Check(context.Background(), testRuntime(t, &fakeStore{}))
	if err == nil || !strings.Contains(err.Error(), "pull/11") {
		t.Fatalf("an unverifiable checkout was accepted: %v", err)
	}
}

func TestDiscoveryRecordsKeepProvenance(t *testing.T) {
	records := []discoveredRecord{{Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint}, {Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint}}
	endpoints := discoveryEndpoints(context.Background(), fakeResolver{"pxe01.corp.example": {"198.51.100.41"}}, dedupeRecords(records), testDomain, "sccmhunter find (database)", time.Now())
	if len(endpoints) != 1 {
		t.Fatalf("duplicates were not removed: %#v", endpoints)
	}
	if endpoints[0].Source == "" || endpoints[0].Role != rolePXEDistributionPoint || endpoints[0].Domain != testDomain {
		t.Fatalf("provenance was not preserved: %#v", endpoints[0])
	}
}

// The installed SCCMhunter documents its subcommands at the top level and the find
// options on the find subcommand. Probing the top-level help for the options rejected
// a working installation and made the TUI report it UNAVAILABLE, so this pins the
// shape the probe has to accept.
func TestSCCMHunterCheckProbesTheSubcommandThatDocumentsTheOptions(t *testing.T) {
	body := `case "$1" in
--help) echo "Usage: sccmhunter [OPTIONS] COMMAND [ARGS]..."; echo "  find  Enumerate LDAP for SCCM assets."; echo "  show  Show and/or recon table results."; exit 0 ;;
find)
  if [ "$2" = "--help" ]; then echo "Options: -u -p -d -dc-ip -ldaps"; exit 0; fi
  exit 0 ;;
esac
exit 1`
	toolLayout(t, "sccmhunter", "sccmhunter.py", body)
	dependencyCacheTTL = 0
	if err := (SCCMHunter{}).Check(context.Background(), testRuntime(t, &fakeStore{})); err != nil {
		t.Fatalf("a working installation that documents its options on find was rejected: %v", err)
	}
}

// A version whose find subcommand no longer documents an option the workflow uses is
// reported, naming the option.
func TestSCCMHunterCheckReportsAMissingFindOption(t *testing.T) {
	body := `case "$1" in
--help) echo "  find"; echo "  show"; exit 0 ;;
find) if [ "$2" = "--help" ]; then echo "Options: -u -p -d -dc-ip"; exit 0; fi; exit 0 ;;
esac
exit 1`
	toolLayout(t, "sccmhunter", "sccmhunter.py", body)
	dependencyCacheTTL = 0
	err := (SCCMHunter{}).Check(context.Background(), testRuntime(t, &fakeStore{}))
	if err == nil || !strings.Contains(err.Error(), "-ldaps") {
		t.Fatalf("a missing find option was not reported: %v", err)
	}
}

// A missing installation, a checkout without an interpreter, and a checkout without
// its entry script are each reported, so the operator learns which part is missing.
func TestSCCMHunterCheckReportsUnusableInstallations(t *testing.T) {
	t.Run("not installed", func(t *testing.T) {
		t.Setenv("PWNFLOW_TOOLS_DIR", t.TempDir())
		dependencyCacheTTL = 0
		err := (SCCMHunter{}).Check(context.Background(), testRuntime(t, &fakeStore{}))
		if err == nil || !strings.Contains(err.Error(), "install.sh --with-sccmhunter") {
			t.Fatalf("a missing installation was not reported with its remedy: %v", err)
		}
	})
	t.Run("interpreter missing", func(t *testing.T) {
		root := toolLayoutWithoutInterpreter(t, "sccmhunter", "sccmhunter.py")
		_ = root
		dependencyCacheTTL = 0
		err := (SCCMHunter{}).Check(context.Background(), testRuntime(t, &fakeStore{}))
		if err == nil || !strings.Contains(err.Error(), "interpreter") {
			t.Fatalf("a missing interpreter was not reported: %v", err)
		}
	})
	t.Run("entry script missing", func(t *testing.T) {
		root := toolLayoutWithoutScript(t, "sccmhunter")
		_ = root
		dependencyCacheTTL = 0
		err := (SCCMHunter{}).Check(context.Background(), testRuntime(t, &fakeStore{}))
		if err == nil || !strings.Contains(err.Error(), "sccmhunter.py is missing") {
			t.Fatalf("a missing entry script was not reported: %v", err)
		}
	})
}

// toolLayoutWithoutInterpreter builds a checkout that has its script but no usable
// virtual environment.
func toolLayoutWithoutInterpreter(t *testing.T, rootName, scriptName string) string {
	t.Helper()
	toolsDirectory := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", toolsDirectory)
	t.Setenv("XDG_DATA_HOME", "")
	root := filepath.Join(toolsDirectory, rootName)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, scriptName), []byte("# entry\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// toolLayoutWithoutScript builds a checkout that has its environment but no entry
// script.
func toolLayoutWithoutScript(t *testing.T, rootName string) string {
	t.Helper()
	toolsDirectory := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", toolsDirectory)
	t.Setenv("XDG_DATA_HOME", "")
	root := filepath.Join(toolsDirectory, rootName)
	if err := os.MkdirAll(filepath.Join(root, ".venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".venv", "bin", "python3"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

// A raw-socket permission failure is classified: the operator sees the requirement,
// the tool's traceback stays in its own artifact, and nothing escalates privileges.
func TestPXEThiefClassifiesRawSocketFailure(t *testing.T) {
	withRawSocketPrivileges(t, true)
	body := `case "$1" in
-h) exit 0 ;;
1) echo "Sending initial DHCP Discover to find PXE boot server..."; echo "Traceback (most recent call last):"; echo "PermissionError: [Errno 1] Operation not permitted"; exit 1 ;;
esac
exit 0`
	_, recordPath := toolLayout(t, "PXEThief", "pxethief.py", body)
	if err := os.WriteFile(filepath.Join(os.Getenv("PWNFLOW_TOOLS_DIR"), "PXEThief", pxeThiefMarker), []byte(prTestHead+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencyCacheTTL = 0
	runtime := testRuntime(t, &fakeStore{})
	var output strings.Builder
	err := (&PXEThief{}).Run(context.Background(), runtime, &output)
	if err == nil {
		t.Fatal("a refused raw socket was reported as success")
	}
	if !strings.Contains(err.Error(), "CAP_NET_RAW") {
		t.Fatalf("the failure does not name the requirement: %v", err)
	}
	if strings.Contains(err.Error(), "Traceback") {
		t.Fatalf("the traceback was used as the summary instead of a diagnostic: %v", err)
	}
	logs, globErr := filepath.Glob(filepath.Join(runtime.ResultsRoot, pxeThiefFolder, "artifacts", "*", "mode-1", "pxethief.log"))
	if globErr != nil || len(logs) != 1 {
		t.Fatalf("expected the tool's own output to be preserved, got %v (%v)", logs, globErr)
	}
	preserved, readErr := os.ReadFile(logs[0])
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(preserved), "Operation not permitted") {
		t.Fatalf("the original error was not preserved for diagnostics:\n%s", preserved)
	}
	for _, invocation := range readInvocations(t, recordPath) {
		if strings.Contains(invocation, "sudo") {
			t.Fatalf("privileges were escalated automatically: %s", invocation)
		}
	}
}

// PwnFlow never grants itself a capability: the PXEThief invocation is the managed
// interpreter and the script, and nothing else.
func TestPXEThiefNeverRunsElevated(t *testing.T) {
	program, base, commandErr := interpreterCommand(dependencies.Status{Interpreter: "/tmp/venv/bin/python3", Script: "/tmp/root/pxethief.py"})
	if commandErr != nil {
		t.Fatal(commandErr)
	}
	if program != "/tmp/venv/bin/python3" || len(base) != 1 || base[0] != "/tmp/root/pxethief.py" {
		t.Fatalf("the managed interpreter is not used directly: %s %v", program, base)
	}
}

// Elevation is scoped, approved per run, and applied to each endpoint separately:
// only PXEThief's own invocations use sudo, and only when the operator approved it.
func TestPXEThiefElevationIsScopedAndPerEndpoint(t *testing.T) {
	withRawSocketPrivileges(t, false)
	body := `case "$1" in
-h) exit 0 ;;
2) echo "[+] mode 2 against $2"; exit 0 ;;
esac
exit 0`
	toolLayout(t, "PXEThief", "pxethief.py", body)
	if err := os.WriteFile(filepath.Join(os.Getenv("PWNFLOW_TOOLS_DIR"), "PXEThief", pxeThiefMarker), []byte(prTestHead+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencyCacheTTL = 0
	sudoCache(t, true)
	sudoRecord := sudoMock(t, "")
	endpoints := []modules.Endpoint{
		{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
		{Address: "198.51.100.42", Hostname: "pxe02.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
	}
	runtime := testRuntime(t, &fakeStore{records: endpoints})

	// Without the operator's approval nothing is elevated, and the requirement is
	// reported instead.
	err := (&PXEThief{}).Run(context.Background(), runtime, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "CAP_NET_RAW") {
		t.Fatalf("an unapproved run did not report the requirement: %v", err)
	}
	if calls, readErr := os.ReadFile(sudoRecord); readErr == nil && len(strings.TrimSpace(string(calls))) != 0 {
		t.Fatalf("sudo ran without approval: %s", calls)
	}

	// With approval, every endpoint is one elevated invocation of the managed
	// interpreter - never a shell, never a combined argument.
	runtime.Elevation = approvingPolicy{moduleIDPXEThief: true}
	var output strings.Builder
	if err := (&PXEThief{}).Run(context.Background(), runtime, &output); err != nil {
		t.Fatalf("approved run failed: %v", err)
	}
	calls, readErr := os.ReadFile(sudoRecord)
	if readErr != nil {
		t.Fatalf("no sudo call was recorded: %v", readErr)
	}
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(lines) != len(endpoints) {
		t.Fatalf("expected one elevated invocation per endpoint, got %v", lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "sudo -n /") || !strings.Contains(line, "pxethief.py 2 198.51.100.") {
			t.Fatalf("an elevated invocation is not the managed interpreter with a single endpoint: %s", line)
		}
		for _, forbidden := range []string{"sh -c", "/bin/sh", "-i "} {
			if strings.Contains(line, forbidden) {
				t.Fatalf("an elevated invocation used a shell (%q): %s", forbidden, line)
			}
		}
	}
	// Other modules never elevate.
	if joined := strings.Join((SCCMHunter{}).CommandArgs(runtime), " "); strings.Contains(joined, "sudo") {
		t.Fatalf("SCCMhunter was elevated: %s", joined)
	}
}

// A refused authorisation is reported and never retried unprivileged.
func TestPXEThiefReportsRefusedAuthorisation(t *testing.T) {
	withRawSocketPrivileges(t, false)
	toolLayout(t, "PXEThief", "pxethief.py", "exit 0")
	if err := os.WriteFile(filepath.Join(os.Getenv("PWNFLOW_TOOLS_DIR"), "PXEThief", pxeThiefMarker), []byte(prTestHead+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencyCacheTTL = 0
	sudoCache(t, true)
	sudoMock(t, "sudo: a password is required")
	runtime := testRuntime(t, &fakeStore{records: []modules.Endpoint{{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain}}})
	runtime.Elevation = approvingPolicy{moduleIDPXEThief: true}
	err := (&PXEThief{}).Run(context.Background(), runtime, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "sudo did not authorise") {
		t.Fatalf("a refused authorisation was not reported: %v", err)
	}
	if strings.Contains(err.Error(), "Traceback") {
		t.Fatalf("the summary is not a diagnostic: %v", err)
	}
}

// Without the capability and without approval, PXEThief is not eligible at all: the
// check refuses, so no execution path can launch it and nothing is printed that
// suggests the operator should go and approve something mid-run.
func TestPXEThiefCheckRefusesWithoutApproval(t *testing.T) {
	withRawSocketPrivileges(t, false)
	toolLayout(t, "PXEThief", "pxethief.py", "exit 0")
	if err := os.WriteFile(filepath.Join(os.Getenv("PWNFLOW_TOOLS_DIR"), "PXEThief", pxeThiefMarker), []byte(prTestHead+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The revision check reads the checkout's HEAD; the fixture answers it without
	// being a repository.
	gitBin := t.TempDir()
	gitStub := "#!/bin/sh\ncase \"$*\" in *\"rev-parse HEAD\"*) echo \"" + prTestHead + "\" ;; esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(gitBin, "git"), []byte(gitStub), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", gitBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dependencyCacheTTL = 0
	module := PXEThief{}
	runtime := testRuntime(t, &fakeStore{})
	if err := module.Check(context.Background(), runtime); err == nil || !strings.Contains(err.Error(), "CAP_NET_RAW") {
		t.Fatalf("an unapproved run was considered eligible: %v", err)
	}
	sudoCache(t, true)
	runtime.Elevation = approvingPolicy{moduleIDPXEThief: true}
	if err := module.Check(context.Background(), runtime); err != nil {
		t.Fatalf("an approved run was refused: %v", err)
	}
	// The requirement message never tells the operator to go and approve something
	// while a run is under way, and never suggests an unprivileged fallback.
	forbidden := []string{"Run it from the TUI and approve", "will fail until", "unprivileged fallback"}
	for _, text := range forbidden {
		if strings.Contains(pxeThiefTestErrors(module, runtime), text) {
			t.Fatalf("the refusal contains misleading advice (%q)", text)
		}
	}
}

// pxeThiefTestErrors renders the errors both entry points can produce, so a test can
// assert on what the operator would read.
func pxeThiefTestErrors(module PXEThief, runtime *modules.Runtime) string {
	checked := module.Check(context.Background(), runtime)
	ran := module.Run(context.Background(), runtime, &strings.Builder{})
	return errorText(checked) + " " + errorText(ran)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Mode 1 and mode 2 obey the same policy: both refuse without approval, and both run
// elevated - once per invocation - with it.
func TestPXEThiefModeOneFollowsTheSamePrivilegePolicy(t *testing.T) {
	withRawSocketPrivileges(t, false)
	toolLayout(t, "PXEThief", "pxethief.py", "case \"$1\" in 1) echo '[+] mode 1'; exit 0 ;; esac; exit 0")
	if err := os.WriteFile(filepath.Join(os.Getenv("PWNFLOW_TOOLS_DIR"), "PXEThief", pxeThiefMarker), []byte(prTestHead+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencyCacheTTL = 0
	sudoCache(t, true)
	sudoRecord := sudoMock(t, "")
	module := PXEThief{}

	// No stored endpoint and no approval: mode 1 must not start.
	runtime := testRuntime(t, &fakeStore{})
	var output strings.Builder
	if err := module.Run(context.Background(), runtime, &output); err == nil || !strings.Contains(err.Error(), "CAP_NET_RAW") {
		t.Fatalf("mode 1 ran without approval: %v", err)
	}
	if strings.Contains(output.String(), "running PXEThief mode 1") {
		t.Fatalf("mode 1 announced itself before it was authorised: %s", output.String())
	}
	if calls, readErr := os.ReadFile(sudoRecord); readErr == nil && len(strings.TrimSpace(string(calls))) != 0 {
		t.Fatalf("sudo ran without approval: %s", calls)
	}

	// Approved: one elevated mode 1 invocation.
	runtime.Elevation = approvingPolicy{moduleIDPXEThief: true}
	var approved strings.Builder
	if err := module.Run(context.Background(), runtime, &approved); err != nil {
		t.Fatalf("approved mode 1 failed: %v", err)
	}
	calls, readErr := os.ReadFile(sudoRecord)
	if readErr != nil {
		t.Fatalf("no sudo call was recorded: %v", readErr)
	}
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "sudo -n /") || !strings.HasSuffix(lines[0], "pxethief.py 1") {
		t.Fatalf("mode 1 was not one elevated invocation: %v", lines)
	}
	if !strings.Contains(approved.String(), "elevated execution you approved") {
		t.Fatalf("an elevated run should say so once: %s", approved.String())
	}
	if strings.Contains(approved.String(), "Run it from the TUI and approve") {
		t.Fatalf("the misleading advice was emitted: %s", approved.String())
	}
}

// Endpoints belong to the assessment they were discovered in: another domain's stored
// addresses are never used as targets.
func TestEndpointsAreResolvedByAssessmentIdentity(t *testing.T) {
	stored := []modules.Endpoint{
		{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
		{Address: "203.0.113.9", Hostname: "pxe01.other.example", Role: rolePXEDistributionPoint, Domain: "other.example"},
	}
	store := &fakeStore{records: stored}
	runtime := testRuntime(t, store)
	endpoints, err := discoveredEndpoints(context.Background(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 1 || endpoints[0].Address != "198.51.100.41" {
		t.Fatalf("the assessment identity was not applied: %#v", endpoints)
	}
	if usable := usableEndpoints(endpoints, runtime.Domain); len(usable) != 1 {
		t.Fatalf("unexpected usable set: %#v", usable)
	}
	// With a different assessment domain, nothing from this one is used.
	if usable := usableEndpoints(stored, "elsewhere.example"); len(usable) != 0 {
		t.Fatalf("another assessment's endpoints were used: %#v", usable)
	}
}
