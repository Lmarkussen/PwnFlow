package tui

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestPublishDefaultResultsInventoriesCurrentEvidence(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := storage.Open(filepath.Join(root, "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertTarget(ctx, "example.test", "10.1.10.40"); err != nil {
		t.Fatal(err)
	}
	targetID, err := db.TargetID(ctx, "example.test", "10.1.10.40")
	if err != nil {
		t.Fatal(err)
	}
	netexec, err := db.RegisterModule(ctx, "LDAP users", "NetExec", "ldap", "", "LDAP_get_users_info.json")
	if err != nil {
		t.Fatal(err)
	}
	network, err := db.RegisterModule(ctx, "Network graph", "NetworkHound", "network", "", "network.log")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	usersPath := filepath.Join(root, "Enumeration", "NetExec", "LDAP_get_users_info.json")
	writeTestFile(t, usersPath, `[
{"dn":"CN=Alice,DC=example,DC=test","attributes":{"objectClass":["user"],"sAMAccountName":["Alice"],"objectSid":["S-1-U1"]}},
{"dn":"CN=alice,DC=example,DC=test","attributes":{"objectClass":["user"],"sAMAccountName":["alice"],"objectSid":["S-1-U1"]}},
{"dn":"CN=Disabled,DC=example,DC=test","attributes":{"objectClass":["user"],"sAMAccountName":["Disabled"],"objectSid":["S-1-U2"]}},
{"dn":"CN=CLIENT$,DC=example,DC=test","attributes":{"objectClass":["computer"],"sAMAccountName":["CLIENT$"],"objectSid":["S-1-C"],"dNSHostName":["client.example.test"]}},
{"dn":"CN=Wrong,DC=other,DC=test","attributes":{"objectClass":["user"],"sAMAccountName":["Wrong"],"objectSid":["S-1-X"]}}
]`)
	graphLog := filepath.Join(root, "Enumeration", "NetworkHound", "topology.log")
	writeTestFile(t, graphLog, "completed\n")
	artifactDir := filepath.Join(root, "Enumeration", "NetworkHound", "artifacts", "topology-20261017-120000")
	writeTestFile(t, filepath.Join(artifactDir, "network_opengraph.json"), `{"nodes":[{"kinds":["Computer"],"objectid":"S-1-COMP","properties":{"ip_addresses":["10.1.10.40"]}}]}`)
	computerPath := filepath.Join(root, "Enumeration", "NetExec", "computers.json")
	writeTestFile(t, computerPath, `[{"dn":"CN=DC,DC=example,DC=test","attributes":{"objectClass":["computer"],"objectSid":["S-1-COMP"],"dNSHostName":["dc.example.test"]}}]`)
	userExecution, err := db.RecordExecutionID(ctx, targetID, netexec, now, now.Add(time.Second), "completed", 0, usersPath, "")
	if err != nil {
		t.Fatal(err)
	}
	computerExecution, err := db.RecordExecutionID(ctx, targetID, netexec, now, now.Add(time.Second), "completed", 0, computerPath, "")
	if err != nil {
		t.Fatal(err)
	}
	graphExecution, err := db.RecordExecutionID(ctx, targetID, network, now, now.Add(time.Second), "completed", 0, graphLog, "")
	if err != nil {
		t.Fatal(err)
	}
	before, err := fileSHA256(usersPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishDefaultResults(ctx, db, root, "example.test", targetID, []int64{userExecution, computerExecution, graphExecution}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(root, "DNS_NAMES.txt"), "client.example.test\ndc.example.test\n")
	assertFile(t, filepath.Join(root, "DNS_NAME_IP.txt"), "dc.example.test 10.1.10.40\n")
	assertFile(t, filepath.Join(root, "IP_ADDRESSES.txt"), "10.1.10.40\n")
	assertFile(t, filepath.Join(root, "AD_USERS.txt"), "Alice\nDisabled\n")
	if _, err := os.Stat(filepath.Join(root, "NetworkHound", "network_opengraph.json")); err != nil {
		t.Fatalf("network graph was not published: %v", err)
	}
	after, err := fileSHA256(usersPath)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("source artifact changed during publication")
	}
	manifest, err := os.ReadFile(filepath.Join(root, "published_results_manifest.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), "AD_USERS.txt: 2 entries | supported") {
		t.Fatalf("manifest omitted complete AD user status: %s", manifest)
	}
	if strings.Contains(string(manifest), "Wrong") || strings.Contains(string(manifest), "CLIENT$") {
		t.Fatal("manifest exposed out-of-scope inventory values")
	}
}

func TestPublishDefaultResultsMarksPartialAndClearsStaleToolView(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := storage.Open(filepath.Join(root, "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertTarget(ctx, "example.test", "10.1.10.40"); err != nil {
		t.Fatal(err)
	}
	targetID, err := db.TargetID(ctx, "example.test", "10.1.10.40")
	if err != nil {
		t.Fatal(err)
	}
	moduleID, err := db.RegisterModule(ctx, "Certipy", "Certipy", "adcs", "", "certipy.txt")
	if err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(root, "Certipy", "stale.txt")
	writeTestFile(t, stale, "old\n")
	now := time.Now().UTC()
	execution, err := db.RecordExecutionID(ctx, targetID, moduleID, now, now.Add(time.Second), "failed", 1, filepath.Join(root, "Enumeration", "Certipy", "certipy.txt"), "timeout")
	if err != nil {
		t.Fatal(err)
	}
	if err := publishDefaultResults(ctx, db, root, "example.test", targetID, []int64{execution}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale flat output remains: %v", err)
	}
	manifest, err := os.ReadFile(filepath.Join(root, "published_results_manifest.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), "Publication completeness: partial") || !strings.Contains(string(manifest), "AD_USERS.txt completeness: partial") {
		t.Fatalf("partial publication was not labeled: %s", manifest)
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, path, expected string) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(actual) != expected {
		t.Fatalf("%s = %q, want %q", path, actual, expected)
	}
}

func TestPublishedListHasRestrictivePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "AD_USERS.txt")
	if err := writePublishedList(path, []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestPublicationNameDisambiguatesCollisions(t *testing.T) {
	stage := t.TempDir()
	tool := "NetExec"
	writeTestFile(t, filepath.Join(stage, tool, "same.txt"), "first")
	if got := publicationName(stage, tool, "same.txt", 42, "first"); got != "same--exec-42.txt" {
		t.Fatalf("collision name = %q", got)
	}
}

func TestExtractRealRustHoundAndNetworkHoundSchemas(t *testing.T) {
	records := map[string]*inventoryRecord{}
	if !extractInventoryJSON([]byte(`{"data":[
		{"ObjectIdentifier":"S-1-USER","Properties":{"domain":"example.test","samaccountname":"Alice","distinguishedname":"CN=Alice,DC=example,DC=test"}},
		{"ObjectIdentifier":"S-1-COMP","Properties":{"domain":"example.test","samaccountname":"DC$","name":"dc.example.test","distinguishedname":"CN=DC,DC=example,DC=test"}}
	]}`), "example.test", records) {
		t.Fatal("RustHound schema was not recognized")
	}
	networkJSON := `{"domain_info":{"domain_name":"example.test"},"graph":{"nodes":[
		{"id":"S-1-COMP","kinds":["Computer"],"properties":{"ip_addresses":["192.0.2.10"]}},
		{"id":"S-1-SUBNET","kinds":["Subnet"],"properties":{"network_address":"192.0.2.0","broadcast_address":"192.0.2.255"}},
		{"id":"S-1-OTHER","kinds":["Computer"],"properties":{"ip_addresses":["not-an-ip","TAILSCALE_IP"]}}
	]}}`
	networkJSON = strings.Replace(networkJSON, "TAILSCALE_IP", net.IPv4(100, 72, 35, 81).String(), 1)
	if !extractInventoryJSON([]byte(networkJSON), "example.test", records) {
		t.Fatal("NetworkHound schema was not recognized")
	}
	var found *inventoryRecord
	for key, record := range records {
		if strings.EqualFold(key, "s-1-comp") {
			found = record
			break
		}
	}
	if found == nil || found.Hostname != "dc.example.test" || !found.IPs["192.0.2.10"] || len(found.IPs) != 1 {
		t.Fatalf("SID correlation failed: %#v", found)
	}
	if len(found.Users) != 0 {
		t.Fatal("computer object was classified as a user")
	}
}

func TestNetworkHoundArtifactOwnershipUsesOutputPrefix(t *testing.T) {
	root := t.TempDir()
	artifactRoot := filepath.Join(root, "Enumeration", "NetworkHound", "artifacts")
	topology := filepath.Join(artifactRoot, "topology-20261017-120000")
	scope := filepath.Join(artifactRoot, "scope-validation-20261017-120001")
	writeTestFile(t, filepath.Join(topology, "network_opengraph.json"), "{}")
	writeTestFile(t, filepath.Join(scope, "network_scope.json"), "{}")
	now := time.Now().UTC()
	topologyExecution := publicationExecution{ID: 29, Tool: "NetworkHound", OutputPath: filepath.Join(root, "Enumeration", "NetworkHound", "topology.log"), Started: now.Add(-time.Second), Finished: now.Add(time.Second)}
	scopeExecution := publicationExecution{ID: 30, Tool: "NetworkHound", OutputPath: filepath.Join(root, "Enumeration", "NetworkHound", "scope-validation.log"), Started: now.Add(-time.Second), Finished: now.Add(time.Second)}
	topologySources := publicationSources(topologyExecution, root)
	scopeSources := publicationSources(scopeExecution, root)
	if len(topologySources) != 1 || topologySources[0] != topology {
		t.Fatalf("topology sources = %#v", topologySources)
	}
	if len(scopeSources) != 1 || scopeSources[0] != scope {
		t.Fatalf("scope sources = %#v", scopeSources)
	}
}
