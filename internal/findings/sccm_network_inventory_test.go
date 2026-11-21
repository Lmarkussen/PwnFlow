package findings

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeSCCMHunterDB(t *testing.T, path string, signing string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{
		`CREATE TABLE SiteServers (Hostname TEXT, SiteCode TEXT, CAS TEXT, SigningStatus TEXT, SiteServer TEXT, SMSProvider TEXT, Config TEXT, MSSQL TEXT)`,
		`CREATE TABLE ManagementPoints (Hostname TEXT, SiteCode TEXT, SigningStatus TEXT)`,
		`CREATE TABLE PXEDistributionPoints (Hostname TEXT, SigningStatus TEXT, SCCM TEXT, WDS TEXT)`,
		`CREATE TABLE Users (cn TEXT, name TEXT, sAMAAccontName TEXT, servicePrincipalName TEXT, description TEXT)`,
		`CREATE TABLE Groups (cn TEXT, name TEXT, sAMAAccontName TEXT, member TEXT, description TEXT)`,
		`INSERT INTO SiteServers VALUES ('cm01.corp.example', '', '', '` + signing + `', 'True', '', '', '')`,
		`INSERT INTO ManagementPoints VALUES ('cm01.corp.example', 'P01', '')`,
		`INSERT INTO PXEDistributionPoints VALUES ('DP01.corp.example', '', '', '')`,
		`INSERT INTO Users VALUES ('svc-naa', 'svc-naa', 'svc-naa', '', 'network access account')`,
		`INSERT INTO Groups VALUES ('SCCM-Admins', 'SCCM-Admins', 'SCCM-Admins', '', '')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSCCMHunterFindings(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "artifacts", "20260601-100000", "home", ".sccmhunter", "logs", "db", "find.db")
	writeSCCMHunterDB(t, dbPath, "False")
	log := filepath.Join(root, "sccmhunter.log")
	os.WriteFile(log, []byte("log"), 0o600)
	completed := time.Date(2026, 6, 1, 10, 5, 0, 0, time.Local)
	if got := sccmHunterArtifact(log, completed); got != dbPath {
		t.Fatalf("artifact discovery %q", got)
	}
	if got := sccmHunterArtifact(log, completed.Add(-time.Hour)); got != "" {
		t.Fatalf("a run newer than the execution was selected: %q", got)
	}
	if got := DiscoverArtifactAt("SCCMhunter", log, completed); got != dbPath {
		t.Fatalf("DiscoverArtifactAt %q", got)
	}
	inputs, err := AnalyzeSCCMHunter(context.Background(), dbPath, 1, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, input := range inputs {
		got[input.FindingType+"|"+input.AffectedObject] = input.Severity
	}
	for key, severity := range map[string]string{
		"sccm_site_inventory|SCCM site P01":                           "informational",
		"sccm_pxe_distribution_point|dp01.corp.example":               "low",
		"sccm_site_system_smb_signing_not_required|cm01.corp.example": "medium",
	} {
		if got[key] != severity {
			t.Fatalf("%s = %q, want %q (all %v)", key, got[key], severity, got)
		}
	}
	for _, input := range inputs {
		if input.FindingType == "sccm_site_inventory" && (!strings.Contains(input.EvidenceJSON, "svc-naa") || !strings.Contains(input.EvidenceJSON, "SCCM-Admins")) {
			t.Fatalf("inventory lost the matched principals: %s", input.EvidenceJSON)
		}
	}
	// An unknown signing state is not reported as unsigned.
	other := filepath.Join(t.TempDir(), "find.db")
	writeSCCMHunterDB(t, other, "")
	inputs, _ = AnalyzeSCCMHunter(context.Background(), other, 1, 2, time.Now())
	for _, input := range inputs {
		if input.FindingType == "sccm_site_system_smb_signing_not_required" {
			t.Fatal("empty SigningStatus reported as not required")
		}
	}
}

func TestNetworkHoundInventories(t *testing.T) {
	root := t.TempDir()
	scopeDir := filepath.Join(root, "artifacts", "ad-host-service-20260601-100000")
	topologyDir := filepath.Join(root, "artifacts", "topology-20260601-095900")
	os.MkdirAll(scopeDir, 0o700)
	os.MkdirAll(topologyDir, 0o700)
	os.WriteFile(filepath.Join(scopeDir, "ad_host_service.json"), []byte(`{"graph":{"nodes":[
		{"id":"MANUAL-DEVICE-1","kinds":["Computer"],"properties":{"ip_addresses":["192.0.2.10"],"open_ports":[445,21]}},
		{"id":"MANUAL-DEVICE-2","kinds":["Computer"],"properties":{"ip_addresses":["192.0.2.11"],"open_ports":[]}},
		{"id":"SITE-1","kinds":["Site"],"properties":{"name":"Site"}}]}}`), 0o600)
	os.WriteFile(filepath.Join(topologyDir, "network_opengraph.json"), []byte(`{"graph":{"nodes":[
		{"id":"S-1-5-21-1-2-3-1001","kinds":["Computer"],"properties":{"name":"DC01.CORP.EXAMPLE","ip_addresses":["192.0.2.10"]}},
		{"id":"S-1-5-21-1-2-3-1102","kinds":["Computer"],"properties":{"name":"OLD01.CORP.EXAMPLE","ip_addresses":[]}}]}}`), 0o600)
	completed := time.Date(2026, 6, 1, 10, 1, 0, 0, time.Local)
	scope := DiscoverArtifactAt("NetworkHound", filepath.Join(root, "scope-validation.log"), completed)
	topology := DiscoverArtifactAt("NetworkHound", filepath.Join(root, "topology.log"), completed)
	if filepath.Base(scope) != "ad_host_service.json" || filepath.Base(topology) != "network_opengraph.json" {
		t.Fatalf("discovery scope=%q topology=%q", scope, topology)
	}
	inputs, err := AnalyzeNetworkHound(context.Background(), scope, 1, 2, time.Now())
	if err != nil || len(inputs) != 1 || inputs[0].FindingType != "networkhound_open_ports" || !strings.Contains(inputs[0].EvidenceJSON, "192.0.2.10: 445, 21") {
		t.Fatalf("scope inventory %+v %v", inputs, err)
	}
	inputs, err = AnalyzeNetworkHound(context.Background(), topology, 1, 2, time.Now())
	if err != nil || len(inputs) != 1 || inputs[0].FindingType != "networkhound_topology_unresolved_computers" || !strings.Contains(inputs[0].EvidenceJSON, "OLD01.CORP.EXAMPLE") || strings.Contains(inputs[0].EvidenceJSON, "DC01") {
		t.Fatalf("topology inventory %+v %v", inputs, err)
	}
}
