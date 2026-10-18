package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestManagerIngestsRustHoundAndIsIdempotent(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, "example.test", "198.51.100.10"); err != nil {
		t.Fatal(err)
	}
	assessment, err := db.TargetID(ctx, "example.test", "198.51.100.10")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO modules(id,name,tool,protocol,description,output_filename) VALUES(1,'RustHound','RustHound-CE','N/A','test','rusthound.log')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordExecutionID(ctx, assessment, 1, time.Now(), time.Now(), "completed", 0, "", ""); err != nil {
		t.Fatal(err)
	}
	var execution int64
	if err := db.QueryRow(`SELECT id FROM executions LIMIT 1`).Scan(&execution); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	body := `{"meta":{"type":"users","version":6,"count":1},"data":[{"ObjectIdentifier":"S-1-5-21-1-1-1-512","Properties":{"name":"Domain Admins@EXAMPLE.TEST","highvalue":true},"Aces":[{"PrincipalSID":"S-1-5-21-1-1-1-1100","PrincipalType":"User","RightName":"WriteDacl","IsInherited":false}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "groups.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(ctx, db)
	job := Job{AssessmentID: assessment, ExecutionID: execution, SourceTool: "RustHound-CE", ArtifactPath: dir, ObservedAt: time.Now()}
	if err := manager.Submit(job); err != nil {
		t.Fatal(err)
	}
	if err := manager.Submit(job); err != nil {
		t.Fatal(err)
	}
	if err := manager.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListFindings(ctx, assessment)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("findings=%d", len(rows))
	}
	var inventory int
	for _, row := range rows {
		if row.FindingType == "ad_privileged_acl_evidence_inventory" {
			inventory++
		}
	}
	if inventory != 1 {
		t.Fatalf("inventory observations=%d", inventory)
	}
	var jobs int
	if err := db.QueryRow(`SELECT COUNT(*) FROM analysis_jobs`).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 {
		t.Fatalf("jobs=%d", jobs)
	}
}

func TestDetectionCatalogueDeclaresUnsupportedProtocolChecks(t *testing.T) {
	catalogue := DetectionCatalogue()
	var found bool
	for _, item := range catalogue {
		if item.ID == "protocol.ldap-signing" {
			found = true
			if item.Supported {
				t.Fatal("LDAP signing must remain unsupported without explicit evidence")
			}
		}
	}
	if !found {
		t.Fatal("catalogue lost LDAP signing entry")
	}
}

func TestDiscoverArtifactUsesFinalizedPXEAndKerberosOutputs(t *testing.T) {
	root := t.TempDir()
	pxe := filepath.Join(root, "pxethief.log")
	if err := os.WriteFile(pxe, []byte("OSDJoinAccount: EXAMPLE\\joiner\nOSDJoinPassword: fictional\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := DiscoverArtifact("PXEThief", pxe); got != pxe {
		t.Fatalf("PXEThief output was not selected: %q", got)
	}
	kerb := filepath.Join(root, "kerberoast.txt")
	if err := os.WriteFile(kerb, []byte("$krb5tgs$23$*svc$EXAMPLE.TEST$HTTP/app*$material\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := DiscoverArtifact("NetExec (nxc)", kerb); got != kerb {
		t.Fatalf("NetExec Kerberos output was not selected: %q", got)
	}
	transcript := filepath.Join(root, "CredentialAuditing", "NetExec", "LDAP_asreproast", "transcript.txt")
	if err := os.MkdirAll(filepath.Dir(transcript), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(transcript, []byte("ASREPRoast synthetic output\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := DiscoverArtifact("NetExec (nxc)", transcript); got != transcript {
		t.Fatalf("NetExec AS-REP transcript was not selected: %q", got)
	}
	generic := filepath.Join(root, "CredentialAuditing", "NetExec", "SMB_auth_check", "transcript.txt")
	if err := os.MkdirAll(filepath.Dir(generic), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(generic, []byte("SMB 10.1.10.40 445 DC [+] EXAMPLE\\operator:synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := DiscoverArtifact("NetExec (nxc)", generic); got != generic {
		t.Fatalf("generic NetExec transcript was not selected: %q", got)
	}
}

func TestDiscoverArtifactAtSelectsCompletedRustHoundRun(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "RustHoundCE", "rusthound-ce.log")
	artifacts := filepath.Join(root, "RustHoundCE", "artifacts")
	for _, name := range []string{"20261018-150226", "20261018-163658"} {
		if err := os.MkdirAll(filepath.Join(artifacts, name), 0750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(output), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("complete"), 0600); err != nil {
		t.Fatal(err)
	}
	completed := time.Date(2026, 10, 18, 15, 2, 26, 0, time.Local)
	want := filepath.Join(artifacts, "20261018-150226")
	if got := DiscoverArtifactAt("RustHound-CE", output, completed); got != want {
		t.Fatalf("artifact=%q want %q", got, want)
	}
}

func TestDiscoverArtifactAssociatesCertipyModuleWithExecutionLog(t *testing.T) {
	root := t.TempDir()
	certipyRoot := filepath.Join(root, "Enumeration", "Certipy")
	artifacts := filepath.Join(certipyRoot, "artifacts")
	oldDir := filepath.Join(artifacts, "20261017-100000")
	newDir := filepath.Join(artifacts, "20261017-110000")
	if err := os.MkdirAll(oldDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(newDir, 0750); err != nil {
		t.Fatal(err)
	}
	oldDiscovery := filepath.Join(oldDir, "20261017-100000_adcs-discovery_Certipy.json")
	newDiscovery := filepath.Join(newDir, "20261017-110000_adcs-discovery_Certipy.json")
	newVulnerable := filepath.Join(newDir, "20261017-110000_vulnerable-templates_Certipy.json")
	for _, path := range []string{oldDiscovery, newDiscovery, newVulnerable} {
		if err := os.WriteFile(path, []byte(`{"Certificate Authorities":{}}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	oldTime := time.Date(2026, time.October, 17, 10, 0, 0, 0, time.UTC)
	newTime := oldTime.Add(time.Hour)
	if err := os.Chtimes(oldDiscovery, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newDiscovery, newTime, newTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newVulnerable, newTime, newTime); err != nil {
		t.Fatal(err)
	}
	discoveryLog := filepath.Join(certipyRoot, "adcs-discovery.log")
	vulnerableLog := filepath.Join(certipyRoot, "vulnerable-templates.log")
	for _, item := range []struct {
		path string
		when time.Time
	}{{discoveryLog, oldTime.Add(time.Minute)}, {vulnerableLog, newTime.Add(time.Minute)}} {
		if err := os.WriteFile(item.path, []byte("complete"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(item.path, item.when, item.when); err != nil {
			t.Fatal(err)
		}
	}
	if got := DiscoverArtifact("Certipy", discoveryLog); got != oldDiscovery {
		t.Fatalf("discovery artifact=%q, want %q", got, oldDiscovery)
	}
	if got := DiscoverArtifact("Certipy", vulnerableLog); got != newVulnerable {
		t.Fatalf("vulnerable artifact=%q, want %q", got, newVulnerable)
	}
}

func TestManagerRecoversPendingJobFromExecutionOutputPath(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := storage.Open(filepath.Join(root, "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertTarget(ctx, "example.test", "198.51.100.11"); err != nil {
		t.Fatal(err)
	}
	assessment, err := db.TargetID(ctx, "example.test", "198.51.100.11")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO modules(id,name,tool,protocol,description,output_filename) VALUES(2,'Kerberoasting','NetExec (nxc)','LDAP','test','transcript.txt')`); err != nil {
		t.Fatal(err)
	}
	artifactDir := filepath.Join(root, "CredentialAuditing", "NetExec", "LDAP_kerberoasting")
	if err := os.MkdirAll(artifactDir, 0750); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(artifactDir, "transcript.txt")
	if err := os.WriteFile(output, []byte("module output\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifactDir, "kerberoast.txt"), []byte("$krb5tgs$23$*svc-sql$EXAMPLE.TEST$MSSQLSvc/sql*$fictional\n"), 0600); err != nil {
		t.Fatal(err)
	}
	execution, err := db.RecordExecutionID(ctx, assessment, 2, time.Now(), time.Now(), "completed", 0, output, "")
	if err != nil {
		t.Fatal(err)
	}
	job := Job{AssessmentID: assessment, ExecutionID: execution, SourceTool: "NetExec (nxc)", ArtifactPath: "", ObservedAt: time.Now()}
	if _, err := db.QueueAnalysis(ctx, jobKey(job), assessment, execution, job.SourceTool, ""); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(ctx, db)
	if err := manager.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListFindings(ctx, assessment)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].FindingType != "kerberos_ticket_material_collected" {
		t.Fatalf("pending job was not recovered: %+v", rows)
	}
}

func TestNetExecArtifactRequiresMatchingModuleAndOutput(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "LDAP_get_users_info.txt")
	if err := os.WriteFile(path, []byte("synthetic output\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := netExecArtifactForExecution("Enumerate Delegation Relationships", path); got != "" {
		t.Fatalf("unrelated NetExec execution borrowed artifact: %q", got)
	}
	if got := netExecArtifactForExecution("Get AD-User Info", path); got != path {
		t.Fatalf("matching NetExec execution did not resolve artifact: %q", got)
	}
}

func TestManagerIngestsNetExecAuthenticationIntoSQLite(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := storage.Open(filepath.Join(root, "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertTarget(ctx, "example.test", "198.51.100.40"); err != nil {
		t.Fatal(err)
	}
	assessment, err := db.TargetID(ctx, "example.test", "198.51.100.40")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO modules(id,name,tool,protocol,description,output_filename) VALUES(3,'SMB Authentication Check','NetExec (nxc)','SMB','test','transcript.txt')`); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "SMB_auth_check", "transcript.txt")
	if err := os.MkdirAll(filepath.Dir(output), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("SMB 198.51.100.40 445 SERVER [+] EXAMPLE\\operator:synthetic (Pwn3d!)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	execution, err := db.RecordExecutionID(ctx, assessment, 3, time.Now(), time.Now(), "completed", 0, output, "")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(ctx, db)
	if err := manager.Submit(Job{AssessmentID: assessment, ExecutionID: execution, SourceTool: "NetExec (nxc)", ArtifactPath: output, ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListFindings(ctx, assessment)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("persisted findings=%d, want success and privileged records", len(rows))
	}
	for _, row := range rows {
		if strings.Contains(row.Title+row.Description+row.EvidenceJSON, "synthetic") {
			t.Fatal("authentication secret leaked into SQLite metadata")
		}
	}
}

func TestManagerIngestsNetExecSecurityDetectorsIntoSQLite(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := storage.Open(filepath.Join(root, "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertTarget(ctx, "example.test", "198.51.100.41"); err != nil {
		t.Fatal(err)
	}
	assessment, err := db.TargetID(ctx, "example.test", "198.51.100.41")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO modules(id,name,tool,protocol,description,output_filename) VALUES(4,'SMB Server Information','NetExec (nxc)','SMB','test','transcript.txt')`); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "SMB_server_info", "transcript.txt")
	if err := os.MkdirAll(filepath.Dir(output), 0750); err != nil {
		t.Fatal(err)
	}
	body := "SMB 198.51.100.41 445 MECM [*] Windows Server (signing:False) (SMBv1:False)\n" +
		"LDAP 198.51.100.40 389 DC [+] User: svc-example\n" +
		"userAccountControl: 66080\n"
	if err := os.WriteFile(output, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	execution, err := db.RecordExecutionID(ctx, assessment, 4, time.Now(), time.Now(), "completed", 0, output, "")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(ctx, db)
	if err := manager.Submit(Job{AssessmentID: assessment, ExecutionID: execution, SourceTool: "NetExec (nxc)", ArtifactPath: output, ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListFindings(ctx, assessment)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row.FindingType] = true
	}
	for _, typ := range []string{"smb_signing_not_required", "ad_account_passwd_notreqd", "ad_account_dont_expire_password"} {
		if !seen[typ] {
			t.Fatalf("missing persisted detector %s: %#v", typ, seen)
		}
	}
}

func TestAnalyzeRustHoundJobAssignsOptionalGPOEvidenceBeforePersistence(t *testing.T) {
	root := t.TempDir()
	artifact := filepath.Join(root, "Enumeration", "RustHoundCE", "artifacts", "20261018-120000")
	if err := os.MkdirAll(artifact, 0750); err != nil {
		t.Fatal(err)
	}
	gpoDir := filepath.Join(root, "Enumeration", "ActiveDirectory", "GPO")
	if err := os.MkdirAll(gpoDir, 0750); err != nil {
		t.Fatal(err)
	}
	gpoID := "22222222-2222-2222-2222-222222222222"
	if err := os.WriteFile(filepath.Join(artifact, "gpos.json"), []byte(`{"meta":{"type":"gpos","version":6},"data":[{"ObjectIdentifier":"22222222-2222-2222-2222-222222222222","Properties":{"name":"TEST-GPO@EXAMPLE.TEST","highvalue":false},"Aces":[{"PrincipalSID":"S-1-5-21-1-1-1-1100","PrincipalType":"Group","RightName":"WriteDacl","IsInherited":false}]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gpoDir, "GPO_metadata.json"), []byte(`{"domain":"example.test","gpos":[{"guid":"11111111-1111-1111-1111-111111111111","object_guid":"`+gpoID+`","attributes":{"displayName":{"values":["TEST-GPO"]}}}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gpoDir, "GPO_applicability.json"), []byte(`{"domain":"example.test","collection_execution_id":9,"configured_relationships":[{"gpo_guid":"11111111-1111-1111-1111-111111111111","source_dn":"OU=Servers,DC=example,DC=test","source_type":"ou","target_container_dn":"OU=Servers,DC=example,DC=test","enabled":true,"enforced":false,"link_order":1,"classification":"configured_direct","applicability":"configured_only","source_artifact":"GPO_links.json"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	inputs, err := analyzeRustHoundJob(context.Background(), Job{AssessmentID: 1, ExecutionID: 8, SourceTool: "RustHound-CE", ArtifactPath: artifact, ObservedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	var acl, gpo bool
	for _, input := range inputs {
		if input.FindingType == "ad_privileged_acl_evidence_inventory" {
			acl = true
		}
		if input.FindingType == "ad_gpo_privilege_relationship_evidence" {
			gpo = true
			if input.ArtifactPath == "" {
				t.Fatal("GPO Finding has empty artifact path")
			}
		}
		if input.ArtifactPath == "" {
			t.Fatalf("producer %q emitted empty artifact path", input.FindingType)
		}
	}
	if !acl || !gpo {
		t.Fatalf("expected ACL and GPO inputs, acl=%v gpo=%v", acl, gpo)
	}
}

func TestManagerConsolidatesLargeACLPopulationWithoutLosingRecords(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := storage.Open(filepath.Join(root, "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertTarget(ctx, "example.test", "198.51.100.12"); err != nil {
		t.Fatal(err)
	}
	assessment, err := db.TargetID(ctx, "example.test", "198.51.100.12")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO modules(id,name,tool,protocol,description,output_filename) VALUES(8,'RustHound','RustHound-CE','N/A','test','rusthound.log')`); err != nil {
		t.Fatal(err)
	}
	execution, err := db.RecordExecutionID(ctx, assessment, 8, time.Now(), time.Now(), "completed", 0, "rusthound.log", "")
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(root, "results", "Enumeration", "RustHoundCE", "artifacts", "20261018-120000")
	if err := os.MkdirAll(artifact, 0750); err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	body.WriteString(`{"meta":{"type":"groups","version":6},"data":[{"ObjectIdentifier":"S-1-5-21-1-512","Properties":{"name":"Domain Admins@EXAMPLE.TEST","domain":"example.test","highvalue":true},"Aces":[`)
	for index := 0; index < 1000; index++ {
		if index > 0 {
			body.WriteByte(',')
		}
		body.WriteString(fmt.Sprintf(`{"PrincipalSID":"S-1-5-21-1-%d","PrincipalType":"User","RightName":"WriteDacl","IsInherited":%t}`, 1000+index, index%2 == 0))
	}
	body.WriteString(`]}]}`)
	if err := os.WriteFile(filepath.Join(artifact, "groups.json"), []byte(body.String()), 0600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(ctx, db)
	if err := manager.Submit(Job{AssessmentID: assessment, ExecutionID: execution, SourceTool: "RustHound-CE", ArtifactPath: artifact, ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListFindings(ctx, assessment)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) >= 20 {
		t.Fatalf("raw ACLs created per-ACE Findings: got %d rows", len(rows))
	}
	var general bool
	for _, row := range rows {
		if row.FindingType == "ad_acl_evidence_inventory" {
			general = true
		}
		if strings.HasPrefix(row.FindingType, "ad_acl_") && row.FindingType != "ad_acl_evidence_inventory" {
			t.Fatalf("raw ACL Finding was persisted: %s", row.FindingType)
		}
	}
	if !general {
		t.Fatalf("consolidated general inventory missing: %#v", rows)
	}
	data, err := os.ReadFile(filepath.Join(root, "results", "Enumeration", "ActiveDirectory", "ACL", fmt.Sprintf("execution-%d", execution), "AD_acl_evidence_inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report GeneralACLInventoryReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.SourceACECount != 1000 || report.RetainedACECount != 1000 || report.OmittedACECount != 0 {
		t.Fatalf("source ACL coverage changed: %+v", report)
	}
}
