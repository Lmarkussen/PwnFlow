package findings

import (
	"context"
	"os"
	"path/filepath"
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
	if len(rows) != 1 {
		t.Fatalf("findings=%d", len(rows))
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
