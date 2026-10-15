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
