package findings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeNetExecKerberosMaterialIsSecretSafeAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kerberoast.txt")
	contents := "header\n$krb5tgs$23$*svc-sql$EXAMPLE.TEST$MSSQLSvc/sql.example.test:1433*$secret-material\n$krb5tgs$23$*svc-sql$EXAMPLE.TEST$MSSQLSvc/sql.example.test:1433*$secret-material-2\nnot material\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := AnalyzeNetExecKerberos(context.Background(), path, 7, 12, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one account-level finding, got %d: %+v", len(findings), findings)
	}
	finding := findings[0]
	if finding.AffectedObject != "svc-sql" || finding.FindingType != "kerberos_ticket_material_collected" {
		t.Fatalf("unexpected material finding: %+v", finding)
	}
	if strings.Contains(finding.EvidenceJSON, "secret-material") || strings.Contains(finding.Title, "secret-material") {
		t.Fatalf("raw material leaked into finding: %+v", finding)
	}
	again, err := AnalyzeNetExecKerberos(context.Background(), path, 7, 12, time.Now())
	if err != nil || len(again) != 1 || again[0].FindingKey != finding.FindingKey {
		t.Fatalf("repeated parsing changed identity: first=%+v again=%+v err=%v", finding, again, err)
	}
}

func TestAnalyzeNetExecASREPRequiresMaterialMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asreproast.txt")
	if err := os.WriteFile(path, []byte("no accounts found\n$krb5asrep$23$user@example.test:secret-material\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := AnalyzeNetExecKerberos(context.Background(), path, 7, 12, time.Now())
	if err != nil || len(findings) != 1 || findings[0].AffectedObject != "user@example.test" {
		t.Fatalf("unexpected AS-REP parsing: %+v err=%v", findings, err)
	}
}
