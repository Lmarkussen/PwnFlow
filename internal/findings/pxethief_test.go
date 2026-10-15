package findings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzePXEThiefExtractsCredentialBearingVariablesWithoutSecrets(t *testing.T) {
	root := filepath.Join(t.TempDir(), "artifacts", "20261015-103251", "10.1.10.41")
	if err := os.MkdirAll(root, 0750); err != nil {
		t.Fatal(err)
	}
	secret := "FictionalPassword-DoNotPersist"
	log := "[+] OSDJoinAccount - EXAMPLE\\join-user\n[+] OSDJoinPassword - " + secret + "\n[+] OSDLocalAdminPassword - local-secret\n"
	path := filepath.Join(root, "pxethief.log")
	if err := os.WriteFile(path, []byte(log), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := AnalyzePXEThief(context.Background(), filepath.Dir(filepath.Dir(root)), 7, 11, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("findings=%d", len(rows))
	}
	row := rows[0]
	if row.Severity != "high" || row.Confidence != "observed-recovered-value" {
		t.Fatalf("severity/confidence=%s/%s", row.Severity, row.Confidence)
	}
	if row.AffectedObject != "10.1.10.41" || row.RelatedObject != `EXAMPLE\join-user` {
		t.Fatalf("objects=%q/%q", row.AffectedObject, row.RelatedObject)
	}
	if strings.Contains(row.EvidenceJSON, secret) || strings.Contains(row.Title, secret) || strings.Contains(row.FindingKey, secret) {
		t.Fatal("recovered secret leaked into finding")
	}
	if !strings.Contains(row.EvidenceJSON, "OSDJoinPassword") {
		t.Fatal("credential variable missing from evidence")
	}
}

func TestAnalyzePXEThiefIgnoresEmptyCredentialMarkersAndSupportsXML(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pxethief.log"), []byte("OSDJoinPassword - no credentials found\nOSDLocalAdminPassword - [none]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "variables.xml"), []byte(`<?xml version="1.0"?><MediaVarList><var name="OSDJoinAccount">EXAMPLE\deploy</var><var name="OSDJoinPassword">synthetic-only</var></MediaVarList>`), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := AnalyzePXEThief(context.Background(), root, 1, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("findings=%d", len(rows))
	}
	if !strings.Contains(rows[0].EvidenceJSON, "OSDJoinAccount") {
		t.Fatal("XML evidence missing")
	}
}
