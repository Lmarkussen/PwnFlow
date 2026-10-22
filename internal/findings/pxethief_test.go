package findings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzePXEThiefExtractsAndConsolidatesCredentialBearingVariables(t *testing.T) {
	root := filepath.Join(t.TempDir(), "artifacts", "20261015-103251", "192.0.2.41")
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
	if row.AffectedObject != "192.0.2.41" || row.RelatedObject != `EXAMPLE\join-user` {
		t.Fatalf("objects=%q/%q", row.AffectedObject, row.RelatedObject)
	}
	if !strings.Contains(row.EvidenceJSON, secret) {
		t.Fatal("recovered secret was not retained as assessment evidence")
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

func TestAnalyzePXEThiefConsolidatesIdenticalSetsAndPreservesReferences(t *testing.T) {
	root := t.TempDir()
	log := "task sequence one\nOSDJoinAccount - LAB\\join\nOSDJoinPassword - join-secret\nOSDLocalAdminPassword - admin-secret\n" +
		"task sequence two\nOSDJoinAccount - LAB\\join\nOSDJoinPassword - join-secret\nOSDLocalAdminPassword - admin-secret\n"
	if err := os.WriteFile(filepath.Join(root, "pxethief.log"), []byte(log), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := AnalyzePXEThief(context.Background(), root, 3, 4, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("findings=%d, want one consolidated finding", len(rows))
	}
	for _, ref := range []string{"line:2", "line:3", "line:4", "line:6", "line:7", "line:8"} {
		if !strings.Contains(rows[0].EvidenceJSON, ref) {
			t.Fatalf("consolidated evidence omitted %s: %s", ref, rows[0].EvidenceJSON)
		}
	}
	if !strings.Contains(rows[0].EvidenceJSON, "credential_values") || !strings.Contains(rows[0].EvidenceJSON, "join-secret") {
		t.Fatal("complete credential set was not retained")
	}
}

func TestAnalyzePXEThiefKeepsDifferentCredentialSetsSeparate(t *testing.T) {
	root := t.TempDir()
	log := "task sequence one\nOSDJoinAccount - LAB\\join\nOSDJoinPassword - join-one\nOSDLocalAdminPassword - admin-one\n" +
		"task sequence two\nOSDJoinAccount - LAB\\other\nOSDJoinPassword - join-two\nOSDLocalAdminPassword - admin-two\n"
	if err := os.WriteFile(filepath.Join(root, "pxethief.log"), []byte(log), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := AnalyzePXEThief(context.Background(), root, 3, 4, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("findings=%d, want separate findings", len(rows))
	}
}
