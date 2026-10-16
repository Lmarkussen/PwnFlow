package findings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeMasscanGrepableOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "masscan.log")
	content := "# Masscan 1.3.2 scan\nHost: 198.51.100.10 () Ports: 443/open/tcp//https///, 445/open/tcp//microsoft-ds///\nHost: 198.51.100.11 () Ports: 22/closed/tcp////\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := AnalyzeMasscan(context.Background(), path, 1, 2, nowForTest())
	if err != nil || len(findings) != 2 {
		t.Fatalf("unexpected Masscan findings: %#v %v", findings, err)
	}
	for _, finding := range findings {
		if finding.FindingType != "masscan_open_port_observed" || finding.Severity != "informational" || finding.SourceTool != "Masscan" {
			t.Fatalf("unexpected observation: %#v", finding)
		}
		if strings.Contains(finding.Description, "vulnerable") {
			t.Fatal("open port was incorrectly described as a vulnerability")
		}
	}
}

func TestAnalyzeMasscanIgnoresMalformedAndDuplicateRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "masscan.log")
	content := "Host: 198.51.100.10 () Ports: 80/open/tcp////,80/open/tcp////\nnot masscan output\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := AnalyzeMasscan(context.Background(), path, 1, 2, nowForTest())
	if err != nil || len(findings) != 1 {
		t.Fatalf("unexpected duplicate handling: %#v %v", findings, err)
	}
	if findings[0].Status != "open" || findings[0].ArtifactRef != "line:1:80/tcp" {
		t.Fatalf("unexpected evidence reference: %#v", findings[0])
	}
}
