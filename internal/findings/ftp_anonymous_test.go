package findings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFTPArtifact(t *testing.T, accepted bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anonymous-ftp.json")
	data := `{"target":"10.1.10.42","port":21,"username":"anonymous","accepted":` + map[bool]string{true: "true", false: "false"}[accepted] + `,"welcome_response":"220 test FTP","auth_response":"` + map[bool]string{true: "230 login successful", false: "530 login refused"}[accepted] + `","stage":"` + map[bool]string{true: "authenticated", false: "rejected"}[accepted] + `"}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAnalyzeFTPAnonymousSuccessOnly(t *testing.T) {
	path := writeFTPArtifact(t, true)
	inputs, err := AnalyzeFTPAnonymous(context.Background(), path, 7, 11, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 1 {
		t.Fatalf("got %d findings, want one", len(inputs))
	}
	input := inputs[0]
	if input.FindingType != "pwntools_ftp_anonymous_access" || input.Severity != "medium" || input.SourceExecution != 11 {
		t.Fatalf("unexpected finding metadata: %+v", input)
	}
	if !strings.Contains(input.Description, "10.1.10.42:21") || !strings.Contains(input.EvidenceJSON, "230 login successful") {
		t.Fatalf("finding omitted useful FTP evidence: %+v", input)
	}
	if strings.Contains(input.Description+input.EvidenceJSON, "password") {
		t.Fatal("finding exposed the supplied password")
	}
}

func TestAnalyzeFTPAnonymousFailureProducesNoFinding(t *testing.T) {
	inputs, err := AnalyzeFTPAnonymous(context.Background(), writeFTPArtifact(t, false), 7, 11, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 0 {
		t.Fatalf("got %d findings for rejected authentication", len(inputs))
	}
}
