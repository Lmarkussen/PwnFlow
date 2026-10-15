package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestFindingsViewFiltersAndDoesNotRenderEvidenceSecrets(t *testing.T) {
	model := &model{findingsView: true, width: 100, height: 24, findingRows: []storage.Finding{{FindingInput: storage.FindingInput{Title: "Potential Shadow Credentials exposure", Severity: "high", Confidence: "potential-condition", AffectedObject: "APP01$", RelatedObject: "svc-a", SourceTool: "RustHound-CE", EvidenceJSON: `{"secret":"fictional-password"}`, ArtifactPath: "restricted.json", ArtifactRef: "/data/0/Aces/0"}, FirstSeen: time.Now()}}}
	frame := ansi.Strip(model.View())
	if !strings.Contains(frame, "Potential Shadow Credentials exposure") {
		t.Fatal("finding title missing")
	}
	if strings.Contains(frame, "fictional-password") {
		t.Fatal("finding summary leaked evidence secret")
	}
	if _, command := model.handleFindingsKey("enter"); command != nil || !model.findingDetail {
		t.Fatal("detail view did not open")
	}
	if !strings.Contains(ansi.Strip(model.View()), "restricted.json") {
		t.Fatal("detail omitted artifact reference")
	}
}
