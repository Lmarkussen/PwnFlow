package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/pwntools"
	"github.com/pwnflow/pwnflow/internal/storage"
)

func pwnToolsListModel(t *testing.T) *model {
	t.Helper()
	m := statusModel(t, []modules.Module{pwntools.SPHunter{}, pwntools.ADWritableObjects{}})
	for index, family := range m.toolFamilies {
		if family == modules.ToolFamilyPwnTools {
			m.setToolFamily(index)
			break
		}
	}
	m.width, m.height = 120, 40
	m.resizeOutput()
	m.focus = focusModules
	return m
}

func TestPwnToolsModuleListShowsBothPrerequisiteIndicators(t *testing.T) {
	m := pwnToolsListModel(t)
	frame := ansi.Strip(m.View())
	rows, _ := renderedRows(frame)
	if len(rows) != 2 {
		t.Fatalf("rendered %d PwnTools rows, want 2:\n%s", len(rows), frame)
	}
	if !strings.Contains(rows[0], "SPHunter Microsoft 365") || !strings.Contains(rows[0], "INPUT-REQ") {
		t.Fatalf("SPHunter row does not show INPUT-REQ: %q", rows[0])
	}
	if !strings.Contains(rows[1], "AD Writable Object Assessment") || !strings.Contains(rows[1], "RUSTHOUND-REQ") {
		t.Fatalf("AD Writable Objects row does not show RUSTHOUND-REQ: %q", rows[1])
	}
}

func TestPwnToolsModuleListKeepsRustHoundRequirementInModuleInformation(t *testing.T) {
	m := pwnToolsListModel(t)
	m.cursor = rowOf(t, m, "ad-writable-objects")
	frame := ansi.Strip(m.View())
	if !strings.Contains(frame, "Requirement: RUSTHOUND-REQ") {
		t.Fatalf("module information lost the prerequisite label:\n%s", frame)
	}
	if !strings.Contains(frame, "Prerequisite: REQUIRES RUSTHOUND") {
		t.Fatalf("module information lost the prerequisite state:\n%s", frame)
	}
}

func TestPwnToolsRequirementIndicatorsRemainReadableAtSupportedWidths(t *testing.T) {
	for _, width := range []int{80, 120} {
		t.Run(fmt.Sprintf("width-%d", width), func(t *testing.T) {
			m := pwnToolsListModel(t)
			m.width = width
			m.resizeOutput()
			rows, _ := renderedRows(ansi.Strip(m.View()))
			if len(rows) != 2 {
				t.Fatalf("rendered %d rows at width %d, want 2", len(rows), width)
			}
			for _, indicator := range []string{"INPUT-REQ", "RUSTHOUND-REQ"} {
				if !strings.Contains(strings.Join(rows, "\n"), indicator) {
					t.Fatalf("width %d hid %s:\n%s", width, indicator, strings.Join(rows, "\n"))
				}
			}
		})
	}
}

func TestPwnToolsRequirementIndicatorDoesNotLeakToOtherModules(t *testing.T) {
	m := statusModel(t, []modules.Module{pwntools.SPHunter{}, pwntools.ADWritableObjects{}, statusModule{
		id: "other-pwn-tool", name: "Other PwnTool", family: modules.ToolFamilyPwnTools,
		category: modules.CategoryEnumeration, protocol: modules.ProtocolNA,
		status: modules.StatusAvailable,
	}})
	for index, family := range m.toolFamilies {
		if family == modules.ToolFamilyPwnTools {
			m.setToolFamily(index)
			break
		}
	}
	frame := ansi.Strip(m.View())
	rows, _ := renderedRows(frame)
	for _, row := range rows {
		if strings.Contains(row, "Other PwnTool") && strings.Contains(row, "RUSTHOUND-REQ") {
			t.Fatalf("requirement leaked to unrelated module row: %q", row)
		}
	}
}

func TestFTPAnonymousFindingUsesPwnToolsCategoryWithoutMovingADWritableObjects(t *testing.T) {
	ftp := storage.Finding{FindingInput: storage.FindingInput{FindingType: "pwntools_ftp_anonymous_access", Title: "FTP Anonymous Access Accepted"}}
	ad := storage.Finding{FindingInput: storage.FindingInput{FindingType: "ad_writable_object_assessment", Title: "AD Writable Object Assessment"}}
	if got := findingCategoryKey(ftp); got != "pwntools" {
		t.Fatalf("FTP finding category=%q, want pwntools", got)
	}
	if got := findingSubcategoryKey(ftp); got != "ftp_anonymous_access" {
		t.Fatalf("FTP finding subcategory=%q, want ftp_anonymous_access", got)
	}
	if got := findingCategoryKey(ad); got != "acl" {
		t.Fatalf("AD writable finding category=%q, want acl", got)
	}
}
