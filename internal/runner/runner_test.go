package runner

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

type testModule struct{}

func (testModule) ID() string                                    { return "test" }
func (testModule) Name() string                                  { return "Test" }
func (testModule) ToolFamily() modules.ToolFamily                { return modules.ToolFamilyNetExec }
func (testModule) Category() modules.Category                    { return modules.CategoryEnumeration }
func (testModule) Description() string                           { return "test" }
func (testModule) Tool() string                                  { return "test" }
func (testModule) Protocol() modules.Protocol                    { return modules.ProtocolLDAP }
func (testModule) RequiredPrivileges() []string                  { return nil }
func (testModule) ReadOnly() bool                                { return true }
func (testModule) SecondaryConnections() []string                { return nil }
func (testModule) Prerequisites() []string                       { return nil }
func (testModule) OutputFile() string                            { return "out.txt" }
func (testModule) Sensitivity() modules.Sensitivity              { return modules.SensitivityStandard }
func (testModule) Check(context.Context, *modules.Runtime) error { return nil }
func (testModule) Run(_ context.Context, _ *modules.Runtime, sink modules.OutputSink) error {
	_, err := sink.Write([]byte("before secret after"))
	return err
}

func TestExecuteRedactsOutput(t *testing.T) {
	dir := t.TempDir()
	result := (Runner{Secrets: []string{"secret"}, BufferLimit: 100}).Execute(context.Background(), testModule{}, &modules.Runtime{}, dir)
	if result.Status != "completed" {
		t.Fatalf("status=%s err=%v", result.Status, result.Err)
	}
	if got := string((&Buffer{limit: 100}).Snapshot()); got != "" {
		t.Fatal(got)
	}
	data, err := os.ReadFile(result.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "before [REDACTED] after" {
		t.Fatalf("%q", data)
	}
}

func TestSuccessfulExecutionRecordsNormalExitCode(t *testing.T) {
	result := (Runner{Secrets: nil, BufferLimit: 100}).Execute(context.Background(), testModule{}, &modules.Runtime{}, t.TempDir())
	if result.Status != "completed" || result.ExitCode != 0 {
		t.Fatalf("status=%s exit=%d err=%v", result.Status, result.ExitCode, result.Err)
	}
}

type failingModule struct {
	testModule
	err error
}

func (f failingModule) Run(context.Context, *modules.Runtime, modules.OutputSink) error { return f.err }

// Execution history stores the runner's error summary, so a failing run must
// never carry a credential into SQLite.
func TestExecuteRedactsErrorSummaryRecordedInHistory(t *testing.T) {
	module := failingModule{err: errors.New("bind failed for audituser using secret")}
	result := (Runner{Secrets: []string{"secret"}, BufferLimit: 100}).Execute(context.Background(), module, &modules.Runtime{}, t.TempDir())
	if result.Status != "failed" {
		t.Fatalf("status=%s err=%v", result.Status, result.Err)
	}
	if result.Err == nil || strings.Contains(result.Err.Error(), "secret") {
		t.Fatalf("error summary leaked the credential: %v", result.Err)
	}
	if !strings.Contains(result.Err.Error(), "[REDACTED]") {
		t.Fatalf("error summary was not redacted: %v", result.Err)
	}
}
