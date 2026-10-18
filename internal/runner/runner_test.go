package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
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

type checkFailingModule struct{ testModule }

func (checkFailingModule) Check(context.Context, *modules.Runtime) error {
	return errors.New("required executable not found in configured tool environment")
}

type ldapFailingModule struct{ testModule }

func (ldapFailingModule) Run(context.Context, *modules.Runtime, modules.OutputSink) error {
	return &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("data 52e")}
}

func TestExecuteFailureDetailsIncludeStageCategoryAndAction(t *testing.T) {
	result := (Runner{Secrets: []string{"secret"}, BufferLimit: 100}).Execute(context.Background(), checkFailingModule{}, &modules.Runtime{}, t.TempDir())
	if result.Status != "unavailable" || result.Err == nil {
		t.Fatalf("status=%s err=%v", result.Status, result.Err)
	}
	for _, want := range []string{"Stage: dependency check", "Category: dependency or required resource unavailable", "Suggested action:"} {
		if !strings.Contains(result.Err.Error(), want) {
			t.Fatalf("missing %q: %v", want, result.Err)
		}
	}
}

func TestExecuteModuleLDAPRejectionIsModuleScopedAndTraceable(t *testing.T) {
	root := t.TempDir()
	result := (Runner{Secrets: []string{"secret"}, BufferLimit: 100}).Execute(context.Background(), ldapFailingModule{}, &modules.Runtime{}, root)
	if result.Status != "failed" || result.Err == nil {
		t.Fatalf("status=%s err=%v", result.Status, result.Err)
	}
	for _, want := range []string{"Stage: execution", "authentication rejected by LDAP server", "49", "52e", "global startup authentication", "Evidence:"} {
		if !strings.Contains(result.Err.Error(), want) {
			t.Fatalf("missing %q: %v", want, result.Err)
		}
	}
}

func TestExecuteToolExitWithoutStructuredCausePreservesUncertainty(t *testing.T) {
	module := failingModule{err: func() error {
		return exec.Command("sh", "-c", "exit 1").Run()
	}()}
	result := (Runner{Secrets: nil, BufferLimit: 100}).Execute(context.Background(), module, &modules.Runtime{}, t.TempDir())
	if !strings.Contains(result.Err.Error(), "tool execution failed (exit 1)") || !strings.Contains(result.Err.Error(), "Review the protected module log") {
		t.Fatalf("unexpected tool failure detail: %v", result.Err)
	}
}

// Tool output is assessment evidence: a bare occurrence of a value is preserved. Only a
// credential sitting in an option position is masked, which the echoing test below
// covers.
func TestExecutePreservesToolOutput(t *testing.T) {
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
	if string(data) != "before secret after" {
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

type echoingModule struct{ testModule }

func (echoingModule) Run(_ context.Context, _ *modules.Runtime, sink modules.OutputSink) error {
	_, err := sink.Write([]byte("rusthound-ce -d corp.example -u audituser -p Sup3rSecret -o artifacts\nrusthound-ce --ldappassword Sup3rSecret -c LdapOnly\n"))
	return err
}

// RustHound's native password argument is accepted, so a collector that echoes
// its own command line must still never place that password in a display
// buffer, the persisted log, or the error summary - in either flag form.
func TestExecuteRedactsEchoedNativePasswordInBothFlagForms(t *testing.T) {
	buffer := NewBuffer(4096)
	result := (Runner{Secrets: []string{"Sup3rSecret"}, BufferLimit: 4096}).ExecuteWithBuffer(context.Background(), echoingModule{}, &modules.Runtime{}, t.TempDir(), buffer)
	if result.Status != "completed" {
		t.Fatalf("status=%s err=%v", result.Status, result.Err)
	}
	persisted, err := os.ReadFile(result.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, surface := range map[string]string{"display buffer": string(buffer.Snapshot()), "persisted log": string(persisted)} {
		if strings.Contains(surface, "Sup3rSecret") {
			t.Fatalf("%s leaked the native password: %q", name, surface)
		}
		if !strings.Contains(surface, "[REDACTED]") {
			t.Fatalf("%s was not redacted: %q", name, surface)
		}
	}
	if !strings.Contains(string(persisted), "-c LdapOnly") {
		t.Fatalf("non-secret arguments must survive redaction: %q", string(persisted))
	}
}

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

// A recovered credential in tool output is evidence, whether it matches the runtime
// password exactly or only partially.
func TestExecutePreservesRecoveredCredentials(t *testing.T) {
	for name, finding := range map[string]string{
		"identical to the input password": "[!] Task sequence password: Sup3rSecret",
		"contains the input password":     "[!] Task sequence password: Sup3rSecret-tail",
		"unrelated recovered value":       "[!] Network Access Account Password: 'fictional-recovered'",
	} {
		t.Run(name, func(t *testing.T) {
			module := recoveringModule{finding: finding}
			result := (Runner{Secrets: []string{"Sup3rSecret"}, BufferLimit: 4096}).Execute(context.Background(), module, &modules.Runtime{}, t.TempDir())
			persisted, err := os.ReadFile(result.OutputPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(persisted), finding) {
				t.Fatalf("the finding was rewritten: %q", string(persisted))
			}
		})
	}
}

type recoveringModule struct {
	testModule
	finding string
}

func (m recoveringModule) Run(_ context.Context, _ *modules.Runtime, sink modules.OutputSink) error {
	_, err := sink.Write([]byte(m.finding + "\n"))
	return err
}
