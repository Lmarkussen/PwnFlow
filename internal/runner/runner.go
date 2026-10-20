package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/pwnflow/pwnflow/internal/artifacts"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/security"
)

type Result struct {
	Status            string
	ExitCode          int
	Err               error
	OutputPath        string
	Started, Finished time.Time
}
type Runner struct {
	Secrets     []string
	BufferLimit int
}

func (r Runner) Execute(ctx context.Context, m modules.Module, runtime *modules.Runtime, root string) Result {
	return r.ExecuteWithBuffer(ctx, m, runtime, root, nil)
}

func (r Runner) ExecuteWithBuffer(ctx context.Context, m modules.Module, runtime *modules.Runtime, root string, shared *Buffer) Result {
	started := time.Now()
	result := Result{Status: "running", Started: started, ExitCode: -1}
	if err := ctx.Err(); err != nil {
		result.Status, result.Err, result.Finished = "cancelled", err, time.Now()
		return result
	}
	if err := m.Check(ctx, runtime); err != nil {
		result.Status, result.Err, result.Finished = statusForCheck(ctx, err), formatFailure("dependency check", err, r.Secrets), time.Now()
		return result
	}
	path := filepath.Join(root, m.OutputFile())
	if provider, ok := m.(modules.ExecutionArtifactPathProvider); ok {
		path = provider.ExecutionArtifactPath(root, started)
		if runtime != nil {
			runtime.ExecutionOutputPath = path
			defer func() { runtime.ExecutionOutputPath = "" }()
		}
	}
	if err := artifacts.EnsureDirectory(filepath.Dir(path), 0750); err != nil {
		result.Status, result.Err, result.Finished = "failed", formatFailure("artifact publication", err, r.Secrets), time.Now()
		return result
	}
	history := filepath.Join(filepath.Dir(path), "history", started.Format("20060102-150405")+".txt")
	if err := artifacts.EnsureDirectory(filepath.Dir(history), 0750); err != nil {
		result.Status, result.Err, result.Finished = "failed", formatFailure("artifact publication", err, r.Secrets), time.Now()
		return result
	}
	file, err := os.OpenFile(history, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		result.Status, result.Err, result.Finished = "failed", formatFailure("artifact publication", err, r.Secrets), time.Now()
		return result
	}
	defer file.Close()
	latest, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		result.Status, result.Err, result.Finished = "failed", formatFailure("artifact publication", err, r.Secrets), time.Now()
		return result
	}
	defer latest.Close()
	redactor := security.NewArgumentRedactor(r.Secrets...)
	buffer := shared
	if buffer == nil {
		buffer = NewBuffer(r.BufferLimit)
	}
	sink := &safeSink{redactor: redactor, displayWriters: []io.Writer{buffer}, persistWriters: []io.Writer{file, latest}}
	err = m.Run(ctx, runtime, sink)
	tail := redactor.Flush()
	if len(tail) > 0 {
		_, _ = sink.writeSanitized(tail)
	}
	// A run that ended because it was stopped says so in its own artifact: the
	// partial output above it is real, and whoever reads the file later has to be
	// able to tell that it is where the tool got to rather than where it finished.
	if err != nil && ctx.Err() != nil {
		_, _ = sink.Write([]byte("\n[i] execution stopped before the tool finished; the output above is partial\n"))
	}
	if _, ok := m.(modules.ExecutionArtifactPathProvider); ok {
		if err := artifacts.NormalizeTree(filepath.Dir(path)); err != nil {
			_, _ = sink.writeSanitized([]byte(fmt.Sprintf("\n[i] artifact ownership handoff incomplete: %v\n", err)))
		}
	} else if err := artifacts.NormalizePaths(path, history); err != nil {
		_, _ = sink.writeSanitized([]byte(fmt.Sprintf("\n[i] artifact ownership handoff incomplete: %v\n", err)))
	}
	result.Finished = time.Now()
	result.OutputPath = path
	if err != nil {
		result.Status, result.Err = statusFor(ctx, err), formatFailure("execution", err, r.Secrets, path)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		}
	} else {
		result.Status, result.ExitCode = "completed", 0
	}
	return result
}

func statusForCheck(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "cancelled"
	}
	var skipped modules.SkipError
	if errors.As(err, &skipped) {
		return "skipped"
	}
	return "unavailable"
}

type safeSink struct {
	redactor       *security.ArgumentRedactor
	displayWriters []io.Writer
	persistWriters []io.Writer
}

func (s *safeSink) Write(p []byte) (int, error) {
	clean, _ := s.redactor.Write(p)
	if len(clean) == 0 {
		return len(p), nil
	}
	if _, err := s.writeSanitized(clean); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (s *safeSink) writeSanitized(p []byte) (int, error) {
	for _, w := range s.displayWriters {
		if _, err := w.Write(p); err != nil {
			return 0, err
		}
	}
	plain := []byte(security.StripANSI(string(p)))
	for _, w := range s.persistWriters {
		if _, err := w.Write(plain); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
func statusFor(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "cancelled"
	}
	var skipped modules.SkipError
	if errors.As(err, &skipped) {
		return "skipped"
	}
	return "failed"
}
func redactError(err error, secrets []string) error {
	return fmt.Errorf("%s", security.RedactString(strings.TrimSpace(err.Error()), secrets...))
}

func formatFailure(stage string, err error, secrets []string, evidencePath ...string) error {
	if err == nil {
		return nil
	}
	category, action := failureCategory(err)
	reason := security.RedactString(strings.TrimSpace(err.Error()), secrets...)
	message := fmt.Sprintf("Stage: %s\nCategory: %s\nReason: %s\nSuggested action: %s", stage, category, reason, action)
	if len(evidencePath) > 0 && evidencePath[0] != "" {
		message += "\nEvidence: " + evidencePath[0]
	}
	return errors.New(message)
}

func failureCategory(err error) (string, string) {
	if errors.Is(err, context.Canceled) {
		return "cancelled", "Retry when the operator is ready."
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultInvalidCredentials:
			return "authentication rejected by LDAP server", "Check this module's authentication mechanism and username/domain format; do not infer that global startup authentication failed."
		case ldap.LDAPResultStrongAuthRequired, ldap.LDAPResultConfidentialityRequired:
			return "LDAP signing/integrity required", "Use the module's supported secure LDAP transport."
		case ldap.LDAPResultInsufficientAccessRights:
			return "permission denied", "Verify the account has the permissions required by this module."
		}
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Sprintf("tool execution failed (exit %d)", exitErr.ExitCode()), "Review the protected module log and the tool's reported error."
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "timeout"), strings.Contains(text, "deadline exceeded"):
		return "timeout", "Verify target service readiness and retry."
	case strings.Contains(text, "permission denied"), strings.Contains(text, "access denied"):
		return "permission denied", "Verify the account and target permissions required by this module."
	case strings.Contains(text, "not found"), strings.Contains(text, "required"):
		return "dependency or required resource unavailable", "Verify the installed tool path and required target resource."
	default:
		return "execution failed; cause not established", "Review the protected module log and underlying tool output."
	}
}
