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
		result.Status, result.Err, result.Finished = statusForCheck(ctx, err), err, time.Now()
		return result
	}
	path := filepath.Join(root, m.OutputFile())
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		result.Status, result.Err, result.Finished = "failed", err, time.Now()
		return result
	}
	history := filepath.Join(filepath.Dir(path), "history", started.Format("20060102-150405")+".txt")
	if err := os.MkdirAll(filepath.Dir(history), 0750); err != nil {
		result.Status, result.Err, result.Finished = "failed", err, time.Now()
		return result
	}
	file, err := os.OpenFile(history, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		result.Status, result.Err, result.Finished = "failed", err, time.Now()
		return result
	}
	defer file.Close()
	latest, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		result.Status, result.Err, result.Finished = "failed", err, time.Now()
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
	result.Finished = time.Now()
	result.OutputPath = path
	if err != nil {
		result.Status, result.Err = statusFor(ctx, err), redactError(err, r.Secrets)
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
	return "failed"
}
func redactError(err error, secrets []string) error {
	return fmt.Errorf("%s", security.RedactString(strings.TrimSpace(err.Error()), secrets...))
}
