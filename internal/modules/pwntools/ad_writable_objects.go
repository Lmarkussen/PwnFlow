package pwntools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pwnflow/pwnflow/internal/dependencies"
	findingengine "github.com/pwnflow/pwnflow/internal/findings"
	"github.com/pwnflow/pwnflow/internal/modules"
)

const (
	adWritableID      = "ad-writable-objects"
	rustHoundArtifact = "rusthound-ce"
	rustHoundOption   = "RUSTHOUND_ARTIFACT"
	adWritableOutput  = "Enumeration/PwnTools/ADWritableObjects/writable-objects.json"
)

type ADWritableObjects struct{}

func (ADWritableObjects) ID() string                     { return adWritableID }
func (ADWritableObjects) Name() string                   { return "AD Writable Object Assessment" }
func (ADWritableObjects) ToolFamily() modules.ToolFamily { return modules.ToolFamilyPwnTools }
func (ADWritableObjects) Category() modules.Category     { return modules.CategoryEnumeration }
func (ADWritableObjects) Tool() string                   { return "PwnFlow / RustHound Analysis" }
func (ADWritableObjects) Protocol() modules.Protocol     { return modules.ProtocolNA }
func (ADWritableObjects) Description() string {
	return "Analyzes the authenticated identity's direct and source-backed nested-group write relationships from the current RustHound evidence; effective modification access is not verified."
}
func (ADWritableObjects) Prerequisites() []string {
	return []string{"RustHound-CE completed in this assessment batch with usable ACL evidence"}
}
func (ADWritableObjects) RequiredPrivileges() []string     { return nil }
func (ADWritableObjects) OutputFile() string               { return adWritableOutput }
func (ADWritableObjects) Sensitivity() modules.Sensitivity { return modules.SensitivitySensitive }
func (ADWritableObjects) ReadOnly() bool                   { return true }
func (ADWritableObjects) SecondaryConnections() []string {
	return []string{"reads only the current batch's RustHound artifact"}
}
func (ADWritableObjects) DependencyKey() string        { return string(dependencies.RustHoundCE) }
func (ADWritableObjects) OptionKeys() []string         { return []string{rustHoundOption} }
func (ADWritableObjects) BatchPrerequisites() []string { return []string{rustHoundArtifact} }

func (ADWritableObjects) Status(runtime *modules.Runtime) modules.Status {
	// RustHound's artifact is produced during the same batch and therefore is
	// not available when the plan is rendered. Check reports the precise
	// prerequisite failure at execution time instead of dropping this module
	// from Default Enumeration during plan construction.
	return modules.StatusAvailable
}

func (ADWritableObjects) StatusReason(runtime *modules.Runtime) string {
	return "RustHound evidence is required; configure RUSTHOUND_ARTIFACT for a manual run or include RustHound in the current batch"
}

func (ADWritableObjects) ModuleListStatus(runtime *modules.Runtime) string {
	if writableArtifact(runtime) == "" {
		return "RUSTHOUND-REQ"
	}
	return ""
}

func (ADWritableObjects) DetailLines(runtime *modules.Runtime) []string {
	requirement := "REQUIRES RUSTHOUND"
	if writableArtifact(runtime) != "" {
		requirement = "REA" + "DY"
	}
	return []string{
		"Requirement: RUSTHOUND-REQ",
		"Prerequisite: " + requirement,
		"Evidence: current-batch RustHound artifact only",
	}
}

func (m ADWritableObjects) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil || strings.TrimSpace(runtime.Domain) == "" || strings.TrimSpace(runtime.Username) == "" {
		return modules.SkipError{Reason: "RustHound writable analysis requires the configured domain and username"}
	}
	dependency := dependencies.DefaultRegistry().CheckOne(ctx, dependencies.RustHoundCE)
	if !dependency.Available {
		return modules.SkipError{Reason: "RustHound dependency unavailable: " + dependency.Detail}
	}
	artifact := writableArtifact(runtime)
	if artifact == "" {
		return modules.SkipError{Reason: "RustHound evidence was not produced by this assessment run"}
	}
	info, err := os.Stat(artifact)
	if err != nil || !info.IsDir() {
		return modules.SkipError{Reason: "RustHound evidence is missing or unusable: " + artifact}
	}
	if !hasRustHoundJSON(artifact) {
		return modules.SkipError{Reason: "RustHound completed without usable JSON evidence: " + artifact}
	}
	return nil
}

func hasRustHoundJSON(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(path), ".json") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func writableArtifact(runtime *modules.Runtime) string {
	if runtime == nil {
		return ""
	}
	if configured, ok := runtime.ModuleOption(adWritableID, rustHoundOption); ok {
		return configured
	}
	if runtime.BatchArtifacts != nil {
		return runtime.BatchArtifacts[rustHoundArtifact]
	}
	return ""
}

func (m ADWritableObjects) ExecutionArtifactPath(resultsRoot string, started time.Time) string {
	name := started.UTC().Format("20060102-150405.000000000") + "-" + uuid.NewString()
	return filepath.Join(resultsRoot, "Enumeration", "PwnTools", "ADWritableObjects", "executions", name, "writable-objects.json")
}

func (m ADWritableObjects) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if err := m.Check(ctx, runtime); err != nil {
		return err
	}
	report, err := findingengine.AnalyzeRustHoundWritableObjects(ctx, writableArtifact(runtime), runtime.Domain, runtime.Username, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("RustHound writable analysis failed: %w", err)
	}
	outputPath := runtime.ExecutionOutputPath
	if outputPath == "" {
		outputPath = m.ExecutionArtifactPath(runtime.ResultsRoot, time.Now())
	}
	if _, err := findingengine.WriteWritableObjectReportAt(outputPath, report); err != nil {
		return err
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		return err
	}
	if _, err := sink.Write(data); err != nil {
		return err
	}
	return nil
}

var _ modules.Module = ADWritableObjects{}
var _ modules.BatchPrerequisiteProvider = ADWritableObjects{}
var _ modules.DependencyKeyProvider = ADWritableObjects{}
var _ modules.OptionDeclarer = ADWritableObjects{}
var _ modules.StatusProvider = ADWritableObjects{}
var _ modules.ModuleListStatusProvider = ADWritableObjects{}
var _ modules.DetailProvider = ADWritableObjects{}
var _ modules.ExecutionArtifactPathProvider = ADWritableObjects{}
