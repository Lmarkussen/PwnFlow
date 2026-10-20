package pwntools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
)

const (
	sphunterID       = "sphunter-tenant-discovery"
	m365DomainOption = "M365_DOMAIN"
	sphunterOutput   = "Enumeration/PwnTools/SPHunter/tenant-discovery.json"
)

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

type SPHunter struct{}

func (SPHunter) ID() string                     { return sphunterID }
func (SPHunter) Name() string                   { return "SPHunter Microsoft 365 / SharePoint Discovery" }
func (SPHunter) ToolFamily() modules.ToolFamily { return modules.ToolFamilyPwnTools }
func (SPHunter) Category() modules.Category     { return modules.CategoryEnumeration }
func (SPHunter) Tool() string                   { return "SPHunter" }
func (SPHunter) Protocol() modules.Protocol     { return modules.ProtocolNA }
func (SPHunter) Description() string {
	return "Unauthenticated Microsoft 365 tenant and SharePoint endpoint discovery; results are reconnaissance evidence, not a vulnerability claim."
}
func (SPHunter) Prerequisites() []string {
	return []string{"SPHunter installed", "an explicitly authorized Microsoft 365 discovery domain"}
}
func (SPHunter) RequiredPrivileges() []string     { return nil }
func (SPHunter) OutputFile() string               { return sphunterOutput }
func (SPHunter) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (SPHunter) ReadOnly() bool                   { return true }
func (SPHunter) SecondaryConnections() []string {
	return []string{"Microsoft OpenID metadata", "optional azmap.dev enrichment", "candidate HTTPS endpoints"}
}
func (SPHunter) DependencyKey() string { return string(dependencies.SPHunter) }
func (SPHunter) OptionKeys() []string  { return []string{m365DomainOption} }
func (SPHunter) CommandPreview(runtime *modules.Runtime) string {
	domain, _ := runtime.ModuleOption(sphunterID, m365DomainOption)
	return fmt.Sprintf("sphunter %s --json <execution-scoped>/tenant-discovery.json", domain)
}

func (SPHunter) ExecutionArtifactPath(resultsRoot string, started time.Time) string {
	name := started.UTC().Format("20060102-150405.000000000") + "-" + uuid.NewString()
	return filepath.Join(resultsRoot, "Enumeration", "PwnTools", "SPHunter", "executions", name, "tenant-discovery.json")
}

func (SPHunter) MissingInputs(runtime *modules.Runtime) []modules.InputField {
	if _, ok := runtime.ModuleOption(sphunterID, m365DomainOption); ok {
		return nil
	}
	return []modules.InputField{{Key: m365DomainOption, Prompt: "Microsoft 365 discovery domain (not the AD domain)", Example: "contoso.com"}}
}

func (SPHunter) ValidateInput(key, value string) error {
	if key != m365DomainOption {
		return fmt.Errorf("unknown option %s", key)
	}
	if !validDomain(value) {
		return errors.New("must be a DNS domain such as contoso.com, without a scheme or path")
	}
	return nil
}

func validDomain(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return len(value) <= 253 && net.ParseIP(value) == nil && domainPattern.MatchString(value)
}

func (SPHunter) Status(runtime *modules.Runtime) modules.Status {
	domain, ok := runtime.ModuleOption(sphunterID, m365DomainOption)
	if !ok {
		return modules.StatusInputRequired
	}
	if !validDomain(domain) {
		return modules.StatusUnavailable
	}
	return modules.StatusAvailable
}

func (SPHunter) StatusReason(runtime *modules.Runtime) string {
	domain, ok := runtime.ModuleOption(sphunterID, m365DomainOption)
	if !ok {
		return "Microsoft 365 discovery domain is not configured"
	}
	if !validDomain(domain) {
		return "Microsoft 365 discovery domain is invalid"
	}
	return ""
}

func (SPHunter) IncludeInGlobalPlanForRuntime(runtime *modules.Runtime) (bool, string) {
	domain, ok := runtime.ModuleOption(sphunterID, m365DomainOption)
	if !ok || strings.TrimSpace(domain) == "" {
		return false, "Skipped — Microsoft 365 domain not configured"
	}
	if !validDomain(domain) {
		return false, "Skipped — invalid Microsoft 365 discovery domain"
	}
	return true, ""
}

func (m SPHunter) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil {
		return errors.New("runtime configuration is required")
	}
	domain, ok := runtime.ModuleOption(sphunterID, m365DomainOption)
	if !ok || !validDomain(domain) {
		return errors.New("an explicitly authorized Microsoft 365 discovery domain is required")
	}
	status := sphunterDependencyStatus(ctx)
	if !status.Available {
		return fmt.Errorf("%s: %s", status.DisplayName, status.Detail)
	}
	return nil
}

func (m SPHunter) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if err := m.Check(ctx, runtime); err != nil {
		return err
	}
	status := sphunterDependencyStatus(ctx)
	domain, _ := runtime.ModuleOption(sphunterID, m365DomainOption)
	outputPath := runtime.ExecutionOutputPath
	if outputPath == "" {
		outputPath = m.ExecutionArtifactPath(runtime.ResultsRoot, time.Now())
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return err
	}
	args := []string{status.Script, domain, "--timeout", "10", "--delay", "0", "--jitter", "0", "--json", outputPath}
	command := sphunterCommandContext(ctx, status.Interpreter, args...)
	command.Dir = status.Root
	output, err := command.CombinedOutput()
	if _, writeErr := sink.Write(output); writeErr != nil {
		return writeErr
	}
	if err != nil {
		return classifySPHunterError(ctx, err, output)
	}
	data, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		return fmt.Errorf("SPHunter completed without producing its JSON artifact: %s", outputPath)
	}
	if !json.Valid(data) {
		return fmt.Errorf("SPHunter produced invalid JSON at %s", outputPath)
	}
	if chmodErr := os.Chmod(outputPath, 0o600); chmodErr != nil {
		return chmodErr
	}
	return nil
}

var sphunterDependencyStatus = func(ctx context.Context) dependencies.Status {
	return dependencies.DefaultRegistry().CheckOne(ctx, dependencies.SPHunter)
}

var sphunterCommandContext = exec.CommandContext

func classifySPHunterError(ctx context.Context, err error, output []byte) error {
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("SPHunter network timeout")
		}
		return ctx.Err()
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return fmt.Errorf("SPHunter execution error: %w", err)
	}
	detail := strings.TrimSpace(string(output))
	lower := strings.ToLower(detail)
	switch exitErr.ExitCode() {
	case 2:
		return fmt.Errorf("SPHunter argument error (exit 2): %s", compactSPHunterDetail(detail))
	case 1:
		if strings.Contains(lower, "timeout") {
			return fmt.Errorf("SPHunter network timeout: %s", compactSPHunterDetail(detail))
		}
		if strings.Contains(lower, "resolve") || strings.Contains(lower, "dns") || strings.Contains(lower, "not found") {
			return fmt.Errorf("SPHunter domain not resolvable: %s", compactSPHunterDetail(detail))
		}
		return fmt.Errorf("SPHunter discovery unsuccessful (exit 1): %s", compactSPHunterDetail(detail))
	default:
		return fmt.Errorf("SPHunter failed with exit %d: %s", exitErr.ExitCode(), compactSPHunterDetail(detail))
	}
}

func compactSPHunterDetail(detail string) string {
	if detail == "" {
		return "no diagnostic output"
	}
	const maxDetail = 600
	if len(detail) > maxDetail {
		return detail[:maxDetail] + "…"
	}
	return detail
}

var _ modules.Module = SPHunter{}
var _ modules.InputRequester = SPHunter{}
var _ modules.InputValidator = SPHunter{}
var _ modules.StatusProvider = SPHunter{}
var _ modules.OptionDeclarer = SPHunter{}
var _ modules.DependencyKeyProvider = SPHunter{}
var _ modules.ScopedGlobalExecutionPolicy = SPHunter{}
var _ modules.ExecutionArtifactPathProvider = SPHunter{}
