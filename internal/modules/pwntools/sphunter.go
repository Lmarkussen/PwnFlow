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
	return fmt.Sprintf("sphunter %s --json", domain)
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
	status := dependencies.DefaultRegistry().CheckOne(ctx, dependencies.SPHunter)
	if !status.Available {
		return fmt.Errorf("%s: %s", status.DisplayName, status.Detail)
	}
	return nil
}

func (m SPHunter) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if err := m.Check(ctx, runtime); err != nil {
		return err
	}
	status := dependencies.DefaultRegistry().CheckOne(ctx, dependencies.SPHunter)
	domain, _ := runtime.ModuleOption(sphunterID, m365DomainOption)
	outputPath := filepath.Join(runtime.ResultsRoot, sphunterOutput)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, status.Interpreter, status.Script, domain, "--timeout", "10", "--delay", "0", "--jitter", "0", "--json")
	command.Dir = status.Root
	output, err := command.CombinedOutput()
	if writeErr := os.WriteFile(outputPath, output, 0o600); writeErr != nil {
		return writeErr
	}
	if logErr := os.WriteFile(strings.TrimSuffix(outputPath, ".json")+".log", output, 0o600); logErr != nil {
		return logErr
	}
	if _, writeErr := sink.Write(output); writeErr != nil {
		return writeErr
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("SPHunter failed: %w", err)
	}
	if !json.Valid(output) {
		return errors.New("SPHunter returned invalid JSON")
	}
	return nil
}

var _ modules.Module = SPHunter{}
var _ modules.InputRequester = SPHunter{}
var _ modules.InputValidator = SPHunter{}
var _ modules.StatusProvider = SPHunter{}
var _ modules.OptionDeclarer = SPHunter{}
var _ modules.DependencyKeyProvider = SPHunter{}
var _ modules.ScopedGlobalExecutionPolicy = SPHunter{}
