package pwntools

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/networkhound"
)

const (
	ftpAnonymousID     = "ftp-anonymous-access"
	ftpEndpointOption  = "FTP_ENDPOINT"
	ftpAnonymousOutput = "Enumeration/PwnTools/FTPAnonymousAccess/anonymous-ftp.json"
	ftpTimeout         = 10 * time.Second
)

type FTPAnonymousAccess struct{}

type FTPAnonymousResult struct {
	Target          string `json:"target"`
	Port            int    `json:"port"`
	Username        string `json:"username"`
	Accepted        bool   `json:"accepted"`
	WelcomeResponse string `json:"welcome_response,omitempty"`
	AuthResponse    string `json:"auth_response,omitempty"`
	Stage           string `json:"stage"`
	Error           string `json:"error,omitempty"`
}

type ftpAnonymousReport struct {
	Assessment              string               `json:"assessment,omitempty"`
	Source                  string               `json:"source,omitempty"`
	DiscoveredEndpoints     int                  `json:"discovered_endpoints"`
	EndpointsTested         int                  `json:"endpoints_tested"`
	AnonymousLoginsAccepted int                  `json:"anonymous_logins_accepted"`
	Rejected                int                  `json:"rejected"`
	Unreachable             int                  `json:"unreachable_or_indeterminate"`
	Results                 []FTPAnonymousResult `json:"results"`
}

func (FTPAnonymousAccess) ID() string                     { return ftpAnonymousID }
func (FTPAnonymousAccess) Name() string                   { return "FTP Anonymous Access" }
func (FTPAnonymousAccess) ToolFamily() modules.ToolFamily { return modules.ToolFamilyPwnTools }
func (FTPAnonymousAccess) Category() modules.Category     { return modules.CategoryServiceEnumeration }
func (FTPAnonymousAccess) Tool() string                   { return "PwnFlow FTP Probe" }
func (FTPAnonymousAccess) Protocol() modules.Protocol     { return modules.ProtocolFTP }
func (FTPAnonymousAccess) Description() string {
	return "Tests confirmed NetworkHound FTP services, or one explicitly selected endpoint, with the single anonymous:password pair; it does not list or modify files."
}
func (FTPAnonymousAccess) Prerequisites() []string {
	return []string{"NetworkHound scope validation, or an explicitly selected FTP endpoint"}
}
func (FTPAnonymousAccess) RequiredPrivileges() []string     { return nil }
func (FTPAnonymousAccess) OutputFile() string               { return ftpAnonymousOutput }
func (FTPAnonymousAccess) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (FTPAnonymousAccess) ReadOnly() bool                   { return true }
func (FTPAnonymousAccess) SecondaryConnections() []string {
	return []string{"one TCP connection per selected FTP endpoint"}
}
func (FTPAnonymousAccess) BatchPrerequisites() []string {
	return []string{"networkhound-scope-validation"}
}
func (FTPAnonymousAccess) OptionKeys() []string {
	return []string{ftpEndpointOption}
}
func (FTPAnonymousAccess) MissingInputs(*modules.Runtime) []modules.InputField { return nil }
func (FTPAnonymousAccess) Status(runtime *modules.Runtime) modules.Status {
	endpoint, ok := runtime.ModuleOption(ftpAnonymousID, ftpEndpointOption)
	if ok {
		if _, _, err := parseFTPEndpoint(endpoint); err != nil {
			return modules.StatusUnavailable
		}
		return modules.StatusAvailable
	}
	if discovered, _ := discoveredEndpoints(runtime); len(discovered) > 0 {
		return modules.StatusAvailable
	}
	// The batch scheduler must retain this module so it can consume the
	// current-run NetworkHound artifact and report a precise skip reason.
	return modules.StatusAvailable
}
func (FTPAnonymousAccess) StatusReason(runtime *modules.Runtime) string {
	endpoint, ok := runtime.ModuleOption(ftpAnonymousID, ftpEndpointOption)
	if ok {
		if _, _, err := parseFTPEndpoint(endpoint); err != nil {
			return err.Error()
		}
		return ""
	}
	if discovered, _ := discoveredEndpoints(runtime); len(discovered) > 0 {
		return "using current NetworkHound open TCP/21 endpoints"
	}
	return "SKIPPED — NetworkHound FTP discovery evidence unavailable or no confirmed open TCP/21 endpoints"
}
func (FTPAnonymousAccess) ValidateOptionValue(key, value string) error {
	if key != ftpEndpointOption {
		return fmt.Errorf("unknown option %s", key)
	}
	_, _, err := parseFTPEndpoint(value)
	return err
}
func (FTPAnonymousAccess) ValidateInput(key, value string) error {
	return (FTPAnonymousAccess{}).ValidateOptionValue(key, value)
}
func (FTPAnonymousAccess) DetailLines(runtime *modules.Runtime) []string {
	endpoint, _ := runtime.ModuleOption(ftpAnonymousID, ftpEndpointOption)
	return []string{
		"Credential: anonymous:[REDACTED] (single attempt)",
		"Endpoint override: " + fallbackEndpoint(endpoint),
		"Automatic source: NetworkHound open TCP/21 artifact",
		"Scope: authentication only; no directory listing or file changes",
		"Timeout: 10 seconds",
	}
}
func (FTPAnonymousAccess) CommandPreview(runtime *modules.Runtime) string {
	endpoint, _ := runtime.ModuleOption(ftpAnonymousID, ftpEndpointOption)
	if strings.TrimSpace(endpoint) == "" {
		return "PwnFlow FTP probe <NetworkHound-discovered-endpoints> --user anonymous --password [REDACTED]"
	}
	return fmt.Sprintf("PwnFlow FTP probe %s --user anonymous --password [REDACTED]", endpoint)
}
func (FTPAnonymousAccess) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil {
		return errors.New("runtime configuration is required")
	}
	if endpoint, ok := runtime.ModuleOption(ftpAnonymousID, ftpEndpointOption); ok {
		_, _, err := parseFTPEndpoint(endpoint)
		return err
	}
	endpoints, reason := discoveredEndpoints(runtime)
	if len(endpoints) == 0 {
		return modules.SkipError{Reason: reason}
	}
	return nil
}
func (FTPAnonymousAccess) ExecutionArtifactPath(resultsRoot string, started time.Time) string {
	name := started.UTC().Format("20060102-150405.000000000") + "-" + uuid.NewString()
	return filepath.Join(resultsRoot, "Enumeration", "PwnTools", "FTPAnonymousAccess", "executions", name, "anonymous-ftp.json")
}

func (FTPAnonymousAccess) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if err := (FTPAnonymousAccess{}).Check(ctx, runtime); err != nil {
		return err
	}
	endpoints, source := selectedEndpoints(runtime)
	if len(endpoints) == 0 {
		return modules.SkipError{Reason: "SKIPPED — No open FTP endpoints found"}
	}
	results := make([]FTPAnonymousResult, len(endpoints))
	sem := make(chan struct{}, 8)
	done := make(chan int, len(endpoints))
	for index, endpoint := range endpoints {
		go func(index int, endpoint string) {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[index] = FTPAnonymousResult{Target: endpoint, Error: "canceled", Stage: "cancelled"}
				done <- index
				return
			}
			results[index] = probeFTPAnonymous(ctx, endpoint)
			<-sem
			done <- index
		}(index, endpoint)
	}
	for range endpoints {
		<-done
	}
	report := buildFTPReport(runtime.Domain, source, endpoints, results)
	outputPath := runtime.ExecutionOutputPath
	if outputPath == "" {
		outputPath = (FTPAnonymousAccess{}).ExecutionArtifactPath(runtime.ResultsRoot, time.Now().UTC())
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := sink.Write([]byte(formatFTPReport(report))); err != nil {
		return err
	}
	// Runner sinks are also responsible for the human-readable latest output.
	// Restore the structured artifact after that write so Findings analysis never
	// attempts to parse the display report as JSON.
	if err := os.WriteFile(outputPath, data, 0o600); err != nil {
		return err
	}
	return nil
}

func selectedEndpoints(runtime *modules.Runtime) ([]string, string) {
	if endpoint, ok := runtime.ModuleOption(ftpAnonymousID, ftpEndpointOption); ok {
		return []string{endpoint}, "explicit FTP endpoint"
	}
	endpoints, _ := discoveredEndpoints(runtime)
	return endpoints, "NetworkHound"
}

func discoveredEndpoints(runtime *modules.Runtime) ([]string, string) {
	if runtime == nil {
		return nil, "SKIPPED — NetworkHound FTP discovery evidence unavailable"
	}
	path, ok := "", false
	artifactKey := "networkhound-scope-validation"
	if runtime.AutomaticBatch {
		artifactKey = networkhound.AutomaticServiceArtifactKey
	}
	if runtime.BatchArtifacts != nil {
		path, ok = runtime.BatchArtifacts[artifactKey]
	}
	if !ok {
		if runtime.AutomaticBatch {
			return nil, "SKIPPED — NetworkHound current-batch service artifact is missing"
		}
		return nil, "SKIPPED — NetworkHound FTP discovery evidence unavailable"
	}
	scope := ""
	if runtime.AutomaticBatch {
		topology := ""
		if runtime.BatchArtifacts != nil {
			topology = runtime.BatchArtifacts["networkhound-topology"]
		}
		addresses, err := networkhound.TopologyHostAddresses(topology)
		if err != nil || len(addresses) == 0 {
			return nil, "SKIPPED — NetworkHound FTP discovery evidence unavailable: current topology scope is missing or invalid"
		}
		scope = strings.Join(addresses, ",")
	} else {
		scope, _ = runtime.ModuleOption("networkhound-scope-validation", "NETWORKS")
		if err := networkhound.ValidateScope(scope); err != nil {
			return nil, "SKIPPED — NetworkHound FTP discovery evidence unavailable: approved scope is missing or invalid"
		}
	}
	endpoints, err := networkhound.OpenFTPEndpoints(path, scope)
	if err != nil {
		return nil, "SKIPPED — NetworkHound FTP discovery evidence unavailable: " + err.Error()
	}
	if len(endpoints) == 0 {
		if runtime.AutomaticBatch {
			return nil, "SKIPPED — No confirmed TCP/21 endpoints in current batch"
		}
		return nil, "SKIPPED — No confirmed open FTP endpoints in current NetworkHound results."
	}
	return endpoints, "NetworkHound"
}

func buildFTPReport(assessment, source string, endpoints []string, results []FTPAnonymousResult) ftpAnonymousReport {
	report := ftpAnonymousReport{Assessment: assessment, Source: source, DiscoveredEndpoints: len(endpoints), EndpointsTested: len(results), Results: results}
	for _, result := range results {
		if result.Accepted {
			report.AnonymousLoginsAccepted++
		} else if result.Stage == "rejected" {
			report.Rejected++
		} else {
			report.Unreachable++
		}
	}
	return report
}

func formatFTPReport(report ftpAnonymousReport) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "FTP ANONYMOUS ACCESS\nAssessment: %s\n\n", fallbackEndpoint(report.Assessment))
	fmt.Fprintf(&builder, "Discovered FTP endpoints: %d\nEndpoints tested:          %d\nAnonymous logins accepted: %d\nRejected:                  %d\nUnreachable/indeterminate: %d\n", report.DiscoveredEndpoints, report.EndpointsTested, report.AnonymousLoginsAccepted, report.Rejected, report.Unreachable)
	if report.AnonymousLoginsAccepted > 0 {
		builder.WriteString("\nCONFIRMED ANONYMOUS ACCESS\n")
	}
	for _, result := range report.Results {
		if result.Accepted {
			fmt.Fprintf(&builder, "\nHost: %s\nPort: %d\nUser: anonymous\nAuthentication: ACCEPTED\nServer response: %s\n", result.Target, result.Port, result.AuthResponse)
		}
	}
	return builder.String()
}

func parseFTPEndpoint(value string) (string, int, error) {
	value = strings.TrimSpace(value)
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || portText == "" {
		return "", 0, errors.New("FTP endpoint must be an explicit host:port value")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("FTP endpoint port must be between 1 and 65535")
	}
	return host, port, nil
}

func fallbackEndpoint(value string) string {
	if strings.TrimSpace(value) == "" {
		return "<host:port>"
	}
	return value
}

func probeFTPAnonymous(ctx context.Context, endpoint string) FTPAnonymousResult {
	host, port, err := parseFTPEndpoint(endpoint)
	result := FTPAnonymousResult{Target: host, Port: port, Username: "anonymous", Stage: "connect"}
	if err != nil {
		result.Error = err.Error()
		return result
	}
	dialer := net.Dialer{Timeout: ftpTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		result.Error = classifyFTPError(ctx, err)
		return result
	}
	defer conn.Close()
	deadline := time.Now().Add(ftpTimeout)
	_ = conn.SetDeadline(deadline)
	cancelled := make(chan struct{})
	defer close(cancelled)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-cancelled:
		}
	}()
	reader := bufio.NewReader(conn)
	welcome, err := readFTPResponse(reader)
	result.WelcomeResponse = welcome
	if err != nil {
		result.Error = classifyFTPError(ctx, err)
		return result
	}
	if ftpCode(welcome) != 220 {
		result.Stage = "rejected"
		result.Error = "unexpected FTP welcome response"
		return result
	}
	result.Stage = "user"
	if _, err = fmt.Fprintf(conn, "USER anonymous\r\n"); err != nil {
		result.Error = classifyFTPError(ctx, err)
		return result
	}
	userResponse, err := readFTPResponse(reader)
	result.AuthResponse = userResponse
	if err != nil {
		result.Error = classifyFTPError(ctx, err)
		return result
	}
	if ftpCode(userResponse) == 230 {
		result.Accepted = true
		result.Stage = "authenticated"
		return result
	}
	if ftpCode(userResponse) != 331 {
		result.Stage = "rejected"
		return result
	}
	result.Stage = "password"
	if _, err = fmt.Fprintf(conn, "PASS password\r\n"); err != nil {
		result.Error = classifyFTPError(ctx, err)
		return result
	}
	result.AuthResponse, err = readFTPResponse(reader)
	if err != nil {
		result.Error = classifyFTPError(ctx, err)
		return result
	}
	if ftpCode(result.AuthResponse) == 230 {
		result.Accepted = true
		result.Stage = "authenticated"
	} else {
		result.Stage = "rejected"
	}
	return result
}

func readFTPResponse(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return strings.TrimSpace(line), err
	}
	return strings.TrimSpace(line), nil
}

func ftpCode(response string) int {
	if len(response) < 3 {
		return 0
	}
	code, err := strconv.Atoi(response[:3])
	if err != nil {
		return 0
	}
	return code
}

func classifyFTPError(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return ctx.Err().Error()
	}
	return err.Error()
}

var _ modules.Module = FTPAnonymousAccess{}
var _ modules.StatusProvider = FTPAnonymousAccess{}
var _ modules.InputRequester = FTPAnonymousAccess{}
var _ modules.InputValidator = FTPAnonymousAccess{}
var _ modules.OptionDeclarer = FTPAnonymousAccess{}
var _ modules.DetailProvider = FTPAnonymousAccess{}
var _ modules.CommandPreviewProvider = FTPAnonymousAccess{}
var _ modules.ExecutionArtifactPathProvider = FTPAnonymousAccess{}
