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

func (FTPAnonymousAccess) ID() string                     { return ftpAnonymousID }
func (FTPAnonymousAccess) Name() string                   { return "FTP Anonymous Access" }
func (FTPAnonymousAccess) ToolFamily() modules.ToolFamily { return modules.ToolFamilyPwnTools }
func (FTPAnonymousAccess) Category() modules.Category     { return modules.CategoryServiceEnumeration }
func (FTPAnonymousAccess) Tool() string                   { return "PwnFlow FTP Probe" }
func (FTPAnonymousAccess) Protocol() modules.Protocol     { return modules.ProtocolFTP }
func (FTPAnonymousAccess) Description() string {
	return "Tests one explicitly selected FTP service with the single anonymous:password credential pair; it does not list or modify files."
}
func (FTPAnonymousAccess) Prerequisites() []string {
	return []string{"an explicitly selected FTP endpoint, supplied as host:port"}
}
func (FTPAnonymousAccess) RequiredPrivileges() []string     { return nil }
func (FTPAnonymousAccess) OutputFile() string               { return ftpAnonymousOutput }
func (FTPAnonymousAccess) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (FTPAnonymousAccess) ReadOnly() bool                   { return true }
func (FTPAnonymousAccess) SecondaryConnections() []string {
	return []string{"one TCP connection to the selected FTP endpoint"}
}
func (FTPAnonymousAccess) OptionKeys() []string { return []string{ftpEndpointOption} }
func (FTPAnonymousAccess) MissingInputs(runtime *modules.Runtime) []modules.InputField {
	if _, ok := runtime.ModuleOption(ftpAnonymousID, ftpEndpointOption); ok {
		return nil
	}
	return []modules.InputField{{Key: ftpEndpointOption, Prompt: "FTP endpoint to test (host:port)", Example: "10.1.10.42:21"}}
}
func (FTPAnonymousAccess) Status(runtime *modules.Runtime) modules.Status {
	endpoint, ok := runtime.ModuleOption(ftpAnonymousID, ftpEndpointOption)
	if !ok {
		return modules.StatusInputRequired
	}
	if _, _, err := parseFTPEndpoint(endpoint); err != nil {
		return modules.StatusUnavailable
	}
	return modules.StatusAvailable
}
func (FTPAnonymousAccess) StatusReason(runtime *modules.Runtime) string {
	endpoint, ok := runtime.ModuleOption(ftpAnonymousID, ftpEndpointOption)
	if !ok {
		return "an explicit FTP endpoint is required; NetworkHound discovery does not select a service automatically"
	}
	if _, _, err := parseFTPEndpoint(endpoint); err != nil {
		return err.Error()
	}
	return ""
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
		"Endpoint: " + fallbackEndpoint(endpoint),
		"Scope: authentication only; no directory listing or file changes",
		"Timeout: 10 seconds",
	}
}
func (FTPAnonymousAccess) CommandPreview(runtime *modules.Runtime) string {
	endpoint, _ := runtime.ModuleOption(ftpAnonymousID, ftpEndpointOption)
	return fmt.Sprintf("PwnFlow FTP probe %s --user anonymous --password [REDACTED]", fallbackEndpoint(endpoint))
}
func (FTPAnonymousAccess) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil {
		return errors.New("runtime configuration is required")
	}
	endpoint, ok := runtime.ModuleOption(ftpAnonymousID, ftpEndpointOption)
	if !ok {
		return modules.SkipError{Reason: "an explicit FTP endpoint is required"}
	}
	_, _, err := parseFTPEndpoint(endpoint)
	return err
}
func (FTPAnonymousAccess) ExecutionArtifactPath(resultsRoot string, started time.Time) string {
	name := started.UTC().Format("20060102-150405.000000000") + "-" + uuid.NewString()
	return filepath.Join(resultsRoot, "Enumeration", "PwnTools", "FTPAnonymousAccess", "executions", name, "anonymous-ftp.json")
}

func (FTPAnonymousAccess) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if err := (FTPAnonymousAccess{}).Check(ctx, runtime); err != nil {
		return err
	}
	endpoint, _ := runtime.ModuleOption(ftpAnonymousID, ftpEndpointOption)
	result := probeFTPAnonymous(ctx, endpoint)
	outputPath := runtime.ExecutionOutputPath
	if outputPath == "" {
		outputPath = (FTPAnonymousAccess{}).ExecutionArtifactPath(runtime.ResultsRoot, time.Now().UTC())
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(outputPath, data, 0o600); err != nil {
		return err
	}
	if _, err := sink.Write(data); err != nil {
		return err
	}
	if !result.Accepted {
		if result.Error != "" {
			return errors.New(result.Error)
		}
		return errors.New("FTP anonymous authentication was not accepted")
	}
	return nil
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
