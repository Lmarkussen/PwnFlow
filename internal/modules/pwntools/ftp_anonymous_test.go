package pwntools

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
)

type ftpMock struct {
	listener net.Listener
	commands chan string
	server   *testing.T
}

type ftpOutputBuffer struct{ data []byte }

func (b *ftpOutputBuffer) Write(data []byte) (int, error) {
	b.data = append(b.data, data...)
	return len(data), nil
}

func startFTPMock(t *testing.T, accepted bool) *ftpMock {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mock := &ftpMock{listener: listener, commands: make(chan string, 4), server: t}
	t.Cleanup(func() { listener.Close() })
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		_, _ = connection.Write([]byte("220 test FTP\r\n"))
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			command := strings.TrimSpace(line)
			mock.commands <- command
			switch command {
			case "USER anonymous":
				_, _ = connection.Write([]byte("331 password required\r\n"))
			case "PASS password":
				if accepted {
					_, _ = connection.Write([]byte("230 login successful\r\n"))
				} else {
					_, _ = connection.Write([]byte("530 login refused\r\n"))
				}
			default:
				_, _ = connection.Write([]byte("500 unexpected command\r\n"))
			}
		}
	}()
	return mock
}

func (m *ftpMock) endpoint() string { return m.listener.Addr().String() }

func TestFTPAnonymousProbeUsesExactlyOneCredentialPair(t *testing.T) {
	mock := startFTPMock(t, true)
	result := probeFTPAnonymous(context.Background(), mock.endpoint())
	if !result.Accepted || result.Username != "anonymous" || result.AuthResponse != "230 login successful" {
		t.Fatalf("unexpected successful result: %+v", result)
	}
	commands := []string{<-mock.commands, <-mock.commands}
	if strings.Join(commands, "|") != "USER anonymous|PASS password" {
		t.Fatalf("FTP probe sent %q, want exactly USER/PASS anonymous pair", commands)
	}
	select {
	case command := <-mock.commands:
		t.Fatalf("probe sent an unnecessary command %q", command)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestFTPAnonymousProbeRejectedCreatesNoSuccess(t *testing.T) {
	mock := startFTPMock(t, false)
	result := probeFTPAnonymous(context.Background(), mock.endpoint())
	if result.Accepted || result.Stage != "rejected" || result.AuthResponse != "530 login refused" {
		t.Fatalf("unexpected rejected result: %+v", result)
	}
}

func TestFTPAnonymousProbeRejectsWrongProtocolResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = connection.Write([]byte("not FTP\r\n"))
	}()
	result := probeFTPAnonymous(context.Background(), listener.Addr().String())
	if result.Accepted || result.Stage != "rejected" || result.Error == "" {
		t.Fatalf("wrong protocol was not rejected: %+v", result)
	}
}

func TestFTPAnonymousProbeCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := probeFTPAnonymous(ctx, "127.0.0.1:1")
	if result.Accepted || !strings.Contains(result.Error, "canceled") {
		t.Fatalf("canceled probe was not classified safely: %+v", result)
	}
}

func TestFTPAnonymousModuleRequiresExplicitEndpoint(t *testing.T) {
	module := FTPAnonymousAccess{}
	runtime := &modules.Runtime{ModuleOptions: map[string]map[string]string{}}
	if status := module.Status(runtime); status != modules.StatusAvailable {
		t.Fatalf("missing endpoint status=%v, want available for dependency-driven execution", status)
	}
	if err := module.ValidateInput(ftpEndpointOption, "198.51.100.42:21"); err != nil {
		t.Fatal(err)
	}
	if err := module.ValidateInput(ftpEndpointOption, "sccm.lab"); err == nil {
		t.Fatal("endpoint without an explicit port was accepted")
	}
	preview := module.CommandPreview(&modules.Runtime{ModuleOptions: map[string]map[string]string{
		ftpAnonymousID: {ftpEndpointOption: "198.51.100.42:21"},
	}})
	if strings.Contains(preview, "password") && !strings.Contains(preview, "[REDACTED]") {
		t.Fatalf("preview leaked password: %s", preview)
	}
}

func TestFTPAnonymousUsesCurrentNetworkHoundArtifact(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "network_scope.json")
	if err := os.WriteFile(artifact, []byte(`{"nodes":[{"properties":{"ip_addresses":["198.51.100.42"],"open_ports":[21,23]}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := &modules.Runtime{ModuleOptions: map[string]map[string]string{
		"networkhound-scope-validation": {"NETWORKS": "198.51.100.0/24"},
	}, BatchArtifacts: map[string]string{"networkhound-scope-validation": artifact}}
	endpoints, reason := discoveredEndpoints(runtime)
	if reason != "NetworkHound" || len(endpoints) != 1 || endpoints[0] != "198.51.100.42:21" {
		t.Fatalf("discovery=%v reason=%q", endpoints, reason)
	}
}

func TestFTPAnonymousMissingDiscoverySkipsWithoutEndpoint(t *testing.T) {
	runtime := &modules.Runtime{BatchArtifacts: map[string]string{}}
	err := (FTPAnonymousAccess{}).Check(context.Background(), runtime)
	var skipped modules.SkipError
	if !errors.As(err, &skipped) || !strings.Contains(skipped.Error(), "NetworkHound FTP discovery evidence unavailable") {
		t.Fatalf("error=%v, want discovery skip", err)
	}
}

func TestFTPAnonymousReportIsHumanReadableAndOmitsPassword(t *testing.T) {
	report := buildFTPReport("sccm.lab", "NetworkHound", []string{"198.51.100.42:21"}, []FTPAnonymousResult{{Target: "198.51.100.42", Port: 21, Username: "anonymous", Accepted: true, AuthResponse: "230 Anonymous login ok", Stage: "authenticated"}})
	output := formatFTPReport(report)
	for _, want := range []string{"FTP ANONYMOUS ACCESS", "Endpoints tested:          1", "Authentication: ACCEPTED", "230 Anonymous login ok"} {
		if !strings.Contains(output, want) {
			t.Fatalf("report missing %q: %s", want, output)
		}
	}
	if strings.Contains(output, "password") {
		t.Fatalf("report exposed password: %s", output)
	}
}

func TestFTPAnonymousRunKeepsJSONArtifactAndReadableSinkOutput(t *testing.T) {
	mock := startFTPMock(t, true)
	artifact := filepath.Join(t.TempDir(), "anonymous-ftp.json")
	runtime := &modules.Runtime{ResultsRoot: t.TempDir(), ExecutionOutputPath: artifact, ModuleOptions: map[string]map[string]string{
		ftpAnonymousID: {ftpEndpointOption: mock.endpoint()},
	}}
	output := &ftpOutputBuffer{}
	if err := (FTPAnonymousAccess{}).Run(context.Background(), runtime, output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	var report ftpAnonymousReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("artifact is not structured JSON: %v", err)
	}
	if report.AnonymousLoginsAccepted != 1 || !strings.Contains(string(output.data), "FTP ANONYMOUS ACCESS") {
		t.Fatalf("report=%+v output=%q", report, output.data)
	}
}
