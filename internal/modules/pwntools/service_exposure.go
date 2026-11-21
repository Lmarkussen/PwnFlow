package pwntools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/networkhound"
)

const (
	serviceExposureID = "network-service-exposure"
	// ServiceExposureTool is the source tool name Findings carry.
	ServiceExposureTool = "PwnFlow Service Probe"
	serviceExposureDir  = "Enumeration/PwnTools/ServiceExposure"
)

// serviceTCPPorts maps the TCP services probed on NetworkHound-confirmed
// open ports to their port.
var serviceTCPPorts = []struct {
	service string
	port    int
}{{"telnet", 23}, {"rdp", 3389}, {"redis", 6379}, {"elasticsearch", 9200}, {"mongodb", 27017}}

// serviceUDPPorts are probed on every host NetworkHound scanned, since a TCP
// scan cannot see them.
var serviceUDPPorts = []struct {
	service string
	port    int
}{{"snmp", 161}, {"ipmi", 623}}

// ServiceExposure checks whether network services answer without
// credentials. Each probe is one read-only exchange: a Telnet banner, an RDP
// security negotiation, Redis INFO, the Elasticsearch banner, MongoDB
// listDatabases, an SNMPv2c GET of sysDescr with the public and private
// community strings, and the IPMI channel capabilities. No login is
// attempted and nothing is written.
type ServiceExposure struct{}

type serviceExposureReport struct {
	SchemaVersion int                  `json:"schema_version"`
	Assessment    string               `json:"assessment"`
	Source        string               `json:"source"`
	ProbedAt      string               `json:"probed_at"`
	Results       []ServiceProbeResult `json:"results"`
}

func (ServiceExposure) ID() string                     { return serviceExposureID }
func (ServiceExposure) Name() string                   { return "Network Service Exposure" }
func (ServiceExposure) ToolFamily() modules.ToolFamily { return modules.ToolFamilyPwnTools }
func (ServiceExposure) Category() modules.Category     { return modules.CategoryServiceEnumeration }
func (ServiceExposure) Tool() string                   { return ServiceExposureTool }
func (ServiceExposure) Protocol() modules.Protocol     { return modules.ProtocolNA }
func (ServiceExposure) Description() string {
	return "Asks the services NetworkHound found - Telnet, RDP, Redis, Elasticsearch, MongoDB - and SNMP and IPMI on every scanned host whether they answer without credentials. One read-only exchange per service: no login attempts, no writes; SNMP is read with the public and private community strings only."
}
func (ServiceExposure) Prerequisites() []string {
	return []string{"NetworkHound scope validation in the same batch or an approved scope"}
}
func (ServiceExposure) RequiredPrivileges() []string { return nil }
func (ServiceExposure) OutputFile() string {
	return filepath.Join(serviceExposureDir, "service-exposure.json")
}
func (ServiceExposure) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (ServiceExposure) ReadOnly() bool                   { return true }
func (ServiceExposure) SecondaryConnections() []string {
	return []string{"one TCP connection or a few UDP datagrams per probed service"}
}
func (ServiceExposure) BatchPrerequisites() []string {
	return []string{"networkhound-scope-validation"}
}
func (ServiceExposure) OptionKeys() []string { return nil }
func (ServiceExposure) DetailLines(*modules.Runtime) []string {
	return []string{
		"TCP (NetworkHound-confirmed): Telnet 23, RDP 3389, Redis 6379, Elasticsearch 9200, MongoDB 27017",
		"UDP (every scanned host): SNMP 161 (public, private; GET only), IPMI 623 (capabilities)",
		"No logins, no writes; one exchange per service, 4 s timeout",
	}
}
func (ServiceExposure) CommandPreview(*modules.Runtime) string {
	return "PwnFlow service probe <NetworkHound endpoints> telnet rdp redis elasticsearch mongodb snmp ipmi"
}

func (m ServiceExposure) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil {
		return errors.New("runtime configuration is required")
	}
	if _, _, reason := serviceTargets(runtime); reason != "" {
		return modules.SkipError{Reason: reason}
	}
	return nil
}

func (ServiceExposure) ExecutionArtifactPath(resultsRoot string, started time.Time) string {
	name := started.UTC().Format("20060102-150405.000000000") + "-" + uuid.NewString()
	return filepath.Join(resultsRoot, serviceExposureDir, "executions", name, "service-exposure.json")
}

type serviceTarget struct {
	service string
	host    string
	port    int
}

// serviceTargets lists what to probe from the batch's NetworkHound results.
func serviceTargets(runtime *modules.Runtime) ([]serviceTarget, string, string) {
	artifactKey := "networkhound-scope-validation"
	if runtime.AutomaticBatch {
		artifactKey = networkhound.AutomaticServiceArtifactKey
	}
	artifact := ""
	if runtime.BatchArtifacts != nil {
		artifact = runtime.BatchArtifacts[artifactKey]
	}
	if artifact == "" {
		return nil, "", "SKIPPED — NetworkHound service results are not available in this batch"
	}
	scope := ""
	if runtime.AutomaticBatch {
		addresses, err := networkhound.TopologyHostAddresses(runtime.BatchArtifacts["networkhound-topology"])
		if err != nil || len(addresses) == 0 {
			return nil, "", "SKIPPED — NetworkHound topology scope is missing or invalid"
		}
		scope = strings.Join(addresses, ",")
	} else {
		scope, _ = runtime.ModuleOption("networkhound-scope-validation", "NETWORKS")
		if err := networkhound.ValidateScope(scope); err != nil {
			return nil, "", "SKIPPED — NetworkHound approved scope is missing or invalid"
		}
	}
	var targets []serviceTarget
	for _, tcp := range serviceTCPPorts {
		endpoints, err := networkhound.OpenPortEndpoints(artifact, scope, tcp.port)
		if err != nil {
			return nil, "", "SKIPPED — NetworkHound service results unreadable: " + err.Error()
		}
		for _, endpoint := range endpoints {
			host, _, _ := net.SplitHostPort(endpoint)
			targets = append(targets, serviceTarget{tcp.service, host, tcp.port})
		}
	}
	hosts, err := networkhound.ScannedHosts(artifact, scope)
	if err != nil {
		return nil, "", "SKIPPED — NetworkHound service results unreadable: " + err.Error()
	}
	for _, host := range hosts {
		for _, udp := range serviceUDPPorts {
			targets = append(targets, serviceTarget{udp.service, host, udp.port})
		}
	}
	if len(targets) == 0 {
		return nil, "", "SKIPPED — NetworkHound found no hosts to probe"
	}
	return targets, "NetworkHound", ""
}

func (m ServiceExposure) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if err := m.Check(ctx, runtime); err != nil {
		return err
	}
	targets, source, _ := serviceTargets(runtime)
	results := make([]ServiceProbeResult, len(targets))
	sem := make(chan struct{}, 16)
	done := make(chan struct{}, len(targets))
	for index, target := range targets {
		go func(index int, target serviceTarget) {
			defer func() { done <- struct{}{} }()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[index] = ServiceProbeResult{Service: target.service, Target: target.host, Port: target.port, Outcome: "error", Detail: "cancelled"}
				return
			}
			results[index] = probeService(ctx, target.service, target.host, target.port)
			<-sem
		}(index, target)
	}
	for range targets {
		<-done
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Service != results[j].Service {
			return results[i].Service < results[j].Service
		}
		return results[i].Target < results[j].Target
	})
	report := serviceExposureReport{SchemaVersion: 1, Assessment: runtime.Domain, Source: source, ProbedAt: time.Now().UTC().Format(time.RFC3339Nano), Results: results}
	var summary strings.Builder
	exposed := 0
	for _, result := range results {
		if result.Outcome == "exposed" {
			exposed++
			fmt.Fprintf(&summary, "[+] %s %s:%d — %s %s\n", result.Service, result.Target, result.Port, result.Detail, result.Evidence)
		}
	}
	fmt.Fprintf(&summary, "[*] Probed %d service endpoint(s); %d answered without credentials\n", len(results), exposed)
	if _, err := sink.Write([]byte(summary.String())); err != nil {
		return err
	}
	outputPath := runtime.ExecutionOutputPath
	if outputPath == "" {
		outputPath = m.ExecutionArtifactPath(runtime.ResultsRoot, time.Now().UTC())
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	// Written after the summary so the runner's display output does not
	// replace the structured artifact the analyzer reads.
	return os.WriteFile(outputPath, append(data, '\n'), 0o600)
}

var _ modules.Module = ServiceExposure{}
