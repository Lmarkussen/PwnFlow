package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const (
	serviceExposureParserVersion = "service-exposure-v1"
	// ServiceExposureTool is the source tool of the network service probe.
	ServiceExposureTool = "PwnFlow Service Probe"
)

// serviceExposureRules describe each probed service: the Finding it yields
// when a host answered without credentials, and how severe that is.
var serviceExposureRules = map[string]struct {
	typ, title, description, severity string
}{
	"telnet": {"network_service_telnet", "Telnet services",
		"These hosts accept Telnet, which carries the session and any credentials in clear text; the banner often names a network device or appliance whose default credentials are documented.", "medium"},
	"rdp": {"network_service_rdp_no_nla", "RDP without Network Level Authentication",
		"These RDP services accept standard RDP security, so they do not require Network Level Authentication: anyone can open a session and reach the Windows logon screen before credentials are checked, and the connection is exposed to RDP-level interception.", "medium"},
	"redis": {"network_service_redis_unauthenticated", "Redis without authentication",
		"These Redis servers answer commands without a password. Anyone who can reach them can read and change the data, and Redis without authentication is commonly turned into code execution as the service account (writing SSH keys or cron entries, or loading a module).", "high"},
	"elasticsearch": {"network_service_elasticsearch_unauthenticated", "Elasticsearch without authentication",
		"These Elasticsearch clusters answer without credentials, so anyone who can reach them can search, export and change every index they hold.", "high"},
	"mongodb": {"network_service_mongodb_unauthenticated", "MongoDB without authentication",
		"These MongoDB instances list their databases without credentials, so anyone who can reach them can read and change the data.", "high"},
	"snmp": {"network_service_snmp_default_community", "SNMP with a default community string",
		"These hosts answer SNMPv2c to the default community string \"public\" or \"private\". SNMP read access exposes interfaces, routes, ARP tables, running processes, installed software and often user names; a read-write community (commonly \"private\") can change the device configuration. Only reads were attempted.", "medium"},
	"ipmi": {"network_service_ipmi_exposed", "IPMI (BMC) reachable",
		"A baseboard management controller answers IPMI on these hosts. IPMI 2.0's RAKP handshake hands out a salted hash of any valid user's password before authentication, and BMCs often keep vendor default accounts; control of a BMC is console-level control of the server. Hashes were not requested.", "medium"},
}

type serviceExposureDocument struct {
	SchemaVersion int `json:"schema_version"`
	Results       []struct {
		Service  string `json:"service"`
		Target   string `json:"target"`
		Port     int    `json:"port"`
		Outcome  string `json:"outcome"`
		Detail   string `json:"detail"`
		Evidence string `json:"evidence"`
	} `json:"results"`
}

// AnalyzeServiceExposure turns the service probe results into one Finding per
// service type that answered without credentials.
func AnalyzeServiceExposure(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return nil, err
	}
	var document serviceExposureDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	exposed := map[string][]string{}
	escalate := map[string]bool{}
	for _, result := range document.Results {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if result.Outcome != "exposed" {
			continue
		}
		line := fmt.Sprintf("%s:%d", result.Target, result.Port)
		if result.Evidence != "" {
			line += " (" + result.Evidence + ")"
		}
		if result.Service == "snmp" && strings.Contains(result.Detail, `"private"`) {
			line += " — community \"private\""
			escalate["snmp"] = true
		}
		if result.Service == "ipmi" && strings.Contains(result.Evidence, "anonymous login enabled") {
			escalate["ipmi"] = true
		}
		exposed[result.Service] = append(exposed[result.Service], line)
	}
	services := make([]string, 0, len(exposed))
	for service := range exposed {
		services = append(services, service)
	}
	sort.Strings(services)
	var result []storage.FindingInput
	for _, service := range services {
		rule, ok := serviceExposureRules[service]
		if !ok {
			continue
		}
		hosts := uniqueStrings(exposed[service])
		sort.Strings(hosts)
		severity := rule.severity
		description := rule.description
		if escalate[service] {
			severity = "high"
			if service == "ipmi" {
				description = "At least one BMC reports anonymous login enabled. " + description
			} else {
				description = "At least one host answered to \"private\", which is usually read-write. " + description
			}
		}
		encoded, _ := json.Marshal(map[string]any{"service": service, "account": fmt.Sprintf("%d host(s)", len(hosts)), "affected_objects": hosts, "host_count": len(hosts)})
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "service-exposure", service, ""), AssessmentID: assessmentID,
			SourceTool: ServiceExposureTool, SourceExecution: executionID, FindingType: rule.typ,
			Title:       fmt.Sprintf("%s (%d host(s))", rule.title, len(hosts)),
			Description: description, Severity: severity, Confidence: "explicit-probe-result",
			AffectedObjectID: service, AffectedObject: fmt.Sprintf("%d host(s)", len(hosts)),
			EvidenceJSON: string(encoded), ArtifactPath: artifactPath, ArtifactRef: "/results", ObservedAt: now, Status: "open", ParserVersion: serviceExposureParserVersion,
		})
	}
	return result, nil
}
