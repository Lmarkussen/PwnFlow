package findings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeServiceExposure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service-exposure.json")
	os.WriteFile(path, []byte(`{"schema_version":1,"results":[
	 {"service":"redis","target":"192.0.2.20","port":6379,"outcome":"exposed","evidence":"redis_version 7.2.4"},
	 {"service":"redis","target":"192.0.2.21","port":6379,"outcome":"protected"},
	 {"service":"snmp","target":"192.0.2.30","port":161,"outcome":"exposed","detail":"SNMPv2c answered to the community string \"public\"","evidence":"Linux core-sw"},
	 {"service":"snmp","target":"192.0.2.31","port":161,"outcome":"exposed","detail":"SNMPv2c answered to the community string \"private\""},
	 {"service":"ipmi","target":"192.0.2.40","port":623,"outcome":"exposed","evidence":"IPMI v2.0 (RAKP)"},
	 {"service":"rdp","target":"192.0.2.50","port":3389,"outcome":"no_answer"}]}`), 0o600)
	inputs, err := AnalyzeServiceExposure(context.Background(), path, 1, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	byType := map[string]string{}
	severity := map[string]string{}
	for _, input := range inputs {
		byType[input.FindingType] = input.EvidenceJSON
		severity[input.FindingType] = input.Severity
	}
	if len(inputs) != 3 {
		t.Fatalf("want redis, snmp and ipmi Findings, got %v", byType)
	}
	if severity["network_service_redis_unauthenticated"] != "high" || !strings.Contains(byType["network_service_redis_unauthenticated"], "192.0.2.20:6379 (redis_version 7.2.4)") || strings.Contains(byType["network_service_redis_unauthenticated"], "192.0.2.21") {
		t.Fatalf("redis %s", byType["network_service_redis_unauthenticated"])
	}
	if severity["network_service_snmp_default_community"] != "high" || !strings.Contains(byType["network_service_snmp_default_community"], `community \"private\"`) {
		t.Fatalf("snmp %s %s", severity["network_service_snmp_default_community"], byType["network_service_snmp_default_community"])
	}
	if severity["network_service_ipmi_exposed"] != "medium" {
		t.Fatalf("ipmi without anonymous login is medium: %s", severity["network_service_ipmi_exposed"])
	}
}
