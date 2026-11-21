package findings

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// buildRegistryPol writes records in the PReg format.
func buildRegistryPol(records ...[4]any) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("PReg")
	binary.Write(&buffer, binary.LittleEndian, uint32(1))
	text := func(value string) []byte {
		var out bytes.Buffer
		for _, unit := range utf16.Encode([]rune(value)) {
			binary.Write(&out, binary.LittleEndian, unit)
		}
		binary.Write(&out, binary.LittleEndian, uint16(0))
		return out.Bytes()
	}
	char := func(c rune) { binary.Write(&buffer, binary.LittleEndian, uint16(c)) }
	for _, record := range records {
		key, name, typ := record[0].(string), record[1].(string), record[2].(uint32)
		var payload []byte
		switch value := record[3].(type) {
		case uint32:
			payload = make([]byte, 4)
			binary.LittleEndian.PutUint32(payload, value)
		case string:
			payload = text(value)
		}
		char('[')
		buffer.Write(text(key))
		char(';')
		buffer.Write(text(name))
		char(';')
		binary.Write(&buffer, binary.LittleEndian, typ)
		char(';')
		binary.Write(&buffer, binary.LittleEndian, uint32(len(payload)))
		char(';')
		buffer.Write(payload)
		char(']')
	}
	return buffer.Bytes()
}

func TestParseRegistryPol(t *testing.T) {
	values := parseRegistryPol(buildRegistryPol(
		[4]any{`Software\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast", uint32(4), uint32(0)},
		[4]any{`Software\Policies\Microsoft\Windows\WindowsUpdate`, "WUServer", uint32(1), "http://wsus.corp.example:8530"},
		[4]any{`Software\Policies\Microsoft\Windows\WindowsUpdate`, "**del.WUStatusServer", uint32(1), " "},
	))
	if len(values) != 2 || !values[0].isNumber || values[0].number != 0 || values[1].text != "http://wsus.corp.example:8530" {
		t.Fatalf("%+v", values)
	}
	if parseRegistryPol([]byte("not a policy")) != nil {
		t.Fatal("non-PReg data parsed")
	}
}

func TestAnalyzeGPORegistryPolicies(t *testing.T) {
	root := t.TempDir()
	write := func(rel string, data []byte) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(path), 0o700)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("A/Registry.pol", buildRegistryPol(
		[4]any{`Software\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast", uint32(4), uint32(0)},
		[4]any{`Software\Policies\Microsoft\Windows\WindowsUpdate`, "WUServer", uint32(1), "http://wsus.corp.example:8530"},
	))
	write("B/Registry.xml", []byte(`<?xml version="1.0" encoding="utf-8"?>
<RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}">
  <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="EnableMDNS">
    <Properties action="U" hive="HKEY_LOCAL_MACHINE" key="SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" name="EnableMDNS" type="REG_DWORD" value="00000000"/>
  </Registry>
  <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="DisabledComponents" disabled="1">
    <Properties action="U" hive="HKEY_LOCAL_MACHINE" key="SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" name="DisabledComponents" type="REG_DWORD" value="000000FF"/>
  </Registry>
</RegistrySettings>`))
	// C disables NetBIOS but is not linked anywhere, so it protects nothing.
	write("C/Registry.pol", buildRegistryPol([4]any{`Software\Policies\Microsoft\Windows NT\DNSClient`, "EnableNetbios", uint32(4), uint32(0)}))
	document := `{"domain":"corp.example","status":"complete","gpos":[
	 {"guid":"A","name":"Workstation Baseline","links":[{"container":"OU=Workstations,DC=corp,DC=example","enabled":true}],"files":{"registry_pol":{"status":"retrieved","file":"A/Registry.pol"},"gpp_registry":{"status":"absent"}}},
	 {"guid":"B","name":"Prefs","links":[{"container":"DC=corp,DC=example","enabled":true}],"files":{"registry_pol":{"status":"absent"},"gpp_registry":{"status":"retrieved","file":"B/Registry.xml"}}},
	 {"guid":"C","name":"Unlinked","links":[],"files":{"registry_pol":{"status":"retrieved","file":"C/Registry.pol"}}}]}`
	path := filepath.Join(root, "registry_policies.json")
	write("registry_policies.json", []byte(document))
	inputs, err := AnalyzeGPORegistryPolicies(context.Background(), path, 2, 4, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	byType := map[string]map[string]any{}
	severity := map[string]string{}
	for _, input := range inputs {
		var evidence map[string]any
		json.Unmarshal([]byte(input.EvidenceJSON), &evidence)
		byType[input.FindingType] = evidence
		severity[input.FindingType] = input.Severity
	}
	name := byType["network_poisoning_name_resolution"]
	if name == nil || severity["network_poisoning_name_resolution"] != "medium" {
		t.Fatalf("name resolution finding missing: %v", byType)
	}
	open := strings.Join(cpStringSlice(name["not_disabled"]), "|")
	if open != "NetBIOS name resolution (NBT-NS): not disabled by any GPO" {
		t.Fatalf("not disabled = %q (LLMNR and mDNS are disabled; the unlinked GPO does not count)", open)
	}
	if byType["network_poisoning_ipv6_dhcpv6"] == nil {
		t.Fatal("a disabled preference item must not count as disabling IPv6")
	}
	if wsus := strings.Join(cpStringSlice(byType["network_poisoning_wsus_http"]["affected_objects"]), "|"); wsus != "Workstation Baseline → WUServer = http://wsus.corp.example:8530" || severity["network_poisoning_wsus_http"] != "high" {
		t.Fatalf("wsus %q", wsus)
	}

	// A partial collection reports only what was observed, never absence.
	write("registry_policies.json", []byte(strings.Replace(document, `"status":"complete"`, `"status":"partial"`, 1)))
	inputs, _ = AnalyzeGPORegistryPolicies(context.Background(), path, 2, 4, time.Now())
	if len(inputs) != 1 || inputs[0].FindingType != "network_poisoning_wsus_http" {
		t.Fatalf("partial collection produced %+v", inputs)
	}
}
