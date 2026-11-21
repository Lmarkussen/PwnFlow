package findings

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const (
	gpoRegistryParserVersion = "gpo-registry-policies-v1"
	// GPORegistryPoliciesTool is the source tool of the registry settings
	// module (gpoevidence.RegistryPoliciesTool).
	GPORegistryPoliciesTool = "GPO Registry Settings"
)

// gpoRegistryValue is one computer registry setting a GPO configures.
type gpoRegistryValue struct {
	key, name string
	text      string
	number    int64
	isNumber  bool
}

type gpoRegistryDocument struct {
	Domain string `json:"domain"`
	Status string `json:"status"`
	GPOs   []struct {
		GUID                     string `json:"guid"`
		Name                     string `json:"name"`
		ComputerSettingsDisabled bool   `json:"computer_settings_disabled"`
		Links                    []struct {
			Container string `json:"container"`
			Enabled   bool   `json:"enabled"`
		} `json:"links"`
		Files map[string]struct {
			Status string `json:"status"`
			File   string `json:"file"`
		} `json:"files"`
	} `json:"gpos"`
}

// AnalyzeGPORegistryPolicies evaluates the registry-based computer settings
// of the GPOs that are linked somewhere with computer settings enabled. A
// protection counts when any such GPO configures it; links are not resolved
// to individual hosts, so a protection set on one OU is credited to the
// domain. Absence is only reported when every policy file was read.
func AnalyzeGPORegistryPolicies(ctx context.Context, documentPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	data, err := os.ReadFile(documentPath)
	if err != nil {
		return nil, err
	}
	var document gpoRegistryDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if document.Status == "failed" {
		return nil, nil
	}
	root := filepath.Dir(documentPath)
	type sourced struct {
		value gpoRegistryValue
		gpo   string
	}
	var settings []sourced
	applying := 0
	for _, gpo := range document.GPOs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		linked := false
		for _, link := range gpo.Links {
			linked = linked || link.Enabled
		}
		if !linked || gpo.ComputerSettingsDisabled {
			continue
		}
		applying++
		name := fallbackString(gpo.Name, gpo.GUID)
		if file := gpo.Files["registry_pol"]; file.Status == "retrieved" && file.File != "" {
			if raw, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.File))); readErr == nil {
				for _, value := range parseRegistryPol(raw) {
					settings = append(settings, sourced{value, name})
				}
			}
		}
		if file := gpo.Files["gpp_registry"]; file.Status == "retrieved" && file.File != "" {
			if raw, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.File))); readErr == nil {
				for _, value := range parseGPPRegistry(raw) {
					settings = append(settings, sourced{value, name})
				}
			}
		}
	}
	find := func(match func(gpoRegistryValue) bool) []string {
		var gpos []string
		for _, setting := range settings {
			if match(setting.value) {
				gpos = append(gpos, setting.gpo)
			}
		}
		return uniqueStrings(gpos)
	}
	dword := func(keySuffix, name string, accept func(int64) bool) func(gpoRegistryValue) bool {
		return func(value gpoRegistryValue) bool {
			return value.isNumber && strings.HasSuffix(strings.ToLower(value.key), strings.ToLower(keySuffix)) && strings.EqualFold(value.name, name) && accept(value.number)
		}
	}
	domain := strings.ToUpper(fallbackString(document.Domain, "domain"))
	complete := document.Status == "complete"
	caveat := fmt.Sprintf(" Evaluated %d GPO(s) that are linked with computer settings enabled, from Administrative Templates (Registry.pol) and Group Policy Preferences registry items; a protection set by any of them counts for the whole domain. Settings made outside Group Policy (images, DHCP options, scripts, local configuration) were not checked.", applying)
	var result []storage.FindingInput
	add := func(typ, title, description, severity string, evidence map[string]any) {
		evidence["domain"] = domain
		evidence["gpos_evaluated"] = applying
		encoded, _ := json.Marshal(evidence)
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "gpo-registry-"+typ, domain, ""), AssessmentID: assessmentID,
			SourceTool: GPORegistryPoliciesTool, SourceExecution: executionID, FindingType: typ, Title: title,
			Description: description + caveat, Severity: severity, Confidence: "policy-configured",
			AffectedObjectID: strings.ToLower(domain), AffectedObject: domain, EvidenceJSON: string(encoded),
			ArtifactPath: documentPath, ArtifactRef: "/gpos", ObservedAt: now, Status: "open", ParserVersion: gpoRegistryParserVersion,
		})
	}

	// LLMNR, NetBIOS name resolution and mDNS.
	llmnr := find(dword(`Software\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast", func(v int64) bool { return v == 0 }))
	netbios := find(dword(`Software\Policies\Microsoft\Windows NT\DNSClient`, "EnableNetbios", func(v int64) bool { return v == 0 }))
	netbios = uniqueStrings(append(netbios, find(func(value gpoRegistryValue) bool {
		return value.isNumber && strings.Contains(strings.ToLower(value.key), `services\netbt\parameters\interfaces\`) && strings.EqualFold(value.name, "NetbiosOptions") && value.number == 2
	})...))
	mdns := find(dword(`Services\Dnscache\Parameters`, "EnableMDNS", func(v int64) bool { return v == 0 }))
	if complete && (len(llmnr) == 0 || len(netbios) == 0 || len(mdns) == 0) {
		var open, protected []string
		for _, item := range []struct {
			label string
			gpos  []string
		}{{"LLMNR", llmnr}, {"NetBIOS name resolution (NBT-NS)", netbios}, {"mDNS", mdns}} {
			if len(item.gpos) == 0 {
				open = append(open, item.label+": not disabled by any GPO")
			} else {
				protected = append(protected, item.label+": disabled by "+strings.Join(item.gpos, ", "))
			}
		}
		severity := "medium"
		if len(llmnr) > 0 && len(netbios) > 0 {
			severity = "low"
		}
		add("network_poisoning_name_resolution", fmt.Sprintf("Multicast and broadcast name resolution not disabled by Group Policy (%s)", domain),
			"When DNS cannot resolve a name, Windows asks the local network through LLMNR, NetBIOS (NBT-NS) and mDNS, and accepts the first answer. Any host on the segment can answer for mistyped, stale or WPAD names and receive the client's NTLM authentication, which can be cracked or relayed. "+strings.Join(open, "; ")+".",
			severity, map[string]any{"account": strings.Join(open, "; "), "affected_objects": append(append([]string{}, open...), protected...), "not_disabled": open, "disabled": protected})
	}

	// IPv6 and DHCPv6 spoofing.
	ipv6 := find(dword(`Services\Tcpip6\Parameters`, "DisabledComponents", func(v int64) bool { return v&0x10 != 0 || v == 0xff }))
	if complete && len(ipv6) == 0 {
		add("network_poisoning_ipv6_dhcpv6", fmt.Sprintf("IPv6 not disabled by Group Policy (%s)", domain),
			"Windows prefers IPv6 and asks for a DHCPv6 configuration even on IPv4-only networks. A host on the segment can answer as DHCPv6 server and become the clients' DNS server (mitm6), then serve WPAD and receive their NTLM authentication for relay. No GPO sets DisabledComponents to disable IPv6 on LAN interfaces; switch-side RA Guard or DHCPv6 Guard and host firewalls blocking DHCPv6 were not checked.",
			"medium", map[string]any{"account": "IPv6 enabled on LAN interfaces", "affected_objects": []string{"DisabledComponents not configured to disable IPv6 by any GPO"}})
	}

	// WSUS over HTTP.
	var wsus []string
	for _, setting := range settings {
		if strings.HasSuffix(strings.ToLower(setting.value.key), `software\policies\microsoft\windows\windowsupdate`) && (strings.EqualFold(setting.value.name, "WUServer") || strings.EqualFold(setting.value.name, "WUStatusServer")) &&
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(setting.value.text)), "http://") {
			wsus = append(wsus, fmt.Sprintf("%s → %s = %s", setting.gpo, setting.value.name, strings.TrimSpace(setting.value.text)))
		}
	}
	if wsus = uniqueStrings(wsus); len(wsus) > 0 {
		sort.Strings(wsus)
		add("network_poisoning_wsus_http", fmt.Sprintf("Windows Update served from WSUS over HTTP (%s)", domain),
			"Group Policy points clients at a WSUS server over plain HTTP. Update metadata is then unauthenticated in transit: anyone who can intercept a client's traffic (ARP or DHCPv6 spoofing, a proxy via WPAD) can serve it a Microsoft-signed binary such as PsExec with arbitrary arguments, which runs as SYSTEM.",
			"high", map[string]any{"account": fmt.Sprintf("%d setting(s)", len(wsus)), "affected_objects": wsus})
	}
	return result, nil
}

// parseRegistryPol reads the PReg format of Registry.pol: a "PReg" signature
// and version, then [key;value;type;size;data] records whose text is
// UTF-16LE. Malformed records end the parse; what was read stays valid.
func parseRegistryPol(data []byte) []gpoRegistryValue {
	if len(data) < 8 || string(data[:4]) != "PReg" {
		return nil
	}
	var result []gpoRegistryValue
	position := 8
	readString := func() (string, bool) {
		var units []uint16
		for position+1 < len(data) {
			unit := binary.LittleEndian.Uint16(data[position:])
			position += 2
			if unit == 0 {
				return string(utf16.Decode(units)), true
			}
			units = append(units, unit)
		}
		return "", false
	}
	expect := func(char uint16) bool {
		if position+1 >= len(data) || binary.LittleEndian.Uint16(data[position:]) != char {
			return false
		}
		position += 2
		return true
	}
	for position < len(data) {
		if !expect('[') {
			break
		}
		key, ok := readString()
		if !ok || !expect(';') {
			break
		}
		name, ok := readString()
		if !ok || !expect(';') || position+4 > len(data) {
			break
		}
		typ := binary.LittleEndian.Uint32(data[position:])
		position += 4
		if !expect(';') || position+4 > len(data) {
			break
		}
		size := int(binary.LittleEndian.Uint32(data[position:]))
		position += 4
		if !expect(';') || size < 0 || position+size > len(data) {
			break
		}
		payload := data[position : position+size]
		position += size
		if !expect(']') {
			break
		}
		value := gpoRegistryValue{key: key, name: name}
		switch typ {
		case 4: // REG_DWORD
			if len(payload) >= 4 {
				value.number, value.isNumber = int64(binary.LittleEndian.Uint32(payload)), true
			}
		case 11: // REG_QWORD
			if len(payload) >= 8 {
				value.number, value.isNumber = int64(binary.LittleEndian.Uint64(payload)), true
			}
		case 1, 2: // REG_SZ, REG_EXPAND_SZ
			units := make([]uint16, 0, len(payload)/2)
			for index := 0; index+1 < len(payload); index += 2 {
				units = append(units, binary.LittleEndian.Uint16(payload[index:]))
			}
			value.text = strings.TrimRight(string(utf16.Decode(units)), "\x00")
		}
		// "**del." and "**delvals." records remove values; they configure
		// nothing to evaluate.
		if strings.HasPrefix(name, "**") {
			continue
		}
		result = append(result, value)
	}
	return result
}

// parseGPPRegistry reads Group Policy Preferences registry items that create
// or update HKEY_LOCAL_MACHINE values. Disabled items are skipped.
func parseGPPRegistry(data []byte) []gpoRegistryValue {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	var result []gpoRegistryValue
	disabled := 0
	depth := 0
	var disabledAt []int
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth++
			attrs := map[string]string{}
			for _, attr := range element.Attr {
				attrs[strings.ToLower(attr.Name.Local)] = attr.Value
			}
			if attrs["disabled"] == "1" {
				disabled++
				disabledAt = append(disabledAt, depth)
			}
			if element.Name.Local != "Properties" || disabled > 0 {
				continue
			}
			action := strings.ToUpper(fallbackString(attrs["action"], "U"))
			if action == "D" || !strings.EqualFold(attrs["hive"], "HKEY_LOCAL_MACHINE") {
				continue
			}
			value := gpoRegistryValue{key: attrs["key"], name: attrs["name"]}
			switch strings.ToUpper(attrs["type"]) {
			case "REG_DWORD", "REG_QWORD":
				if number, err := strconv.ParseInt(strings.TrimSpace(attrs["value"]), 16, 64); err == nil {
					value.number, value.isNumber = number, true
				}
			default:
				value.text = attrs["value"]
			}
			result = append(result, value)
		case xml.EndElement:
			if len(disabledAt) > 0 && disabledAt[len(disabledAt)-1] == depth {
				disabledAt = disabledAt[:len(disabledAt)-1]
				disabled--
			}
			depth--
		}
	}
	return result
}
