package findings

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGPOControlFindings(t *testing.T) {
	raw := func(value any) json.RawMessage { encoded, _ := json.Marshal(value); return encoded }
	object := func(id, name, typ string, properties map[string]any, top map[string]any) collectedObject {
		props := map[string]json.RawMessage{"name": raw(name), "domain": raw("CORP.EXAMPLE")}
		for key, value := range properties {
			props[key] = raw(value)
		}
		var topFields map[string]json.RawMessage
		if top != nil {
			topFields = map[string]json.RawMessage{}
			for key, value := range top {
				topFields[key] = raw(value)
			}
		}
		return collectedObject{ID: id, Name: name, Type: typ, Properties: props, Top: topFields}
	}
	const sid = "S-1-5-21-1-2-3-"
	objects := map[string]collectedObject{
		"DOMAIN":     object("DOMAIN", "CORP.EXAMPLE", "domains", nil, map[string]any{"Links": []map[string]any{{"GUID": "gpo-root"}}, "ChildObjects": []map[string]any{{"ObjectIdentifier": "OU-DC"}, {"ObjectIdentifier": "OU-WS"}}}),
		"OU-DC":      object("OU-DC", "DOMAIN CONTROLLERS@CORP.EXAMPLE", "ous", nil, map[string]any{"Links": []map[string]any{{"GUID": "GPO-DC"}}, "ChildObjects": []map[string]any{{"ObjectIdentifier": sid + "1000"}}}),
		"OU-WS":      object("OU-WS", "WORKSTATIONS@CORP.EXAMPLE", "ous", nil, map[string]any{"Links": []map[string]any{{"GUID": "GPO-WS"}}, "ChildObjects": []map[string]any{{"ObjectIdentifier": sid + "2000"}, {"ObjectIdentifier": sid + "2001"}}}),
		sid + "1000": object(sid+"1000", "DC01.CORP.EXAMPLE", "computers", map[string]any{"isdc": true}, nil),
		sid + "2000": object(sid+"2000", "WS01.CORP.EXAMPLE", "computers", nil, nil),
		sid + "2001": object(sid+"2001", "WS02.CORP.EXAMPLE", "computers", nil, nil),
		"GPO-ROOT":   object("GPO-ROOT", "BASELINE@CORP.EXAMPLE", "gpos", nil, nil),
		"GPO-DC":     object("GPO-DC", "DC POLICY@CORP.EXAMPLE", "gpos", nil, nil),
		"GPO-WS":     object("GPO-WS", "WORKSTATION POLICY@CORP.EXAMPLE", "gpos", nil, nil),
		"GPO-UNUSED": object("GPO-UNUSED", "UNLINKED@CORP.EXAMPLE", "gpos", nil, nil),
		sid + "3000": object(sid+"3000", "HELPDESK@CORP.EXAMPLE", "groups", nil, nil),
		sid + "3001": object(sid+"3001", "GPO-ADMINS@CORP.EXAMPLE", "groups", nil, nil),
	}
	ace := func(target, principal, right string) collectedACE {
		return collectedACE{Object: objects[target], ACE: map[string]json.RawMessage{"PrincipalSID": raw(principal), "RightName": raw(right)}}
	}
	privileged := map[string][]string{sid + "3001": {"Domain Admins"}}
	aces := []collectedACE{
		ace("GPO-WS", sid+"3000", "GenericWrite"),   // computers only
		ace("GPO-DC", sid+"3000", "WriteDacl"),      // reaches a domain controller
		ace("OU-DC", sid+"3000", "WriteGPLink"),     // can link a GPO to the DC OU
		ace("GPO-UNUSED", sid+"3000", "GenericAll"), // unlinked: applies to nothing
		ace("GPO-ROOT", sid+"3001", "GenericAll"),   // privileged principal: expected
		ace("GPO-WS", sid+"3000", "ReadProperty"),   // not a control right
	}
	findings := gpoControlFindings(objects, aces, privileged, 1, 2, time.Now())
	if len(findings) != 1 || findings[0].Severity != "high" {
		t.Fatalf("want one high finding, got %+v", findings)
	}
	var evidence map[string]any
	json.Unmarshal([]byte(findings[0].EvidenceJSON), &evidence)
	lines := cpStringSlice(evidence["affected_objects"])
	joined := strings.Join(lines, "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "Tier 0") || !strings.Contains(joined, "WriteGPLink on links on DOMAIN CONTROLLERS@CORP.EXAMPLE") || !strings.Contains(joined, "GenericWrite on GPO WORKSTATION POLICY@CORP.EXAMPLE (linked to WORKSTATIONS@CORP.EXAMPLE); applies to 2 computer(s)") || strings.Contains(joined, "UNLINKED") || strings.Contains(joined, "GPO-ADMINS") {
		t.Fatalf("grants:\n%s", joined)
	}
	if !strings.Contains(joined, "domain controller DC01.CORP.EXAMPLE") {
		t.Fatalf("Tier 0 reason missing:\n%s", joined)
	}
}
