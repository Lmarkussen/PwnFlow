package findings

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// delegationRiskFindings resolves delegation targets across the collection:
// constrained delegation whose target is a domain controller, and
// resource-based constrained delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
// exported as AllowedToAct. RustHound puts both at the top level of the
// object, so they are read from collectedObject.Top.
func delegationRiskFindings(objects map[string]collectedObject, assessmentID, executionID int64, now time.Time) []storage.FindingInput {
	isDC := func(id string) bool {
		object, ok := objects[id]
		if !ok {
			return false
		}
		value, _ := rawBoolValue(object.Properties, "isdc")
		return value
	}
	dcHosts := map[string]bool{}
	for _, object := range objects {
		if strings.EqualFold(object.Type, "computers") && isDC(object.ID) {
			name := strings.ToLower(object.Name)
			dcHosts[name] = true
			if index := strings.IndexByte(name, '.'); index > 0 {
				dcHosts[name[:index]] = true
			}
		}
	}
	ids := make([]string, 0, len(objects))
	for id := range objects {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var result []storage.FindingInput
	for _, id := range ids {
		object := objects[id]
		if !strings.EqualFold(object.Type, "users") && !strings.EqualFold(object.Type, "computers") {
			continue
		}
		if enabled, known := rawBoolValue(object.Properties, "enabled"); known && !enabled {
			continue
		}
		// Constrained delegation to a domain controller.
		var dcTargets []string
		for _, target := range topReferences(object, "AllowedToDelegate") {
			if isDC(target) {
				dcTargets = appendUniqueString(dcTargets, objectLabel(objects[target]))
			}
		}
		for _, spn := range rawStringSlice(object.Properties, "allowedtodelegate") {
			host := spn
			if index := strings.IndexByte(host, '/'); index >= 0 {
				host = host[index+1:]
			}
			host = strings.ToLower(strings.SplitN(host, ":", 2)[0])
			if dcHosts[host] {
				dcTargets = appendUniqueString(dcTargets, spn)
			}
		}
		if len(dcTargets) > 0 {
			transition, _ := rawBoolValue(object.Properties, "trustedtoauth")
			severity := "medium"
			description := "The account may delegate to services on a domain controller. Anyone who controls it can obtain service tickets to the domain controller on behalf of a user who authenticates to it."
			if transition {
				severity = "high"
				description = "The account may delegate to services on a domain controller with protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION). Anyone who controls it can obtain a ticket to the domain controller as any user, including a domain administrator, without that user's involvement. No ticket was requested."
			}
			evidence, _ := json.Marshal(delegationEvidence(object, "constrained", map[string]any{"allowed_to_delegate": dcTargets, "trusted_to_auth": transition, "domain_controller": true}))
			result = append(result, storage.FindingInput{
				FindingKey: stableSourceKey(assessmentID, "rusthound-constrained-to-dc", object.ID, dcTargets), AssessmentID: assessmentID,
				SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "constrained_delegation_to_dc",
				Title: "Constrained delegation to a domain controller: " + objectLabel(object), Description: description,
				Severity: severity, Confidence: "observed-directory-property", AffectedObjectID: object.ID, AffectedObject: object.Name,
				EvidenceJSON: string(evidence), ArtifactPath: object.Artifact, ArtifactRef: strings.TrimSuffix(object.RefPrefix, "/Properties") + "/AllowedToDelegate",
				ObservedAt: now, Status: "open", ParserVersion: hygieneParserVersion,
			})
		}
		// Resource-based constrained delegation configured on this object.
		var principals []string
		for _, principal := range topReferences(object, "AllowedToAct") {
			principals = appendUniqueString(principals, fallbackString(objects[principal].Name, principal))
		}
		if len(principals) > 0 {
			targetDC := isDC(object.ID)
			severity := "medium"
			description := fmt.Sprintf("Resource-based constrained delegation on %s lets %s obtain service tickets to it as any user. Anyone who controls one of those principals can impersonate an administrator on this host. No ticket was requested.", objectLabel(object), strings.Join(principals, ", "))
			if targetDC {
				severity = "high"
				description = "Resource-based constrained delegation is configured on a domain controller: " + strings.Join(principals, ", ") + " can obtain tickets to it as any user, which is control of the domain for anyone who controls them. No ticket was requested."
			}
			evidence, _ := json.Marshal(delegationEvidence(object, "resource-based", map[string]any{"allowed_to_delegate": principals, "allowed_to_act": principals, "domain_controller": targetDC}))
			result = append(result, storage.FindingInput{
				FindingKey: stableSourceKey(assessmentID, "rusthound-rbcd", object.ID, principals), AssessmentID: assessmentID,
				SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "rbcd_observed",
				Title: "Resource-based delegation configured: " + objectLabel(object), Description: description,
				Severity: severity, Confidence: "observed-directory-property", AffectedObjectID: object.ID, AffectedObject: object.Name,
				EvidenceJSON: string(evidence), ArtifactPath: object.Artifact, ArtifactRef: strings.TrimSuffix(object.RefPrefix, "/Properties") + "/AllowedToAct",
				ObservedAt: now, Status: "open", ParserVersion: hygieneParserVersion,
			})
		}
	}
	return result
}

// topReferences reads a top-level list of {"ObjectIdentifier": ...} entries.
func topReferences(object collectedObject, field string) []string {
	raw, ok := object.Top[field]
	if !ok {
		return nil
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return nil
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if id := rawString(entry, "ObjectIdentifier"); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}
