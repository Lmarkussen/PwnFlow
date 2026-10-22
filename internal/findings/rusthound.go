// Package findings contains offline analyzers for evidence already collected by
// PwnFlow. It deliberately does not calculate BloodHound attack paths.
package findings

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const (
	ParserVersion        = "rusthound-acl-v1"
	MaxJSONBytes         = 64 << 20
	MaxCollection        = 512 << 20
	MaxZIPEntries        = 2048
	MaxZIPFileSize       = 64 << 20
	MaxGeneralACLRecords = 100000
)

var supportedRights = map[string]bool{
	"genericall": true, "genericwrite": true, "writedacl": true,
	"writeowner": true, "addmember": true, "forcechangepassword": true,
	"addallowedtoact": true, "addkeycredentiallink": true, "writespn": true,
	"getchanges": true, "getchangesall": true, "getchangesinfilteredset": true,
}

type AnalysisReport struct {
	CollectorVersion  string
	SchemaVersion     int
	Domain            string
	Files             int
	Objects           int
	ACLs              int
	Findings          int
	Skipped           []string
	ACLRecords        []GeneralACLRecord `json:"-"`
	ACLRecordsOmitted int                `json:"-"`
	UnsupportedACLs   int                `json:"-"`
}

type GeneralACLRecord struct {
	TargetID            string `json:"target_id"`
	TargetName          string `json:"target_name,omitempty"`
	TargetType          string `json:"target_type,omitempty"`
	PrincipalID         string `json:"principal_id,omitempty"`
	PrincipalName       string `json:"principal_name,omitempty"`
	PrincipalType       string `json:"principal_type,omitempty"`
	Permission          string `json:"permission"`
	Decision            string `json:"decision"`
	Inheritance         string `json:"inheritance"`
	ObjectType          string `json:"object_type,omitempty"`
	InheritedObjectType string `json:"inherited_object_type,omitempty"`
	Artifact            string `json:"artifact"`
	ArtifactRef         string `json:"artifact_ref"`
}

type rustHoundExport struct {
	Meta struct {
		CollectorVersion string          `json:"collectorversion"`
		Version          json.RawMessage `json:"version"`
		Type             string          `json:"type"`
	} `json:"meta"`
	Data []json.RawMessage `json:"data"`
}

type collectedObject struct {
	ID         string
	Name       string
	Type       string
	HighValue  bool
	Properties map[string]json.RawMessage
	Artifact   string
	RefPrefix  string
}

type collectedACE struct {
	Object    collectedObject
	ObjectPos int
	ACE       map[string]json.RawMessage
	ACEPos    int
	Artifact  string
	RefPrefix string
}

// AnalyzeRustHound reads a JSON file, a RustHound JSON directory, or a ZIP
// collection. It never writes or extracts the source artifact.
func AnalyzeRustHound(ctx context.Context, inputPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, AnalysisReport, error) {
	if assessmentID <= 0 {
		return nil, AnalysisReport{}, errors.New("assessment id must be positive")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var exports []struct {
		path string
		data []byte
	}
	info, err := os.Stat(inputPath)
	if err != nil {
		return nil, AnalysisReport{}, err
	}
	switch {
	case info.IsDir():
		var total int64
		err = filepath.WalkDir(inputPath, func(filePath string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() || strings.ToLower(filepath.Ext(filePath)) != ".json" {
				return nil
			}
			fileInfo, err := entry.Info()
			if err != nil {
				return err
			}
			if fileInfo.Size() > MaxJSONBytes || total+fileInfo.Size() > MaxCollection {
				return fmt.Errorf("RustHound collection exceeds parser size limit at %s", filePath)
			}
			data, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}
			total += int64(len(data))
			exports = append(exports, struct {
				path string
				data []byte
			}{filePath, data})
			return nil
		})
	case strings.EqualFold(filepath.Ext(inputPath), ".zip"):
		exports, err = readZIP(inputPath, ctx)
	default:
		if info.Size() > MaxJSONBytes {
			return nil, AnalysisReport{}, fmt.Errorf("RustHound JSON exceeds parser size limit")
		}
		data, readErr := os.ReadFile(inputPath)
		err = readErr
		if err == nil {
			exports = append(exports, struct {
				path string
				data []byte
			}{inputPath, data})
		}
	}
	if err != nil {
		return nil, AnalysisReport{}, err
	}

	report := AnalysisReport{}
	objects := make(map[string]collectedObject)
	var aces []collectedACE
	for _, item := range exports {
		if err := ctx.Err(); err != nil {
			return nil, report, err
		}
		var export rustHoundExport
		if err := json.Unmarshal(item.data, &export); err != nil {
			return nil, report, fmt.Errorf("parse RustHound artifact %s: %w", item.path, err)
		}
		if export.Meta.Type == "" || export.Data == nil {
			report.Skipped = append(report.Skipped, item.path)
			continue
		}
		if report.CollectorVersion == "" {
			report.CollectorVersion = export.Meta.CollectorVersion
			report.SchemaVersion, _ = rawInt(export.Meta.Version)
		}
		report.Files++
		for objectPos, rawObject := range export.Data {
			if err := ctx.Err(); err != nil {
				return nil, report, err
			}
			object, aceValues, err := decodeObject(rawObject, export.Meta.Type)
			if err != nil {
				return nil, report, fmt.Errorf("parse object %d in %s: %w", objectPos, item.path, err)
			}
			if object.ID == "" {
				report.Skipped = append(report.Skipped, fmt.Sprintf("%s#/data/%d missing ObjectIdentifier", item.path, objectPos))
				continue
			}
			object.Artifact = item.path
			object.RefPrefix = fmt.Sprintf("/data/%d/Properties", objectPos)
			if report.Domain == "" {
				report.Domain = firstString(object.Properties, "domain")
			}
			objects[object.ID] = object
			report.Objects++
			for acePos, ace := range aceValues {
				aces = append(aces, collectedACE{Object: object, ObjectPos: objectPos, ACE: ace, ACEPos: acePos, Artifact: item.path, RefPrefix: fmt.Sprintf("/data/%d/Aces/%d", objectPos, acePos)})
			}
		}
	}

	findings := make([]storage.FindingInput, 0, len(aces))
	for _, object := range objects {
		if object.Type == "users" {
			findings = append(findings, identityFindings(object, assessmentID, executionID, now)...)
		}
		if object.Type == "users" || object.Type == "computers" {
			findings = append(findings, delegationFindings(object, assessmentID, executionID, now)...)
		}
	}
	for _, ace := range aces {
		if err := ctx.Err(); err != nil {
			return nil, report, err
		}
		right := aceString(ace.ACE, "RightName")
		rightKey := normalize(right)
		if !supportedRights[rightKey] {
			report.UnsupportedACLs++
			continue
		}
		report.ACLs++
		principalID := aceString(ace.ACE, "PrincipalSID")
		principal := objects[principalID]
		principalName := principal.Name
		if principalID != "" && principalName == "" {
			principalName = "unresolved principal"
		}
		if len(report.ACLRecords) < MaxGeneralACLRecords {
			report.ACLRecords = append(report.ACLRecords, GeneralACLRecord{
				TargetID: ace.Object.ID, TargetName: ace.Object.Name, TargetType: ace.Object.Type,
				PrincipalID: principalID, PrincipalName: principalName, PrincipalType: aceString(ace.ACE, "PrincipalType"),
				Permission: right, Decision: aceDecision(ace.ACE), Inheritance: aceInheritance(ace.ACE),
				ObjectType: aceString(ace.ACE, "ObjectType"), InheritedObjectType: aceString(ace.ACE, "InheritedObjectType"),
				Artifact: ace.Artifact, ArtifactRef: ace.RefPrefix,
			})
		} else {
			report.ACLRecordsOmitted++
		}
		if rightKey == "genericall" && aceInheritance(ace.ACE) == "explicit" &&
			strings.EqualFold(ace.Object.Type, "users") &&
			strings.EqualFold(aceString(ace.ACE, "PrincipalType"), "user") &&
			principalID != "" && ace.Object.ID != "" {
			evidence, _ := json.Marshal(map[string]any{
				"domain":                  report.Domain,
				"principal_id":            principalID,
				"principal_name":          principalName,
				"target_id":               ace.Object.ID,
				"target_name":             ace.Object.Name,
				"target_type":             ace.Object.Type,
				"permission":              right,
				"ace_decision":            aceDecision(ace.ACE),
				"inheritance":             aceInheritance(ace.ACE),
				"effective_authorization": "not_verified",
				"source_artifact":         ace.Artifact,
				"source_reference":        ace.RefPrefix,
				"qualification":           "direct_genericall_user_target",
			})
			keyHash := sha256.Sum256([]byte(strings.Join([]string{
				strings.ToLower(report.Domain), principalID, ace.Object.ID, rightKey, "explicit",
			}, "\x00")))
			findings = append(findings, storage.FindingInput{
				FindingKey:       "ad-acl-genericall:" + hex.EncodeToString(keyHash[:]),
				AssessmentID:     assessmentID,
				SourceTool:       "RustHound-CE",
				SourceExecution:  executionID,
				FindingType:      "ad_acl_genericall",
				Title:            "Excessive GenericAll Control Over AD User",
				Description:      "A direct GenericAll relationship was observed between a user principal and an AD user object. Effective authorization and exploitation were not verified.",
				Severity:         "medium",
				Confidence:       "observed-direct-ace",
				AffectedObjectID: ace.Object.ID,
				AffectedObject:   ace.Object.Name,
				RelatedObjectID:  principalID,
				RelatedObject:    principalName,
				EvidenceJSON:     string(evidence),
				ArtifactPath:     ace.Artifact,
				ArtifactRef:      ace.RefPrefix,
				ObservedAt:       now,
				Status:           "open",
				ParserVersion:    ParserVersion,
			})
		}
	}
	report.Findings = len(findings)
	return findings, report, nil
}

// IngestRustHound is the explicit lifecycle entry point. Callers decide when a
// completed artifact is ready; the analyzer never watches partially written
// module output or runs automatically at application startup.
func IngestRustHound(ctx context.Context, db *storage.DB, inputPath string, assessmentID, executionID int64, now time.Time) (AnalysisReport, error) {
	inputs, report, err := AnalyzeRustHound(ctx, inputPath, assessmentID, executionID, now)
	if err != nil {
		return report, err
	}
	if err := db.IngestFindings(ctx, inputs); err != nil {
		return report, err
	}
	return report, nil
}

func readZIP(filePath string, ctx context.Context) ([]struct {
	path string
	data []byte
}, error) {
	archive, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	if len(archive.File) > MaxZIPEntries {
		return nil, fmt.Errorf("RustHound ZIP has too many entries")
	}
	var total uint64
	result := make([]struct {
		path string
		data []byte
	}, 0)
	for _, entry := range archive.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		clean := path.Clean(entry.Name)
		if entry.Name == "" || strings.HasPrefix(entry.Name, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
			return nil, fmt.Errorf("unsafe ZIP entry %q", entry.Name)
		}
		if entry.FileInfo().Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink ZIP entry %q is not allowed", entry.Name)
		}
		if entry.UncompressedSize64 > MaxZIPFileSize || total+entry.UncompressedSize64 > MaxCollection {
			return nil, fmt.Errorf("RustHound ZIP exceeds parser size limit")
		}
		if strings.ToLower(filepath.Ext(entry.Name)) != ".json" {
			continue
		}
		reader, err := entry.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, MaxZIPFileSize+1))
		reader.Close()
		if readErr != nil {
			return nil, readErr
		}
		if len(data) > MaxZIPFileSize {
			return nil, fmt.Errorf("ZIP entry %q exceeds parser size limit", entry.Name)
		}
		total += uint64(len(data))
		result = append(result, struct {
			path string
			data []byte
		}{filePath + "!" + clean, data})
	}
	return result, nil
}

func decodeObject(raw json.RawMessage, objectType string) (collectedObject, []map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return collectedObject{}, nil, err
	}
	properties := rawObject(fields, "Properties")
	object := collectedObject{ID: rawString(fields, "ObjectIdentifier"), Type: objectType, Properties: properties}
	object.Name = firstString(properties, "name", "samaccountname", "distinguishedname", "dn")
	object.HighValue = rawBool(properties, "highvalue")
	var aces []map[string]json.RawMessage
	if rawAces, ok := fields["Aces"]; ok && string(rawAces) != "null" {
		if err := json.Unmarshal(rawAces, &aces); err != nil {
			return collectedObject{}, nil, err
		}
	}
	return object, aces, nil
}

func rawObject(fields map[string]json.RawMessage, key string) map[string]json.RawMessage {
	var value map[string]json.RawMessage
	_ = json.Unmarshal(fields[key], &value)
	return value
}

func firstString(fields map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		if value := rawString(fields, key); value != "" {
			return value
		}
	}
	return ""
}

func rawString(fields map[string]json.RawMessage, key string) string {
	for candidate, raw := range fields {
		if strings.EqualFold(candidate, key) {
			var value string
			if json.Unmarshal(raw, &value) == nil {
				return value
			}
		}
	}
	return ""
}

func rawBool(fields map[string]json.RawMessage, key string) bool {
	for candidate, raw := range fields {
		if strings.EqualFold(candidate, key) {
			var value bool
			if json.Unmarshal(raw, &value) == nil {
				return value
			}
		}
	}
	return false
}

func aceString(ace map[string]json.RawMessage, key string) string { return rawString(ace, key) }
func aceBool(ace map[string]json.RawMessage, key string) bool     { return rawBool(ace, key) }

func aceDecision(ace map[string]json.RawMessage) string {
	for _, key := range []string{"Decision", "AccessControlType", "AceType"} {
		if value := aceString(ace, key); value != "" {
			return value
		}
	}
	return "unknown"
}

func aceInheritance(ace map[string]json.RawMessage) string {
	if inherited, known := rawBoolValue(ace, "IsInherited"); known {
		if inherited {
			return "inherited"
		}
		return "explicit"
	}
	return "unknown"
}

func normalize(value string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "_", "", "-", "").Replace(value))
}

func objectLabel(object collectedObject) string {
	if object.Name != "" {
		return object.Name
	}
	return object.ID
}

func stableACLKey(assessmentID int64, objectID, principalID, right string, ace map[string]json.RawMessage) string {
	canonical, _ := json.Marshal(ace)
	hash := sha256.Sum256([]byte(strconv.FormatInt(assessmentID, 10) + "\x00acl\x00" + objectID + "\x00" + principalID + "\x00" + right + "\x00" + string(canonical)))
	return "acl:" + hex.EncodeToString(hash[:])
}

func rawInt(raw json.RawMessage) (int, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var value int
	err := json.Unmarshal(raw, &value)
	return value, err
}

func identityFindings(object collectedObject, assessmentID, executionID int64, now time.Time) []storage.FindingInput {
	props := object.Properties
	name := object.Name
	enabled, enabledKnown := rawBoolValue(props, "enabled")
	if enabledKnown && !enabled {
		return nil
	}
	spns := rawStringSlice(props, "serviceprincipalnames")
	hasSPN, hasSPNKnown := rawBoolValue(props, "hasspn")
	if !hasSPNKnown {
		hasSPNKnown = len(spns) > 0
	}
	var result []storage.FindingInput
	if hasSPN {
		confidence := "observed-directory-properties"
		severity := "medium"
		if !enabledKnown {
			confidence = "candidate-enabled-unknown"
			severity = "informational"
		}
		evidence, _ := json.Marshal(map[string]any{"account_id": object.ID, "account_name": name, "enabled": enabled, "enabled_known": enabledKnown, "spn_count": len(spns), "service_principal_names": spns, "ticket_material_collected": false})
		result = append(result, storage.FindingInput{FindingKey: stableSourceKey(assessmentID, "rusthound-kerberoastable", object.ID, map[string]any{"spn_count": len(spns)}), AssessmentID: assessmentID, SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "kerberoastable_account", Title: "Kerberoastable account: " + name, Description: "The directory export shows an enabled user account with one or more service principal names. This supports service-ticket eligibility; it does not prove a ticket was requested or cracked.", Severity: severity, Confidence: confidence, AffectedObjectID: object.ID, AffectedObject: name, EvidenceJSON: string(evidence), ArtifactPath: object.Artifact, ArtifactRef: object.RefPrefix + "/serviceprincipalnames", ObservedAt: now, Status: "open", ParserVersion: ParserVersion})
	}
	dontReq, dontReqKnown := rawBoolValue(props, "dontreqpreauth")
	if !dontReq && dontReqKnown {
		return result
	}
	if !dontReqKnown {
		if uac, ok := rawIntValue(props, "useraccountcontrol"); ok {
			dontReq = uac&0x400000 != 0
			dontReqKnown = true
		}
	}
	if dontReq {
		confidence := "observed-directory-properties"
		severity := "medium"
		if !enabledKnown {
			confidence = "configuration-enabled-unknown"
			severity = "informational"
		}
		evidence, _ := json.Marshal(map[string]any{"account_id": object.ID, "account_name": name, "dontreqpreauth": true, "enabled": enabled, "enabled_known": enabledKnown, "material_collected": false})
		result = append(result, storage.FindingInput{FindingKey: stableSourceKey(assessmentID, "rusthound-asrep", object.ID, "dontreqpreauth"), AssessmentID: assessmentID, SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "asrep_roastable_account", Title: "AS-REP roastable account: " + name, Description: "The directory export indicates Kerberos preauthentication is disabled for this user. This identifies a configuration exposure; no AS-REP material was requested by this parser.", Severity: severity, Confidence: confidence, AffectedObjectID: object.ID, AffectedObject: name, EvidenceJSON: string(evidence), ArtifactPath: object.Artifact, ArtifactRef: object.RefPrefix + "/dontreqpreauth", ObservedAt: now, Status: "open", ParserVersion: ParserVersion})
	}
	return result
}

func delegationFindings(object collectedObject, assessmentID, executionID int64, now time.Time) []storage.FindingInput {
	if object.Artifact == "" {
		return nil
	}
	result := make([]storage.FindingInput, 0, 2)
	if unconstrained, known := rawBoolValue(object.Properties, "unconstraineddelegation"); known && unconstrained {
		evidence, _ := json.Marshal(delegationEvidence(object, "unconstrained", map[string]any{"direct_property": true}))
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "rusthound-unconstrained-delegation", object.ID, "unconstrained"), AssessmentID: assessmentID,
			SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "unconstrained_delegation_configured",
			Title: "Unconstrained delegation configured: " + objectLabel(object), Description: "RustHound directly reports unconstrained delegation on this directory object. Review whether the configuration is expected; this observation does not prove credential capture or abuse.",
			Severity: "medium", Confidence: "observed-directory-property", AffectedObjectID: object.ID, AffectedObject: object.Name,
			EvidenceJSON: string(evidence), ArtifactPath: object.Artifact, ArtifactRef: object.RefPrefix + "/unconstraineddelegation", ObservedAt: now, Status: "open", ParserVersion: ParserVersion,
		})
	}
	trusted, trustedKnown := rawBoolValue(object.Properties, "trustedtoauth")
	services := rawStringSlice(object.Properties, "allowedtodelegate")
	if (trustedKnown && trusted) || len(services) > 0 {
		evidence, _ := json.Marshal(delegationEvidence(object, "constrained", map[string]any{"trusted_to_auth": trusted, "trusted_to_auth_known": trustedKnown, "allowed_to_delegate": services}))
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "rusthound-constrained-delegation", object.ID, services), AssessmentID: assessmentID,
			SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "constrained_delegation_configured",
			Title: "Constrained delegation configured: " + objectLabel(object), Description: "RustHound directly reports constrained delegation properties for this object. Review the explicitly listed services and trust boundary; exploitability and ticket abuse are not inferred.",
			Severity: "informational", Confidence: "observed-directory-property", AffectedObjectID: object.ID, AffectedObject: object.Name,
			EvidenceJSON: string(evidence), ArtifactPath: object.Artifact, ArtifactRef: object.RefPrefix + "/allowedtodelegate", ObservedAt: now, Status: "open", ParserVersion: ParserVersion,
		})
	}
	return result
}

func delegationEvidence(object collectedObject, delegationType string, extra map[string]any) map[string]any {
	objectType := object.Type
	if strings.EqualFold(objectType, "users") {
		objectType = "User"
	} else if strings.EqualFold(objectType, "computers") {
		objectType = "Computer"
	}
	evidence := map[string]any{"object_id": object.ID, "object_name": object.Name, "delegation_type": delegationType, "object_type": objectType}
	for _, field := range []struct{ output, source string }{{"domain", "domain"}, {"distinguishedname", "distinguishedname"}, {"useraccountcontrol", "useraccountcontrol"}, {"enabled", "enabled"}, {"serviceprincipalnames", "serviceprincipalnames"}} {
		if raw, ok := object.Properties[field.source]; ok {
			var value any
			if json.Unmarshal(raw, &value) == nil {
				evidence[field.output] = value
			}
		}
	}
	for key, value := range extra {
		evidence[key] = value
	}
	return evidence
}

func rawBoolValue(fields map[string]json.RawMessage, key string) (bool, bool) {
	for candidate, raw := range fields {
		if strings.EqualFold(candidate, key) {
			var value bool
			if json.Unmarshal(raw, &value) == nil {
				return value, true
			}
			var text string
			if json.Unmarshal(raw, &text) == nil {
				parsed := strings.EqualFold(text, "true") || text == "1"
				return parsed, true
			}
		}
	}
	return false, false
}
func rawIntValue(fields map[string]json.RawMessage, key string) (int64, bool) {
	for candidate, raw := range fields {
		if strings.EqualFold(candidate, key) {
			var value int64
			if json.Unmarshal(raw, &value) == nil {
				return value, true
			}
			var text string
			if json.Unmarshal(raw, &text) == nil {
				parsed, err := strconv.ParseInt(text, 0, 64)
				return parsed, err == nil
			}
		}
	}
	return 0, false
}
func rawStringSlice(fields map[string]json.RawMessage, key string) []string {
	for candidate, raw := range fields {
		if strings.EqualFold(candidate, key) {
			var values []string
			if json.Unmarshal(raw, &values) == nil {
				return values
			}
			var value string
			if json.Unmarshal(raw, &value) == nil && value != "" {
				return []string{value}
			}
		}
	}
	return nil
}
