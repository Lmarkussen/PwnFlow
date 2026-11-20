package findings

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// Account and domain hygiene detectors over a finished RustHound collection.
//
// Every detector reads properties RustHound already exported; nothing here
// contacts the directory. A property that is absent from the export is treated
// as unknown and never as a negative or positive observation, so an older
// collector that does not emit a field produces no Finding for it.

const (
	hygieneParserVersion = "rusthound-hygiene-v1"

	// staleLogonAge is the inactivity window for enabled accounts. The
	// lastLogonTimestamp attribute replicates lazily (up to about 14 days
	// behind), so the window is deliberately wide.
	staleLogonAge = 90 * 24 * time.Hour
	// krbtgtReviewAge and krbtgtHighAge bracket the krbtgt password age.
	krbtgtReviewAge = 180 * 24 * time.Hour
	krbtgtHighAge   = 365 * 24 * time.Hour
	// maxHygieneObjects bounds the object list stored in one grouped Finding.
	maxHygieneObjects = 1000
)

// privilegedRIDs are the well-known relative identifiers whose presence in
// sIDHistory grants the same token membership as the group itself.
var privilegedRIDs = map[string]string{
	"500": "Administrator", "502": "krbtgt", "512": "Domain Admins", "516": "Domain Controllers",
	"518": "Schema Admins", "519": "Enterprise Admins", "520": "Group Policy Creator Owners",
	"521": "Read-only Domain Controllers", "544": "Administrators", "548": "Account Operators",
	"549": "Server Operators", "550": "Print Operators", "551": "Backup Operators",
}

// Trust attribute bits, as defined for trustAttributes in [MS-ADTS].
const (
	trustNonTransitive       = 0x00000001
	trustQuarantinedDomain   = 0x00000004
	trustForestTransitive    = 0x00000008
	trustCrossOrganization   = 0x00000010
	trustWithinForest        = 0x00000020
	trustTreatAsExternal     = 0x00000040
	trustUsesRC4             = 0x00000080
	trustEnableTGTDelegation = 0x00000800
)

type hygieneContext struct {
	assessmentID, executionID int64
	now                       time.Time
	reference                 time.Time
	referenceSource           string
}

type hygieneEntry struct {
	object collectedObject
	detail map[string]any
}

func hygieneFindings(objects map[string]collectedObject, assessmentID, executionID int64, now, collectedAt time.Time) []storage.FindingInput {
	ctx := hygieneContext{assessmentID: assessmentID, executionID: executionID, now: now, reference: collectedAt, referenceSource: "collection file modification time"}
	if ctx.reference.IsZero() || ctx.reference.After(now) {
		ctx.reference, ctx.referenceSource = now, "analysis time"
	}

	ids := make([]string, 0, len(objects))
	for id := range objects {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	protectedUsers := map[string]bool{}
	for _, id := range ids {
		object := objects[id]
		if strings.EqualFold(object.Type, "groups") && strings.HasSuffix(object.ID, "-525") {
			for _, member := range groupMemberIDs(object) {
				protectedUsers[member] = true
			}
		}
	}

	var result []storage.FindingInput
	grouped := map[string]map[string][]hygieneEntry{} // detector -> domain -> entries
	add := func(detector string, object collectedObject, detail map[string]any) {
		domain := strings.ToUpper(firstString(object.Properties, "domain"))
		if grouped[detector] == nil {
			grouped[detector] = map[string][]hygieneEntry{}
		}
		grouped[detector][domain] = append(grouped[detector][domain], hygieneEntry{object: object, detail: detail})
	}

	for _, id := range ids {
		object := objects[id]
		props := object.Properties
		switch strings.ToLower(object.Type) {
		case "users":
			enabled, enabledKnown := rawBoolValue(props, "enabled")
			if history := rawStringSlice(props, "sidhistory"); len(history) > 0 {
				result = append(result, sidHistoryFinding(ctx, object, history))
			}
			if attributes := populatedPasswordAttributes(props); len(attributes) > 0 {
				result = append(result, passwordAttributeFinding(ctx, object, attributes, enabled, enabledKnown))
			}
			if value, known := rawBoolValue(props, "passwordnotreqd"); known && value && enabledKnown && !isKRBTGT(object) {
				result = append(result, passwordNotRequiredFinding(ctx, object, enabled))
			}
			if isKRBTGT(object) {
				if finding, ok := krbtgtAgeFinding(ctx, object); ok {
					result = append(result, finding)
				}
				continue
			}
			if !enabledKnown || !enabled {
				continue
			}
			if value, known := rawBoolValue(props, "encryptedtextpwdallowed"); known && value {
				result = append(result, accountFlagFinding(ctx, object, "reversible_encryption", "Reversible password encryption allowed: ", "ENCRYPTED_TEXT_PWD_ALLOWED",
					"The account's userAccountControl allows the password to be stored with reversible encryption. A password set while the flag is present is recoverable by anyone who can read the domain secrets. Whether a reversibly stored password currently exists was not verified.", "medium"))
			}
			if value, known := rawBoolValue(props, "usedeskeyonly"); known && value {
				result = append(result, accountFlagFinding(ctx, object, "des_only", "DES-only Kerberos encryption: ", "USE_DES_KEY_ONLY",
					"The account's userAccountControl restricts Kerberos to DES encryption types. DES is cryptographically broken and disabled by default on supported Windows versions; authentication may fail or fall back. Ticket requests were not made.", "low"))
			}
			if value, known := rawBoolValue(props, "pwdneverexpires"); known && value {
				add("pwd_never_expires", object, map[string]any{"admincount": rawBool(props, "admincount")})
			}
			if rawBool(props, "admincount") {
				sensitive, sensitiveKnown := rawBoolValue(props, "sensitive")
				if sensitiveKnown && !sensitive && !protectedUsers[object.ID] {
					add("privileged_not_protected", object, nil)
				}
			}
			if detail, stale := staleLogon(ctx, props); stale {
				add("stale_enabled_users", object, detail)
			}
		case "computers":
			if history := rawStringSlice(props, "sidhistory"); len(history) > 0 {
				result = append(result, sidHistoryFinding(ctx, object, history))
			}
			enabled, enabledKnown := rawBoolValue(props, "enabled")
			if !enabledKnown || !enabled {
				continue
			}
			if detail, stale := staleLogon(ctx, props); stale {
				add("stale_enabled_computers", object, detail)
			}
			isDC, _ := rawBoolValue(props, "isdc")
			if hasLAPS, known := rawBoolValue(props, "haslaps"); known && !hasLAPS && !isDC && isWindowsOrUnknownOS(props) {
				add("laps_not_observed", object, map[string]any{"operatingsystem": firstString(props, "operatingsystem")})
			}
		case "groups":
			if history := rawStringSlice(props, "sidhistory"); len(history) > 0 {
				result = append(result, sidHistoryFinding(ctx, object, history))
			}
		case "domains":
			result = append(result, domainConfigurationFindings(ctx, object)...)
			result = append(result, trustFindings(ctx, object)...)
		}
	}

	detectors := make([]string, 0, len(grouped))
	for detector := range grouped {
		detectors = append(detectors, detector)
	}
	sort.Strings(detectors)
	for _, detector := range detectors {
		domains := make([]string, 0, len(grouped[detector]))
		for domain := range grouped[detector] {
			domains = append(domains, domain)
		}
		sort.Strings(domains)
		for _, domain := range domains {
			result = append(result, groupedHygieneFinding(ctx, detector, domain, grouped[detector][domain]))
		}
	}
	return result
}

type groupedDefinition struct {
	findingType, title, condition, description, severity, noun string
}

var groupedDefinitions = map[string]groupedDefinition{
	"pwd_never_expires": {
		findingType: "ad_account_pwd_never_expires", title: "Enabled users with non-expiring passwords", noun: "enabled user(s)",
		condition:   "DONT_EXPIRE_PASSWORD",
		description: "RustHound reports the DONT_EXPIRE_PASSWORD flag on enabled user accounts. Their passwords are exempt from the domain maximum password age, so a disclosed or weak password stays valid indefinitely. Password strength and actual age were not assessed.",
		severity:    "low",
	},
	"privileged_not_protected": {
		findingType: "ad_account_privileged_not_protected", title: "Privileged users without delegation protection", noun: "enabled adminCount user(s)",
		condition:   "adminCount=1 without NOT_DELEGATED or direct Protected Users membership",
		description: "Enabled accounts marked adminCount=1 are neither flagged 'Account is sensitive and cannot be delegated' nor direct members of Protected Users. Their credentials can be delegated to any host trusted for delegation. adminCount can be stale after an account leaves a protected group, and nested Protected Users membership was not expanded.",
		severity:    "low",
	},
	"stale_enabled_users": {
		findingType: "ad_account_stale_enabled_users", title: "Stale enabled user accounts", noun: "enabled user(s)",
		condition:   "no logon recorded within 90 days",
		description: "Enabled user accounts show no lastLogonTimestamp within 90 days of collection, or have never logged on and were created more than 90 days earlier. Unused enabled accounts widen the attack surface. lastLogonTimestamp replicates lazily and does not record every authentication type.",
		severity:    "low",
	},
	"stale_enabled_computers": {
		findingType: "ad_account_stale_enabled_computers", title: "Stale enabled computer accounts", noun: "enabled computer(s)",
		condition:   "no logon recorded within 90 days",
		description: "Enabled computer accounts show no lastLogonTimestamp within 90 days of collection, or have never logged on and were created more than 90 days earlier. Such accounts usually belong to retired hosts. lastLogonTimestamp replicates lazily.",
		severity:    "low",
	},
	"laps_not_observed": {
		findingType: "ad_account_laps_not_observed", title: "Computers without observed LAPS", noun: "enabled non-DC computer(s)",
		condition:   "no LAPS expiration attribute observed",
		description: "RustHound found no Windows LAPS or legacy LAPS password-expiration attribute on these enabled, non-domain-controller computers. Without LAPS, local administrator passwords are commonly shared between hosts. An expiration attribute that the collecting account cannot read is indistinguishable from an absent one.",
		severity:    "medium",
	},
}

func groupedHygieneFinding(ctx hygieneContext, detector, domain string, entries []hygieneEntry) storage.FindingInput {
	definition := groupedDefinitions[detector]
	sort.Slice(entries, func(i, j int) bool { return objectLabel(entries[i].object) < objectLabel(entries[j].object) })
	names := make([]string, 0, min(len(entries), maxHygieneObjects))
	objects := make([]map[string]any, 0, min(len(entries), maxHygieneObjects))
	privileged := 0
	for index, entry := range entries {
		if admin, ok := entry.detail["admincount"].(bool); ok && admin {
			privileged++
		}
		if index >= maxHygieneObjects {
			continue
		}
		names = append(names, objectLabel(entry.object))
		record := map[string]any{"object_id": entry.object.ID, "object_name": entry.object.Name}
		for key, value := range entry.detail {
			record[key] = value
		}
		objects = append(objects, record)
	}
	severity := definition.severity
	if detector == "pwd_never_expires" && privileged > 0 {
		severity = "medium"
	}
	scope := fmt.Sprintf("%d %s", len(entries), definition.noun)
	evidence := map[string]any{
		"domain": domain, "detector": detector, "account": scope, "flag": definition.condition, "enabled": true,
		"user_account_control": scope, "object_count": len(entries), "affected_objects": names, "objects": objects,
		"objects_omitted": max(0, len(entries)-maxHygieneObjects), "reference_time": ctx.reference.UTC().Format(time.RFC3339),
		"reference_source": ctx.referenceSource, "source_artifact": entries[0].object.Artifact,
	}
	if detector == "pwd_never_expires" {
		evidence["privileged_count"] = privileged
	}
	encoded, _ := json.Marshal(evidence)
	title := definition.title
	if domain != "" {
		title += " (" + domain + ")"
	}
	return storage.FindingInput{
		FindingKey: stableSourceKey(ctx.assessmentID, "rusthound-hygiene-"+detector, domain, "grouped"), AssessmentID: ctx.assessmentID,
		SourceTool: "RustHound-CE", SourceExecution: ctx.executionID, FindingType: definition.findingType,
		Title: title, Description: fmt.Sprintf("%s Affected: %s.", definition.description, scope),
		Severity: severity, Confidence: "observed-directory-properties", AffectedObjectID: domain, AffectedObject: domain,
		EvidenceJSON: string(encoded), ArtifactPath: entries[0].object.Artifact, ArtifactRef: entries[0].object.RefPrefix,
		ObservedAt: ctx.now, Status: "open", ParserVersion: hygieneParserVersion,
	}
}

func accountFlagFinding(ctx hygieneContext, object collectedObject, detector, titlePrefix, flag, description, severity string) storage.FindingInput {
	evidence, _ := json.Marshal(map[string]any{
		"account": objectLabel(object), "object_id": object.ID, "flag": flag, "enabled": true,
		"user_account_control": flagObservation(object.Properties, flag), "domain": strings.ToUpper(firstString(object.Properties, "domain")),
	})
	return storage.FindingInput{
		FindingKey: stableSourceKey(ctx.assessmentID, "rusthound-hygiene-"+detector, object.ID, flag), AssessmentID: ctx.assessmentID,
		SourceTool: "RustHound-CE", SourceExecution: ctx.executionID, FindingType: "ad_account_" + detector,
		Title: titlePrefix + objectLabel(object), Description: description, Severity: severity, Confidence: "observed-directory-property",
		AffectedObjectID: object.ID, AffectedObject: object.Name, EvidenceJSON: string(evidence), ArtifactPath: object.Artifact,
		ArtifactRef: object.RefPrefix + "/useraccountcontrol", ObservedAt: ctx.now, Status: "open", ParserVersion: hygieneParserVersion,
	}
}

// passwordNotRequiredFinding reports PASSWD_NOTREQD with the same Finding type
// the NetExec password-not-required query uses, so both sources land in the
// same Account Security view. A disabled account is informational.
func passwordNotRequiredFinding(ctx hygieneContext, object collectedObject, enabled bool) storage.FindingInput {
	severity := "medium"
	if !enabled {
		severity = "informational"
	}
	evidence, _ := json.Marshal(map[string]any{
		"account": objectLabel(object), "object_id": object.ID, "flag": "PASSWD_NOTREQD", "enabled": enabled, "account_class": "user",
		"user_account_control": flagObservation(object.Properties, "PASSWD_NOTREQD"), "domain": strings.ToUpper(firstString(object.Properties, "domain")),
	})
	return storage.FindingInput{
		FindingKey: stableSourceKey(ctx.assessmentID, "rusthound-hygiene-passwd-notreqd", object.ID, "PASSWD_NOTREQD"), AssessmentID: ctx.assessmentID,
		SourceTool: "RustHound-CE", SourceExecution: ctx.executionID, FindingType: "ad_account_passwd_notreqd",
		Title:       "Password Not Required Account: " + objectLabel(object),
		Description: "The account has the PASSWD_NOTREQD user-account-control flag, so a password policy does not stop it from having an empty password. This does not prove that the account has a blank password; no authentication was attempted.",
		Severity:    severity, Confidence: "observed-directory-property", AffectedObjectID: object.ID, AffectedObject: object.Name,
		EvidenceJSON: string(evidence), ArtifactPath: object.Artifact, ArtifactRef: object.RefPrefix + "/passwordnotreqd",
		ObservedAt: ctx.now, Status: "open", ParserVersion: hygieneParserVersion,
	}
}

func flagObservation(props map[string]json.RawMessage, flag string) string {
	if uac, ok := rawIntValue(props, "useraccountcontrol"); ok {
		return fmt.Sprintf("%s set (userAccountControl %d)", flag, uac)
	}
	return flag + " set"
}

func sidHistoryFinding(ctx hygieneContext, object collectedObject, history []string) storage.FindingInput {
	domainSID := firstString(object.Properties, "domainsid")
	entries := make([]map[string]any, 0, len(history))
	var privileged []string
	for _, sid := range history {
		entry := map[string]any{"sid": sid}
		if index := strings.LastIndexByte(sid, '-'); index > 0 {
			rid, prefix := sid[index+1:], sid[:index]
			sameDomain := domainSID != "" && strings.EqualFold(prefix, domainSID)
			entry["same_domain"] = sameDomain
			if name, ok := privilegedRIDs[rid]; ok && (sameDomain || prefix == "S-1-5-32") {
				entry["well_known_privileged"] = name
				privileged = append(privileged, name)
			}
		}
		entries = append(entries, entry)
	}
	severity, description := "medium", "The object carries sIDHistory values. Every SID in sIDHistory is added to the object's logon token, so the object is treated as each listed principal as well. sIDHistory is expected only during a domain migration; outside one it is a known persistence technique. Whether SID filtering strips the values at a trust boundary was not evaluated."
	if len(privileged) > 0 {
		severity = "high"
		description = "The object's sIDHistory contains a well-known privileged SID (" + strings.Join(privileged, ", ") + ") of its own domain. That SID is added to the object's logon token, granting the privileged group's rights. This is a known persistence technique and is not expected outside a supervised migration. Effective token construction was not verified."
	}
	evidence, _ := json.Marshal(map[string]any{
		"account": objectLabel(object), "object_id": object.ID, "object_type": object.Type, "flag": "sIDHistory populated",
		"user_account_control": fmt.Sprintf("%d sIDHistory value(s)", len(history)), "sid_history": entries, "domain_sid": domainSID,
		"domain": strings.ToUpper(firstString(object.Properties, "domain")),
	})
	return storage.FindingInput{
		FindingKey: stableSourceKey(ctx.assessmentID, "rusthound-hygiene-sid-history", object.ID, history), AssessmentID: ctx.assessmentID,
		SourceTool: "RustHound-CE", SourceExecution: ctx.executionID, FindingType: "ad_account_sid_history_present",
		Title: "sIDHistory present: " + objectLabel(object), Description: description, Severity: severity, Confidence: "observed-directory-property",
		AffectedObjectID: object.ID, AffectedObject: object.Name, EvidenceJSON: string(evidence), ArtifactPath: object.Artifact,
		ArtifactRef: object.RefPrefix + "/sidhistory", ObservedAt: ctx.now, Status: "open", ParserVersion: hygieneParserVersion,
	}
}

// populatedPasswordAttributes names the legacy password attributes RustHound
// exported with a value. Only the attribute names leave this function; the
// values themselves are never copied into a Finding.
func populatedPasswordAttributes(props map[string]json.RawMessage) []string {
	var names []string
	for _, attribute := range []string{"userpassword", "unixpassword", "unicodepassword", "sfupassword"} {
		if strings.TrimSpace(rawString(props, attribute)) != "" {
			names = append(names, attribute)
		}
	}
	return names
}

func passwordAttributeFinding(ctx hygieneContext, object collectedObject, attributes []string, enabled, enabledKnown bool) storage.FindingInput {
	severity := "medium"
	if enabledKnown && !enabled {
		severity = "low"
	}
	evidence := map[string]any{
		"account": objectLabel(object), "object_id": object.ID, "flag": "readable password attribute populated",
		"user_account_control": strings.Join(attributes, ", ") + " populated (value withheld)", "attributes": attributes,
		"value_recorded": false, "domain": strings.ToUpper(firstString(object.Properties, "domain")),
	}
	if enabledKnown {
		evidence["enabled"] = enabled
	}
	encoded, _ := json.Marshal(evidence)
	return storage.FindingInput{
		FindingKey: stableSourceKey(ctx.assessmentID, "rusthound-hygiene-password-attribute", object.ID, attributes), AssessmentID: ctx.assessmentID,
		SourceTool: "RustHound-CE", SourceExecution: ctx.executionID, FindingType: "ad_account_password_attribute_populated",
		Title:       "Password attribute populated: " + objectLabel(object),
		Description: "The collecting account could read a populated legacy password attribute (" + strings.Join(attributes, ", ") + ") on this user. These attributes often hold a plaintext or weakly encoded password. The value stays only in the original restricted artifact and was not tested for authentication.",
		Severity:    severity, Confidence: "observed-directory-property", AffectedObjectID: object.ID, AffectedObject: object.Name,
		EvidenceJSON: string(encoded), ArtifactPath: object.Artifact, ArtifactRef: object.RefPrefix + "/" + attributes[0],
		ObservedAt: ctx.now, Status: "open", ParserVersion: hygieneParserVersion,
	}
}

func isKRBTGT(object collectedObject) bool {
	if strings.HasSuffix(object.ID, "-502") {
		return true
	}
	return strings.EqualFold(firstString(object.Properties, "samaccountname"), "krbtgt")
}

func krbtgtAgeFinding(ctx hygieneContext, object collectedObject) (storage.FindingInput, bool) {
	lastSet, known := rawIntValue(object.Properties, "pwdlastset")
	if !known || lastSet <= 0 {
		return storage.FindingInput{}, false
	}
	setAt := time.Unix(lastSet, 0).UTC()
	age := ctx.reference.Sub(setAt)
	if age < krbtgtReviewAge {
		return storage.FindingInput{}, false
	}
	days := int(age.Hours() / 24)
	severity := "low"
	if age >= krbtgtHighAge {
		severity = "medium"
	}
	evidence, _ := json.Marshal(map[string]any{
		"account": objectLabel(object), "object_id": object.ID, "flag": "krbtgt password age",
		"user_account_control": fmt.Sprintf("password last set %s (%d days before reference time)", setAt.Format("2006-01-02"), days),
		"pwdlastset":           setAt.Format(time.RFC3339), "age_days": days, "reference_time": ctx.reference.UTC().Format(time.RFC3339),
		"reference_source": ctx.referenceSource, "domain": strings.ToUpper(firstString(object.Properties, "domain")),
	})
	return storage.FindingInput{
		FindingKey: stableSourceKey(ctx.assessmentID, "rusthound-hygiene-krbtgt-age", object.ID, "pwdlastset"), AssessmentID: ctx.assessmentID,
		SourceTool: "RustHound-CE", SourceExecution: ctx.executionID, FindingType: "ad_account_krbtgt_password_age",
		Title:       fmt.Sprintf("krbtgt password not rotated for %d days", days),
		Description: fmt.Sprintf("The krbtgt account password was last set %s, %d days before collection. Every Kerberos ticket in the domain is signed with this key, so a key obtained at any point since then still forges valid tickets. Microsoft recommends periodic rotation (commonly every 180 days) performed twice.", setAt.Format("2006-01-02"), days),
		Severity:    severity, Confidence: "observed-directory-property", AffectedObjectID: object.ID, AffectedObject: object.Name,
		EvidenceJSON: string(evidence), ArtifactPath: object.Artifact, ArtifactRef: object.RefPrefix + "/pwdlastset",
		ObservedAt: ctx.now, Status: "open", ParserVersion: hygieneParserVersion,
	}, true
}

// staleLogon reports whether an enabled account has no recent logon. An
// account without lastLogonTimestamp counts only once it is older than the
// window, so newly created accounts are not reported.
func staleLogon(ctx hygieneContext, props map[string]json.RawMessage) (map[string]any, bool) {
	lastLogon, logonKnown := rawIntValue(props, "lastlogontimestamp")
	if !logonKnown {
		return nil, false
	}
	if lastLogon > 0 {
		at := time.Unix(lastLogon, 0).UTC()
		if ctx.reference.Sub(at) < staleLogonAge {
			return nil, false
		}
		return map[string]any{"last_logon": at.Format("2006-01-02"), "days_since_logon": int(ctx.reference.Sub(at).Hours() / 24)}, true
	}
	created, createdKnown := rawIntValue(props, "whencreated")
	if !createdKnown || created <= 0 {
		return nil, false
	}
	createdAt := time.Unix(created, 0).UTC()
	if ctx.reference.Sub(createdAt) < staleLogonAge {
		return nil, false
	}
	return map[string]any{"last_logon": "never", "created": createdAt.Format("2006-01-02")}, true
}

func isWindowsOrUnknownOS(props map[string]json.RawMessage) bool {
	system := strings.TrimSpace(firstString(props, "operatingsystem"))
	return system == "" || strings.Contains(strings.ToLower(system), "windows")
}

func groupMemberIDs(object collectedObject) []string {
	var members []map[string]json.RawMessage
	if raw, ok := object.Top["Members"]; ok {
		_ = json.Unmarshal(raw, &members)
	}
	ids := make([]string, 0, len(members))
	for _, member := range members {
		if id := rawString(member, "ObjectIdentifier"); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func domainConfigurationFindings(ctx hygieneContext, object collectedObject) []storage.FindingInput {
	props := object.Properties
	domain := strings.ToUpper(fallbackString(firstString(props, "name"), firstString(props, "domain")))
	var result []storage.FindingInput
	if level := strings.TrimSpace(firstString(props, "functionallevel")); level != "" && !strings.EqualFold(level, "unknown") {
		severity, description := "informational", "RustHound reports the domain functional level as "+level+"."
		if functionalLevelBelow2012R2(level) {
			severity = "low"
			description += " Domain-controller-side Protected Users protections and authentication policies require Windows Server 2012 R2 or later; they are not available at this level."
		}
		evidence, _ := json.Marshal(map[string]any{"domain": domain, "functional_level": level})
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(ctx.assessmentID, "rusthound-domain-functional-level", object.ID, "functionallevel"), AssessmentID: ctx.assessmentID,
			SourceTool: "RustHound-CE", SourceExecution: ctx.executionID, FindingType: "ad_domain_config_functional_level",
			Title: "Domain functional level " + level + " (" + domain + ")", Description: description, Severity: severity,
			Confidence: "observed-directory-property", AffectedObjectID: object.ID, AffectedObject: domain, EvidenceJSON: string(evidence),
			ArtifactPath: object.Artifact, ArtifactRef: object.RefPrefix + "/functionallevel", ObservedAt: ctx.now, Status: "open", ParserVersion: hygieneParserVersion,
		})
	}
	// dSHeuristics character 7 (fLDAPBlockAnonOps) set to '2' lifts the block
	// on anonymous LDAP operations beyond the rootDSE.
	if heuristics := firstString(props, "dsheuristics"); len(heuristics) >= 7 && heuristics[6] == '2' {
		evidence, _ := json.Marshal(map[string]any{"domain": domain, "dsheuristics": heuristics, "character_7": "2"})
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(ctx.assessmentID, "rusthound-domain-anonymous-ldap", object.ID, heuristics), AssessmentID: ctx.assessmentID,
			SourceTool: "RustHound-CE", SourceExecution: ctx.executionID, FindingType: "ad_domain_config_anonymous_ldap_operations",
			Title:       "Anonymous LDAP operations enabled (" + domain + ")",
			Description: "The forest dSHeuristics value has its seventh character set to 2, which disables the block on anonymous LDAP operations. Unauthenticated clients may then read whatever the directory ACLs grant to Anonymous Logon. An anonymous bind was not attempted.",
			Severity:    "medium", Confidence: "observed-directory-property", AffectedObjectID: object.ID, AffectedObject: domain, EvidenceJSON: string(evidence),
			ArtifactPath: object.Artifact, ArtifactRef: object.RefPrefix + "/dsheuristics", ObservedAt: ctx.now, Status: "open", ParserVersion: hygieneParserVersion,
		})
	}
	return result
}

func functionalLevelBelow2012R2(level string) bool {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "2000 mixed/native", "2003 interim", "2003", "2008", "2008 r2", "2012":
		return true
	}
	return false
}

func fallbackString(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func trustFindings(ctx hygieneContext, object collectedObject) []storage.FindingInput {
	var trusts []map[string]json.RawMessage
	if raw, ok := object.Top["Trusts"]; ok {
		_ = json.Unmarshal(raw, &trusts)
	}
	domain := strings.ToUpper(fallbackString(firstString(object.Properties, "name"), firstString(object.Properties, "domain")))
	var result []storage.FindingInput
	for index, trust := range trusts {
		target := strings.ToUpper(rawString(trust, "TargetDomainName"))
		if target == "" {
			continue
		}
		attributes, attributesKnown := rawIntValue(trust, "TrustAttributes")
		direction := rawString(trust, "TrustDirection")
		trustType := rawString(trust, "TrustType")
		transitive, _ := rawBoolValue(trust, "IsTransitive")
		ref := fmt.Sprintf("%s/Trusts/%d", strings.TrimSuffix(object.RefPrefix, "/Properties"), index)
		evidence := map[string]any{
			"domain": domain, "target_domain": target, "target_domain_sid": rawString(trust, "TargetDomainSid"),
			"direction": direction, "trust_type": trustType, "transitive": transitive,
		}
		if attributesKnown {
			evidence["trust_attributes"] = attributes
			evidence["trust_attribute_flags"] = trustAttributeNames(attributes)
		}
		encoded, _ := json.Marshal(evidence)
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(ctx.assessmentID, "rusthound-trust", domain, target), AssessmentID: ctx.assessmentID,
			SourceTool: "RustHound-CE", SourceExecution: ctx.executionID, FindingType: "ad_trust_observed",
			Title:       fmt.Sprintf("Domain trust: %s → %s (%s, %s)", domain, target, fallbackString(trustType, "unknown type"), fallbackString(direction, "unknown direction")),
			Description: "RustHound exported this trust relationship from the domain object. A trust extends the set of principals that can authenticate to resources in the trusting domain.",
			Severity:    "informational", Confidence: "observed-directory-property", AffectedObjectID: object.ID, AffectedObject: domain,
			RelatedObject: target, EvidenceJSON: string(encoded), ArtifactPath: object.Artifact, ArtifactRef: ref,
			ObservedAt: ctx.now, Status: "open", ParserVersion: hygieneParserVersion,
		})
		if !attributesKnown {
			continue
		}
		// SID filtering is enforced by the trusting side, so it concerns this
		// domain only when it trusts the target (outbound or bidirectional).
		trusting := strings.EqualFold(direction, "Outbound") || strings.EqualFold(direction, "Bidirectional")
		if !trusting || attributes&trustWithinForest != 0 {
			continue
		}
		condition := ""
		switch {
		case attributes&trustForestTransitive != 0 && attributes&trustTreatAsExternal != 0:
			condition = "The forest trust has TREAT_AS_EXTERNAL set, which enables SID history across the trust: sIDHistory values from the trusted forest are accepted except for well-known privileged RIDs below 1000."
		case attributes&trustForestTransitive == 0 && attributes&trustQuarantinedDomain == 0:
			condition = "The external trust does not have QUARANTINED_DOMAIN set, so SID filtering is disabled: sIDHistory values presented by the trusted domain, including privileged SIDs of this domain, are accepted."
		}
		if condition != "" {
			result = append(result, storage.FindingInput{
				FindingKey: stableSourceKey(ctx.assessmentID, "rusthound-trust-sid-filtering", domain, target), AssessmentID: ctx.assessmentID,
				SourceTool: "RustHound-CE", SourceExecution: ctx.executionID, FindingType: "ad_trust_sid_filtering_relaxed",
				Title:       fmt.Sprintf("SID filtering relaxed on trust %s → %s", domain, target),
				Description: condition + " A compromise of the trusted domain can then extend into this one. The trust attributes were read from the directory; the trusted domain was not contacted.",
				Severity:    "medium", Confidence: "observed-trust-attributes", AffectedObjectID: object.ID, AffectedObject: domain,
				RelatedObject: target, EvidenceJSON: string(encoded), ArtifactPath: object.Artifact, ArtifactRef: ref,
				ObservedAt: ctx.now, Status: "open", ParserVersion: hygieneParserVersion,
			})
		}
		if attributes&trustEnableTGTDelegation != 0 {
			result = append(result, storage.FindingInput{
				FindingKey: stableSourceKey(ctx.assessmentID, "rusthound-trust-tgt-delegation", domain, target), AssessmentID: ctx.assessmentID,
				SourceTool: "RustHound-CE", SourceExecution: ctx.executionID, FindingType: "ad_trust_tgt_delegation_enabled",
				Title:       fmt.Sprintf("TGT delegation enabled on trust %s → %s", domain, target),
				Description: "The trust has CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION set, so ticket-granting tickets may be delegated across it to hosts with unconstrained delegation in the trusted domain. Microsoft disables this by default since 2019.",
				Severity:    "low", Confidence: "observed-trust-attributes", AffectedObjectID: object.ID, AffectedObject: domain,
				RelatedObject: target, EvidenceJSON: string(encoded), ArtifactPath: object.Artifact, ArtifactRef: ref,
				ObservedAt: ctx.now, Status: "open", ParserVersion: hygieneParserVersion,
			})
		}
	}
	return result
}

func trustAttributeNames(attributes int64) []string {
	var names []string
	for _, flag := range []struct {
		bit  int64
		name string
	}{
		{trustNonTransitive, "NON_TRANSITIVE"}, {trustQuarantinedDomain, "QUARANTINED_DOMAIN"}, {trustForestTransitive, "FOREST_TRANSITIVE"},
		{trustCrossOrganization, "CROSS_ORGANIZATION"}, {trustWithinForest, "WITHIN_FOREST"}, {trustTreatAsExternal, "TREAT_AS_EXTERNAL"},
		{trustUsesRC4, "USES_RC4_ENCRYPTION"}, {trustEnableTGTDelegation, "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"},
	} {
		if attributes&flag.bit != 0 {
			names = append(names, flag.name)
		}
	}
	return names
}
