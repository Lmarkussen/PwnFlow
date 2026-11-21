package findings

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// tier0ControlRights are the ACE rights that give control of the object they
// are granted on.
var tier0ControlRights = map[string]bool{
	"genericall": true, "genericwrite": true, "writedacl": true, "writeowner": true, "owns": true,
	"allextendedrights": true, "forcechangepassword": true, "addmember": true, "addmembers": true,
	"addself": true, "addkeycredentiallink": true, "writespn": true, "writeaccountrestrictions": true,
	"addallowedtoact": true, "getchangesall": true,
}

// shadowAdminFindings reports principals outside the privileged groups that
// hold a control right over a Tier 0 object: a privileged group, a member of
// one, a domain controller, the domain object, or AdminSDHolder (whose ACL is
// stamped onto every protected account). Such a principal is an
// administrator in effect without appearing in any admin group.
func shadowAdminFindings(objects map[string]collectedObject, aces []collectedACE, privileged map[string][]string, assessmentID, executionID int64, now time.Time) []storage.FindingInput {
	privilegedGroupRIDs := map[string]bool{"512": true, "516": true, "518": true, "519": true, "521": true, "544": true, "548": true, "549": true, "551": true}
	tier0Reason := func(object collectedObject) string {
		rid := object.ID[strings.LastIndexByte(object.ID, '-')+1:]
		switch {
		case strings.EqualFold(object.Type, "domains"):
			return "domain object"
		case strings.EqualFold(object.Type, "groups") && privilegedGroupRIDs[rid]:
			return "privileged group"
		case strings.EqualFold(object.Type, "groups") && len(privileged[object.ID]) > 0:
			return "group nested in a privileged group"
		case strings.EqualFold(object.Type, "containers") && strings.HasPrefix(strings.ToUpper(object.Name), "ADMINSDHOLDER@"):
			return "AdminSDHolder"
		case strings.EqualFold(object.Type, "computers"):
			if isDC, _ := rawBoolValue(object.Properties, "isdc"); isDC {
				return "domain controller"
			}
		case strings.EqualFold(object.Type, "users") && len(privileged[object.ID]) > 0:
			return "privileged account"
		}
		return ""
	}
	type grant struct {
		principal, principalID, right, target, targetReason, inheritance string
	}
	perDomain := map[string][]grant{}
	firstObject := map[string]collectedObject{}
	seen := map[string]bool{}
	for _, ace := range aces {
		right := normalize(aceString(ace.ACE, "RightName"))
		if !tier0ControlRights[right] || strings.EqualFold(aceDecision(ace.ACE), "deny") {
			continue
		}
		reason := tier0Reason(ace.Object)
		if reason == "" {
			continue
		}
		if right == "getchangesall" && reason != "domain object" {
			continue
		}
		principalID := aceString(ace.ACE, "PrincipalSID")
		if principalID == "" || principalID == ace.Object.ID || classifyReader(principalID) == readerPrivileged || len(privileged[principalID]) > 0 || builtinNonPrincipal(principalID) {
			continue
		}
		principal, resolved := objects[principalID]
		// Only a principal in the collection can be shown to be outside the
		// privileged groups; an unresolved one might be a member. Well-known
		// broad principals need no resolution.
		if !resolved && classifyReader(principalID) != readerBroad {
			continue
		}
		if isDC, _ := rawBoolValue(principal.Properties, "isdc"); isDC {
			continue
		}
		name := fallbackString(principal.Name, wellKnownReaderName(principalID))
		key := principalID + "\x00" + ace.Object.ID + "\x00" + right
		if seen[key] {
			continue
		}
		seen[key] = true
		domain := strings.ToUpper(fallbackString(firstString(ace.Object.Properties, "domain"), firstString(principal.Properties, "domain")))
		if _, ok := firstObject[domain]; !ok {
			firstObject[domain] = ace.Object
		}
		perDomain[domain] = append(perDomain[domain], grant{name, principalID, aceString(ace.ACE, "RightName"), objectLabel(ace.Object), reason, aceInheritance(ace.ACE)})
	}
	domains := make([]string, 0, len(perDomain))
	for domain := range perDomain {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	var result []storage.FindingInput
	for _, domain := range domains {
		grants := perDomain[domain]
		sort.Slice(grants, func(i, j int) bool {
			if grants[i].principal != grants[j].principal {
				return grants[i].principal < grants[j].principal
			}
			return grants[i].target+grants[i].right < grants[j].target+grants[j].right
		})
		principals := map[string]bool{}
		broad := false
		var affected []string
		var records []map[string]any
		for _, g := range grants {
			principals[g.principalID] = true
			broad = broad || classifyReader(g.principalID) == readerBroad
			if len(affected) < maxHygieneObjects {
				affected = append(affected, fmt.Sprintf("%s → %s on %s (%s)", g.principal, g.right, g.target, g.targetReason))
				records = append(records, map[string]any{"principal": g.principal, "principal_id": g.principalID, "right": g.right, "target": g.target, "target_class": g.targetReason, "inheritance": g.inheritance})
			}
		}
		severity := "high"
		description := fmt.Sprintf("%d principal(s) outside the privileged groups hold control rights over Tier 0 objects. Each can take over the object it controls - add itself to an admin group, reset an admin's password, rewrite the domain or AdminSDHolder ACL - and is an administrator in effect. Nested membership was expanded for the privileged groups; effective rights were not verified.", len(principals))
		if broad {
			description = "A broad principal such as Authenticated Users or Domain Users holds a control right over a Tier 0 object, so practically any account in the domain can take it over. " + description
		}
		encoded, _ := json.Marshal(map[string]any{"domain": domain, "account": fmt.Sprintf("%d principal(s)", len(principals)), "flag": "control right over Tier 0", "affected_objects": affected, "grants": records, "grant_count": len(grants), "grants_omitted": max(0, len(grants)-maxHygieneObjects)})
		object := firstObject[domain]
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "rusthound-shadow-admins", domain, "tier0"), AssessmentID: assessmentID,
			SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "ad_shadow_admin_rights",
			Title:       fmt.Sprintf("Non-privileged principals with control over Tier 0 (%s)", domain),
			Description: description, Severity: severity, Confidence: "observed-directory-acl", AffectedObjectID: domain, AffectedObject: domain,
			EvidenceJSON: string(encoded), ArtifactPath: object.Artifact, ArtifactRef: object.RefPrefix, ObservedAt: now, Status: "open", ParserVersion: hygieneParserVersion,
		})
	}
	return result
}

// builtinNonPrincipal names SIDs that appear in ACLs but are not principals
// an attacker can be: CREATOR OWNER, SELF and the like.
func builtinNonPrincipal(sid string) bool {
	switch strings.ToUpper(coreSID(sid)) {
	case "S-1-3-0", "S-1-3-1", "S-1-5-10", "S-1-5-32-560", "S-1-5-32-561":
		return true
	}
	return false
}
