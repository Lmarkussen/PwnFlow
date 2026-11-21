package findings

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// gpoControlRights are the ACE rights on a GPO that let a principal change
// the policy it delivers.
var gpoControlRights = map[string]bool{
	"genericall": true, "genericwrite": true, "writedacl": true, "writeowner": true, "owns": true,
}

// gpoScope is what one GPO applies to, from the containers that link it.
type gpoScope struct {
	containers []string
	domainWide bool
	tier0      []string // why the scope holds Tier 0 objects
	computers  int
}

// gpoControlFindings reports principals outside the privileged groups that
// can edit a linked GPO, or link GPOs to a container, whose scope holds Tier 0
// objects or computers. Editing a GPO runs code as SYSTEM on every computer
// it applies to (or as each user it applies to), so control of a GPO that
// reaches a domain controller or a privileged account is control of the
// domain. Link state, security filtering and WMI filters were not evaluated.
func gpoControlFindings(objects map[string]collectedObject, aces []collectedACE, privileged map[string][]string, assessmentID, executionID int64, now time.Time) []storage.FindingInput {
	children := map[string][]string{}
	links := map[string][]string{} // GPO ID -> container IDs
	for id, object := range objects {
		kind := strings.ToLower(object.Type)
		if kind != "ous" && kind != "domains" {
			continue
		}
		var childList []struct {
			ObjectIdentifier string `json:"ObjectIdentifier"`
		}
		_ = json.Unmarshal(object.Top["ChildObjects"], &childList)
		for _, child := range childList {
			children[id] = append(children[id], child.ObjectIdentifier)
		}
		var linkList []struct {
			GUID string `json:"GUID"`
		}
		_ = json.Unmarshal(object.Top["Links"], &linkList)
		for _, link := range linkList {
			links[strings.ToUpper(link.GUID)] = append(links[strings.ToUpper(link.GUID)], id)
		}
	}
	tier0Object := func(id string) string {
		object, ok := objects[id]
		if !ok {
			return ""
		}
		if isDC, _ := rawBoolValue(object.Properties, "isdc"); isDC && strings.EqualFold(object.Type, "computers") {
			return "domain controller " + objectLabel(object)
		}
		if len(privileged[id]) > 0 && (strings.EqualFold(object.Type, "users") || strings.EqualFold(object.Type, "groups")) {
			return "privileged account " + objectLabel(object)
		}
		return ""
	}
	// containerScope walks the subtree below a container.
	containerScope := func(root string) (tier0 []string, computers int) {
		seen := map[string]bool{}
		queue := []string{root}
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]
			if seen[id] {
				continue
			}
			seen[id] = true
			if reason := tier0Object(id); reason != "" && len(tier0) < 3 {
				tier0 = append(tier0, reason)
			}
			if strings.EqualFold(objects[id].Type, "computers") {
				computers++
			}
			queue = append(queue, children[id]...)
		}
		return tier0, computers
	}
	scopes := map[string]*gpoScope{}
	scopeOf := func(gpo string) *gpoScope {
		if scope, ok := scopes[gpo]; ok {
			return scope
		}
		scope := &gpoScope{}
		for _, container := range links[gpo] {
			object := objects[container]
			scope.containers = append(scope.containers, objectLabel(object))
			if strings.EqualFold(object.Type, "domains") {
				scope.domainWide = true
				scope.tier0 = append(scope.tier0, "linked to the domain root")
			}
			tier0, computers := containerScope(container)
			scope.tier0 = append(scope.tier0, tier0...)
			scope.computers += computers
		}
		scope.tier0 = uniqueStrings(scope.tier0)
		sort.Strings(scope.containers)
		scopes[gpo] = scope
		return scope
	}
	type grant struct {
		principal, principalID, right, target, scope string
		tier0                                        bool
		computers                                    int
	}
	perDomain := map[string][]grant{}
	firstObject := map[string]collectedObject{}
	seen := map[string]bool{}
	for _, ace := range aces {
		right := normalize(aceString(ace.ACE, "RightName"))
		kind := strings.ToLower(ace.Object.Type)
		if strings.EqualFold(aceDecision(ace.ACE), "deny") {
			continue
		}
		var scope *gpoScope
		var target string
		switch {
		case kind == "gpos" && gpoControlRights[right]:
			scope = scopeOf(strings.ToUpper(ace.Object.ID))
			if len(scope.containers) == 0 {
				continue // an unlinked GPO applies to nothing
			}
			target = fmt.Sprintf("GPO %s (linked to %s)", objectLabel(ace.Object), strings.Join(scope.containers, ", "))
		case (kind == "ous" || kind == "domains") && right == "writegplink":
			tier0, computers := containerScope(ace.Object.ID)
			if kind == "domains" {
				tier0 = append([]string{"the domain root"}, tier0...)
			}
			scope = &gpoScope{tier0: tier0, computers: computers, domainWide: kind == "domains"}
			target = "links on " + objectLabel(ace.Object)
		default:
			continue
		}
		if len(scope.tier0) == 0 && scope.computers == 0 {
			continue
		}
		principalID := aceString(ace.ACE, "PrincipalSID")
		if principalID == "" || classifyReader(principalID) == readerPrivileged || len(privileged[principalID]) > 0 || builtinNonPrincipal(principalID) {
			continue
		}
		principal, resolved := objects[principalID]
		if !resolved && classifyReader(principalID) != readerBroad {
			continue
		}
		if isDC, _ := rawBoolValue(principal.Properties, "isdc"); isDC {
			continue
		}
		key := principalID + "\x00" + ace.Object.ID + "\x00" + right
		if seen[key] {
			continue
		}
		seen[key] = true
		reach := fmt.Sprintf("%d computer(s)", scope.computers)
		if len(scope.tier0) > 0 {
			reach = "Tier 0: " + strings.Join(scope.tier0, "; ")
		}
		domain := strings.ToUpper(fallbackString(firstString(ace.Object.Properties, "domain"), firstString(principal.Properties, "domain")))
		if _, ok := firstObject[domain]; !ok {
			firstObject[domain] = ace.Object
		}
		perDomain[domain] = append(perDomain[domain], grant{fallbackString(principal.Name, wellKnownReaderName(principalID)), principalID, aceString(ace.ACE, "RightName"), target, reach, len(scope.tier0) > 0, scope.computers})
	}
	domains := make([]string, 0, len(perDomain))
	for domain := range perDomain {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	var result []storage.FindingInput
	for _, domain := range domains {
		grants := perDomain[domain]
		sort.SliceStable(grants, func(i, j int) bool {
			if grants[i].tier0 != grants[j].tier0 {
				return grants[i].tier0
			}
			return grants[i].principal+grants[i].target < grants[j].principal+grants[j].target
		})
		tier0, broad := false, false
		var affected []string
		var records []map[string]any
		for _, g := range grants {
			tier0 = tier0 || g.tier0
			broad = broad || classifyReader(g.principalID) == readerBroad
			if len(affected) < maxHygieneObjects {
				affected = append(affected, fmt.Sprintf("%s → %s on %s; applies to %s", g.principal, g.right, g.target, g.scope))
				records = append(records, map[string]any{"principal": g.principal, "principal_id": g.principalID, "right": g.right, "target": g.target, "reach": g.scope, "tier0": g.tier0, "computers": g.computers})
			}
		}
		severity := "medium"
		description := fmt.Sprintf("%d grant(s) let principals outside the privileged groups change Group Policy that applies to computers. A GPO edit runs code as SYSTEM on every computer in its scope at the next policy refresh (or as each user it applies to).", len(grants))
		if tier0 {
			severity = "high"
			description = fmt.Sprintf("%d grant(s) let principals outside the privileged groups change Group Policy that reaches Tier 0 - the domain root, a domain controller or a privileged account. A GPO edit there runs code as SYSTEM on a domain controller or as a privileged user, which is control of the domain.", len(grants))
		}
		if broad {
			description = "A broad principal such as Authenticated Users or Domain Users is among them. " + description
		}
		description += " Link state, block-inheritance, security filtering and WMI filters were not evaluated; nested membership was expanded for the privileged groups only."
		encoded, _ := json.Marshal(map[string]any{"domain": domain, "account": fmt.Sprintf("%d grant(s)", len(grants)), "flag": "control of Group Policy", "affected_objects": affected, "grants": records, "grant_count": len(grants), "grants_omitted": max(0, len(grants)-maxHygieneObjects)})
		object := firstObject[domain]
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "rusthound-gpo-control", domain, ""), AssessmentID: assessmentID,
			SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "ad_gpo_control_by_non_admin",
			Title:       fmt.Sprintf("Non-privileged principals can change Group Policy (%s)", domain),
			Description: description, Severity: severity, Confidence: "observed-directory-acl", AffectedObjectID: domain, AffectedObject: domain,
			EvidenceJSON: string(encoded), ArtifactPath: object.Artifact, ArtifactRef: object.RefPrefix, ObservedAt: now, Status: "open", ParserVersion: hygieneParserVersion,
		})
	}
	return result
}
