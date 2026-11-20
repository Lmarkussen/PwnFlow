package findings

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// Reader classes for principals that hold a password-read right.
const (
	readerPrivileged = "privileged" // administrators and domain controllers by design
	readerBroad      = "broad"      // every user, computer or authenticated session
	readerDelegated  = "delegated"  // any other principal: an explicit delegation
)

// maxReaderTargets bounds the computers listed per LAPS reader.
const maxReaderTargets = 50

// broadReaderSIDs and broadReaderRIDs name principals that include ordinary
// users or computers; a password-read right granted to them is readable by
// practically anyone in the domain.
var (
	broadReaderSIDs = map[string]string{
		"S-1-1-0": "Everyone", "S-1-5-7": "Anonymous Logon", "S-1-5-11": "Authenticated Users",
		"S-1-5-32-545": "Users", "S-1-5-32-546": "Guests",
	}
	broadReaderRIDs        = map[string]string{"513": "Domain Users", "514": "Domain Guests", "515": "Domain Computers"}
	privilegedReaderSIDs   = map[string]bool{"S-1-5-18": true, "S-1-5-9": true, "S-1-5-32-544": true, "S-1-5-32-548": true, "S-1-5-32-549": true, "S-1-5-32-551": true}
	privilegedReaderRIDs   = map[string]bool{"498": true, "512": true, "516": true, "518": true, "519": true, "521": true, "526": true, "527": true}
	passwordReaderRightKey = map[string]string{"readlapspassword": "laps", "readgmsapassword": "gmsa"}
)

type passwordReader struct {
	ID, Name, Type, Class, Inheritance string
}

// classifyReader places a principal SID in one of the reader classes.
// RustHound prefixes well-known SIDs with the domain name, so the SID is
// read from its "S-1-" part.
func classifyReader(sid string) string {
	if index := strings.Index(strings.ToUpper(sid), "S-1-"); index >= 0 {
		sid = strings.ToUpper(sid[index:])
	}
	if _, ok := broadReaderSIDs[sid]; ok {
		return readerBroad
	}
	if privilegedReaderSIDs[sid] {
		return readerPrivileged
	}
	if strings.HasPrefix(sid, "S-1-5-21-") {
		rid := sid[strings.LastIndexByte(sid, '-')+1:]
		if _, ok := broadReaderRIDs[rid]; ok {
			return readerBroad
		}
		if privilegedReaderRIDs[rid] || rid == "500" {
			return readerPrivileged
		}
	}
	return readerDelegated
}

// passwordReaderFindings reports who can read LAPS and gMSA passwords from
// the ReadLAPSPassword and ReadGMSAPassword relationships RustHound exports.
// Nothing is read from the directory: the Findings name the principals that
// hold the right, not any password.
func passwordReaderFindings(objects map[string]collectedObject, aces []collectedACE, assessmentID, executionID int64, now time.Time) []storage.FindingInput {
	type targetReaders struct {
		object  collectedObject
		readers map[string]passwordReader
	}
	byKind := map[string]map[string]*targetReaders{"laps": {}, "gmsa": {}}
	for _, ace := range aces {
		kind, ok := passwordReaderRightKey[normalize(aceString(ace.ACE, "RightName"))]
		if !ok || ace.Object.ID == "" || strings.EqualFold(aceDecision(ace.ACE), "deny") {
			continue
		}
		principalID := aceString(ace.ACE, "PrincipalSID")
		if principalID == "" {
			continue
		}
		entry := byKind[kind][ace.Object.ID]
		if entry == nil {
			entry = &targetReaders{object: ace.Object, readers: map[string]passwordReader{}}
			byKind[kind][ace.Object.ID] = entry
		}
		name := objects[principalID].Name
		if name == "" {
			name = wellKnownReaderName(principalID)
		}
		entry.readers[principalID] = passwordReader{ID: principalID, Name: name, Type: aceString(ace.ACE, "PrincipalType"), Class: classifyReader(principalID), Inheritance: aceInheritance(ace.ACE)}
	}

	var result []storage.FindingInput

	// gMSA: one Finding per account, because each gMSA names its own readers.
	gmsaIDs := make([]string, 0, len(byKind["gmsa"]))
	for id := range byKind["gmsa"] {
		gmsaIDs = append(gmsaIDs, id)
	}
	sort.Strings(gmsaIDs)
	for _, id := range gmsaIDs {
		entry := byKind["gmsa"][id]
		readers := sortedReaders(entry.readers)
		classes := readerClasses(readers)
		severity := "informational"
		switch {
		case classes[readerBroad] > 0:
			severity = "high"
		case classes[readerDelegated] > 0 && rawBool(entry.object.Properties, "admincount"):
			severity = "medium"
		case classes[readerDelegated] > 0:
			severity = "low"
		}
		names := readerNames(readers)
		evidence, _ := json.Marshal(map[string]any{
			"account": objectLabel(entry.object), "object_id": entry.object.ID, "domain": strings.ToUpper(firstString(entry.object.Properties, "domain")),
			"flag": "gMSA password readable", "enabled": true, "user_account_control": fmt.Sprintf("%d principal(s) hold ReadGMSAPassword", len(readers)),
			"affected_objects": names, "readers": readerRecords(readers, nil), "reader_classes": classes, "value_recorded": false,
		})
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "rusthound-gmsa-readers", entry.object.ID, "ReadGMSAPassword"), AssessmentID: assessmentID,
			SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "ad_account_gmsa_password_readers",
			Title:       "gMSA password readable by " + strings.Join(names, ", ") + ": " + objectLabel(entry.object),
			Description: readerDescription("the managed password of this gMSA", classes) + " The principals come from the account's msDS-GroupMSAMembership as exported by RustHound; nested group membership was not expanded and no password was read.",
			Severity:    severity, Confidence: "observed-directory-acl", AffectedObjectID: entry.object.ID, AffectedObject: entry.object.Name,
			EvidenceJSON: string(evidence), ArtifactPath: entry.object.Artifact, ArtifactRef: entry.object.RefPrefix,
			ObservedAt: now, Status: "open", ParserVersion: hygieneParserVersion,
		})
	}

	// LAPS: one Finding per domain, listing each reader and the computers whose
	// LAPS password it can read.
	type lapsReader struct {
		passwordReader
		computers []string
	}
	perDomain := map[string]map[string]*lapsReader{}
	firstObject := map[string]collectedObject{}
	for _, entry := range byKind["laps"] {
		domain := strings.ToUpper(firstString(entry.object.Properties, "domain"))
		if perDomain[domain] == nil {
			perDomain[domain] = map[string]*lapsReader{}
			firstObject[domain] = entry.object
		}
		for id, reader := range entry.readers {
			item := perDomain[domain][id]
			if item == nil {
				item = &lapsReader{passwordReader: reader}
				perDomain[domain][id] = item
			}
			item.computers = append(item.computers, objectLabel(entry.object))
		}
	}
	domains := make([]string, 0, len(perDomain))
	for domain := range perDomain {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	for _, domain := range domains {
		readers := make([]passwordReader, 0, len(perDomain[domain]))
		targets := map[string][]string{}
		for id, item := range perDomain[domain] {
			sort.Strings(item.computers)
			readers = append(readers, item.passwordReader)
			targets[id] = item.computers
		}
		readers = sortReaders(readers)
		classes := readerClasses(readers)
		severity := "informational"
		switch {
		case classes[readerBroad] > 0:
			severity = "high"
		case classes[readerDelegated] > 0:
			severity = "medium"
		}
		affected := make([]string, 0, len(readers))
		for _, reader := range readers {
			affected = append(affected, fmt.Sprintf("%s → %d computer(s)", reader.Name, len(targets[reader.ID])))
		}
		evidence, _ := json.Marshal(map[string]any{
			"account": fmt.Sprintf("%d principal(s)", len(readers)), "domain": domain, "flag": "LAPS password readable", "enabled": true,
			"user_account_control": "ReadLAPSPassword on computers with LAPS", "affected_objects": affected,
			"readers": readerRecords(readers, targets), "reader_classes": classes, "value_recorded": false,
		})
		object := firstObject[domain]
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "rusthound-laps-readers", domain, "ReadLAPSPassword"), AssessmentID: assessmentID,
			SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "ad_account_laps_password_readers",
			Title:       fmt.Sprintf("Principals that can read LAPS passwords (%s)", domain),
			Description: readerDescription("LAPS local administrator passwords", classes) + " RustHound derives ReadLAPSPassword from rights on computers that have LAPS; nested group membership was not expanded and no password was read.",
			Severity:    severity, Confidence: "observed-directory-acl", AffectedObjectID: domain, AffectedObject: domain,
			EvidenceJSON: string(evidence), ArtifactPath: object.Artifact, ArtifactRef: object.RefPrefix,
			ObservedAt: now, Status: "open", ParserVersion: hygieneParserVersion,
		})
	}
	return result
}

func readerDescription(what string, classes map[string]int) string {
	switch {
	case classes[readerBroad] > 0:
		return "A broad principal such as Domain Users or Authenticated Users can read " + what + ", so practically any account in the domain can recover it."
	case classes[readerDelegated] > 0:
		return "Principals other than the built-in administrators can read " + what + ". Confirm that each delegation is intended; every member of a listed group can recover the password."
	default:
		return "Only built-in privileged principals can read " + what + "."
	}
}

func wellKnownReaderName(sid string) string {
	core := sid
	if index := strings.Index(strings.ToUpper(sid), "S-1-"); index >= 0 {
		core = strings.ToUpper(sid[index:])
	}
	if name, ok := broadReaderSIDs[core]; ok {
		return name
	}
	if name, ok := broadReaderRIDs[core[strings.LastIndexByte(core, '-')+1:]]; ok && strings.HasPrefix(core, "S-1-5-21-") {
		return name
	}
	return sid
}

func sortedReaders(readers map[string]passwordReader) []passwordReader {
	list := make([]passwordReader, 0, len(readers))
	for _, reader := range readers {
		list = append(list, reader)
	}
	return sortReaders(list)
}

// sortReaders lists broad readers first, then delegated, then privileged.
func sortReaders(list []passwordReader) []passwordReader {
	rank := map[string]int{readerBroad: 0, readerDelegated: 1, readerPrivileged: 2}
	sort.Slice(list, func(i, j int) bool {
		if rank[list[i].Class] != rank[list[j].Class] {
			return rank[list[i].Class] < rank[list[j].Class]
		}
		return list[i].Name < list[j].Name
	})
	return list
}

func readerClasses(readers []passwordReader) map[string]int {
	classes := map[string]int{}
	for _, reader := range readers {
		classes[reader.Class]++
	}
	return classes
}

func readerNames(readers []passwordReader) []string {
	names := make([]string, 0, len(readers))
	for _, reader := range readers {
		names = append(names, reader.Name)
	}
	return names
}

func readerRecords(readers []passwordReader, targets map[string][]string) []map[string]any {
	records := make([]map[string]any, 0, len(readers))
	for _, reader := range readers {
		record := map[string]any{"principal_id": reader.ID, "principal_name": reader.Name, "principal_type": reader.Type, "reader_class": reader.Class, "inheritance": reader.Inheritance}
		if targets != nil {
			computers := targets[reader.ID]
			record["computer_count"] = len(computers)
			record["computers"] = computers[:min(len(computers), maxReaderTargets)]
			record["computers_omitted"] = max(0, len(computers)-maxReaderTargets)
		}
		records = append(records, record)
	}
	return records
}
