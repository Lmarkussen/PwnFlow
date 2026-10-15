package findings

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const (
	PXEThiefParserVersion = "pxethief-credentials-v1"
	maxPXEFileBytes       = 32 << 20
	maxPXEFiles           = 512
)

var pxeCredentialPattern = regexp.MustCompile(`(?i)\b(OSDJoinAccount|OSDJoinPassword|OSDLocalAdminPassword)\b\s*(?:[:=\-]|=>)?\s*(.*)$`)
var pxeCredentialNames = map[string]bool{"osdjoinaccount": true, "osdjoinpassword": true, "osdlocaladminpassword": true}

type pxeCredentialObservation struct {
	Name, Account string
	Line          int
	Ref           string
	Context       string
}

// AnalyzePXEThief consumes finalized PXEThief logs and task-sequence files only.
// It never contacts a distribution point and deliberately excludes recovered
// password values from structured evidence.
func AnalyzePXEThief(ctx context.Context, inputPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	paths, err := pxeArtifactFiles(inputPath)
	if err != nil {
		return nil, err
	}
	var findings []storage.FindingInput
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		observations, err := parsePXEFile(path)
		if err != nil {
			return nil, err
		}
		if len(observations) == 0 {
			continue
		}
		groups := map[string]map[string]pxeCredentialObservation{}
		for _, item := range observations {
			if groups[item.Context] == nil {
				groups[item.Context] = map[string]pxeCredentialObservation{}
			}
			if _, ok := groups[item.Context][strings.ToLower(item.Name)]; !ok {
				groups[item.Context][strings.ToLower(item.Name)] = item
			}
		}
		contexts := make([]string, 0, len(groups))
		for context := range groups {
			contexts = append(contexts, context)
		}
		sort.Strings(contexts)
		for _, context := range contexts {
			seen := groups[context]
			variables := make([]string, 0, len(seen))
			account := ""
			refs := make([]string, 0, len(seen))
			for _, name := range []string{"OSDJoinAccount", "OSDJoinPassword", "OSDLocalAdminPassword"} {
				if item, ok := seen[strings.ToLower(name)]; ok {
					variables = append(variables, item.Name)
					refs = append(refs, item.Ref)
					if strings.EqualFold(item.Name, "OSDJoinAccount") {
						account = item.Account
					}
				}
			}
			endpoint := endpointFromArtifact(path)
			evidence, _ := json.Marshal(map[string]any{"credential_variables": variables, "account_identity": account, "task_sequence_context": context, "artifact_records": refs, "value_present": true})
			findingKey := pxeFindingKey(assessmentID, path, context, variables)
			findings = append(findings, storage.FindingInput{
				FindingKey: findingKey, AssessmentID: assessmentID, SourceTool: "PXEThief", SourceExecution: executionID,
				FindingType: "sccm_task_sequence_credentials_exposed", Title: "SCCM task-sequence credentials exposed",
				Description: fmt.Sprintf("PXEThief recovered credential-bearing task-sequence variables (%s) from a finalized artifact. The original restricted artifact contains the complete values; this finding intentionally does not copy passwords.", strings.Join(variables, ", ")),
				Severity:    "high", Confidence: "observed-recovered-value", AffectedObjectID: endpoint, AffectedObject: endpoint,
				RelatedObjectID: account, RelatedObject: account, EvidenceJSON: string(evidence), ArtifactPath: path, ArtifactRef: refs[0], ObservedAt: now,
				Status: "open", ParserVersion: PXEThiefParserVersion,
			})
		}
	}
	return findings, nil
}

func IngestPXEThief(ctx context.Context, db *storage.DB, inputPath string, assessmentID, executionID int64, now time.Time) error {
	findings, err := AnalyzePXEThief(ctx, inputPath, assessmentID, executionID, now)
	if err != nil {
		return err
	}
	return db.IngestFindings(ctx, findings)
}

func pxeArtifactFiles(inputPath string) ([]string, error) {
	info, err := os.Stat(inputPath)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{inputPath}, nil
	}
	var paths []string
	err = filepath.WalkDir(inputPath, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if len(paths) >= maxPXEFiles {
			return fmt.Errorf("PXEThief artifact count exceeds limit")
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("PXEThief symlink artifact is not allowed")
		}
		name := strings.ToLower(entry.Name())
		if name != "pxethief.log" && name != "variables.xml" && !strings.HasSuffix(name, ".boot.var") {
			return nil
		}
		if stat, err := entry.Info(); err != nil {
			return err
		} else if stat.Size() > maxPXEFileBytes {
			return fmt.Errorf("PXEThief artifact exceeds parser size limit")
		}
		paths = append(paths, path)
		return nil
	})
	sort.Strings(paths)
	return paths, err
}

func parsePXEFile(path string) ([]pxeCredentialObservation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > maxPXEFileBytes {
		return nil, fmt.Errorf("PXEThief artifact exceeds parser size limit")
	}
	if strings.EqualFold(filepath.Ext(path), ".xml") {
		return parsePXEXML(data, path)
	}
	return parsePXELines(data, path), nil
}

func parsePXELines(data []byte, path string) []pxeCredentialObservation {
	text := string(data)
	if !utf8.Valid(data) {
		text = decodeUTF16(data)
	}
	var result []pxeCredentialObservation
	scanner := bufio.NewScanner(strings.NewReader(text))
	line := 0
	contextName := "artifact"
	for scanner.Scan() {
		line++
		lineText := scanner.Text()
		lowerLine := strings.ToLower(lineText)
		if strings.Contains(lowerLine, "task sequence") && !strings.Contains(lowerLine, "no task sequence") {
			contextName = fmt.Sprintf("task-sequence-line:%d", line)
		}
		match := pxeCredentialPattern.FindStringSubmatch(lineText)
		if len(match) < 3 || !pxeCredentialNames[strings.ToLower(match[1])] {
			continue
		}
		value := strings.TrimSpace(strings.Trim(match[2], "-:=[] \t"))
		if !credentialValuePresent(value) {
			continue
		}
		item := pxeCredentialObservation{Name: canonicalPXEName(match[1]), Line: line, Ref: fmt.Sprintf("line:%d", line), Context: contextName}
		if strings.EqualFold(item.Name, "OSDJoinAccount") {
			item.Account = value
		}
		result = append(result, item)
	}
	return result
}

func parsePXEXML(data []byte, path string) ([]pxeCredentialObservation, error) {
	if !utf8.Valid(data) {
		data = []byte(decodeUTF16(data))
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var result []pxeCredentialObservation
	line := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse PXEThief XML: %w", err)
		}
		switch item := token.(type) {
		case xml.StartElement:
			if !strings.EqualFold(item.Name.Local, "var") {
				continue
			}
			var name string
			for _, attr := range item.Attr {
				if strings.EqualFold(attr.Name.Local, "name") {
					name = canonicalPXEName(attr.Value)
				}
			}
			if !pxeCredentialNames[strings.ToLower(name)] {
				continue
			}
			var value string
			if err := decoder.DecodeElement(&value, &item); err != nil {
				return nil, err
			}
			line++
			if !credentialValuePresent(strings.TrimSpace(value)) {
				continue
			}
			observation := pxeCredentialObservation{Name: name, Line: line, Ref: fmt.Sprintf("xml:var[%d]", line), Context: "xml"}
			if strings.EqualFold(name, "OSDJoinAccount") {
				observation.Account = strings.TrimSpace(value)
			}
			result = append(result, observation)
		}
	}
	return result, nil
}

func credentialValuePresent(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	for _, empty := range []string{"none", "null", "n/a", "not found", "not set", "no value", "no credentials", "not present", "empty"} {
		if lower == empty || strings.Contains(lower, "no credentials found") {
			return false
		}
	}
	return true
}
func canonicalPXEName(value string) string {
	for name := range pxeCredentialNames {
		if strings.EqualFold(name, value) {
			switch name {
			case "osdjoinaccount":
				return "OSDJoinAccount"
			case "osdjoinpassword":
				return "OSDJoinPassword"
			default:
				return "OSDLocalAdminPassword"
			}
		}
	}
	return value
}
func endpointFromArtifact(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if net.ParseIP(parts[i]) != nil {
			return parts[i]
		}
	}
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := parts[i]
		if candidate != "" && !strings.Contains(candidate, ".") && candidate != "artifacts" && !strings.HasPrefix(candidate, "20") && len(candidate) <= 64 {
			return candidate
		}
	}
	return ""
}
func pxeFindingKey(assessmentID int64, path, context string, variables []string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s", assessmentID, path, context, strings.Join(variables, ","))))
	return "pxethief:" + hex.EncodeToString(hash[:])
}
func decodeUTF16(data []byte) string {
	if len(data)%2 == 1 {
		data = data[:len(data)-1]
	}
	little := true
	if len(data) >= 2 && binary.BigEndian.Uint16(data[:2]) == 0xfeff {
		little = false
		data = data[2:]
	} else if len(data) >= 2 && binary.LittleEndian.Uint16(data[:2]) == 0xfeff {
		data = data[2:]
	}
	values := make([]uint16, len(data)/2)
	for i := range values {
		if little {
			values[i] = binary.LittleEndian.Uint16(data[i*2:])
		} else {
			values[i] = binary.BigEndian.Uint16(data[i*2:])
		}
	}
	return string(utf16.Decode(values))
}
