package findings

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestAnalyzeNetExecDomainPolicyFindsPolicyConditions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LDAP_password_policy.txt")
	body := strings.Join([]string{
		"LDAP 10.1.10.40 389 sccm.lab [+] sccm.lab\\pwnflow",
		"Domain: sccm.lab",
		"minPwdLength: 5",
		"maxPwdAge: 0",
		"ms-DS-MachineAccountQuota: 10",
		"minPwdLength: 5", // duplicate source line must not duplicate the finding.
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecDomainPolicy(context.Background(), path, 7, 9, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 3 {
		t.Fatalf("findings=%d, want three unique domain conditions", len(inputs))
	}
	seen := map[string]bool{}
	for _, input := range inputs {
		seen[input.FindingType] = true
		if input.AffectedObject != "sccm.lab" || input.AffectedObjectID != "sccm.lab" {
			t.Fatalf("domain attribution=%q/%q", input.AffectedObject, input.AffectedObjectID)
		}
		var evidence map[string]any
		if err := json.Unmarshal([]byte(input.EvidenceJSON), &evidence); err != nil {
			t.Fatal(err)
		}
		if evidence["policy_scope"] != "domain default policy" || !strings.Contains(input.EvidenceJSON, "fine_grained_policy_limitation") {
			t.Fatalf("missing scope limitation: %s", input.EvidenceJSON)
		}
	}
	for _, typ := range []string{"ad_domain_policy_weak_minimum_password_length", "ad_domain_policy_password_expiration_not_enforced", "ad_domain_policy_machine_account_creation_quota"} {
		if !seen[typ] {
			t.Fatalf("missing %s", typ)
		}
	}
}

func TestAnalyzeNetExecDomainPolicyRejectsUnsupportedValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LDAP_password_policy.txt")
	body := strings.Join([]string{
		"Domain: example.test",
		"Minimum password length: 0",
		"Maximum password age: not-a-duration",
		"ms-DS-MachineAccountQuota: nope",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecDomainPolicy(context.Background(), path, 1, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 0 {
		t.Fatalf("unsupported values produced findings: %#v", inputs)
	}
}

func TestAnalyzeNetExecDomainPolicyDoesNotFlagLongMinimum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LDAP_password_policy.txt")
	if err := os.WriteFile(path, []byte("Domain: example.test\nMinimum password length: 12\n"), 0600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecDomainPolicy(context.Background(), path, 1, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 0 {
		t.Fatalf("long minimum produced findings: %#v", inputs)
	}
}

func TestParseDomainPolicyAgeHandlesADIntervalsAndBoundaries(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		nonExpiring  bool
		wantContains string
		valid        bool
	}{
		{"zero", "0", true, "non-expiring", true},
		{"negative finite", "-864000000000", false, "1 days", true},
		{"positive finite", "864000000000", false, "positive interval", true},
		{"minimum int64", "-9223372036854775808", false, "10675199 days", true},
		{"never", "never", true, "non-expiring", true},
		{"invalid", "signed nonsense", false, "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			age, valid := parseDomainPolicyAge(test.value)
			if valid != test.valid || (valid && age.NonExpiring != test.nonExpiring) {
				t.Fatalf("age=%#v valid=%v", age, valid)
			}
			if test.wantContains != "" && !strings.Contains(age.Display, test.wantContains) {
				t.Fatalf("display=%q, want %q", age.Display, test.wantContains)
			}
		})
	}
}

func TestNetExecDomainPolicyUsesSQLitePipeline(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := storage.Open(filepath.Join(root, "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertTarget(ctx, "sccm.lab", "10.1.10.40"); err != nil {
		t.Fatal(err)
	}
	assessment, err := db.TargetID(ctx, "sccm.lab", "10.1.10.40")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO modules(id,name,tool,protocol,description,output_filename) VALUES(99,'Enumerate Domain Password Policy','NetExec (nxc)','LDAP','test','LDAP_password_policy.txt')`); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "LDAP_password_policy.txt")
	if err := os.WriteFile(path, []byte("LDAP 10.1.10.40 389 sccm.lab [+] sccm.lab\\pwnflow\nMinimum password length: 5\nMaximum password age: 0 days 0 hours\n"), 0600); err != nil {
		t.Fatal(err)
	}
	execution, err := db.RecordExecutionID(ctx, assessment, 99, time.Now(), time.Now(), "completed", 0, path, "")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(ctx, db)
	defer manager.Close()
	if err := manager.Submit(Job{AssessmentID: assessment, ExecutionID: execution, SourceTool: "NetExec (nxc)", ArtifactPath: path, ObservedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListFindings(ctx, assessment)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatalf("persisted findings=%d, want policy findings", len(rows))
	}
	policyCount := 0
	for _, row := range rows {
		if strings.HasPrefix(row.FindingType, "ad_domain_policy_") {
			policyCount++
		}
		count, countErr := db.FindingEvidenceCount(ctx, row.ID)
		if countErr != nil || count != 1 {
			t.Fatalf("finding %d evidence count=%d err=%v", row.ID, count, countErr)
		}
	}
	if policyCount != 2 {
		t.Fatalf("persisted policy findings=%d, want two", policyCount)
	}
}

func TestNetExecDomainPolicyArtifactDispatch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "LDAP_password_policy.txt")
	if err := os.WriteFile(path, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := netExecArtifactForExecution("Enumerate Domain Password Policy", path); got != path {
		t.Fatalf("password-policy artifact=%q", got)
	}
	quota := filepath.Join(root, "LDAP_machine_account_quota.txt")
	if err := os.WriteFile(quota, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := netExecArtifactForExecution("Check Machine Account Quota", quota); got != quota {
		t.Fatalf("quota artifact=%q", got)
	}
}
