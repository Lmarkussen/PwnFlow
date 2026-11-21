package findings

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeNetExecSessions(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	loggedOn := write("SMB_loggedon_users.txt", `SMB                      192.0.2.10      445    DC               [*] Windows Server 2019 Build 17763 x64 (name:DC) (domain:corp.example) (signing:True) (SMBv1:False)
SMB                      192.0.2.10      445    DC               [+] corp.example\helpdesk:[REDACTED] (Pwn3d!)
SMB                      192.0.2.10      445    DC               CORP\DC$                       logon_server: 
SMB                      192.0.2.10      445    DC               CORP\administrator             logon_server: DC
SMB                      192.0.2.11      445    APP01            [+] corp.example\helpdesk:[REDACTED] 
SMB                      192.0.2.11      445    APP01            [-] Error enumerating logged on users: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB                      192.0.2.12      445    WS01             [+] corp.example\helpdesk:[REDACTED] (Pwn3d!)
SMB                      192.0.2.12      445    WS01             CORP\jdoe                      logon_server: DC
SMB                      192.0.2.12      445    WS01             NT AUTHORITY\SYSTEM            logon_server: 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
`)
	inputs, err := AnalyzeNetExecSessions(context.Background(), loggedOn, 3, 9, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sessions := map[string][]string{}
	var reach []string
	for _, input := range inputs {
		var evidence map[string]any
		_ = json.Unmarshal([]byte(input.EvidenceJSON), &evidence)
		switch input.FindingType {
		case "smb_signed_in_accounts":
			for _, account := range evidence["accounts"].([]any) {
				sessions[input.AffectedObject] = append(sessions[input.AffectedObject], account.(string))
			}
		case "netexec_admin_reach":
			reach = append(reach, input.Title)
			for _, host := range evidence["affected_objects"].([]any) {
				reach = append(reach, host.(string))
			}
		}
	}
	if strings.Join(sessions["DC"], ",") != `CORP\administrator` || strings.Join(sessions["WS01"], ",") != `CORP\jdoe` || len(sessions) != 2 {
		t.Fatalf("sessions %v (machine and built-in accounts must be dropped)", sessions)
	}
	if strings.Join(reach, "|") != `Local administrator on 2 host(s): corp.example\helpdesk|DC (192.0.2.10)|WS01 (192.0.2.12)` {
		t.Fatalf("admin reach %v", reach)
	}

	registry := write("SMB_registry_sessions.txt", `SMB                      192.0.2.10      445    DC               [+] Remote Registry enumerated sessions
SMB                      192.0.2.10      445    DC               USERNAME           SID                                            
SMB                      192.0.2.10      445    DC               ================== ===============================================
SMB                      192.0.2.10      445    DC               CORP\svc-backup    S-1-5-21-1-2-3-1105 
`)
	terminal := write("SMB_terminal_sessions.txt", `SMB                      192.0.2.10      445    DC               SESSIONNAME  USERNAME           ID  IPv4 Address     STATE         Desktop   ConnectTime          DisconnectTime       
SMB                      192.0.2.10      445    DC               ============ ================== === ================ ============= ========= ==================== ==================== 
SMB                      192.0.2.10      445    DC               Services                        0                    Disconnected  Unlocked  None                 None                 
SMB                      192.0.2.10      445    DC               Console      CORP\opsadmin      1                    Active        Unlocked  2026/11/21 21:07:59  None                 
`)
	for path, want := range map[string]string{registry: `CORP\svc-backup`, terminal: `CORP\opsadmin`} {
		inputs, err := AnalyzeNetExecSessions(context.Background(), path, 3, 9, time.Now())
		if err != nil || len(inputs) != 1 || !strings.Contains(inputs[0].EvidenceJSON, strings.ReplaceAll(want, `\`, `\\`)) {
			t.Fatalf("%s: %v %+v", filepath.Base(path), err, inputs)
		}
	}
	if !isNetExecSessionArtifact("/x/SMB_loggedon_users.txt") || isNetExecSessionArtifact("/x/SMB_shares.txt") {
		t.Fatal("session artifact detection")
	}
}
