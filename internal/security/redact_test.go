package security

import "testing"

func TestSplitChunkRedaction(t *testing.T) {
	r := NewRedactor("secret")
	a, _ := r.Write([]byte("pass se"))
	b, _ := r.Write([]byte("cret value"))
	got := string(append(a, b...)) + string(r.Flush())
	if got != "pass [REDACTED] value" {
		t.Fatalf("%q", got)
	}
}

// Streamed tool output is a finding. A value is masked only when it sits in an option
// position for a credential option, so recovered material survives untouched.
func TestArgumentRedactorPreservesFindingsAndMasksOptionValues(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"bare occurrence is a finding":          {"before secret after", "before secret after"},
		"recovered password keeps its value":    {"[!] Network Access Account Password: 'recovered-value'", "[!] Network Access Account Password: 'recovered-value'"},
		"task sequence name is preserved":       {"[+] Writing decrypted TS_Sequence XML to 'TaskSequence_policy_ABC.xml'", "[+] Writing decrypted TS_Sequence XML to 'TaskSequence_policy_ABC.xml'"},
		"short option form is masked":           {"collector -p Sup3rSecret -o artifacts", "collector -p [REDACTED] -o artifacts"},
		"long option form is masked":            {"collector --ldappassword Sup3rSecret", "collector --ldappassword [REDACTED]"},
		"equals form is masked":                 {"collector --password=Sup3rSecret", "collector --password=[REDACTED]"},
		"hashes are masked":                     {"collector -H aad3b435b51404eeaad3b435b51404ee", "collector -H [REDACTED]"},
		"a finding that matches an input value": {"[!] Collection Variable Secret: 'Sup3rSecret'", "[!] Collection Variable Secret: 'Sup3rSecret'"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			redactor := NewArgumentRedactor("Sup3rSecret")
			out, _ := redactor.Write([]byte(test.in + "\n"))
			out = append(out, redactor.Flush()...)
			if got := string(out); got != test.want+"\n" {
				t.Fatalf("got %q, want %q", got, test.want+"\n")
			}
		})
	}
}

// A partially matching value is not partially masked: the whole line is either a
// credential in option position or it is a finding.
func TestArgumentRedactorDoesNotPartiallyMaskFindings(t *testing.T) {
	redactor := NewArgumentRedactor("Sup3rSecret")
	line := "[!] Network Access Account Password: 'Sup3rSecret-tail'\n"
	out, _ := redactor.Write([]byte(line))
	out = append(out, redactor.Flush()...)
	if string(out) != line {
		t.Fatalf("a finding was rewritten: %q", string(out))
	}
}
