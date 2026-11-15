package security

import (
	"bytes"
	"strings"
	"testing"
)

func TestCredentialSinkSplitAuthenticationEcho(t *testing.T) {
	var out bytes.Buffer
	s := NewCredentialSink(&out, "secret")
	s.Write([]byte("SMB [+] lab:sec"))
	s.Write([]byte("ret\nCN=Lab WRITE_DAC\nsec"))
	s.Write([]byte("ret"))
	s.Flush()
	if strings.Contains(out.String(), "secret") || !strings.Contains(out.String(), "CN=Lab WRITE_DAC") {
		t.Fatal(out.String())
	}
}

func TestNetExecLoginEchoPreservesRecoveredEvidence(t *testing.T) {
	var out bytes.Buffer
	sink := NewNetExecAuthenticationSink(&out, "synthetic-secret")
	sink.Write([]byte("LDAPS 192.0.2.1 636 DC [+] lab/user:synthe"))
	sink.Write([]byte("tic-secret (Pwn3d!)\nGPP_PASS 192.0.2.1 445 DC Password: synthetic-secret\n"))
	sink.Flush()
	want := "LDAPS 192.0.2.1 636 DC [+] lab/user:[REDACTED] (Pwn3d!)\nGPP_PASS 192.0.2.1 445 DC Password: synthetic-secret\n"
	if out.String() != want {
		t.Fatalf("%q", out.String())
	}
}
