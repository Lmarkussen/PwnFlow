package security

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"sync"
)

// CredentialSink removes the supplied authentication secret from diagnostic
// output for enumeration tools that echo it outside command option positions.
// It is deliberately opt-in: recovered credential collectors retain their own
// output policy. Buffering lines handles credentials split across writes.
type CredentialSink struct {
	mu                 sync.Mutex
	target             io.Writer
	secret             []byte
	pending            []byte
	authenticationOnly bool
}

func NewCredentialSink(target io.Writer, secret string) *CredentialSink {
	return &CredentialSink{target: target, secret: []byte(secret)}
}

// NewNetExecAuthenticationSink masks supplied credentials only on protocol login
// records. Module result lines, including recovered credentials, are preserved.
func NewNetExecAuthenticationSink(target io.Writer, secret string) *CredentialSink {
	return &CredentialSink{target: target, secret: []byte(secret), authenticationOnly: true}
}

var netExecLoginPrefix = regexp.MustCompile(`(?i)^\s*(?:SMB|LDAPS?|WINRM|RDP|SSH|WMI|FTP|VNC|MSSQL|NFS)\s+\S+\s+\d+\s+\S+\s+\[[+-]\]\s+(.*)$`)

func (s *CredentialSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, p...)
	if end := bytes.LastIndexByte(s.pending, '\n'); end >= 0 {
		if err := s.write(s.pending[:end+1]); err != nil {
			return 0, err
		}
		s.pending = append([]byte(nil), s.pending[end+1:]...)
	}
	return len(p), nil
}
func (s *CredentialSink) write(p []byte) error {
	if len(s.secret) > 0 {
		if s.authenticationOnly {
			var out bytes.Buffer
			for _, line := range bytes.SplitAfter(p, []byte("\n")) {
				match := netExecLoginPrefix.FindStringSubmatch(strings.TrimRight(StripANSI(string(line)), "\r\n"))
				if len(match) == 2 && (strings.Contains(match[1], ":"+string(s.secret)) || strings.HasPrefix(match[1], string(s.secret))) {
					line = []byte(RedactString(string(line), string(s.secret)))
				}
				out.Write(line)
			}
			p = out.Bytes()
		} else {
			p = bytes.ReplaceAll(p, s.secret, []byte(replacement))
		}
	}
	_, err := s.target.Write(p)
	return err
}

func (s *CredentialSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.write(s.pending)
	s.pending = nil
	return err
}
