// Package trust records the operator's decisions about certificates PwnFlow
// cannot chain to an authority the host trusts.
//
// Standard verification stays the preferred path: this package is only consulted
// after the chain, host name, validity window, and server-auth usage have been
// checked, and only the issuing-authority question is handed to the operator.
// Decisions are scoped to the target and certificate identity and are stored as
// non-secret metadata in a file only the owner can read. Credentials never reach
// this package.
package trust

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/pwnflow/pwnflow/internal/ldaptransport"
)

// Record is the non-secret metadata kept for an operator-approved certificate.
type Record struct {
	Target      string    `json:"target"`
	Identity    string    `json:"identity"`
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotAfter    time.Time `json:"notAfter"`
	ApprovedAt  time.Time `json:"approvedAt"`
}

func scopeKey(target, identity string) string { return target + "\x00" + identity }

// Store holds approved certificates in a local file with owner-only permissions.
type Store struct {
	path    string
	records map[string]Record
}

// DefaultPath is the per-user location for approved certificate metadata.
func DefaultPath() (string, error) {
	if directory := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); directory != "" {
		return filepath.Join(directory, "pwnflow", "trusted-certificates.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "pwnflow", "trusted-certificates.json"), nil
}

// Load reads the store. A missing file is an empty store, not an error.
func Load(path string) (*Store, error) {
	store := &Store{path: path, records: map[string]Record{}}
	contents, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(contents))) == 0 {
		return store, nil
	}
	var records []Record
	if err := json.Unmarshal(contents, &records); err != nil {
		return nil, fmt.Errorf("trust store %s could not be read: %w", path, err)
	}
	for _, record := range records {
		store.records[scopeKey(record.Target, record.Identity)] = record
	}
	return store, nil
}

// Path reports where the store lives.
func (s *Store) Path() string { return s.path }

// Lookup returns the approved record for a target and identity.
func (s *Store) Lookup(target, identity string) (Record, bool) {
	record, ok := s.records[scopeKey(target, identity)]
	return record, ok
}

// Approve records a decision and writes the store with owner-only permissions.
func (s *Store) Approve(record Record) error {
	s.records[scopeKey(record.Target, record.Identity)] = record
	return s.save()
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	ordered := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		ordered = append(ordered, record)
	}
	sort.Slice(ordered, func(first, second int) bool {
		if ordered[first].Identity != ordered[second].Identity {
			return ordered[first].Identity < ordered[second].Identity
		}
		return ordered[first].Target < ordered[second].Target
	})
	contents, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.path, append(contents, '\n'), 0o600); err != nil {
		return err
	}
	// An existing file may have been created with looser permissions.
	return os.Chmod(s.path, 0o600)
}

// Decider answers certificate trust questions, consulting the store first and the
// operator second. Missing input is never acceptance.
type Decider struct {
	Store *Store
	In    io.Reader
	Out   io.Writer
	// Interactive overrides the terminal check. It lets a caller that already
	// knows a decision can be asked, such as a wrapper around stdin, and lets the
	// prompt logic be exercised without a terminal.
	Interactive func() bool
	session     map[string]string
}

// Decide implements ldaptransport.TrustHandler.
func (d *Decider) Decide(info ldaptransport.CertificateInfo) (ldaptransport.TrustDecision, error) {
	if d.session == nil {
		d.session = map[string]string{}
	}
	scope := scopeKey(info.Target, info.Identity)
	if fingerprint, ok := d.session[scope]; ok && fingerprint == info.Fingerprint {
		fmt.Fprintf(d.Out, "[i] certificate for %s already accepted for this session\n", info.Identity)
		return ldaptransport.TrustSession, nil
	}
	if d.Store != nil {
		if record, ok := d.Store.Lookup(info.Target, info.Identity); ok {
			if record.Fingerprint == info.Fingerprint {
				fmt.Fprintf(d.Out, "[i] certificate for %s matches the stored approval (SHA-256 %s)\n", info.Identity, info.Fingerprint)
				return ldaptransport.TrustSession, nil
			}
			fmt.Fprintf(d.Out, "[!] the certificate presented by %s differs from the stored approval; a new decision is required\n", info.Identity)
		}
	}
	if !d.interactive() {
		return ldaptransport.TrustReject, fmt.Errorf("the certificate for %s is not trusted and no interactive terminal is available to decide; re-run in a terminal, or pass --insecure-skip-verify only if skipping verification is acceptable", info.Identity)
	}
	decision := d.prompt(info)
	switch decision {
	case ldaptransport.TrustPersist:
		if d.Store == nil {
			d.session[scope] = info.Fingerprint
			return ldaptransport.TrustSession, nil
		}
		record := Record{
			Target:      info.Target,
			Identity:    info.Identity,
			Fingerprint: info.Fingerprint,
			Subject:     info.Subject,
			Issuer:      info.Issuer,
			NotAfter:    info.NotAfter,
			ApprovedAt:  time.Now().UTC(),
		}
		if err := d.Store.Approve(record); err != nil {
			fmt.Fprintf(d.Out, "[!] the certificate was accepted for this session, but the approval could not be stored: %v\n", err)
		} else {
			fmt.Fprintf(d.Out, "[i] certificate approved for %s and stored in %s\n", info.Identity, d.Store.Path())
		}
		d.session[scope] = info.Fingerprint
		return ldaptransport.TrustPersist, nil
	case ldaptransport.TrustSession:
		d.session[scope] = info.Fingerprint
		return ldaptransport.TrustSession, nil
	}
	return ldaptransport.TrustReject, fmt.Errorf("the certificate for %s was rejected by the operator", info.Identity)
}

// prompt shows the certificate and asks, defaulting to rejection.
func (d *Decider) prompt(info ldaptransport.CertificateInfo) ldaptransport.TrustDecision {
	remaining := int(time.Until(info.NotAfter).Hours() / 24)
	fmt.Fprintf(d.Out, "\n[!] The certificate presented by %s (%s) is not trusted:\n", info.Target, info.Identity)
	fmt.Fprintf(d.Out, "      Subject:   %s\n", info.Subject)
	fmt.Fprintf(d.Out, "      Issuer:    %s\n", info.Issuer)
	fmt.Fprintf(d.Out, "      Valid:     %s .. %s (%d days remaining)\n",
		info.NotBefore.UTC().Format(time.RFC3339), info.NotAfter.UTC().Format(time.RFC3339), remaining)
	fmt.Fprintf(d.Out, "      SHA-256:   %s\n", info.Fingerprint)
	fmt.Fprintf(d.Out, "      Problem:   %s\n", info.Reason)
	fmt.Fprint(d.Out, "    [t] trust and remember this certificate for this target\n")
	fmt.Fprint(d.Out, "    [s] accept this certificate for this session only\n")
	fmt.Fprint(d.Out, "    [r] reject and exit (default)\n")
	fmt.Fprint(d.Out, "    Choice [r]: ")

	answer, err := bufio.NewReader(d.In).ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintf(d.Out, "could not read the trust decision: %v\n", err)
		return ldaptransport.TrustReject
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "t", "trust":
		return ldaptransport.TrustPersist
	case "s", "session":
		return ldaptransport.TrustSession
	}
	// Empty input, end of input, or anything else: not acceptance.
	return ldaptransport.TrustReject
}

func isInteractive(in io.Reader) bool {
	file, ok := in.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func (d *Decider) interactive() bool {
	if d.Interactive != nil {
		return d.Interactive()
	}
	return isInteractive(d.In)
}
