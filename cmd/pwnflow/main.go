package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/dependencies"
	findingengine "github.com/pwnflow/pwnflow/internal/findings"
	"github.com/pwnflow/pwnflow/internal/ldaptransport"
	"github.com/pwnflow/pwnflow/internal/password"
	"github.com/pwnflow/pwnflow/internal/preflight"
	"github.com/pwnflow/pwnflow/internal/storage"
	"github.com/pwnflow/pwnflow/internal/trust"
	"github.com/pwnflow/pwnflow/internal/tui"
	"golang.org/x/term"
)

var version = "0.1.0"

// multiFlag collects a repeatable string flag in order.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func main() {
	target := flag.String("target", "", "target address or hostname")
	domain := flag.String("domain", "", "Active Directory domain")
	username := flag.String("username", "", "username")
	passwordFlag := flag.String("password", "", "password (avoid on shared systems)")
	insecureSkipVerify := flag.Bool("insecure-skip-verify", false, "skip LDAPS/StartTLS certificate verification (only when the target certificate cannot be validated)")
	flushDB := flag.Bool("flushdb", false, "Clear previous database assessment records before starting; preserve raw evidence")
	resetFindings := flag.Bool("reset-findings", false, "remove derived Findings history for this assessment; original artifacts remain")
	confirmResetFindings := flag.Bool("confirm-reset-findings", false, "confirm --reset-findings")
	reanalyzeLatest := flag.Bool("reanalyze-latest", false, "offline-analyze the latest supported saved artifacts; never starts modules")
	var moduleOptionsFlag multiFlag
	flag.Var(&moduleOptionsFlag, "module-options", "value for one module option, as MODULE.KEY=VALUE; repeat for more options")
	flag.Parse()
	if *target == "" || *domain == "" || *username == "" {
		fmt.Fprintln(os.Stderr, "usage: pwnflow --target ADDRESS --domain DOMAIN --username USER")
		os.Exit(2)
	}
	passwordValue := *passwordFlag
	passwordProvided := false
	flag.Visit(func(f *flag.Flag) { passwordProvided = passwordProvided || f.Name == "password" })
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	if *flushDB && (*resetFindings || *reanalyzeLatest) {
		fail(errors.New("--flushdb cannot be combined with --reset-findings or --reanalyze-latest"))
	}
	if *flushDB {
		root, err := config.ProjectRoot()
		if err != nil {
			fail(err)
		}
		cfg, err := config.New(*target, *domain, *username, "", root)
		if err != nil {
			fail(err)
		}
		backupDir := filepath.Join(filepath.Dir(root), "pwnflow-backups")
		report, err := storage.FlushAssessment(ctx, filepath.Join(cfg.ResultsRoot(), "enumeration.db"), cfg.Domain, cfg.Target, backupDir)
		if err != nil {
			fail(fmt.Errorf("--flushdb failed: %w", err))
		}
		fmt.Fprintf(os.Stdout, "Flushed assessment database for %s; removed %d findings, %d observations/evidence links, %d analysis jobs, and %d executions. Backup: %s\n", cfg.Domain, report.Findings, report.Evidence, report.AnalysisJobs, report.Executions, report.BackupPath)
	}
	if *resetFindings {
		if !*confirmResetFindings {
			fail(errors.New("--reset-findings requires --confirm-reset-findings; original artifacts are preserved"))
		}
		root, err := config.ProjectRoot()
		if err != nil {
			fail(err)
		}
		cfg, err := config.New(*target, *domain, *username, "", root)
		if err != nil {
			fail(err)
		}
		db, err := storage.Open(filepath.Join(cfg.ResultsRoot(), "enumeration.db"))
		if err != nil {
			fail(err)
		}
		defer db.Close()
		if err := db.UpsertTarget(ctx, cfg.Domain, cfg.Target); err != nil {
			fail(err)
		}
		assessmentID, err := db.TargetID(ctx, cfg.Domain, cfg.Target)
		if err != nil {
			fail(err)
		}
		removed, err := db.ResetDerivedState(ctx, assessmentID)
		if err != nil {
			fail(err)
		}
		fmt.Fprintf(os.Stdout, "Reset %d derived findings for %s; original artifacts were preserved.\n", removed, cfg.Domain)
		return
	}
	dependencyRegistry := dependencies.DefaultRegistry()
	dependencyReasons := make(map[string]string)
	for _, status := range dependencyRegistry.Check(ctx) {
		if !status.Available {
			dependencyReasons[string(status.ID)] = fmt.Sprintf("%s: %s", status.DisplayName, status.Detail)
			if status.Required && status.State == "missing" {
				fmt.Fprintf(os.Stderr, "[!] Missing dependency: %s\n", status.DisplayName)
			} else if status.Required {
				fmt.Fprintf(os.Stderr, "[!] Dependency check %s: %s\n", strings.ToUpper(status.State), status.DisplayName)
			}
			if status.Required {
				fmt.Fprintf(os.Stderr, "%s-dependent modules are unavailable: %s\nInstall dependencies with: ./install.sh\n", status.DisplayName, status.Detail)
			}
		}
	}
	if !passwordProvided {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintln(os.Stderr, "password input requires an interactive terminal")
			os.Exit(2)
		}
		var err error
		passwordValue, err = password.Prompt(os.Stdin, os.Stderr)
		if err != nil {
			if errors.Is(err, password.ErrCancelled) {
				fmt.Fprintln(os.Stderr, "password input cancelled")
				os.Exit(130)
			}
			fail(err)
		}
	}
	if passwordValue == "" {
		fail(errors.New("password cannot be empty"))
	}
	moduleOptions, err := config.ParseModuleOptions(moduleOptionsFlag)
	if err != nil {
		fail(err)
	}

	root, err := config.ProjectRoot()
	if err != nil {
		fail(err)
	}
	cfg, err := config.New(*target, *domain, *username, passwordValue, root)
	if err != nil {
		fail(err)
	}
	cfg.InsecureSkipVerify = *insecureSkipVerify
	cfg.ModuleOptions = moduleOptions
	if *reanalyzeLatest {
		db, err := storage.Open(filepath.Join(cfg.ResultsRoot(), "enumeration.db"))
		if err != nil {
			fail(err)
		}
		defer db.Close()
		if err := db.UpsertTarget(ctx, cfg.Domain, cfg.Target); err != nil {
			fail(err)
		}
		assessmentID, err := db.TargetID(ctx, cfg.Domain, cfg.Target)
		if err != nil {
			fail(err)
		}
		manager := findingengine.NewManager(ctx, db)
		if err := manager.ReanalyzeLatestSupported(ctx, assessmentID); err != nil {
			manager.Close()
			fail(err)
		}
		wait, cancel := context.WithTimeout(ctx, 5*time.Minute)
		err = manager.Wait(wait)
		cancel()
		manager.Close()
		if err != nil {
			fail(err)
		}
		fmt.Printf("Latest supported saved artifacts analyzed for %s.\n", cfg.Domain)
		return
	}
	trustIn, trustOut := trustTerminal()
	ldapOptions := trustOptions(cfg, trustIn, trustOut)
	cfg.LDAPOptions = ldapOptions
	connection, err := preflight.Run(ctx, cfg, ldapOptions)
	if err != nil {
		fail(err)
	}
	identityNote := ""
	if name := connection.Identity.ServerName; name != "" && name != cfg.Target {
		identityNote = fmt.Sprintf(", certificate verified as %s", name)
	}
	if connection.Transport != ldaptransport.LDAP || connection.Insecure || identityNote != "" {
		note := ""
		if connection.Insecure {
			note = "; certificate verification skipped"
		}
		fmt.Fprintf(os.Stderr, "[i] LDAP bind over %s (%s)%s%s\n", connection.Transport, connection.Endpoint, identityNote, note)
	}
	db, err := storage.Open(filepath.Join(cfg.ResultsRoot(), "enumeration.db"))
	if err != nil {
		fail(err)
	}
	defer db.Close()
	if err := db.UpsertTarget(ctx, cfg.Domain, cfg.Target); err != nil {
		fail(err)
	}
	if err := tui.Run(ctx, cfg, db, version, dependencyReasons); err != nil && !errors.Is(err, tui.ErrQuit) {
		fail(err)
	}
}

// trustOptions builds the verification options for the LDAP preflight: the
// operator's explicit flag, plus the interactive certificate decision that lets
// an internal CA be approved for one run or remembered for this target.
//
// The decision handler is always installed. The approval store only controls
// whether a decision can be remembered, so a store that cannot be read or written
// must never remove the operator's ability to approve a certificate for the run.
func trustOptions(cfg config.Config, in io.Reader, out io.Writer) ldaptransport.Options {
	options := ldaptransport.Options{InsecureSkipVerify: cfg.InsecureSkipVerify}
	decider := &trust.Decider{In: in, Out: out}
	path, err := trust.DefaultPath()
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "[!] certificate approvals cannot be stored: %v; they can still be accepted for this run\n", err)
	default:
		store, loadErr := trust.Load(path)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "[!] %v; a certificate can still be accepted for this run, but not remembered\n", loadErr)
		} else {
			decider.Store = store
		}
	}
	options.CertificateTrust = decider.Decide
	return options
}

// trustTerminal reports where the certificate decision is asked and answered.
//
// The question is for the operator, so it must not depend on standard input
// being the keyboard: a run that supplies the password as a flag and redirects
// its input would otherwise have nobody able to approve the certificate, and the
// connection would fail with a trust error instead of asking. When there is no
// terminal at all the decision stays fail-closed - a certificate is never
// accepted without a person saying so.
func trustTerminal() (io.Reader, io.Writer) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return os.Stdin, os.Stderr
	}
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return os.Stdin, os.Stderr
	}
	return terminal, terminal
}

func fail(err error) { fmt.Fprintln(os.Stderr, "pwnflow:", err); os.Exit(1) }
