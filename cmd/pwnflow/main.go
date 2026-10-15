package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/ldaptransport"
	"github.com/pwnflow/pwnflow/internal/password"
	"github.com/pwnflow/pwnflow/internal/preflight"
	"github.com/pwnflow/pwnflow/internal/storage"
	"github.com/pwnflow/pwnflow/internal/tui"
	"golang.org/x/term"
)

var version = "0.1.0"

func main() {
	target := flag.String("target", "", "target address or hostname")
	domain := flag.String("domain", "", "Active Directory domain")
	username := flag.String("username", "", "username")
	passwordFlag := flag.String("password", "", "password (avoid on shared systems)")
	insecureSkipVerify := flag.Bool("insecure-skip-verify", false, "skip LDAPS/StartTLS certificate verification (only when the target certificate cannot be validated)")
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

	root, err := config.ProjectRoot()
	if err != nil {
		fail(err)
	}
	cfg, err := config.New(*target, *domain, *username, passwordValue, root)
	if err != nil {
		fail(err)
	}
	cfg.InsecureSkipVerify = *insecureSkipVerify
	connection, err := preflight.Run(ctx, cfg)
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

func fail(err error) { fmt.Fprintln(os.Stderr, "pwnflow:", err); os.Exit(1) }
