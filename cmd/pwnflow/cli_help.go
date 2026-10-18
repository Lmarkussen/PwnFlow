package main

import (
	_ "embed"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"
)

//go:embed banner.txt
var embeddedBanner string

type cliTheme struct{ enabled bool }

func newCLITheme(w io.Writer) cliTheme {
	file, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) || os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return cliTheme{}
	}
	return cliTheme{enabled: true}
}

func (t cliTheme) paint(value, code string) string {
	if !t.enabled || value == "" {
		return value
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func cliWidth(w io.Writer) int {
	if raw := os.Getenv("COLUMNS"); raw != "" {
		if width, err := strconv.Atoi(raw); err == nil && width > 0 {
			return width
		}
	}
	if file, ok := w.(*os.File); ok {
		if width, _, err := term.GetSize(int(file.Fd())); err == nil && width > 0 {
			return width
		}
	}
	return 100
}

func renderBanner(theme cliTheme, width int) string {
	banner := strings.TrimRight(embeddedBanner, "\n")
	if width < 1 {
		width = 1
	}
	for _, line := range strings.Split(banner, "\n") {
		if ansi.StringWidthWc(line) > width {
			return theme.paint("PwnFlow", "1;92")
		}
	}
	var lines []string
	for _, line := range strings.Split(banner, "\n") {
		lines = append(lines, theme.paint(line, "1;92"))
	}
	return strings.Join(lines, "\n")
}

func cliSection(theme cliTheme, name string) string {
	return theme.paint(name, "1;96")
}

func cliOption(theme cliTheme, name string) string {
	return theme.paint(name, "1;97")
}

func cliWarning(theme cliTheme, value string) string {
	return theme.paint(value, "1;93")
}

func cliError(theme cliTheme, value string) string {
	return theme.paint(value, "1;91")
}

func wrapCLI(value string, width int) []string {
	if width < 1 {
		width = 1
	}
	var lines []string
	for _, paragraph := range strings.Split(value, "\n") {
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}
		current := ""
		for _, word := range words {
			if current == "" {
				if ansi.StringWidthWc(word) > width {
					parts := strings.Split(ansi.HardwrapWc(word, width, true), "\n")
					lines = append(lines, parts[:len(parts)-1]...)
					current = parts[len(parts)-1]
				} else {
					current = word
				}
				continue
			}
			if ansi.StringWidthWc(current)+1+ansi.StringWidthWc(word) <= width {
				current += " " + word
				continue
			}
			lines = append(lines, current)
			current = word
		}
		if current != "" {
			lines = append(lines, current)
		}
	}
	return lines
}

func printFullHelp(w io.Writer) {
	theme := newCLITheme(w)
	width := cliWidth(w)
	fmt.Fprintln(w, renderBanner(theme, width))
	fmt.Fprintln(w)
	fmt.Fprintln(w, theme.paint("PwnFlow v"+version, "1;92"))
	for _, line := range wrapCLI("Active Directory Enumeration & Security Evidence", width) {
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, cliSection(theme, "USAGE"))
	for _, line := range wrapCLI("pwnflow --target ADDRESS --domain DOMAIN --username USER [OPTIONS]", maxCLI(1, width-2)) {
		fmt.Fprintf(w, "  %s\n", line)
	}
	fmt.Fprintln(w)
	printCLIOptions(w, theme, width, "CONNECTION", []cliHelpOption{
		{"--target ADDRESS", "Domain controller address or hostname"},
		{"--domain DOMAIN", "Active Directory domain"},
		{"--username USER", "Authentication username"},
		{"--password PASSWORD", "Password; avoid exposing credentials in shell history or shared systems"},
	})
	printCLIOptions(w, theme, width, "TRANSPORT", []cliHelpOption{
		{"--insecure-skip-verify", "Skip LDAPS/StartTLS certificate verification; use only when the target certificate cannot be validated"},
	})
	printCLIOptions(w, theme, width, "MODULE OPTIONS", []cliHelpOption{
		{"--module-options MODULE.KEY=VALUE", "Set one module option; repeat this flag for additional options"},
	})
	printCLIOptions(w, theme, width, "EVIDENCE & MAINTENANCE", []cliHelpOption{
		{"--reanalyze-latest", "Offline-analyze the latest supported saved artifacts; never starts modules"},
		{"--reset-findings", "Remove derived Findings history for this assessment; original artifacts remain"},
		{"--confirm-reset-findings", "Confirm the destructive --reset-findings operation"},
		{"--flushdb", "Reset assessment database records before starting; preserves raw evidence and writes a backup"},
	})
	printCLIOptions(w, theme, width, "HELP", []cliHelpOption{
		{"-h, --help", "Show this screen"},
	})
	fmt.Fprintln(w, cliSection(theme, "EXAMPLES"))
	for _, line := range wrapCLI("pwnflow --target 10.1.10.40 --domain sccm.lab --username USER", maxCLI(1, width-2)) {
		fmt.Fprintf(w, "  %s\n", line)
	}
	fmt.Fprintln(w)
	for _, line := range wrapCLI("Warning: --flushdb and --reset-findings can remove derived database state; review their safeguards before use.", maxCLI(1, width)) {
		fmt.Fprintln(w, cliWarning(theme, line))
	}
}

type cliHelpOption struct{ name, description string }

func printCLIOptions(w io.Writer, theme cliTheme, width int, heading string, options []cliHelpOption) {
	fmt.Fprintln(w, cliSection(theme, heading))
	nameWidth := 29
	if width < 70 {
		nameWidth = 24
	}
	for _, option := range options {
		name := cliOption(theme, option.name)
		plainNameWidth := ansi.StringWidthWc(option.name)
		if plainNameWidth > nameWidth || width < nameWidth+18 {
			fmt.Fprintf(w, "  %s\n", name)
			for _, line := range wrapCLI(option.description, maxCLI(1, width-4)) {
				fmt.Fprintf(w, "    %s\n", line)
			}
			continue
		}
		indent := strings.Repeat(" ", maxCLI(1, nameWidth-plainNameWidth))
		descriptionWidth := maxCLI(1, width-nameWidth-2)
		lines := wrapCLI(option.description, descriptionWidth)
		fmt.Fprintf(w, "  %s%s%s\n", name, indent, lines[0])
		for _, line := range lines[1:] {
			fmt.Fprintf(w, "  %s%s\n", strings.Repeat(" ", nameWidth), line)
		}
	}
	fmt.Fprintln(w)
}

func printShortUsage(w io.Writer) {
	theme := newCLITheme(w)
	width := cliWidth(w)
	fmt.Fprintln(w, renderBanner(theme, width))
	fmt.Fprintln(w)
	for _, line := range wrapCLI("PwnFlow — Active Directory Enumeration & Security Evidence", width) {
		fmt.Fprintln(w, theme.paint(line, "1;92"))
	}
	for _, line := range wrapCLI("Usage: pwnflow --target ADDRESS --domain DOMAIN --username USER [OPTIONS]", maxCLI(1, width)) {
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w, "Run 'pwnflow --help' for grouped options and examples.")
}

func configureCLIFlagSet() {
	flagSet := flag.CommandLine
	flagSet.SetOutput(os.Stderr)
	flagSet.Usage = func() { printFullHelp(os.Stderr) }
}

func hasHelpArgument(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

func maxCLI(left, right int) int {
	if left > right {
		return left
	}
	return right
}
