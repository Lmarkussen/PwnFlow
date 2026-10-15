package tui

import (
	"strings"
	"unicode"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func safeANSI(input string) string {
	var out strings.Builder
	for i := 0; i < len(input); {
		if input[i] != 0x1b {
			r := rune(input[i])
			if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 {
				out.WriteByte(input[i])
			}
			i++
			continue
		}
		if i+1 >= len(input) {
			break
		}
		if input[i+1] == '[' {
			end := i + 2
			for end < len(input) && (input[end] < 0x40 || input[end] > 0x7e) {
				end++
			}
			if end < len(input) && input[end] == 'm' {
				out.WriteString(input[i : end+1])
			}
			i = end + 1
			continue
		}
		if input[i+1] == ']' {
			i += 2
			for i < len(input) && input[i] != 0x07 {
				if input[i] == 0x1b && i+1 < len(input) && input[i+1] == '\\' {
					i += 2
					break
				}
				i++
			}
			if i < len(input) {
				i++
			}
			continue
		}
		i += 2
	}
	return out.String()
}

func displayOutput(raw string, width int) string {
	clean := safeANSI(raw)
	if ansi.Strip(clean) == clean {
		clean = highlightOutput(clean)
	}
	return wrapWatcherOutput(clean, width)
}

func wrapPaneText(value string, width int) string {
	if width < 1 {
		width = 1
	}
	return ansi.HardwrapWc(value, width, true)
}

func wrapPaneStyle(style lipgloss.Style, value string, width int) string {
	return style.Render(wrapPaneText(value, width))
}

func highlightOutput(input string) string {
	lines := strings.Split(input, "\n")
	for i, line := range lines {
		if strings.Contains(line, "[+]") {
			lines[i] = strings.ReplaceAll(line, "[+]", lipgloss.NewStyle().Foreground(green).Render("[+]"))
		} else if strings.Contains(line, "[-]") {
			lines[i] = strings.ReplaceAll(line, "[-]", lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5C5C")).Render("[-]"))
		} else if strings.Contains(line, "[*]") {
			lines[i] = strings.ReplaceAll(line, "[*]", lipgloss.NewStyle().Foreground(lipgloss.Color("#FFC857")).Render("[*]"))
		}
	}
	return strings.Join(lines, "\n")
}

func isPrintable(r rune) bool { return r == '\n' || r == '\r' || r == '\t' || !unicode.IsControl(r) }
