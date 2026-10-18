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
	var wrapped strings.Builder
	for lineIndex, line := range strings.Split(value, "\n") {
		if lineIndex > 0 {
			wrapped.WriteByte('\n')
		}
		if ansi.StringWidthWc(line) <= width || !strings.Contains(line, ",") {
			wrapped.WriteString(ansi.HardwrapWc(line, width, true))
			continue
		}
		current := ""
		for _, part := range strings.SplitAfter(line, ",") {
			if current != "" && ansi.StringWidthWc(current)+ansi.StringWidthWc(part) > width {
				wrapped.WriteString(ansi.HardwrapWc(current, width, true))
				wrapped.WriteByte('\n')
				current = ""
			}
			current += part
		}
		if current != "" {
			wrapped.WriteString(ansi.HardwrapWc(current, width, true))
		}
	}
	return wrapped.String()
}

func wrapPaneStyle(style lipgloss.Style, value string, width int) string {
	return style.Render(wrapPaneText(value, width))
}

func highlightOutput(input string) string {
	lines := strings.Split(input, "\n")
	for i, line := range lines {
		if styled, ok := styleWatcherLogPrefix(line); ok {
			lines[i] = styled
			continue
		}
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

// styleWatcherLogPrefix only recognizes a level at the beginning of a line or
// immediately after a timestamp. Arbitrary words later in command output are
// intentionally left alone.
func styleWatcherLogPrefix(line string) (string, bool) {
	leading := len(line) - len(strings.TrimLeft(line, " \t"))
	trimmed := line[leading:]
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return line, false
	}
	levelIndex := 0
	if strings.HasPrefix(fields[0], "[") && strings.HasSuffix(fields[0], "]") {
		levelIndex = 1
	} else if len(fields) > 2 && strings.Contains(fields[0], "-") && strings.Contains(fields[1], ":") {
		levelIndex = 2
	}
	if levelIndex >= len(fields) {
		return line, false
	}
	level := strings.Trim(fields[levelIndex], "[]:")
	style := watcherLogLevelStyle(level)
	if style == nil {
		return line, false
	}
	offset := leading
	for index := 0; index < levelIndex; index++ {
		position := strings.Index(trimmed[offset-leading:], fields[index])
		if position < 0 {
			return line, false
		}
		offset += position + len(fields[index])
		for offset < len(line) && (line[offset] == ' ' || line[offset] == '\t') {
			offset++
		}
	}
	levelStart := offset
	levelEnd := levelStart + len(fields[levelIndex])
	if levelEnd > len(line) {
		return line, false
	}
	prefix := line[:levelStart]
	if levelIndex == 2 || (levelIndex == 1 && strings.HasPrefix(fields[0], "[")) {
		prefix = dim.Render(prefix)
	}
	return prefix + style.Render(line[levelStart:levelEnd]) + line[levelEnd:], true
}

func watcherLogLevelStyle(level string) *lipgloss.Style {
	var style lipgloss.Style
	switch strings.ToUpper(level) {
	case "DEBUG":
		style = dim
	case "INFO":
		style = watcherInfoStyle
	case "WARN", "WARNING":
		style = warn
	case "ERROR", "FATAL":
		style = severityCriticalStyle
	case "SUCCESS":
		style = lipgloss.NewStyle().Foreground(green).Bold(true)
	default:
		return nil
	}
	return &style
}

func isPrintable(r rune) bool { return r == '\n' || r == '\r' || r == '\t' || !unicode.IsControl(r) }
