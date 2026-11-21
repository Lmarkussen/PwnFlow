package tui

import (
	"fmt"
	"html"
	"regexp"
	"strings"
)

var (
	htmlBold     = regexp.MustCompile(`\*\*(.+?)\*\*`)
	htmlCode     = regexp.MustCompile("`([^`]+)`")
	htmlLink     = regexp.MustCompile(`\[([^\]]+)\]\((https://[^)\s]+)\)`)
	htmlSeverity = regexp.MustCompile(`\[(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)\]`)
	htmlOrdered  = regexp.MustCompile(`^(\d+)\. (.*)$`)
	htmlAnchor   = regexp.MustCompile(`[^a-z0-9]+`)
)

// reportHTML renders the Markdown report as one self-contained HTML page. It
// understands exactly the Markdown RenderReport writes - headings, tables,
// nested lists, bold, inline code and https links - and escapes every value,
// so text taken from Findings cannot add markup.
func reportHTML(markdown, title string) string {
	var body strings.Builder
	var toc []string
	lines := strings.Split(markdown, "\n")
	listDepth := 0
	closeLists := func(depth int) {
		for listDepth > depth {
			body.WriteString("</ul>\n")
			listDepth--
		}
	}
	anchors := map[string]int{}
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			closeLists(0)
		case strings.HasPrefix(line, "#"):
			closeLists(0)
			level := len(line) - len(strings.TrimLeft(line, "#"))
			text := strings.TrimSpace(line[level:])
			anchor := htmlAnchor.ReplaceAllString(strings.ToLower(text), "-")
			anchors[anchor]++
			if anchors[anchor] > 1 {
				anchor = fmt.Sprintf("%s-%d", anchor, anchors[anchor])
			}
			fmt.Fprintf(&body, "<h%d id=\"%s\">%s</h%d>\n", level, anchor, htmlInline(text), level)
			if level == 2 || level == 3 {
				toc = append(toc, fmt.Sprintf("<li class=\"toc%d\"><a href=\"#%s\">%s</a></li>", level, anchor, htmlInline(text)))
			}
		case strings.HasPrefix(trimmed, "|"):
			closeLists(0)
			body.WriteString("<table>\n")
			header := true
			for ; index < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[index]), "|"); index++ {
				cells := splitTableRow(strings.TrimSpace(lines[index]))
				if len(cells) > 0 && strings.Trim(strings.Join(cells, ""), "-: ") == "" {
					continue
				}
				tag := "td"
				if header {
					tag = "th"
				}
				body.WriteString("<tr>")
				for _, cell := range cells {
					fmt.Fprintf(&body, "<%s>%s</%s>", tag, htmlInline(cell), tag)
				}
				body.WriteString("</tr>\n")
				header = false
			}
			index--
			body.WriteString("</table>\n")
		case strings.HasPrefix(trimmed, "- ") || htmlOrdered.MatchString(trimmed):
			indent := len(line) - len(strings.TrimLeft(line, " "))
			depth := 1 + indent/2
			for listDepth < depth {
				body.WriteString("<ul>\n")
				listDepth++
			}
			closeLists(depth)
			item := strings.TrimPrefix(trimmed, "- ")
			if match := htmlOrdered.FindStringSubmatch(trimmed); match != nil {
				item = match[1] + ". " + match[2]
			}
			fmt.Fprintf(&body, "<li>%s</li>\n", htmlInline(item))
		default:
			closeLists(0)
			fmt.Fprintf(&body, "<p>%s</p>\n", htmlInline(trimmed))
		}
	}
	closeLists(0)
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(title) + `</title>
<style>
:root{--bg:#ffffff;--fg:#1d2433;--muted:#5b6475;--line:#d9dee7;--panel:#f5f7fa;--link:#1f5fbf;--crit:#a3122c;--high:#c2410c;--med:#a16207;--low:#2563eb;--info:#5b6475}
@media (prefers-color-scheme: dark){:root{--bg:#11151c;--fg:#e4e8ef;--muted:#9aa4b5;--line:#2a3140;--panel:#181e28;--link:#7fb0ff;--crit:#ff6b81;--high:#ff9a5c;--med:#f2c94c;--low:#7fb0ff;--info:#9aa4b5}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 64px}nav{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:16px 0}
nav ul{margin:0;padding-left:18px}.toc3{margin-left:16px;font-size:14px}h1{font-size:26px;margin:8px 0}h2{font-size:21px;margin-top:36px;border-bottom:1px solid var(--line);padding-bottom:6px}
h3{font-size:17px;margin-top:24px}h4{font-size:15px;margin-top:18px;color:var(--muted)}a{color:var(--link);word-break:break-word}
table{border-collapse:collapse;margin:8px 0}th,td{border:1px solid var(--line);padding:4px 10px;text-align:left}th{background:var(--panel)}
ul{padding-left:20px}li{margin:3px 0}code{background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:0 4px;font-size:13px;word-break:break-all}
.sev{font-weight:700;border-radius:4px;padding:0 6px;font-size:12px;letter-spacing:.02em}.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low{color:var(--low)}.sev-informational{color:var(--info)}
</style></head><body><main>
<nav><strong>Contents</strong><ul>` + strings.Join(toc, "") + `</ul></nav>
` + body.String() + `</main></body></html>
`
}

// htmlInline escapes a Markdown fragment and then applies the inline markup
// RenderReport uses. reportText already turned < and > into entities, so
// they are restored before escaping to avoid double escaping.
func htmlInline(text string) string {
	text = strings.NewReplacer("&lt;", "<", "&gt;", ">", `\|`, "|").Replace(text)
	text = html.EscapeString(text)
	text = htmlLink.ReplaceAllString(text, `<a href="$2" rel="noopener noreferrer">$1</a>`)
	text = htmlBold.ReplaceAllString(text, "<strong>$1</strong>")
	text = htmlCode.ReplaceAllString(text, "<code>$1</code>")
	return htmlSeverity.ReplaceAllStringFunc(text, func(match string) string {
		level := strings.ToLower(strings.Trim(match, "[]"))
		return `<span class="sev sev-` + level + `">` + strings.ToUpper(level) + `</span>`
	})
}

// splitTableRow splits a Markdown table row on unescaped pipes.
func splitTableRow(row string) []string {
	row = strings.TrimSuffix(strings.TrimPrefix(row, "|"), "|")
	var cells []string
	var cell strings.Builder
	for index := 0; index < len(row); index++ {
		if row[index] == '\\' && index+1 < len(row) && row[index+1] == '|' {
			cell.WriteString(`\|`)
			index++
			continue
		}
		if row[index] == '|' {
			cells = append(cells, strings.TrimSpace(cell.String()))
			cell.Reset()
			continue
		}
		cell.WriteByte(row[index])
	}
	return append(cells, strings.TrimSpace(cell.String()))
}
