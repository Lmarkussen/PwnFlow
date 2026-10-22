package tui

const helpText = "Navigation: Arrows to move around · Space=Select · Ctrl+F=Findings · Ctrl+R=Run Selected Modules · Ctrl+A=Run Default Enumeration · Ctrl+X=Abort All · Tab=Focus · Ctrl+W=Watcher · Q=Quit"

// shortHelpText is what the module pane falls back to when the terminal is too
// short for the full hint: the rows the operator navigates are worth more than
// the last few words of the footer.
const shortHelpText = "Arrows Move · Space Select · ^F Findings · ^R Run · ^A Default · ^X Abort All · Tab Focus · ^W Watcher · Q Quit"

const minimalHelpText = "^X Abort All · Q Quit"
