package tui

import (
	"sync"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// registeredModuleKeys identifies the modules the current build registers, by
// name and tool, matching the rows RegisterModule keeps in the database.
var registeredModuleKeys = sync.OnceValue(func() map[string]bool {
	keys := map[string]bool{}
	for _, module := range RegisteredModules() {
		keys[module.Name()+"\x00"+module.Tool()] = true
	}
	return keys
})

// markRetiredSources flags Findings whose source module is no longer part of
// PwnFlow. They cannot be re-observed, so they are treated like Findings the
// latest run did not report again.
func markRetiredSources(rows []storage.Finding) []storage.Finding {
	keys := registeredModuleKeys()
	for index := range rows {
		row := &rows[index]
		if row.SourceModule == "" || keys[row.SourceModule+"\x00"+row.SourceModuleTool] {
			continue
		}
		row.SourceModuleRetired = true
		row.NotReobserved = true
	}
	return rows
}
