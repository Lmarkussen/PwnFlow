package tui

import (
	"context"
	"reflect"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

type namedNetExecModule struct {
	selectionModule
	moduleName string
}

func (m namedNetExecModule) ModuleName() string { return m.moduleName }

func TestToolRunnerSortsOrdinaryToolsAndNetExecModulesTogether(t *testing.T) {
	log := &executionLog{}
	registered := []modules.Module{
		selectionModule{id: "zulu", name: "Get this", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log},
		namedNetExecModule{selectionModule: selectionModule{id: "alpha", name: "Find something", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log}, moduleName: "alpha"},
		selectionModule{id: "bravo", name: "find user", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log},
		namedNetExecModule{selectionModule: selectionModule{id: "charlie", name: "Get that", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log}, moduleName: "charlie"},
		selectionModule{id: "same-z", name: "Same", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log},
		namedNetExecModule{selectionModule: selectionModule{id: "same-a", name: "same", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log}, moduleName: "same-a"},
	}
	ids := []int64{1, 2, 3, 4, 5, 6}
	model := newModel(context.Background(), testConfig(t), nil, registered, ids, 1, "test")
	model.toolFamilyIndex = 0
	model.categoryIndex = 0
	model.protocolIndex = 0
	model.filterModules()
	got := make([]string, len(model.modules))
	for index, module := range model.modules {
		got[index] = module.Name()
	}
	want := []string{"Find something", "find user", "Get that", "Get this", "same", "Same"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Tool Runner order=%v, want %v", got, want)
	}
	if model.moduleKeys[0] != 1 || model.moduleKeys[2] != 3 {
		t.Fatalf("selection identity was not remapped with sorted rows: %v", model.moduleKeys)
	}
}
