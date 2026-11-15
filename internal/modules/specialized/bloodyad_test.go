package specialized

import (
	"context"
	"fmt"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBloodyADWritableCommand(t *testing.T) {
	r := &modules.Runtime{Target: "192.0.2.1", Domain: "example.test", Username: "lab", Password: "secret"}
	want := []string{"-H", r.Target, "-d", r.Domain, "-u", r.Username, "-p", r.Password, "get", "writable", "--detail"}
	for _, m := range Modules() {
		if m.ID() != "bloodyad-writable" {
			continue
		}
		if !reflect.DeepEqual(m.definition.Args(r, ""), want) {
			t.Fatal(m.definition.Args(r, ""))
		}
		if strings.Contains(m.CommandPreview(r), r.Password) {
			t.Fatal("password in preview")
		}
		if !m.ReadOnly() {
			t.Fatal("not read only")
		}
		bin := t.TempDir()
		for _, executable := range []string{"bloodyAD", "bloodyad"} {
			if err := os.WriteFile(filepath.Join(bin, executable), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("PATH", bin)
		if m.Check(context.Background(), r) == nil {
			t.Fatal("unusable dependency accepted")
		}
		return
	}
	t.Fatal("missing registration")
}

func TestBloodyADRunnerPreservesDetailAndFailureStatus(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			bin := t.TempDir()
			output := "distinguishedName: CN=Lab,DC=example,DC=test\nservicePrincipalName: WRITE\nuser: CREATE_CHILD"
			script := "#!/bin/sh\ncase \"$*\" in *--help*) echo --detail;exit 0;; esac\necho '" + output + "'\necho 'diagnostic: synthetic-secret'\n"
			if failed {
				script += "exit 1\n"
			}
			if err := os.WriteFile(filepath.Join(bin, "bloodyAD"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin)
			for _, m := range Modules() {
				if m.ID() != "bloodyad-writable" {
					continue
				}
				r := &modules.Runtime{Target: "192.0.2.1", Domain: "example.test", Username: "lab", Password: "synthetic-secret", ResultsRoot: t.TempDir()}
				result := (runner.Runner{Secrets: []string{r.Password}}).Execute(context.Background(), m, r, r.ResultsRoot)
				want := "completed"
				if failed {
					want = "failed"
				}
				if result.Status != want {
					t.Fatalf("%+v", result)
				}
				data, err := os.ReadFile(result.OutputPath)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(data), output) || strings.Contains(string(data), r.Password) {
					t.Fatal(string(data))
				}
				return
			}
			t.Fatal("missing registration")
		})
	}
}
