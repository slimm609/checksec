// pkg/utils/report_format_test.go
package utils

import (
	"os"
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/target"
)

const machoFixtureDir = "../../tests/binaries/output/macho"

func requireMachoFixture(t *testing.T, name string) string {
	t.Helper()
	p := machoFixtureDir + "/" + name
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture %q missing: %v", name, err)
	}
	return p
}

func TestRunPathChecks_ELFReportCarriesFormat(t *testing.T) {
	bin := buildLinuxELF(t)
	reports := RunPathChecks(bin, "")
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want 1", len(reports))
	}
	r := reports[0]
	if r.Format != string(target.ELF) || r.Arch != "" || r.Name != bin {
		t.Errorf("unexpected report header: format=%q arch=%q name=%q", r.Format, r.Arch, r.Name)
	}
	for _, f := range ELFFields {
		if _, ok := r.Checks[f.Key]; !ok {
			t.Errorf("missing ELF field %q", f.Key)
		}
	}
}

func TestRunPathChecks_FatYieldsOneReportPerSlice(t *testing.T) {
	p := requireMachoFixture(t, "fat")
	reports := RunPathChecks(p, "")
	if len(reports) != 2 {
		t.Fatalf("got %d reports, want 2", len(reports))
	}
	for _, r := range reports {
		if r.Format != string(target.MachO) {
			t.Errorf("format = %q, want macho", r.Format)
		}
		if !strings.HasPrefix(r.Name, p+" [") || !strings.HasSuffix(r.Name, "]") {
			t.Errorf("fat slice name %q must be '<path> [<arch>]'", r.Name)
		}
		if r.Arch == "" || !strings.Contains(r.Name, "["+r.Arch+"]") {
			t.Errorf("arch %q not reflected in name %q", r.Arch, r.Name)
		}
		if r.Exploitability != nil {
			t.Error("exploitability must stay nil on Mach-O")
		}
	}
	if reports[0].Arch == reports[1].Arch {
		t.Errorf("slices must differ in arch: %q", reports[0].Arch)
	}
}

func TestRunPathChecks_ThinMachOKeepsPlainName(t *testing.T) {
	p := requireMachoFixture(t, "exec_arm64")
	reports := RunPathChecks(p, "", WithExploit())
	if len(reports) != 1 || reports[0].Name != p || reports[0].Format != string(target.MachO) || reports[0].Arch != "arm64" {
		t.Fatalf("unexpected: %+v", reports)
	}
	if reports[0].Exploitability != nil {
		t.Error("--exploit must not attach to Mach-O")
	}
}

func TestRunPathChecks_UnknownFormatUsesELFFieldsAsErr(t *testing.T) {
	p := t.TempDir() + "/plain.txt"
	if err := os.WriteFile(p, []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	reports := RunPathChecks(p, "")
	if len(reports) != 1 || reports[0].Format != string(target.Unknown) {
		t.Fatalf("unexpected: %+v", reports)
	}
	for _, f := range ELFFields {
		res, ok := reports[0].Checks[f.Key]
		if !ok {
			t.Errorf("field %q missing on unknown format", f.Key)
			continue
		}
		// fortified / fortifyable report "N/A" on the error path (existing
		// behavior); every other field must be an Err result.
		if f.Key == "fortified" || f.Key == "fortifyable" {
			if res.Value != "N/A" {
				t.Errorf("field %q = %+v, want N/A", f.Key, res)
			}
			continue
		}
		if !strings.HasPrefix(res.Value, "Error checking") {
			t.Errorf("field %q should be Err on unknown format, got %+v", f.Key, res)
		}
	}
}

func TestFieldsFor(t *testing.T) {
	if got := FieldsFor(target.ELF); len(got) != len(ELFFields) {
		t.Errorf("ELF: got %d fields", len(got))
	}
	if got := FieldsFor(target.Unknown); len(got) != len(ELFFields) {
		t.Errorf("Unknown must fall back to ELF fields")
	}
	if got := FieldsFor(target.Format("")); len(got) != len(ELFFields) {
		t.Errorf("empty format (legacy reports) must fall back to ELF fields")
	}
	if FileFields[0].Key != ELFFields[0].Key || len(FileFields) != len(ELFFields) {
		t.Error("FileFields must alias ELFFields")
	}
}

func TestAllFields_UnionDedupedInOrder(t *testing.T) {
	all := AllFields()
	seen := map[string]bool{}
	for _, f := range all {
		if seen[f.Key] {
			t.Errorf("duplicate key %q in AllFields", f.Key)
		}
		seen[f.Key] = true
	}
	for i, f := range ELFFields {
		if all[i].Key != f.Key {
			t.Fatalf("AllFields[%d] = %q, want ELF field %q first", i, all[i].Key, f.Key)
		}
	}
	for _, f := range MachOFields {
		if !seen[f.Key] {
			t.Errorf("Mach-O key %q missing from AllFields", f.Key)
		}
	}
}
