package checksec

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestKernelConfig_ValidConfig(t *testing.T) {
	fixture := "../../tests/kernel.config"
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("kernel.config fixture not found: %v", err)
	}

	results := KernelConfig(fixture)
	if len(results) == 0 {
		t.Fatal("KernelConfig() returned no results")
	}
	for i, r := range results {
		if r.Name == "" || r.Desc == "" || r.Type == "" {
			t.Errorf("result[%d] has empty metadata: %+v", i, r)
		}
		if r.Result.Value == "" || r.Result.Status == "" {
			t.Errorf("result[%d] has empty result: %+v", i, r)
		}
	}
}

func TestKernelConfig_NonExistentFile(t *testing.T) {
	t.Skip("KernelConfig calls os.Exit(1) on missing file — not testable without process isolation")
}

func TestKernelConfig_GzippedConfig(t *testing.T) {
	gzPath := filepath.Join(t.TempDir(), "kernel.config.gz")

	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatalf("create gz: %v", err)
	}
	gw, err := gzip.NewWriterLevel(f, gzip.BestSpeed)
	if err != nil {
		f.Close()
		t.Fatalf("gzip writer: %v", err)
	}
	_, err = gw.Write([]byte("CONFIG_STACKPROTECTOR=y\n# CONFIG_DEVKMEM is not set\n"))
	gw.Close()
	f.Close()
	if err != nil {
		t.Fatalf("write gzip: %v", err)
	}

	results := KernelConfig(gzPath)
	if len(results) == 0 {
		t.Error("expected non-empty results from gzipped config")
	}
	var found bool
	for _, r := range results {
		if r.Name == "CONFIG_STACKPROTECTOR" && r.Result.Value == "Enabled" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CONFIG_STACKPROTECTOR=Enabled in results, got %+v", results)
	}
}
