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

	results, colors := KernelConfig(fixture)

	if len(results) == 0 {
		t.Fatal("KernelConfig() returned no results")
	}
	if len(results) != len(colors) {
		t.Fatalf("results length %d != colors length %d", len(results), len(colors))
	}

	for i, r := range results {
		m, ok := r.(map[string]interface{})
		if !ok {
			t.Errorf("result[%d] is %T, want map[string]interface{}", i, r)
			continue
		}
		if len(m) == 0 {
			t.Errorf("result[%d] map is empty", i)
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

	results, colors := KernelConfig(gzPath)
	if len(results) != len(colors) {
		t.Fatalf("results length %d != colors length %d", len(results), len(colors))
	}
	if len(results) == 0 {
		t.Error("expected non-empty results from gzipped config")
	}
}
