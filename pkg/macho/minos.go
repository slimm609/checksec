package macho

import (
	dm "debug/macho"
	"fmt"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// formatVersion renders the X.Y.Z packed as 0xXXXXYYZZ, omitting a zero patch.
func formatVersion(v uint32) string {
	major, minor, patch := v>>16, (v>>8)&0xff, v&0xff
	if patch == 0 {
		return fmt.Sprintf("%d.%d", major, minor)
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

// platformName maps LC_BUILD_VERSION platform ids from <mach-o/loader.h>.
func platformName(p uint32) string {
	names := map[uint32]string{
		1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS",
		6: "macCatalyst", 7: "iOS Simulator", 8: "tvOS Simulator",
		9: "watchOS Simulator", 10: "DriverKit", 11: "visionOS", 12: "visionOS Simulator",
	}
	if n, ok := names[p]; ok {
		return n
	}
	return fmt.Sprintf("platform %d", p)
}

// MinOS reports the deployment target from LC_BUILD_VERSION, falling back to
// the legacy LC_VERSION_MIN_* commands. Always informational.
func MinOS(f *dm.File) *checksec.Result {
	if l, ok := findLoad(f, lcBuildVersion); ok {
		if len(l.Data) < 24 { // build_version_command: cmd, cmdsize, platform, minos, sdk, ntools
			return &checksec.Result{Value: "Unknown", Status: checksec.StatusWarn}
		}
		plat := f.ByteOrder.Uint32(l.Data[8:12])
		minos := f.ByteOrder.Uint32(l.Data[12:16])
		return &checksec.Result{Value: platformName(plat) + " " + formatVersion(minos), Status: checksec.StatusInfo}
	}
	legacy := []struct {
		cmd  uint32
		plat uint32
	}{
		{lcVersionMinMacOSX, 1}, {lcVersionMinIPhone, 2}, {lcVersionMinTvOS, 3}, {lcVersionMinWatchOS, 4},
	}
	for _, c := range legacy {
		if l, ok := findLoad(f, c.cmd); ok {
			if len(l.Data) < 16 { // version_min_command: cmd, cmdsize, version, sdk
				return &checksec.Result{Value: "Unknown", Status: checksec.StatusWarn}
			}
			return &checksec.Result{Value: platformName(c.plat) + " " + formatVersion(f.ByteOrder.Uint32(l.Data[8:12])), Status: checksec.StatusInfo}
		}
	}
	return &checksec.Result{Value: "Unknown", Status: checksec.StatusWarn}
}
