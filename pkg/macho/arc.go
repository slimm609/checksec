package macho

import (
	dm "debug/macho"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// arcRuntime are runtime entry points only ARC-compiled code calls directly;
// manual retain/release goes through objc_msgSend and never imports these.
var arcRuntime = map[string]bool{
	"_objc_release":                            true,
	"_objc_retain":                             true,
	"_objc_storeStrong":                        true,
	"_objc_autoreleaseReturnValue":             true,
	"_objc_retainAutoreleasedReturnValue":      true,
	"_objc_retainAutorelease":                  true,
	"_objc_retainAutoreleaseReturnValue":       true,
	"_objc_unsafeClaimAutoreleasedReturnValue": true,
}

// ARC reports Objective-C automatic reference counting. N/A without an
// __objc_imageinfo section (no Objective-C in the image).
func ARC(f *dm.File) *checksec.Result {
	if f.Section("__objc_imageinfo") == nil {
		return &checksec.Result{Value: "N/A", Status: checksec.StatusNA}
	}
	for _, name := range importedNames(f) {
		if arcRuntime[name] {
			return &checksec.Result{Value: "ARC", Status: checksec.StatusGood}
		}
	}
	return &checksec.Result{Value: "No ARC", Status: checksec.StatusWarn}
}
