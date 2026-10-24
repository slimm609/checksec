package utils

import "github.com/slimm609/checksec/v3/pkg/macho"

func init() {
	MachOFields = []Field{
		{"pie", "PIE", runMachO("PIE", macho.PIE)},
		{"nx", "NX", runMachO("NX", macho.NX)},
		{"canary", "Stack Canary", runMachO("canary", macho.Canary)},
		{"symbols", "Symbols", runMachO("SYMBOLS", macho.Symbols)},
		{"rpath", "RPATH", runMachO("RPATH", macho.RPATH)},
		{"separate_code", "W^X Seg", runMachO("SeparateCode", macho.SeparateCode)},
		{"cfi", "CFI", runMachO("CFI", macho.CFI)},
		{"fortify_source", "FORTIFY", runMachO("Fortify", macho.FortifySource)},
		{"sanitizers", "Sanitizers", runMachO("Sanitizers", macho.Sanitizers)},
		{"signature", "Signature", runMachO("Signature", macho.Signature)},
		{"hardened_runtime", "Hardened", runMachO("HardenedRuntime", macho.HardenedRuntime)},
		{"entitlements", "Entitlements", runMachO("Entitlements", macho.Entitlements)},
		{"encrypted", "Encrypted", runMachO("Encrypted", macho.Encrypted)},
		{"fixups", "Fixups", runMachO("Fixups", macho.Fixups)},
		{"dyld_env", "DYLD Env", runMachO("DyldEnv", macho.DyldEnv)},
		{"restrict", "Restrict", runMachO("Restrict", macho.Restrict)},
		{"arc", "ARC", runMachO("ARC", macho.ARC)},
		{"min_os", "Min OS", runMachO("MinOS", macho.MinOS)},
	}
}
