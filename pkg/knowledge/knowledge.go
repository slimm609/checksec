package knowledge

// Check is the machine-readable ground truth for one checksec check.
type Check struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Meaning     string   `json:"meaning"`
	Remediation string   `json:"remediation,omitempty"`
	Refs        []string `json:"refs,omitempty"`
}

// registry MUST cover every id in utils.FileFields (enforced by a test in
// package utils, which can import both without a cycle).
var registry = map[string]Check{
	"relro":          {ID: "relro", Name: "RELRO", Meaning: "GOT/data write protection.", Remediation: "link `-Wl,-z,relro,-z,now`"},
	"canary":         {ID: "canary", Name: "Stack Canary", Meaning: "Stack-smashing guard.", Remediation: "compile `-fstack-protector-strong`"},
	"cfi":            {ID: "cfi", Name: "CFI", Meaning: "Control-flow integrity for indirect calls.", Remediation: "build with `-fcf-protection` / `-fsanitize=cfi`"},
	"nx":             {ID: "nx", Name: "NX", Meaning: "Non-executable stack/heap."},
	"pie":            {ID: "pie", Name: "PIE", Meaning: "Position independence → ASLR for the executable.", Remediation: "`-fPIE -pie`"},
	"rpath":          {ID: "rpath", Name: "RPATH", Meaning: "Hard-coded library search path (hijack risk).", Remediation: "remove `-Wl,-rpath`"},
	"runpath":        {ID: "runpath", Name: "RUNPATH", Meaning: "Library search path (hijack risk).", Remediation: "remove `-Wl,-rpath` / audit RUNPATH"},
	"symbols":        {ID: "symbols", Name: "Symbols", Meaning: "Symbol table presence (aids reversing).", Remediation: "`strip` for release builds"},
	"safestack":      {ID: "safestack", Name: "SafeStack", Meaning: "Separate unsafe stack for buffers.", Remediation: "`-fsanitize=safe-stack`"},
	"stack_clash":    {ID: "stack_clash", Name: "Stack Clash", Meaning: "Stack-clash probing in prologues.", Remediation: "`-fstack-clash-protection`"},
	"separate_code":  {ID: "separate_code", Name: "W^X Seg", Meaning: "No writable+executable segment.", Remediation: "avoid RWX segments / `-Wl,-z,separate-code`"},
	"selfrando":      {ID: "selfrando", Name: "Selfrando", Meaning: "Function-level load randomization."},
	"sanitizers":     {ID: "sanitizers", Name: "Sanitizers", Meaning: "ASan/UBSan instrumentation present."},
	"fortify_level":  {ID: "fortify_level", Name: "FORTIFY Lvl", Meaning: "_FORTIFY_SOURCE level.", Remediation: "`-D_FORTIFY_SOURCE=3 -O2`"},
	"glibcxx_assert": {ID: "glibcxx_assert", Name: "GLIBCXX Assert", Meaning: "libstdc++ hardening assertions.", Remediation: "`-D_GLIBCXX_ASSERTIONS`"},
	"fortify_source": {ID: "fortify_source", Name: "FORTIFY", Meaning: "Fortified libc call substitution.", Remediation: "`-D_FORTIFY_SOURCE=2 -O2`"},
	"fortified":      {ID: "fortified", Name: "Fortified", Meaning: "Count of fortified call sites."},
	"fortifyable":    {ID: "fortifyable", Name: "Fortifiable", Meaning: "Count of fortifiable call sites."},
	"seccomp":        {ID: "seccomp", Name: "Seccomp", Meaning: "Process seccomp-bpf syscall filtering (proc mode)."},
	// Mach-O specific keys. Core keys (pie, nx, canary, ...) share the entries above.
	"signature":        {ID: "signature", Name: "Signature", Meaning: "Embedded code signature kind (structure only; trust is not verified).", Remediation: "`codesign -s <identity> --options runtime`"},
	"hardened_runtime": {ID: "hardened_runtime", Name: "Hardened Runtime", Meaning: "Blocks DYLD injection, unsigned dylibs and debugger attach.", Remediation: "`codesign --options runtime`"},
	"entitlements":     {ID: "entitlements", Name: "Entitlements", Meaning: "Entitlements that weaken the hardened runtime (get-task-allow, disable-library-validation, ...).", Remediation: "remove debug/injection entitlements from release signing"},
	"encrypted":        {ID: "encrypted", Name: "Encrypted", Meaning: "FairPlay-encrypted __TEXT (App Store builds)."},
	"fixups":           {ID: "fixups", Name: "Fixups", Meaning: "Chained fixups / bind-at-load: no writable lazy-pointer table (RELRO analogue).", Remediation: "target macOS 12+ or link `-Wl,-bind_at_load`"},
	"dyld_env":         {ID: "dyld_env", Name: "DYLD Env", Meaning: "LC_DYLD_ENVIRONMENT sets DYLD_* variables for the binary itself.", Remediation: "remove `-Wl,-dyld_env`"},
	"restrict":         {ID: "restrict", Name: "Restrict", Meaning: "__RESTRICT segment: dyld ignores DYLD_* variables (legacy)."},
	"arc":              {ID: "arc", Name: "ARC", Meaning: "Objective-C automatic reference counting.", Remediation: "compile `-fobjc-arc`"},
	"min_os":           {ID: "min_os", Name: "Min OS", Meaning: "Deployment target (platform and minimum version)."},
}

func Lookup(id string) (Check, bool) {
	c, ok := registry[id]
	return c, ok
}

// Present returns knowledge for the given ids in order, with a fallback entry
// for any id lacking a registry record.
func Present(ids []string) []Check {
	out := make([]Check, 0, len(ids))
	for _, id := range ids {
		if c, ok := registry[id]; ok {
			out = append(out, c)
		} else {
			out = append(out, Check{ID: id, Name: id, Meaning: "(no description available)"})
		}
	}
	return out
}
