package checksec

import (
	"errors"
	"io/fs"

	"github.com/lorenzosaino/go-sysctl"
)

// sysctlValueMap maps a raw sysctl value (e.g. "0", "1", "2") to its Result.
type sysctlValueMap map[string]Result

type sysctlCheckDef struct {
	name   string
	desc   string
	values sysctlValueMap
}

var (
	onOff = sysctlValueMap{
		"0": {Value: "Disabled", Status: StatusBad},
		"1": {Value: "Enabled", Status: StatusGood},
	}
	offOn = sysctlValueMap{
		"1": {Value: "Disabled", Status: StatusBad},
		"0": {Value: "Enabled", Status: StatusGood},
	}
	tristate = sysctlValueMap{
		"0": {Value: "Disabled", Status: StatusBad},
		"1": {Value: "Partial", Status: StatusWarn},
		"2": {Value: "Enabled", Status: StatusGood},
	}
	bpfDisabled = sysctlValueMap{
		"0": {Value: "Disabled", Status: StatusBad},
		"1": {Value: "Enabled", Status: StatusGood},
		"2": {Value: "Enabled (Locked)", Status: StatusGood},
	}
)

var sysctlChecks = []sysctlCheckDef{
	{"fs.protected_symlinks", "Protected symlinks", onOff},
	{"fs.protected_hardlinks", "Protected hardlinks", onOff},
	{"net.ipv4.conf.all.rp_filter", "Ipv4 reverse path filtering", onOff},
	{"kernel.yama.ptrace_scope", "YAMA", onOff},
	{"kernel.exec-shield", "Exec Shield", onOff},
	{"kernel.unprivileged_bpf_disabled", "Unprivileged BPF Disabled", bpfDisabled},
	{"kernel.randomize_va_space", "Vanilla Kernel ASLR", tristate},
	{"kernel.dmesg_restrict", "Dmesg Restrictions", onOff},
	{"kernel.kptr_restrict", "Kernel Pointer Restrictions", tristate},
	{"fs.protected_fifos", "Protected fifos", tristate},
	{"fs.protected_regular", "Protected regular", tristate},
	{"kernel.perf_event_paranoid", "Performance events by normal users", sysctlValueMap{
		"-1": {Value: "Disabled", Status: StatusBad},
		"0":  {Value: "Disabled", Status: StatusBad},
		"1":  {Value: "Partial", Status: StatusWarn},
		"2":  {Value: "Enabled", Status: StatusGood},
		"3":  {Value: "Enabled", Status: StatusGood},
	}},
	{"dev.tty.ldisc_autoload", "Disable Autoload TTY Line Disciplines", offOn},
	{"dev.tty.legacy_tiocsti", "Disable Legacy TIOCSTI (breaks screen readers)", offOn},
	{"kernel.kexec_load_disabled", "Turn off kexec", onOff},
	{"net.core.bpf_jit_harden", "Turn on BPF JIT hardening", tristate},
	{"vm.unprivileged_userfaultfd", "Disable userfaultfd usage", offOn},
	{"fs.suid_dumpable", "Ensure suid binaries can't be dumped", sysctlValueMap{
		"2": {Value: "Disabled", Status: StatusBad},
		"1": {Value: "Partial", Status: StatusWarn},
		"0": {Value: "Enabled", Status: StatusGood},
	}},
}

// SysctlCheck reads each known security-relevant sysctl and returns its
// evaluated KernelCheck.
// resolveSysctlResult maps a raw sysctl read into a Result. A knob the kernel
// does not expose at all (kernel.exec-shield on modern kernels, or any sysctl
// on a system without /proc/sys) is reported as N/A rather than Unknown, so
// "not present" is not confused with "present but unreadable or unrecognized".
func resolveSysctlResult(raw string, err error, values sysctlValueMap) Result {
	if errors.Is(err, fs.ErrNotExist) {
		return Result{Value: "N/A", Status: StatusNA}
	}
	if err != nil || raw == "" {
		return Result{Value: "Unknown", Status: StatusNA}
	}
	if r, ok := values[raw]; ok {
		return r
	}
	return Result{Value: "Unknown", Status: StatusNA}
}

func SysctlCheck() []KernelCheck {
	results := make([]KernelCheck, 0, len(sysctlChecks))
	for _, s := range sysctlChecks {
		raw, err := sysctl.Get(s.name)
		results = append(results, KernelCheck{
			Name: s.name, Desc: s.desc, Type: "Sysctl",
			Result: resolveSysctlResult(raw, err, s.values),
		})
	}
	return results
}
