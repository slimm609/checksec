package utils

import (
	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// Function indirections for testability
var (
	kernelConfigFn = checksec.KernelConfig
	sysctlCheckFn  = checksec.SysctlCheck
)

// ParseKernel parses the kernel config at filename and returns the combined
// kernel-config + sysctl checks.
func ParseKernel(filename string) []checksec.KernelCheck {
	return append(kernelConfigFn(filename), sysctlCheckFn()...)
}
