package checksec

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/opencontainers/selinux/go-selinux"
	"github.com/slimm609/checksec/v3/pkg/output"
)

// kernelConfigCheck describes one CONFIG_* expectation.
type kernelConfigCheck struct {
	name   string
	arch   string
	expect string
	desc   string
}

var kernelConfigChecks = []kernelConfigCheck{
	{"CONFIG_COMPAT_BRK", "all", "y", "Kernel Heap Randomization"},
	{"CONFIG_STACKPROTECTOR", "all", "y", "Stack Protector"},
	{"CONFIG_STACKPROTECTOR_STRONG", "all", "y", "Stack Protector Strong"},
	{"CONFIG_CC_STACKPROTECTOR", "all", "y", "GCC Stack Protector"},
	{"CONFIG_CC_STACKPROTECTOR_REGULAR", "all", "y", "GCC Stack Protector Regular"},
	{"CONFIG_CC_STACKPROTECTOR_AUTO", "all", "y", "GCC Stack Protector Auto"},
	{"CONFIG_CC_STACKPROTECTOR_STRONG", "all", "y", "GCC Stack Protector Strong"},
	{"CONFIG_GCC_PLUGIN_STRUCTLEAK", "all", "y", "GCC structleak plugin"},
	{"CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL", "all", "y", "GCC structleak by ref plugin"},
	{"CONFIG_SLAB_FREELIST_RANDOM", "all", "y", "SLAB freelist randomization"},
	{"CPU_SW_DOMAIN_PAN", "all", "y", "Use CPU domains"},
	{"CONFIG_VMAP_STACK", "all", "y", "Virtually-mapped kernel stack"},
	{"CONFIG_STRICT_DEVMEM", "all", "y", "Restrict /dev/mem access"},
	{"CONFIG_STRICT_KERNEL_RWX", "all", "y", "Restrict Kernel RWX"},
	{"CONFIG_STRICT_MODULE_RWX", "all", "y", "Restrict Module RWX"},
	{"CONFIG_IO_STRICT_DEVMEM", "all", "y", "Restrict I/O access to /dev/mem"},
	{"CONFIG_REFCOUNT_FULL", "all", "y", "Full reference count validation"},
	{"CONFIG_HARDENED_USERCOPY", "all", "y", "Hardened Usercopy"},
	{"CONFIG_FORTIFY_SOURCE", "all", "y", "Harden str/mem functions"},
	{"CONFIG_DEVKMEM", "all", "y", "Restrict /dev/kmem access"},
	{"CONFIG_DEBUG_STRICT_USER_COPY_CHECKS", "amd", "y", "Strict user copy checks"},
	{"CONFIG_ARM_KERNMEM_PERMS", "arm", "y", "Restrict kernel memory permissions"},
	{"CONFIG_DEBUG_ALIGN_RODATA", "all", "y", "Make rodata strictly non-excutable"},
	{"CONFIG_UNMAP_KERNEL_AT_EL0", "arm64", "y", "Unmap kernel in userspace (KAISER)"},
	{"CONFIG_HARDEN_BRANCH_PREDICTOR", "arm64", "y", "Harden branch predictor"},
	{"CONFIG_HARDEN_EL2_VECTORS", "arm64", "y", "Harden EL2 vector mapping"},
	{"CONFIG_ARM64_SSBD", "arm64", "y", "Speculative store bypass disable"},
	{"CONFIG_ARM64_SW_TTBR0_PAN", "arm64", "y", "Emulate privileged access never"},
	{"CONFIG_RANDOMIZE_BASE", "arm64", "y", "Randomize address of kernel image"},
	{"CONFIG_RANDOMIZE_MODULE_REGION_FULL", "arm64", "y", "Randomize module region over 4GB"},
	{"CONFIG_DEBUG_WX", "all", "y", "Report dangerous memory permissions"},
	{"CONFIG_SYN_COOKIES", "all", "y", "Syn Flood protection"},
	{"CONFIG_LIST_HARDENED", "all", "y", "Check integrity of linked list manipulation"},
	{"CONFIG_DEBUG_NOTIFIERS", "all", "y", "Debug notifier call chains"},
	{"CONFIG_DEBUG_LIST", "all", "y", "Debug linked list manipulation"},
	{"CONFIG_DEBUG_SG", "all", "y", "Debug SG table operations"},
	{"CONFIG_DEBUG_VIRTUAL", "all", "y", "Debug VM translations"},
	{"CONFIG_SCHED_STACK_END_CHECK", "all", "y", "Detect stack corruption on calls to schedule"},
	{"CONFIG_SECCOMP", "all", "y", "Safely execute untrusted bytecode"},
	{"CONFIG_SECCOMP_FILTER", "all", "y", "Secure computing for BPF"},
	{"CONFIG_LDISC_AUTOLOAD", "all", "is not set", "Automatically load TTY Line Disciplines"},
	{"CONFIG_SECURITY", "all", "y", "Enable different security models"},
	{"CONFIG_SECURITY_YAMA", "all", "y", "Security Yama support"},
	{"CONFIG_SECURITY_LANDLOCK", "all", "y", "Security Landlock support"},
	{"CONFIG_SECURITY_SELINUX", "all", "y", "SELinux Kernel Flag"},
	{"CONFIG_SECURITY_SELINUX_BOOTPARAM", "all", "is not set", "Allow disabling selinux at boot"},
	{"CONFIG_SECURITY_SELINUX_DEVELOP", "all", "is not set", "SELinux Development Support"},
	{"CONFIG_SECURITY_SELINUX_DEBUG", "all", "is not set", "SELinux Debug Support"},
	{"CONFIG_SECURITY_LOCKDOWN_LSM", "all", "y", "Enable the lockdown LSM"},
	{"CONFIG_SECURITY_LOCKDOWN_LSM_EARLY", "all", "y", "Enable the lockdown LSM early in boot"},
	{"CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY", "all", "y", "kernel runs in confidentiality mode"},
	{"CONFIG_HARDENED_USERCOPY_FALLBACK", "all", "is not set", "Allow usercopy whitelist violations to fallback to object size"},
	{"CONFIG_HARDENED_USERCOPY_PAGESPAN", "all", "is not set", "Refuse to copy allocations that span multiple pages"},
}

// KernelConfig parses the kernel config at name and returns a KernelCheck for
// every known CONFIG_* key present in it, plus the runtime SELinux status.
func KernelConfig(name string) []KernelCheck {
	data, err := parseKernelConfig(name)
	if err != nil {
		output.Fatalf("Error parsing kernel config: %v", err)
	}

	var results []KernelCheck
	for _, k := range kernelConfigChecks {
		val, present := data[k.name]
		if !present {
			continue
		}
		res := Result{Value: "Disabled", Status: StatusBad}
		if val == k.expect {
			res = Result{Value: "Enabled", Status: StatusGood}
		}
		results = append(results, KernelCheck{
			Name: k.name, Desc: k.desc, Type: "Kernel Config", Result: res,
		})
	}

	se := Result{Value: "Disabled", Status: StatusBad}
	if selinux.GetEnabled() {
		se = Result{Value: "Enabled", Status: StatusGood}
	}
	results = append(results, KernelCheck{
		Name: "SELinux", Desc: "SELinux Enabled", Type: "SELinux", Result: se,
	})

	return results
}

func parseKernelConfig(filename string) (map[string]string, error) {
	stat, err := os.Stat(filename)
	var bytes []byte
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("Not a file: %s", filename)
	}
	if strings.HasSuffix(filename, ".gz") {
		file, err := os.Open(filename)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		reader, err := gzip.NewReader(file)
		if err != nil {
			log.Fatal(err)
		}
		defer reader.Close()

		bytes, err = io.ReadAll(reader)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		bytes, err = os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
	}

	options := make(map[string]string)

	scanner := bufio.NewScanner(strings.NewReader(string(bytes)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "CONFIG_") {
			split := strings.Split(line, "=")
			options[split[0]] = strings.TrimPrefix(line, fmt.Sprintf("%s=", split[0]))
		} else if strings.HasPrefix(line, "# CONFIG_") && strings.HasSuffix(scanner.Text(), "is not set") {
			opt := strings.TrimPrefix(line, "# ")
			opt = strings.TrimSuffix(opt, " is not set")
			options[opt] = "is not set"
		}
	}

	return options, nil
}
