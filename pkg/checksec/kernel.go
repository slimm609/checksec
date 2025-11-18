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
	"github.com/slimm609/checksec/v3/pkg/utils"
)

func KernelConfig(name string) ([]interface{}, []interface{}) {
	var Results []interface{}
	var ColorResults []interface{}
	var Secolor string
	var SelinuxStatus string
	var Seres []interface{}
	var Secolors []interface{}

	kernelChecks := []map[string]interface{}{
		{"name": "CONFIG_COMPAT_BRK", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Kernel Heap Randomization"}},
		{"name": "CONFIG_STACKPROTECTOR", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Stack Protector"}},
		{"name": "CONFIG_STACKPROTECTOR_STRONG", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Stack Protector Strong"}},
		{"name": "CONFIG_CC_STACKPROTECTOR", "values": map[string]string{"arch": "all", "expect": "y", "desc": "GCC Stack Protector"}},
		{"name": "CONFIG_CC_STACKPROTECTOR_REGULAR", "values": map[string]string{"arch": "all", "expect": "y", "desc": "GCC Stack Protector Regular"}},
		{"name": "CONFIG_CC_STACKPROTECTOR_AUTO", "values": map[string]string{"arch": "all", "expect": "y", "desc": "GCC Stack Protector Auto"}},
		{"name": "CONFIG_CC_STACKPROTECTOR_STRONG", "values": map[string]string{"arch": "all", "expect": "y", "desc": "GCC Stack Protector Strong"}},
		{"name": "CONFIG_GCC_PLUGIN_STRUCTLEAK", "values": map[string]string{"arch": "all", "expect": "y", "desc": "GCC structleak plugin"}},
		{"name": "CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL", "values": map[string]string{"arch": "all", "expect": "y", "desc": "GCC structleak by ref plugin"}},
		{"name": "CONFIG_SLAB_FREELIST_RANDOM", "values": map[string]string{"arch": "all", "expect": "y", "desc": "SLAB freelist randomization"}},
		{"name": "CPU_SW_DOMAIN_PAN", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Use CPU domains"}},
		{"name": "CONFIG_VMAP_STACK", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Virtually-mapped kernel stack"}},
		{"name": "CONFIG_STRICT_DEVMEM", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Restrict /dev/mem access"}},
		{"name": "CONFIG_STRICT_KERNEL_RWX", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Restrict Kernel RWX"}},
		{"name": "CONFIG_STRICT_MODULE_RWX", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Restrict Module RWX"}},
		{"name": "CONFIG_IO_STRICT_DEVMEM", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Restrict I/O access to /dev/mem"}},
		{"name": "CONFIG_REFCOUNT_FULL", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Full reference count validation"}},
		{"name": "CONFIG_HARDENED_USERCOPY", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Hardened Usercopy"}},
		{"name": "CONFIG_FORTIFY_SOURCE", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Harden str/mem functions"}},
		{"name": "CONFIG_DEVKMEM", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Restrict /dev/kmem access"}},
		{"name": "CONFIG_DEBUG_STRICT_USER_COPY_CHECKS", "values": map[string]string{"arch": "amd", "expect": "y", "desc": "Strict user copy checks"}},
		{"name": "CONFIG_ARM_KERNMEM_PERMS", "values": map[string]string{"arch": "arm", "expect": "y", "desc": "Restrict kernel memory permissions"}},
		{"name": "CONFIG_DEBUG_ALIGN_RODATA", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Make rodata strictly non-excutable"}},
		{"name": "CONFIG_UNMAP_KERNEL_AT_EL0", "values": map[string]string{"arch": "arm64", "expect": "y", "desc": "Unmap kernel in userspace (KAISER)"}},
		{"name": "CONFIG_HARDEN_BRANCH_PREDICTOR", "values": map[string]string{"arch": "arm64", "expect": "y", "desc": "Harden branch predictor"}},
		{"name": "CONFIG_HARDEN_EL2_VECTORS", "values": map[string]string{"arch": "arm64", "expect": "y", "desc": "Harden EL2 vector mapping"}},
		{"name": "CONFIG_ARM64_SSBD", "values": map[string]string{"arch": "arm64", "expect": "y", "desc": "Speculative store bypass disable"}},
		{"name": "CONFIG_ARM64_SW_TTBR0_PAN", "values": map[string]string{"arch": "arm64", "expect": "y", "desc": "Emulate privileged access never"}},
		{"name": "CONFIG_RANDOMIZE_BASE", "values": map[string]string{"arch": "arm64", "expect": "y", "desc": "Randomize address of kernel image"}},
		{"name": "CONFIG_RANDOMIZE_MODULE_REGION_FULL", "values": map[string]string{"arch": "arm64", "expect": "y", "desc": "Randomize module region over 4GB"}},
		{"name": "CONFIG_DEBUG_WX", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Report dangerous memory permissions"}},
		{"name": "CONFIG_SYN_COOKIES", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Syn Flood protection"}},
		{"name": "CONFIG_LIST_HARDENED", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Check integrity of linked list manipulation"}},
		{"name": "CONFIG_DEBUG_NOTIFIERS", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Debug notifier call chains"}},
		{"name": "CONFIG_DEBUG_LIST", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Debug linked list manipulation"}},
		{"name": "CONFIG_DEBUG_SG", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Debug SG table operations"}},
		{"name": "CONFIG_DEBUG_VIRTUAL", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Debug VM translations"}},
		{"name": "CONFIG_SCHED_STACK_END_CHECK", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Detect stack corruption on calls to schedule"}},
		{"name": "CONFIG_SECCOMP", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Safely execute untrusted bytecode"}},
		{"name": "CONFIG_SECCOMP_FILTER", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Secure computing for BPF"}},
		{"name": "CONFIG_LDISC_AUTOLOAD", "values": map[string]string{"arch": "all", "expect": "is not set", "desc": "Automatically load TTY Line Disciplines"}},
		{"name": "CONFIG_SECURITY", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Enable different security models"}},
		{"name": "CONFIG_SECURITY_YAMA", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Security Yama support"}},
		{"name": "CONFIG_SECURITY_LANDLOCK", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Security Landlock support"}},
		{"name": "CONFIG_SECURITY_SELINUX", "values": map[string]string{"arch": "all", "expect": "y", "desc": "SELinux Kernel Flag"}},
		{"name": "CONFIG_SECURITY_SELINUX_BOOTPARAM", "values": map[string]string{"arch": "all", "expect": "is not set", "desc": "Allow disabling selinux at boot"}},
		{"name": "CONFIG_SECURITY_SELINUX_DEVELOP", "values": map[string]string{"arch": "all", "expect": "is not set", "desc": "SELinux Development Support"}},
		{"name": "CONFIG_SECURITY_SELINUX_DEBUG", "values": map[string]string{"arch": "all", "expect": "is not set", "desc": "SELinux Debug Support"}},
		{"name": "CONFIG_SECURITY_LOCKDOWN_LSM", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Enable the lockdown LSM"}},
		{"name": "CONFIG_SECURITY_LOCKDOWN_LSM_EARLY", "values": map[string]string{"arch": "all", "expect": "y", "desc": "Enable the lockdown LSM early in boot"}},
		{"name": "CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY", "values": map[string]string{"arch": "all", "expect": "y", "desc": "kernel runs in confidentiality mode"}},
		{"name": "CONFIG_HARDENED_USERCOPY_FALLBACK", "values": map[string]string{"arch": "all", "expect": "is not set", "desc": "Allow usercopy whitelist violations to fallback to object size"}},
		{"name": "CONFIG_HARDENED_USERCOPY_PAGESPAN", "values": map[string]string{"arch": "all", "expect": "is not set", "desc": "Refuse to copy allocations that span multiple pages"}},
	}

	data, err := parseKernelConfig(name)
	if err != nil {
		utils.Fatalf("Error parsing kernel config: %v", err)
	}
	for configKey, configVal := range data {
		for _, k := range kernelChecks {
			var res []interface{}
			var colors []interface{}
			var output string
			var color string
			if k["name"] == configKey {
				values := k["values"].(map[string]string)
				if values["expect"] == configVal {
					output = "Enabled"
					color = "green"
				} else {
					output = "Disabled"
					color = "red"
				}
				res = []interface{}{
					map[string]interface{}{
						"name":  k["name"],
						"value": output,
						"desc":  values["desc"],
						"type":  "Kernel Config",
					},
				}
				colors = []interface{}{
					map[string]interface{}{
						"name":  k["name"],
						"value": output,
						"color": color,
						"desc":  values["desc"],
						"type":  "Kernel Config",
					},
				}
			}
			Results = append(Results, res...)
			ColorResults = append(ColorResults, colors...)

		}
	}

	sestatus := selinux.GetEnabled()
	if sestatus {
		Secolor = "green"
		SelinuxStatus = "Enabled"
	} else {
		Secolor = "red"
		SelinuxStatus = "Disabled"
	}

	Seres = []interface{}{
		map[string]interface{}{
			"name":  "SELinux",
			"value": SelinuxStatus,
			"desc":  "SELinux Enabled",
			"type":  "SELinux",
		},
	}
	Secolors = []interface{}{
		map[string]interface{}{
			"name":  "SELinux",
			"value": SelinuxStatus,
			"color": Secolor,
			"desc":  "SELinux Enabled",
			"type":  "SELinux",
		},
	}
	Results = append(Results, Seres...)
	ColorResults = append(ColorResults, Secolors...)

	return Results, ColorResults
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
