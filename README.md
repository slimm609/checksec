checksec
========
Checksec checks the properties of executables (like PIE, RELRO, Canaries, ASLR, Fortify Source).
It has been originally written by Tobias Klein and the original source is available here: http://www.trapkit.de/tools/checksec.html. Over time this has expanded in feature set and has now moved from Bash to Golang.

Version: 3.0.1

Updates
-------
  Checksec was originally released with 1.0 in early 2009 and has been used for validating binary checks of Linux systems for over a decade. Over time as more checks were supported and Linux distributions have changed, this has brought more dependencies into checksec. Adding more and more dependenies to be able to check the security flags of files, it not an ideal solution for systems with minor dependencies including embedded systems, distroless containers, and cross platform checks.
  - Feature partial between the bash version and the golang version will be mostly supported.
    - Adding support for yaml output
    - Removing support for CSV
    - JSON and XML will still both be supported
  - Much faster results. When checking 694 files in a directory
      - bash: real  0m10.348s
      - golang: real  0m0.691s


For OSX
-------
Checksec can scan linux files from OSX however, some checks may be limited due to OS dependencies on resources like glibc.


Examples
--------

**normal (or --format=cli)**

    $checksec file /bin/ls
    RELRO           Stack Canary      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY    Fortified   Fortifiable      Name
    Partial RELRO   Canary Found      NX enabled    PIE Enabled     No RPATH   No RUNPATH   No Symbols      No         0           14               /bin/ls

**yaml**

    $ checksec file /bin/ls --output yaml
    - checks:
        canary: Canary Found
        fortified: "0"
        fortify_source: "No"
        fortifyable: "14"
        nx: NX enabled
        pie: PIE Enabled
        relro: Partial RELRO
        rpath: No RPATH
        runpath: No RUNPATH
        symbols: No Symbols
      name: /bin/ls

**xml**

    $ checksec file /bin/ls --output xml
    <SecurityCheck>
      <Name>/bin/ls</Name>
      <Checks>
        <Canary>Canary Found</Canary>
        <Fortified>0</Fortified>
        <FortifyAble>14</FortifyAble>
        <FortifySource>No</FortifySource>
        <NX>NX enabled</NX>
        <PIE>PIE Enabled</PIE>
        <Relro>Partial RELRO</Relro>
        <RPath>No RPATH</RPath>
        <RunPath>No RUNPATH</RunPath>
        <Symbols>No Symbols</Symbols>
      </Checks>
    </SecurityCheck>

**json**

    $ checksec file /bin/ls --output json
    [
      {
        "checks": {
        "canary": "Canary Found",
        "fortified": "0",
        "fortify_source": "No",
        "fortifyable": "14",
        "nx": "NX enabled",
        "pie": "PIE Enabled",
        "relro": "Partial RELRO",
        "rpath": "No RPATH",
        "runpath": "No RUNPATH",
        "symbols": "No Symbols"
        },
        "name": "/bin/ls"
      }
    ]

**Fortify test in cli**

    $ checksec fortifyProc 1

      _____ _    _ ______ _____ _  __ _____ ______ _____
     / ____| |  | |  ____/ ____| |/ // ____|  ____/ ____|
    | |    | |__| | |__ | |    | ' /| (___ | |__ | |
    | |    |  __  |  __|| |    |  <  \___ \|  __|| |
    | |____| |  | | |___| |____| . \ ____) | |___| |____
     \_____|_|  |_|______\_____|_|\_\_____/|______\_____|

    * FORTIFY_SOURCE support available (libc): Yes
    * Binary compiled with FORTIFY_SOURCE support: No

    ------ EXECUTABLE-FILE ------- | -------- LIBC --------
    Fortifiable library functions  | Checked function names
    Coming Soon

    SUMMARY
    * Number of checked functions in libc                : 18
    * Total number of library functions in the executable: 2011
    * Number of Fortifiable functions in the executable  : 12
    * Number of checked functions in the executable      : 0
    * Number of unchecked functions in the executable    : 12


**Kernel test in Cli**

    $ checksec kernel

      _____ _    _ ______ _____ _  __ _____ ______ _____
     / ____| |  | |  ____/ ____| |/ // ____|  ____/ ____|
    | |    | |__| | |__ | |    | ' /| (___ | |__ | |
    | |    |  __  |  __|| |    |  <  \___ \|  __|| |
    | |____| |  | | |___| |____| . \ ____) | |___| |____
     \_____|_|  |_|______\_____|_|\_\_____/|______\_____|

    Kernel configs only print what is supported by the specific kernel/kernel config
    Description                                                   Value            Check Type            Config Key
    Virtually-mapped kernel stack                                 Disabled         Kernel Config         CONFIG_VMAP_STACK
    Harden str/mem functions                                      Disabled         Kernel Config         CONFIG_FORTIFY_SOURCE
    Restrict Kernel RWX                                           Enabled          Kernel Config         CONFIG_STRICT_KERNEL_RWX
    Restrict /dev/mem access                                      Enabled          Kernel Config         CONFIG_STRICT_DEVMEM
    SELinux Kernel Flag                                           Disabled         Kernel Config         CONFIG_SECURITY_SELINUX
    Emulate privileged access never                               Disabled         Kernel Config         CONFIG_ARM64_SW_TTBR0_PAN
    Restrict I/O access to /dev/mem                               Disabled         Kernel Config         CONFIG_IO_STRICT_DEVMEM
    Kernel Heap Randomization                                     Disabled         Kernel Config         CONFIG_COMPAT_BRK
    Stack Protector Strong                                        Disabled         Kernel Config         CONFIG_STACKPROTECTOR_STRONG
    Hardened Usercopy                                             Disabled         Kernel Config         CONFIG_HARDENED_USERCOPY
    Restrict Module RWX                                           Enabled          Kernel Config         CONFIG_STRICT_MODULE_RWX
    Address space layout randomization                            Disabled         Kernel Config         CONFIG_RANDOMIZE_BASE
    Randomize address of kernel image                             Disabled         Kernel Config         CONFIG_RANDOMIZE_BASE
    Stack Protector                                               Disabled         Kernel Config         CONFIG_STACKPROTECTOR
    Unmap kernel in userspace (KAISER)                            Enabled          Kernel Config         CONFIG_UNMAP_KERNEL_AT_EL0
    SLAB freelist randomization                                   Disabled         Kernel Config         CONFIG_SLAB_FREELIST_RANDOM
    SELinux Enabled                                               Disabled         SELinux               SELinux
    Protected symlinks                                            Enabled          Sysctl                fs.protected_symlinks
    Protected hardlinks                                           Enabled          Sysctl                fs.protected_hardlinks
    Ipv4 reverse path filtering                                   Disabled         Sysctl                net.ipv4.conf.all.rp_filter
    YAMA                                                          Unknown          Sysctl                kernel.yama.ptrace_scope
    Exec Shield                                                   Unknown          Sysctl                kernel.exec-shield
    Unprivileged BPF Disabled                                     Disabled         Sysctl                kernel.unprivileged_bpf_disabled
    Vanilla Kernel ASLR                                           Enabled          Sysctl                kernel.randomize_va_space
    Dmesg Restrictions                                            Enabled          Sysctl                kernel.dmesg_restrict
    Kernel Pointer Restrictions                                   Disabled         Sysctl                kernel.kptr_restrict
    Protected fifos                                               Disabled         Sysctl                fs.protected_fifos
    Protected regular                                             Disabled         Sysctl                fs.protected_regular
    Performance events by normal users                            Enabled          Sysctl                kernel.perf_event_paranoid
    Disable Autoload TTY Line Disciplines                         Disabled         Sysctl                dev.tty.ldisc_autoload
    Disable Legacy TIOCSTI                                        Disabled         Sysctl                dev.tty.legacy_tiocsti


**Kernel Test in XML**

    $ checksec kernel --output xml
    <KernelCheck>
      <Name>CONFIG_IO_STRICT_DEVMEM</Name>
      <Description>Restrict I/O access to /dev/mem</Description>
      <Value>Disabled</Value>
      <CheckType>Kernel Config</CheckType>
    </KernelCheck>
    <KernelCheck>
      <Name>CONFIG_STRICT_MODULE_RWX</Name>
      <Description>Restrict Module RWX</Description>
      <Value>Enabled</Value>
      <CheckType>Kernel Config</CheckType>
    </KernelCheck>
    <KernelCheck>
      <Name>CONFIG_SECURITY_SELINUX</Name>
      <Description>SELinux Kernel Flag</Description>
      <Value>Disabled</Value>
      <CheckType>Kernel Config</CheckType>
    </KernelCheck>

**Kernel Test in Json**

    $ checksec kernel --output json
    [
      {
        "desc": "Hardened Usercopy",
        "name": "CONFIG_HARDENED_USERCOPY",
        "type": "Kernel Config",
        "value": "Disabled"
      },
      {
        "desc": "Harden str/mem functions",
        "name": "CONFIG_FORTIFY_SOURCE",
        "type": "Kernel Config",
        "value": "Disabled"
      },
      {
        "desc": "Restrict Kernel RWX",
        "name": "CONFIG_STRICT_KERNEL_RWX",
        "type": "Kernel Config",
        "value": "Enabled"
      },
      {
        "desc": "Virtually-mapped kernel stack",
        "name": "CONFIG_VMAP_STACK",
        "type": "Kernel Config",
        "value": "Disabled"
      },
      {
        "desc": "SELinux Kernel Flag",
        "name": "CONFIG_SECURITY_SELINUX",
        "type": "Kernel Config",
        "value": "Disabled"
      }
    ]

Using with Cross-compiled Systems
---------------------------------------
The checksec tool can be used against cross-compiled target file-systems offline.  Key limitations to note:
* Kernel tests - require you to execute the script on the running system you'd like to check as they directly access kernel resources to identify system configuration/state. You can specify the config file for the kernel after the -k option.

* File check -  the offline testing works for all the checks but the Fortify feature.  By default, Fortify, uses the running system's libraries vs those in the offline file-system. There are ways to workaround this (chroot) but at the moment, the ideal configuration would have this script executing on the running system when checking the files. An other option is to specify where the cross-compiled libc is located through the -libc option.

The checksec tool's normal use case is for runtime checking of the systems configuration.  If the system is an embedded target, the native binutils tools like readelf may not be present.  This would restrict which parts of the script will work.

Even with those limitations, the amount of valuable information this script provides, still makes it a valuable tool for checking offline file-systems.
