checksec
========

Checksec.sh is a bash scrip to check executable properties like (PIE, RELRO, PaX, Canaries, ASLR, Fortify Source).
It has been originally written by Tobias Klein and the original source is available here: http://www.trapkit.de/tools/checksec.html

Updates
-------

	Implemented changelog
	merged in JIT and MODHARDEN changes (Thanks N8Fear)
	Removed deprecated Kern Heap section (thanks Unspawn)
	Added SELinux checks as additional checks for kernel security.
	Added update option to pull the latest release of checksec.
	Added foritfy_source to proc-all output.
	Added Json, strict XML and updated Grsecurity setion.
	Carried over Robin David's changes with XML and CSV.

Examples
--------

**normal (or --format cli)**

    $checksec.sh --file /bin/ls
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   /bin/ls

**csv**

    $ checksec.sh --format csv --file /bin/ls
    Partial RELRO,Canary found,NX enabled,No PIE,No RPATH,No RUNPATH,/bin/ls

**xml**
    
    $ checksec.sh --format xml --file /bin/ls
    <?xml version="1.0" encoding="UTF-8"?>
    <file relro="partial" canary="yes" nx="yes" pie="no" rpath="no" runpath="no" filename='/bin/ls'/>

**json**
	$ checksec.sh --format json --file /bin/ls	
	{ "file": { "relro":"partial","canary":"yes","nx":"yes","pie":"no","rpath":"no","runpath":"no","filename":"/bin/ls" } }

**Fortify test in cli**

    $ checksec.sh --fortify-proc 1
    * Process name (PID)                         : init (1)
    * FORTIFY_SOURCE support available (libc)    : Yes
    * Binary compiled with FORTIFY_SOURCE support: Yes

    ------ EXECUTABLE-FILE ------- . -------- LIBC --------
    FORTIFY-able library functions | Checked function names
    -------------------------------------------------------
    fdelt_chk                      | __fdelt_chk
    read                           | __read_chk
    syslog_chk                     | __syslog_chk
    fprintf_chk                    | __fprintf_chk
    vsnprintf_chk                  | __vsnprintf_chk
    fgets                          | __fgets_chk
    strncpy                        | __strncpy_chk
    snprintf_chk                   | __snprintf_chk
    memset                         | __memset_chk
    strncat_chk                    | __strncat_chk
    memcpy                         | __memcpy_chk
    fread                          | __fread_chk
    sprintf_chk                    | __sprintf_chk

    SUMMARY:

    * Number of checked functions in libc                : 78
    * Total number of library functions in the executable: 116
    * Number of FORTIFY-able functions in the executable : 13
    * Number of checked functions in the executable      : 7
    * Number of unchecked functions in the executable    : 6


**Kernel test in Cli**

	$ checksec.sh --kernel
	* Kernel protection information:

	Description - List the status of kernel protection mechanisms. Rather than
	inspect kernel mechanisms that may aid in the prevention of exploitation of
	userspace processes, this option lists the status of kernel configuration
	options that harden the kernel itself against attack.

	Kernel config: /proc/config.gz
 
		GCC stack protector support:            Enabled
		Strict user copy checks:                Disabled
		Enforce read-only kernel data:          Disabled
		Restrict /dev/mem access:               Enabled
		Restrict /dev/kmem access:              Enabled

	* grsecurity / PaX: Auto GRKERNSEC

		Non-executable kernel pages:            Enabled
		Non-executable pages:                   Enabled
		Paging Based Non-executable pages:      Enabled
		Restrict MPROTECT:                      Enabled
		Address Space Layout Randomization:     Enabled
		Randomize Kernel Stack:                 Enabled
		Randomize User Stack:                   Enabled
		Randomize MMAP Stack:                   Enabled
		Sanitize freed memory:                  Enabled
 		Sanitize Kernel Stack:                  Enabled
		Prevent userspace pointer deref:        Enabled
		Prevent kobject refcount overflow:      Enabled
		Bounds check heap object copies:        Enabled
		JIT Hardening:	 			            Enabled
		Thread Stack Random Gaps: 	            Enabled
 		Disable writing to kmem/mem/port:       Enabled
     	Disable privileged I/O:                 Enabled
     	Harden module auto-loading:             Enabled
     	Chroot Protection:     	        		Enabled
     	Deter ptrace process snooping:	  		Enabled
     	Larger Entropy Pools:                   Enabled
     	TCP/UDP Blackhole:                      Enabled
     	Deter Exploit Bruteforcing:             Enabled
     	Hide kernel symbols:                    Enabled

	* Kernel Heap Hardening: No KERNHEAP

	The KERNHEAP hardening patchset is available here:
	 https://www.subreption.com/kernheap/


**Kernel Test in XML**

	$ checksec.sh --format xml --kernel
	<?xml version="1.0" encoding="UTF-8"?>
	<kernel config='/boot/config-3.11-2-amd64' gcc_stack_protector='yes' strict_user_copy_check='no' ro_kernel_data='yes' restrict_dev_mem_access='yes' restrict_dev_kmem_access='no'>
		<grsecurity config='no' />
    	<kernheap config='no' />
	</kernel>

**Kernel Test in Json**

	$ checksec.sh --format json --kernel
 	{ "kernel": { "KernelConfig":"/boot/config-3.11-2-amd64","gcc_stack_protector":"yes","strict_user_copy_check":"no","ro_kernel_data":"yes","restrict_dev_mem_access":"yes","restrict_dev_kmem_access":"no" },{ "grsecurity_config":"no" },{ "kernheap_config":"no" } }


Warning
-------

Due to the original structure of the script the **--format** argument should be placed first on the command line arguments. Doing differently would require really big changes in the code.
