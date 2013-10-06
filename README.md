checksec
========

Checksec.sh is a bash scrip to check executable properties like (PIE, RELRO, PaX, Canaries, ASLR).
It has been originally written by Tobias Klein and available here: http://www.trapkit.de/tools/checksec.html

Enhancement
-----------

The main issue dealing with the original checksec version is the cli interface which can only be exploited by a human. That is the
reason why I have modified the script to take various other kind of outputs like CSV and XML. By this way the output of this script can easily be reused
by any other programs.

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
    <file relro="partial" canary="yes" nx="yes" pie="no" rpath="no" runpath="no" filename='/bin/ls'/>

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


**Fortify test in csv**

    $ checksec.sh --format csv --fortify-proc 1
    Yes,Yes
    fdelt_chk,fdelt,no
    read,read,yes
    syslog_chk,syslog,no
    fprintf_chk,fprintf,no
    vsnprintf_chk,vsnprintf,no
    fgets,fgets,yes
    strncpy,strncpy,yes
    snprintf_chk,snprintf,no
    memset,memset,yes
    strncat_chk,strncat,no
    memcpy,memcpy,yes
    fread,fread,yes
    sprintf_chk,sprintf,no
    78,116,13,13,6


**Fortify test in xml**

    $ checksec.sh --format xml --fortify-proc 1
    <fortify-test name='init' pid='1'  libc_fortify_source='yes' binary_compiled_with_fortify='yes'>
	<function name='fdelt_chk' libc='fdelt' fortifyable='no' />
	<function name='read' libc='read' fortifyable='yes' />
	<function name='syslog_chk' libc='syslog' fortifyable='no' />
	<function name='fprintf_chk' libc='fprintf' fortifyable='no' />
	<function name='vsnprintf_chk' libc='vsnprintf' fortifyable='no' />
	<function name='fgets' libc='fgets' fortifyable='yes' />
	<function name='strncpy' libc='strncpy' fortifyable='yes' />
	<function name='snprintf_chk' libc='snprintf' fortifyable='no' />
	<function name='memset' libc='memset' fortifyable='yes' />
	<function name='strncat_chk' libc='strncat' fortifyable='no' />
	<function name='memcpy' libc='memcpy' fortifyable='yes' />
	<function name='fread' libc='fread' fortifyable='yes' />
	<function name='sprintf_chk' libc='sprintf' fortifyable='no' />

	<stats nb_libc_func='78' nb_total_func='116' nb_fortifyable_func='13' nb_checked_func='13' nb_unchecked_func='6' />
    </fortify-test>


Warning
-------

Due to the original structure of the script the **--format** argument should be placed first on the command line arguments. Doing differently would have obliged me to do really big changes in the code.