#!/bin/bash
#
# The BSD License (http://www.opensource.org/licenses/bsd-license.php) 
# specifies the terms and conditions of use for checksec.sh:
#
# Copyright (c) 2009-2011, Tobias Klein.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions 
# are met:
# 
# * Redistributions of source code must retain the above copyright 
#   notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright 
#   notice, this list of conditions and the following disclaimer in 
#   the documentation and/or other materials provided with the 
#   distribution.
# * Neither the name of Tobias Klein nor the name of trapkit.de may be 
#   used to endorse or promote products derived from this software 
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
# DAMAGE.
#
# --- Modified Version ---
# Name    : checksec.sh
# Version : based on 1.5
# Author  : Robin David
# Date    : October 2013
# Download: https://github.com/RobinDavid/checksec
#
# --- Original version ---
# Name    : checksec.sh
# Version : 1.5
# Author  : Tobias Klein
# Date    : November 2011
# Download: http://www.trapkit.de/tools/checksec.html
# Changes : http://www.trapkit.de/tools/checksec_changes.txt


# global vars
have_readelf=1
verbose=false
format="cli"

# FORTIFY_SOURCE vars
FS_end=_chk
FS_cnt_total=0
FS_cnt_checked=0
FS_cnt_unchecked=0
FS_chk_func_libc=0
FS_functions=0
FS_libc=0
 
# version information
version() {
  echo "checksec v1.5, Tobias Klein, www.trapkit.de, November 2011"
  echo 
}

# help
help() {
  echo "Usage: checksec [--format {cli|csv|xml}] [OPTION]"
  echo
  echo
  echo "Options:"
  echo
  echo "  --file <executable-file>"
  echo "  --dir <directory> [-v]"
  echo "  --proc <process name>"
  echo "  --proc-all"
  echo "  --proc-libs <process ID>"
  echo "  --kernel"
  echo "  --fortify-file <executable-file>"
  echo "  --fortify-proc <process ID>"
  echo "  --version"
  echo "  --help"
  echo
  echo "For more information, see:"
  echo "  http://www.trapkit.de/tools/checksec.html"
  echo
}

echo_message() {
  if [[ $format == "cli" ]]; then
      echo -n -e "$1"
  elif [[ $format == "csv" ]]; then
      echo -n -e "$2"
  else #XML
      echo -n -e "$3"
  fi
}

# check if command exists
command_exists () {
  type $1  > /dev/null 2>&1;
}

# check if directory exists
dir_exists () {
  if [ -d $1 ] ; then
    return 0
  else
    return 1
  fi
}

# check user privileges
root_privs () {
  if [ $(/usr/bin/id -u) -eq 0 ] ; then
    return 0
  else
    return 1
  fi
}

# check if input is numeric
isNumeric () {
  echo "$@" | grep -q -v "[^0-9]"
}

# check if input is a string
isString () {
  echo "$@" | grep -q -v "[^A-Za-z]"
}

# check file(s)
filecheck() {
  # check for RELRO support
  if readelf -l $1 2>/dev/null | grep -q 'GNU_RELRO'; then
    if readelf -d $1 2>/dev/null | grep -q 'BIND_NOW'; then
      echo_message '\033[32mFull RELRO   \033[m   ' 'Full RELRO,' '<file relro="full"'
    else
      echo_message '\033[33mPartial RELRO\033[m   ' 'Partial RELRO,' '<file relro="partial"'
    fi
  else
    echo_message '\033[31mNo RELRO     \033[m   ' 'No RELRO,' '<file relro="no"'
  fi

  # check for stack canary support
  if readelf -s $1 2>/dev/null | grep -q '__stack_chk_fail'; then
    echo_message '\033[32mCanary found   \033[m   ' 'Canary found,' ' canary="yes"'
  else
    echo_message '\033[31mNo canary found\033[m   ' 'No Canary found,' ' canary="no"'
  fi

  # check for NX support
  if readelf -W -l $1 2>/dev/null | grep 'GNU_STACK' | grep -q 'RWE'; then
    echo_message '\033[31mNX disabled\033[m   ' 'NX disabled,' ' nx="no"'
  else
    echo_message '\033[32mNX enabled \033[m   ' 'NX enabled,' ' nx="yes"'
  fi 

  # check for PIE support
  if readelf -h $1 2>/dev/null | grep -q 'Type:[[:space:]]*EXEC'; then
    echo_message '\033[31mNo PIE       \033[m   ' 'No PIE,' ' pie="no"'
  elif readelf -h $1 2>/dev/null | grep -q 'Type:[[:space:]]*DYN'; then
    if readelf -d $1 2>/dev/null | grep -q '(DEBUG)'; then
      echo_message '\033[32mPIE enabled  \033[m   ' 'PIE enabled,' ' pie="yes"'
    else   
      echo_message '\033[33mDSO          \033[m   ' 'DSO,' ' pie="dso"'
    fi
  else
    echo_message '\033[33mNot an ELF file\033[m   ' 'Not an ELF file,' ' pie="notelf"'
  fi 

  # check for rpath / run path
  if readelf -d $1 2>/dev/null | grep -q 'rpath'; then
   echo_message '\033[31mRPATH    \033[m  ' 'RPATH,' ' rpath="yes"'
  else
   echo_message '\033[32mNo RPATH \033[m  ' 'No RPATH,' ' rpath="no"'
  fi

  if readelf -d $1 2>/dev/null | grep -q 'runpath'; then
   echo_message '\033[31mRUNPATH    \033[m  ' 'RUNPATH' ' runpath="yes"'
  else
   echo_message '\033[32mNo RUNPATH \033[m  ' 'No RUNPATH' ' runpath="no"'
  fi
}

# check process(es)
proccheck() {
  # check for RELRO support
  if readelf -l $1/exe 2>/dev/null | grep -q 'Program Headers'; then
    if readelf -l $1/exe 2>/dev/null | grep -q 'GNU_RELRO'; then
      if readelf -d $1/exe 2>/dev/null | grep -q 'BIND_NOW'; then
	echo_message '\033[32mFull RELRO   \033[m   ' 'Full RELRO,' ' relro="full"'
      else
	echo_message '\033[33mPartial RELRO\033[m   ' 'Partial RELRO,' ' relro="partial"'
      fi
    else
      echo_message '\033[31mNo RELRO     \033[m   ' 'No RELRO,' ' relro="no"'
    fi
  else
    echo -n -e '\033[31mPermission denied (please run as root)\033[m\n'
    exit 1
  fi

  # check for stack canary support
  if readelf -s $1/exe 2>/dev/null | grep -q 'Symbol table'; then
    if readelf -s $1/exe 2>/dev/null | grep -q '__stack_chk_fail'; then
      echo_message '\033[32mCanary found   \033[m   ' 'Canary found,' ' canary="yes"'
    else
      echo_message '\033[31mNo canary found\033[m   ' 'No Canary found,' ' canary="no"'
    fi
  else
    if [ "$1" != "1" ] ; then
      echo -n -e '\033[33mPermission denied    \033[m  '
    else
      echo -n -e '\033[33mNo symbol table found\033[m  '
    fi
  fi

  # first check for PaX support
  if cat $1/status 2> /dev/null | grep -q 'PaX:'; then
    pageexec=( $(cat $1/status 2> /dev/null | grep 'PaX:' | cut -b6) )
    segmexec=( $(cat $1/status 2> /dev/null | grep 'PaX:' | cut -b10) )
    mprotect=( $(cat $1/status 2> /dev/null | grep 'PaX:' | cut -b8) )
    randmmap=( $(cat $1/status 2> /dev/null | grep 'PaX:' | cut -b9) )
    if [[ "$pageexec" = "P" || "$segmexec" = "S" ]] && [[ "$mprotect" = "M" && "$randmmap" = "R" ]] ; then
      echo_message '\033[32mPaX enabled\033[m   ' 'Pax enabled,' ' pax="yes"'
    elif [[ "$pageexec" = "p" && "$segmexec" = "s" && "$randmmap" = "R" ]] ; then
      echo_message '\033[33mPaX ASLR only\033[m ' 'Pax ASLR only,' ' pax="aslr_only"'
    elif [[ "$pageexec" = "P" || "$segmexec" = "S" ]] && [[ "$mprotect" = "m" && "$randmmap" = "R" ]] ; then
      echo_message '\033[33mPaX mprot off \033[m' 'Pax mprot off,' ' pax="mprot_off"'
    elif [[ "$pageexec" = "P" || "$segmexec" = "S" ]] && [[ "$mprotect" = "M" && "$randmmap" = "r" ]] ; then
      echo_message '\033[33mPaX ASLR off\033[m  ' 'Pax ASLR off,' ' pax="aslr_off"'
    elif [[ "$pageexec" = "P" || "$segmexec" = "S" ]] && [[ "$mprotect" = "m" && "$randmmap" = "r" ]] ; then
      echo_message '\033[33mPaX NX only\033[m   ' 'Pax NX only,' ' pax="nx_only"'
    else
      echo_message '\033[31mPaX disabled\033[m  ' 'Pax disabled,' ' pax="no"'
    fi
  # fallback check for NX support
  elif readelf -W -l $1/exe 2>/dev/null | grep 'GNU_STACK' | grep -q 'RWE'; then
    echo_message '\033[31mNX disabled\033[m   ' 'NX disabled,' ' nx="no"'
  else
    echo_message '\033[32mNX enabled \033[m   ' 'NX enabled,' ' pax="yes"'
  fi 

  # check for PIE support
  if readelf -h $1/exe 2>/dev/null | grep -q 'Type:[[:space:]]*EXEC'; then
    echo_message '\033[31mNo PIE               \033[m   ' 'No PIE' ' pie="no">'
  elif readelf -h $1/exe 2>/dev/null | grep -q 'Type:[[:space:]]*DYN'; then
    if readelf -d $1/exe 2>/dev/null | grep -q '(DEBUG)'; then
      echo_message '\033[32mPIE enabled          \033[m   ' 'PIE enabled' ' pie="yes">'
    else   
      echo_message '\033[33mDynamic Shared Object\033[m   ' 'Dynamic Shared Object' ' pie="dynamic_shared_object">'
    fi
  else
    echo_message '\033[33mNot an ELF file      \033[m   ' 'Not an ELF file' ' pie="not_elf">'
  fi
}

# check mapped libraries
libcheck() {
  libs=( $(awk '{ print $6 }' /proc/$1/maps | grep '/' | sort -u | xargs file | grep ELF | awk '{ print $1 }' | sed 's/:/ /') )
 
  echo_message "\n* Loaded libraries (file information, # of mapped files: ${#libs[@]}):\n\n" "" ""
  
  for element in $(seq 0 $((${#libs[@]} - 1)))
  do
    echo_message "  ${libs[$element]}:\n" "${libs[$element]}," ""
    echo_message "    " "" "    "
    filecheck ${libs[$element]}
    echo_message "\n\n" "\n" " filename='${libs[$element]}' />\n"
  done
}

# check for system-wide ASLR support
aslrcheck() {
  # PaX ASLR support
  if !(cat /proc/1/status 2> /dev/null | grep -q 'Name:') ; then
    echo_message ':\033[33m insufficient privileges for PaX ASLR checks\033[m\n' '' ''
    echo_message '  Fallback to standard Linux ASLR check' '' ''
  fi
  
  if cat /proc/1/status 2> /dev/null | grep -q 'PaX:'; then
    printf ": "
    if cat /proc/1/status 2> /dev/null | grep 'PaX:' | grep -q 'R'; then
      echo_message '\033[32mPaX ASLR enabled\033[m\n\n' '' ''
    else
      echo_message '\033[31mPaX ASLR disabled\033[m\n\n' '' ''
    fi
  else
    # standard Linux 'kernel.randomize_va_space' ASLR support
    # (see the kernel file 'Documentation/sysctl/kernel.txt' for a detailed description)
    echo_message " (kernel.randomize_va_space): " '' ''
    if /sbin/sysctl -a 2>/dev/null | grep -q 'kernel.randomize_va_space = 1'; then
      echo_message '\033[33mOn (Setting: 1)\033[m\n\n' '' ''
      echo_message "  Description - Make the addresses of mmap base, stack and VDSO page randomized.\n" '' ''
      echo_message "  This, among other things, implies that shared libraries will be loaded to \n" '' ''
      echo_message "  random addresses. Also for PIE-linked binaries, the location of code start\n" '' ''
      echo_message "  is randomized. Heap addresses are *not* randomized.\n\n" '' ''
    elif /sbin/sysctl -a 2>/dev/null | grep -q 'kernel.randomize_va_space = 2'; then
      echo_message '\033[32mOn (Setting: 2)\033[m\n\n' '' ''
      echo_message "  Description - Make the addresses of mmap base, heap, stack and VDSO page randomized.\n" '' ''
      echo_message "  This, among other things, implies that shared libraries will be loaded to random \n" '' ''
      echo_message "  addresses. Also for PIE-linked binaries, the location of code start is randomized.\n\n" '' ''
    elif /sbin/sysctl -a 2>/dev/null | grep -q 'kernel.randomize_va_space = 0'; then
      echo_message '\033[31mOff (Setting: 0)\033[m\n' '' ''
    else
      echo_message '\033[31mNot supported\033[m\n' '' ''
    fi
    echo_message "  See the kernel file 'Documentation/sysctl/kernel.txt' for more details.\n\n" '' ''
  fi 
}

# check cpu nx flag
nxcheck() {
  if grep -q nx /proc/cpuinfo; then
    echo_message '\033[32mYes\033[m\n\n' '' ''
  else
    echo_message '\033[31mNo\033[m\n\n' '' ''
  fi
}

# check for kernel protection mechanisms
kernelcheck() {
  echo_message "  Description - List the status of kernel protection mechanisms. Rather than\n" '' ''
  echo_message "  inspect kernel mechanisms that may aid in the prevention of exploitation of\n" '' ''
  echo_message "  userspace processes, this option lists the status of kernel configuration\n" '' ''
  echo_message "  options that harden the kernel itself against attack.\n\n" '' ''
  echo_message "  Kernel config: " '' ''
 
  if [ -f /proc/config.gz ] ; then
    kconfig="zcat /proc/config.gz"
    echo_message "\033[32m/proc/config.gz\033[m\n\n" '/proc/config.gz' '<kernel config="/proc/config.gz"'
  elif [ -f /boot/config-`uname -r` ] ; then
    kconfig="cat /boot/config-`uname -r`"
    kern=`uname -r`
    echo_message "\033[33m/boot/config-$kern\033[m\n\n" "/boot/config-$kern," "<kernel config='/boot/config-$kern'"
    echo_message "  Warning: The config on disk may not represent running kernel config!\n\n" "" ""
  elif [ -f "${KBUILD_OUTPUT:-/usr/src/linux}"/.config ] ; then
    kconfig="cat ${KBUILD_OUTPUT:-/usr/src/linux}/.config"
    echo_message "\033[33m%s\033[m\n\n" "${KBUILD_OUTPUT:-/usr/src/linux}/.config" "${KBUILD_OUTPUT:-/usr/src/linux}/.config," "<kernel config='${KBUILD_OUTPUT:-/usr/src/linux}/.config'"
    echo_message "  Warning: The config on disk may not represent running kernel config!\n\n" "" ""
  else
    echo_message "\033[31mNOT FOUND\033[m\n\n" "NOT FOUND,,,,,,," "<kernel config='not_found' />"
    exit 0
  fi

  echo_message "  GCC stack protector support:            " "" ""
  if $kconfig | grep -qi 'CONFIG_CC_STACKPROTECTOR=y'; then
    echo_message "\033[32mEnabled\033[m\n" "Enabled," " gcc_stack_protector='yes'"
  else
    echo_message "\033[31mDisabled\033[m\n" "Disabled," " gcc_stack_protector='no'"
  fi

  echo_message "  Strict user copy checks:                " "" ""
  if $kconfig | grep -qi 'CONFIG_DEBUG_STRICT_USER_COPY_CHECKS=y'; then
    echo_message "\033[32mEnabled\033[m\n" "Enabled," " strict_user_copy_check='yes'"
  else
    echo_message "\033[31mDisabled\033[m\n" "Disabled," " strict_user_copy_check='no'"
  fi

  echo_message "  Enforce read-only kernel data:          " "" ""
  if $kconfig | grep -qi 'CONFIG_DEBUG_RODATA=y'; then
    echo_message "\033[32mEnabled\033[m\n" "Enabled," " ro_kernel_data='yes'"
  else
    echo_message "\033[31mDisabled\033[m\n" "Disabled," " ro_kernel_data='no'"
  fi
  echo_message "  Restrict /dev/mem access:               " "" ""
  if $kconfig | grep -qi 'CONFIG_STRICT_DEVMEM=y'; then
    echo_message "\033[32mEnabled\033[m\n" "Enabled," " restrict_dev_mem_access='yes'"
  else
    echo_message "\033[31mDisabled\033[m\n" "Disabled," " restrict_dev_mem_access='no'"
  fi

  echo_message "  Restrict /dev/kmem access:              " "" ""
  if $kconfig | grep -qi 'CONFIG_DEVKMEM=y'; then
    echo_message "\033[31mDisabled\033[m\n" "Enabled" " restrict_dev_kmem_access='yes'>"
  else
    echo_message "\033[32mEnabled\033[m\n" "Disabled" " restrict_dev_kmem_access='no'>"
  fi

  echo_message "\n" "\n" "\n"
  echo_message "* grsecurity / PaX: " "" ""

  if $kconfig | grep -qi 'CONFIG_GRKERNSEC=y'; then
    if $kconfig | grep -qi 'CONFIG_GRKERNSEC_HIGH=y'; then
      echo_message "\033[32mHigh GRKERNSEC\033[m\n\n" "High GRKERNSEC," "    <grsecurity config='high'"
    elif $kconfig | grep -qi 'CONFIG_GRKERNSEC_MEDIUM=y'; then
      echo_message "\033[33mMedium GRKERNSEC\033[m\n\n" "Medium GRKERNSEC," "    <grsecurity config='medium'"
    elif $kconfig | grep -qi 'CONFIG_GRKERNSEC_LOW=y'; then
      echo_message "\033[31mLow GRKERNSEC\033[m\n\n" "Low GRKERNSEC," "    <grsecurity config='low'"
    else
      echo_message "\033[33mCustom GRKERNSEC\033[m\n\n" "Custom GRKERNSEC," "    <grsecurity config='custom'"
    fi

    echo_message "  Non-executable kernel pages:            " "" ""
    if $kconfig | grep -qi 'CONFIG_PAX_KERNEXEC=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " config_pax_kernexec='yes'"
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " config_pax_kernexec='no'"
    fi

    echo_message "  Prevent userspace pointer deref:        " "" ""
    if $kconfig | grep -qi 'CONFIG_PAX_MEMORY_UDEREF=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " config_pax_memory_uderef='yes'"
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " config_pax_memory_uderef='no'"
    fi

    echo_message "  Prevent kobject refcount overflow:      " "" ""
    if $kconfig | grep -qi 'CONFIG_PAX_REFCOUNT=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " config_pax_refcount='yes'"
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " config_pax_refcount='no'"
    fi

    echo_message "  Bounds check heap object copies:        " "" ""
    if $kconfig | grep -qi 'CONFIG_PAX_USERCOPY=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " config_pax_usercopy='yes'"
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " config_pax_usercopy='no'"
    fi

    echo_message "  Disable writing to kmem/mem/port:       " "" ""
    if $kconfig | grep -qi 'CONFIG_GRKERNSEC_KMEM=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " config_grkernsec_kmem='yes'"
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " config_grkernsec_kmem='no'"
    fi

    echo_message "  Disable privileged I/O:                 " "" ""
    if $kconfig | grep -qi 'CONFIG_GRKERNSEC_IO=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " config_grkernsec_io='yes'"
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " config_grkernsec_io='no'"
    fi

    echo_message "  Harden module auto-loading:             " "" ""
    if $kconfig | grep -qi 'CONFIG_GRKERNSEC_MODHARDEN=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " config_grkernsec_modharden='yes'"
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " config_grkernsec_modharden='no'"
    fi

    echo_message "  Hide kernel symbols:                    " "" ""
    if $kconfig | grep -qi 'CONFIG_GRKERNSEC_HIDESYM=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled" " config_grkernsec_hidesym='yes' />"
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled" " config_grkernsec_hidesym='no'/>"
    fi
  else
    echo_message "\033[31mNo GRKERNSEC\033[m\n\n" "No GRKERNSEC,,,,,,,," "    <grsecurity config='no' />"
    echo_message "  The grsecurity / PaX patchset is available here:\n" "" ""
    echo_message "    http://grsecurity.net/\n" "" ""
  fi

  echo_message "\n" "\n" "\n"
  echo_message "* Kernel Heap Hardening: " "" ""

  if $kconfig | grep -qi 'CONFIG_KERNHEAP=y'; then
    if $kconfig | grep -qi 'CONFIG_KERNHEAP_FULLPOISON=y'; then
      echo_message "\033[32mFull KERNHEAP\033[m\n\n" "Full KERNHEAP\n" "    <kernheap config='yes' />\n</kernel>\n"
    else
      echo_message "\033[33mPartial KERNHEAP\033[m\n\n" "Partial KERNHEAP\n" "    <kernheap config='partial' />\n</kernel>\n"
    fi
  else
    echo_message "\033[31mNo KERNHEAP\033[m\n\n" "No KERNHEAP\n" "    <kernheap config='no' />\n</kernel>\n"
    echo_message "  The KERNHEAP hardening patchset is available here:\n"
    echo_message "    https://www.subreption.com/kernheap/\n\n"
  fi
}

# --- FORTIFY_SOURCE subfunctions (start) ---

# is FORTIFY_SOURCE supported by libc?
FS_libc_check() {
  echo_message "* FORTIFY_SOURCE support available (libc)    : " "" ""

  if [ "${#FS_chk_func_libc[@]}" != "0" ] ; then
    echo_message "\033[32mYes\033[m\n" "Yes," " libc_fortify_source='yes'"
  else
    echo_message "\033[31mNo\033[m\n" "No," " libc_fortify_source='no' />"
    exit 1
  fi
}

# was the binary compiled with FORTIFY_SOURCE?
FS_binary_check() {
  echo_message "* Binary compiled with FORTIFY_SOURCE support: " "" ""

  for FS_elem_functions in $(seq 0 $((${#FS_functions[@]} - 1)))
  do
    if [[ ${FS_functions[$FS_elem_functions]} =~ _chk ]] ; then
      echo_message "\033[32mYes\033[m\n" "Yes\n" " binary_compiled_with_fortify='yes'>\n"
      return
    fi
  done
  echo_message "\033[31mNo\033[m\n" "No\n" " binary_compiled_with_fortify='no'>\n"
  exit 1
}

FS_comparison() {
  echo_message "\n" "" ""
  echo_message " ------ EXECUTABLE-FILE ------- . -------- LIBC --------\n" "" ""
  echo_message " FORTIFY-able library functions | Checked function names\n" "" ""
  echo_message " -------------------------------------------------------\n" "" ""

  for FS_elem_libc in $(seq 0 $((${#FS_chk_func_libc[@]} - 1)))
  do
    for FS_elem_functions in $(seq 0 $((${#FS_functions[@]} - 1)))
    do
      FS_tmp_func=${FS_functions[$FS_elem_functions]}
      FS_tmp_libc=${FS_chk_func_libc[$FS_elem_libc]}

      if [[ $FS_tmp_func =~ ^$FS_tmp_libc$ ]] ; then
	if [[ $format == "cli" ]]; then
	    printf " \033[31m%-30s\033[m | __%s%s\n" $FS_tmp_func $FS_tmp_libc $FS_end
	else
	  echo_message "" "$FS_tmp_func,$FS_tmp_libc,yes\n" "    <function name='$FS_tmp_func' libc='$FS_tmp_libc' fortifyable='yes' />\n"
	fi
        let FS_cnt_total++
        let FS_cnt_unchecked++
      elif [[ $FS_tmp_func =~ ^$FS_tmp_libc(_chk) ]] ; then
      	if [[ $format == "cli" ]]; then
	    printf " \033[32m%-30s\033[m | __%s%s\n" $FS_tmp_func $FS_tmp_libc $FS_end
	else
	  echo_message "" "$FS_tmp_func,$FS_tmp_libc,no\n" "    <function name='$FS_tmp_func' libc='$FS_tmp_libc' fortifyable='no' />\n"
	fi
        let FS_cnt_total++
        let FS_cnt_checked++
      fi

    done
  done
}

FS_summary() {
  echo_message "\n" "" "\n"
  echo_message "SUMMARY:\n\n" "" ""
  echo_message "* Number of checked functions in libc                : ${#FS_chk_func_libc[@]}\n" "${#FS_chk_func_libc[@]}," "    <stats nb_libc_func='${#FS_chk_func_libc[@]}'"
  echo_message "* Total number of library functions in the executable: ${#FS_functions[@]}\n" "${#FS_functions[@]}," " nb_total_func='${#FS_functions[@]}'"
  echo_message "* Number of FORTIFY-able functions in the executable : $FS_cnt_total\n"  "$FS_cnt_total," " nb_fortifyable_func='$FS_cnt_total'"
  echo_message "* Number of checked functions in the executable      : \033[32m$FS_cnt_checked\033[m\n" "$FS_cnt_total," " nb_checked_func='$FS_cnt_total'"
  echo_message "* Number of unchecked functions in the executable    : \033[31m$FS_cnt_unchecked\033[m\n" "$FS_cnt_unchecked" " nb_unchecked_func='$FS_cnt_unchecked' />"
  echo_message "\n" "\n" "\n"
}

# --- FORTIFY_SOURCE subfunctions (end) ---

if !(command_exists readelf) ; then
  echo "\033[31mWarning: 'readelf' not found! It's required for most checks.\033[m\n\n"
  have_readelf=0
fi

while [[ "$@" != "" ]]
do
  # parse command-line arguments
  case "$1" in

  --version)
    version
    exit 0
    ;;

  --help)
    help
    exit 0
    ;;

  --format)
    list="cli csv xml"
    if [ -n "$2" ]; then
      if [[ ! $list =~ "$2" ]]; then
	  printf "\033[31mError: Please provide a valid format {cli, csv, xml}.\033[m\n\n"
	  exit 1
      fi
    fi
    format="$2"
    shift 2
    ;;
  
  --dir)
    if [ "$3" = "-v" ] ; then
      verbose=true
    fi
    if [ $have_readelf -eq 0 ] ; then
      exit 1
    fi
    if [ -z "$2" ] ; then
      printf "\033[31mError: Please provide a valid directory.\033[m\n\n"
      exit 1
    fi
    # remove trailing slashes
    tempdir=`echo $2 | sed -e "s/\/*$//"`
    if [ ! -d $tempdir ] ; then
      printf "\033[31mError: The directory '$tempdir' does not exist.\033[m\n\n"
      exit 1
    fi
    cd $tempdir
    echo_message "RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE\n" '' "<dir name='$tempdir'>\n"
    
    for N in [A-Za-z]*; do
      if [ "$N" != "[A-Za-z]*" ]; then
	# read permissions?
	if [ ! -r $N ]; then
	  printf "\033[31mError: No read permissions for '$tempdir/$N' (run as root).\033[m\n"
	else
	  # ELF executable?
	  out=`file $N`
	  if [[ ! $out =~ ELF ]] ; then
	    if [ "$verbose" = "true" ] ; then
	      echo_message "\033[34m*** Not an ELF file: $tempdir/" "" ""
	      file $N
	      echo_message "\033[m" "" ""
	    fi
	  else
	    echo_message "" "" "    "
	    filecheck $N
	    if [ `find $tempdir/$N \( -perm -004000 -o -perm -002000 \) -type f -print` ]; then
	      echo_message "\033[37;41m$2$N\033[m\n" ",$2$N\n" " filename='$2$N' />\n"
	    else
	      echo_message "$tempdir/$N\n" ",$tempdir/$N\n" " filename='$tempdir/$N' />\n" 
	    fi
	  fi
	fi
      fi
    done
    echo_message "" "" "</dir>\n"
    exit 0
    ;;
  
  --file)
    if [ $have_readelf -eq 0 ] ; then
      exit 1
    fi
    if [ -z "$2" ] ; then
      printf "\033[31mError: Please provide a valid file.\033[m\n\n"
    exit 1
    fi
    # does the file exist?
    if [ ! -e $2 ] ; then
      printf "\033[31mError: The file '$2' does not exist.\033[m\n\n"
      exit 1
    fi
    # read permissions?
    if [ ! -r $2 ] ; then
      printf "\033[31mError: No read permissions for '$2' (run as root).\033[m\n\n"
      exit 1
    fi
    # ELF executable?
    out=`file $2`
    if [[ ! $out =~ ELF ]] ; then
      printf "\033[31mError: Not an ELF file: "
      file $2
      printf "\033[m\n"
      exit 1
    fi
    echo_message "RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE\n" '' ''
    filecheck $2
    if [ `find $2 \( -perm -004000 -o -perm -002000 \) -type f -print` ] ; then
      echo_message "\033[37;41m$2$N\033[m" ",$2$N" " filename='$2$N'/>\n"
    else
      echo_message "$2\n" ",$2\n" " filename='$2'/>\n"
    fi
    echo
    exit 0
    ;;

  --proc-all)
    if [ $have_readelf -eq 0 ] ; then
      exit 1
    fi
    cd /proc
    echo_message "* System-wide ASLR" '' ''
    aslrcheck
    echo_message "* Does the CPU support NX: " '' ''
    nxcheck
    echo_message "         COMMAND    PID RELRO           STACK CANARY      NX/PaX        PIE\n" '' ''
    for N in [1-9]*; do
      if [ $N != $$ ] && readlink -q $N/exe > /dev/null; then
	name=`head -1 $N/status | cut -b 7-`
	if [[ $format == "cli" ]]; then
	    printf "%16s" $name
	    printf "%7d " $N
	else
	  echo_message "" "$name," "<proc name='$name'"
	  echo_message "" "$N," " pid='$N'"
	fi
	proccheck $N
	echo_message "\n" "\n" "</proc>\n"
      fi
    done
    if [ ! -e /usr/bin/id ] ; then
      echo_message "\n\033[33mNote: If you are running 'checksec.sh' as an unprivileged user, you\n" "" ""
      echo_message "      will not see all processes. Please run the script as root.\033[m\n\n" "" ""
    else 
      if !(root_privs) ; then
	echo_message "\n\033[33mNote: You are running 'checksec.sh' as an unprivileged user.\n" "" ""
	echo_message "      Too see all processes, please run the script as root.\033[m\n\n" "" ""
      fi
    fi
    exit 0
    ;;

  --proc)
    if [ $have_readelf -eq 0 ] ; then
      exit 1
    fi
    if [ -z "$2" ] ; then
      printf "\033[31mError: Please provide a valid process name.\033[m\n\n"
      exit 1
    fi
    if !(isString "$2") ; then
      printf "\033[31mError: Please provide a valid process name.\033[m\n\n"
      exit 1
    fi
    cd /proc
    echo_message "* System-wide ASLR" '' ''
    aslrcheck
    echo_message "* Does the CPU support NX: " '' ''
    nxcheck
    echo_message "         COMMAND    PID RELRO             STACK CANARY           NX/PaX        PIE\n" '' ''
    for N in `ps -Ao pid,comm | grep $2 | cut -b1-6`; do
      if [ -d $N ] ; then
	name=`head -1 $N/status | cut -b 7-`
	if [[ $format == "cli" ]]; then
	    printf "%16s" $name
	    printf "%7d " $N
	else
	  echo_message "" "$name," "<proc name='$name'"
	  echo_message "" "$N," " pid='$N'"
	fi
	if [ ! -r $N/exe ] ; then
	  if !(root_privs) ; then
	    printf "\033[31mNo read permissions for '/proc/$N/exe' (run as root).\033[m\n\n"
	    exit 1
	  fi
	  if [ ! `readlink $N/exe` ] ; then
	    printf "\033[31mPermission denied. Requested process ID belongs to a kernel thread.\033[m\n\n"
	    exit 1
	  fi
	  exit 1
	fi
	proccheck $N
	echo_message "\n" "\n" "</proc>\n"
      fi
    done
    exit 0
    ;;

  --proc-libs)
    if [ $have_readelf -eq 0 ] ; then
      exit 1
    fi
    if [ -z "$2" ] ; then
      printf "\033[31mError: Please provide a valid process ID.\033[m\n\n"
      exit 1
    fi
    if !(isNumeric "$2") ; then
      printf "\033[31mError: Please provide a valid process ID.\033[m\n\n"
      exit 1
    fi
    cd /proc
    echo_message "* System-wide ASLR" '' ''
    aslrcheck
    echo_message "* Does the CPU support NX: " '' ''
    nxcheck
    echo_message "* Process information:\n\n" "" ""
    echo_message "         COMMAND    PID RELRO             STACK CANARY           NX/PaX        PIE\n" '' ''
    N=$2
    if [ -d $N ] ; then
	name=`head -1 $N/status | cut -b 7-`
	if [[ $format == "cli" ]]; then
	    printf "%16s" $name
	    printf "%7d " $N
	else
	  echo_message "" "$name," "<proc name='$name'"
	  echo_message "" "$N," " pid='$N'"
	fi
      # read permissions?
      if [ ! -r $N/exe ] ; then
	if !(root_privs) ; then
	  printf "\033[31mNo read permissions for '/proc/$N/exe' (run as root).\033[m\n\n"
	  exit 1
	fi
	if [ ! `readlink $N/exe` ] ; then
	  printf "\033[31mPermission denied. Requested process ID belongs to a kernel thread.\033[m\n\n"
	  exit 1
	fi
	exit 1
      fi
      proccheck $N
      echo_message "\n" "\n" "\n"
      libcheck $N
      echo_message "\n" "\n" "</proc>\n"
    fi
    exit 0
    ;;

  --kernel)
    cd /proc
    echo_message "* Kernel protection information:\n\n" "" ""
    kernelcheck
    exit 0
    ;;

  --fortify-file)
    if [ $have_readelf -eq 0 ] ; then
      exit 1
    fi
    if [ -z "$2" ] ; then
      printf "\033[31mError: Please provide a valid file.\033[m\n\n"
    exit 1
    fi
    # does the file exist?
    if [ ! -e $2 ] ; then
      printf "\033[31mError: The file '$2' does not exist.\033[m\n\n"
      exit 1
    fi
    # read permissions?
    if [ ! -r $2 ] ; then
      printf "\033[31mError: No read permissions for '$2' (run as root).\033[m\n\n"
      exit 1
    fi
    # ELF executable?
    out=`file $2`
    if [[ ! $out =~ ELF ]] ; then
      printf "\033[31mError: Not an ELF file: "
      file $2
      printf "\033[m\n"
      exit 1
    fi
    if [ -e /lib/libc.so.6 ] ; then
      FS_libc=/lib/libc.so.6
    elif [ -e /lib64/libc.so.6 ] ; then
      FS_libc=/lib64/libc.so.6
    elif [ -e /lib/i386-linux-gnu/libc.so.6 ] ; then
      FS_libc=/lib/i386-linux-gnu/libc.so.6
    elif [ -e /lib/x86_64-linux-gnu/libc.so.6 ] ; then
      FS_libc=/lib/x86_64-linux-gnu/libc.so.6
    else
      printf "\033[31mError: libc not found.\033[m\n\n"
      exit 1
    fi

    FS_chk_func_libc=( $(readelf -s $FS_libc | grep _chk@@ | awk '{ print $8 }' | cut -c 3- | sed -e 's/_chk@.*//') )
    FS_functions=( $(readelf -s $2 | awk '{ print $8 }' | sed 's/_*//' | sed -e 's/@.*//') )

    echo_message "" "" "<fortify-test name='$2' "
    FS_libc_check
    FS_binary_check
    FS_comparison
    FS_summary
    echo_message "" "" "</fortify-test>\n"
    exit 0
    ;;

  --fortify-proc)
    if [ $have_readelf -eq 0 ] ; then
      exit 1
    fi
    if [ -z "$2" ] ; then
      printf "\033[31mError: Please provide a valid process ID.\033[m\n\n"
      exit 1
    fi
    if !(isNumeric "$2") ; then
      printf "\033[31mError: Please provide a valid process ID.\033[m\n\n"
      exit 1
    fi
    cd /proc
    N=$2
    if [ -d $N ] ; then
      # read permissions?
      if [ ! -r $N/exe ] ; then
	if !(root_privs) ; then
	  printf "\033[31mNo read permissions for '/proc/$N/exe' (run as root).\033[m\n\n"
	  exit 1
	fi
	if [ ! `readlink $N/exe` ] ; then
	  printf "\033[31mPermission denied. Requested process ID belongs to a kernel thread.\033[m\n\n"
	  exit 1
	fi
	exit 1
      fi
      if [ -e /lib/libc.so.6 ] ; then
	FS_libc=/lib/libc.so.6
      elif [ -e /lib64/libc.so.6 ] ; then
	FS_libc=/lib64/libc.so.6
      elif [ -e /lib/i386-linux-gnu/libc.so.6 ] ; then
	FS_libc=/lib/i386-linux-gnu/libc.so.6
      elif [ -e /lib/x86_64-linux-gnu/libc.so.6 ] ; then
	FS_libc=/lib/x86_64-linux-gnu/libc.so.6
      else
	printf "\033[31mError: libc not found.\033[m\n\n"
	exit 1
      fi
      name=`head -1 $N/status | cut -b 7-`
      echo_message  "* Process name (PID)                         : $name ($N)\n" "" ""
      FS_chk_func_libc=( $(readelf -s $FS_libc | grep _chk@@ | awk '{ print $8 }' | cut -c 3- | sed -e 's/_chk@.*//') )
      FS_functions=( $(readelf -s $2/exe | awk '{ print $8 }' | sed 's/_*//' | sed -e 's/@.*//') )

      echo_message "" "" "<fortify-test name='$name' pid='$N' "
      FS_libc_check
      FS_binary_check
      FS_comparison
      FS_summary
      echo_message "" "" "</fortify-test>\n"
    fi
    exit 0
    ;;

  *)
    if [ "$#" != "0" ] ; then
      printf "\033[31mError: Unknown option '$1'.\033[m\n\n"
    fi
    help
    exit 1
    ;;
  esac
done