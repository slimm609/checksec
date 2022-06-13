#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

chk_kernel() {
  if [[ ${CHK_KERNEL} == "kernel" ]]; then
    CHK_KERNEL=""
  fi
  if [[ -e "${CHK_KERNEL}" ]] && [[ ! -d "${CHK_KERNEL}" ]]; then
    if [[ -s "$(pwd -P)/${CHK_KERNEL}" ]]; then
      configfile=$(pwd -P)/${CHK_KERNEL}
    elif [[ -s "${CHK_KERNEL}" ]]; then
      configfile=${CHK_KERNEL}
    else
      "Error: config file specified do not exist"
      exit 1
    fi
    echo_message "* Kernel protection information for : $configfile \n\n" "" "" ""
    cd /proc && kernelcheck "$configfile" || exit
  else
    cd /proc || exit
    echo_message "* Kernel protection information:\n\n" "" "" ""
    kernelcheck
  fi
}

# check selinux status
getsestatus() {
  local status
  if (command_exists getenforce); then
    sestatus=$(getenforce)
    if [[ "${sestatus}" == "Disabled" ]]; then
      status=0
    elif [[ "${sestatus}" == "Permissive" ]]; then
      status=1
    elif [[ "${sestatus}" == "Enforcing" ]]; then
      status=2
    fi
  elif (command_exists sestatus); then
    sestatus=$(sestatus | grep "SELinux status" | awk '{ print $3}')
    if [[ "${sestatus}" == "disabled" ]]; then
      status=0
    elif [[ "${sestatus}" == "enabled" ]]; then
      sestatus2=$(sestatus | grep "Current" | awk '{ print $3}')
      if [[ "${sestatus2}" == "permissive" ]]; then
        status=1
      elif [[ "${sestatus2}" == "enforcing" ]]; then
        status=2
      fi
    fi
  fi
  return ${status}
}

# check for kernel protection mechanisms
kernelcheck() {
  echo_message "  Description - List the status of kernel protection mechanisms. Rather than\n" '' '' ''
  echo_message "  inspect kernel mechanisms that may aid in the prevention of exploitation of\n" '' '' ''
  echo_message "  userspace processes, this option lists the status of kernel configuration\n" '' '' ''
  echo_message "  options that harden the kernel itself against attack.\n\n" '' '' ''
  echo_message "  Kernel config:\n" '' '' '{ "kernel": '

  if [[ ! "${1}" == "" ]]; then
    kconfig="cat ${1}"
    echo_message "  Warning: The config ${1} on disk may not represent running kernel config!\n\n" "${1}" "<kernel config=\"${1}\"" "{ \"KernelConfig\":\"${1}\""
    # update the architecture based on the config rather than the system
    if ${kconfig} | grep -qi 'CONFIG_ARM=y\|CONFIG_ARM=y'; then
      arch="arm"
    fi
    if ${kconfig} | grep -qi 'CONFIG_ARM64=y'; then
      arch="aarch64"
    fi
    if ${kconfig} | grep -qi 'CONFIG_X86_64=y'; then
      arch="64"
    fi
    if ${kconfig} | grep -qi 'CONFIG_X86_32=y'; then
      arch="32"
    fi
  elif [[ -f /proc/config.gz ]]; then
    kconfig="zcat /proc/config.gz"
    echo_message "\033[32m/proc/config.gz\033[m\n\n" '/proc/config.gz' '<kernel config="/proc/config.gz"' '{ "KernelConfig":"/proc/config.gz"'
  elif [[ -f /boot/config-"$(uname -r)" ]]; then
    kern=$(uname -r)
    kconfig="cat /boot/config-${kern}"
    echo_message "\033[33m    /boot/config-${kern}\033[m\n\n" "/boot/config-${kern}," "<kernel config='/boot/config-${kern}'" "{ \"KernelConfig\":\"/boot/config-${kern}\""
    echo_message "  Warning: The config on disk may not represent running kernel config!\n           Running kernel: ${kern}\n\n" "" "" ""
  elif [[ -f "${KBUILD_OUTPUT:-/usr/src/linux}"/.config ]]; then
    kconfig="cat ${KBUILD_OUTPUT:-/usr/src/linux}/.config"
    echo_message "\033[33m${KBUILD_OUTPUT:-/usr/src/linux}/.config\033[m\n\n" "${KBUILD_OUTPUT:-/usr/src/linux}/.config," "<kernel config='${KBUILD_OUTPUT:-/usr/src/linux}/.config'" "{ \"KernelConfig\":\"${KBUILD_OUTPUT:-/usr/src/linux}/.config\""
    echo_message "  Warning: The config on disk may not represent running kernel config!\n\n" "" "" ""
  else
    echo_message "\033[31mNOT FOUND\033[m\n\n" "NOT FOUND,,,,,,," "<kernel config='not_found' />" '{ "KernelConfig":"not_found" } }'
    exit 0
  fi

  echo_message "  Vanilla Kernel ASLR:                    " "" "" ""
  randomize_va=$(sysctl -n kernel.randomize_va_space)
  if [[ "${randomize_va}" == "2" ]]; then
    echo_message "\033[32mFull\033[m\n" "Full," " randomize_va_space='full'" ', "randomize_va_space":"full"'
  elif [[ "${randomize_va}" == "1" ]]; then
    echo_message "\033[33mPartial\033[m\n" "Partial," " randomize_va_space='partial'" ', "randomize_va_space":"partial"'
  else
    echo_message "\033[31mNone\033[m\n" "None," " randomize_va_space='none'" ', "randomize_va_space":"none"'
  fi

  echo_message "  NX protection:                          " "" "" ""
  if (command_exists journalctl); then
    nx_protection=$(journalctl -kb -o cat | grep -Fw NX | head -n 1)
  elif (command_exists dmesg) && (root_privs); then
    nx_protection=$(dmesg -t 2> /dev/null | grep -Fw NX)
  fi
  if [ -n "$nx_protection" ]; then
    if [[ "${nx_protection}" == "NX (Execute Disable) protection: active" ]]; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " nx_protection='yes'" ', "nx_protection":"yes"'
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " nx_protection='no'" ', "nx_protection":"no"'
    fi
  else
    echo_message "\033[33mSkipped\033[m\n" "Skipped," " nx_protection='skipped'" ', "nx_protection":"skipped"'
  fi

  echo_message "  Protected symlinks:                     " "" "" ""
  symlink=$(sysctl -n fs.protected_symlinks)
  if [[ "${symlink}" == "1" ]]; then
    echo_message "\033[32mEnabled\033[m\n" "Enabled," " protect_symlinks='yes'" ', "protect_symlinks":"yes"'
  else
    echo_message "\033[31mDisabled\033[m\n" "Disabled," " protect_symlinks='no'" ', "protect_symlinks":"no"'
  fi

  echo_message "  Protected hardlinks:                    " "" "" ""
  hardlink=$(sysctl -n fs.protected_hardlinks)
  if [[ "${hardlink}" == "1" ]]; then
    echo_message "\033[32mEnabled\033[m\n" "Enabled," " protect_hardlinks='yes'" ', "protect_hardlinks":"yes"'
  else
    echo_message "\033[31mDisabled\033[m\n" "Disabled," " protect_hardlinks='no'" ', "protect_hardlinks":"no"'
  fi

  echo_message "  Protected fifos:                        " "" "" ""
  fifos=$(sysctl -n fs.protected_fifos)
  if [[ -z "${fifos}" ]]; then
    echo_message "\033[33mUnsupported\033[m\n" "Unsupported," " protect_fifos='unsupported'" ', "protect_fifos":"unsupported"'
  elif [[ "${fifos}" == "1" ]]; then
    echo_message "\033[33mPartial\033[m\n" "Partial," " protect_fifos='partial'" ', "protect_fifos":"partial"'
  elif [[ "${fifos}" == "2" ]]; then
    echo_message "\033[32mEnabled\033[m\n" "Enabled," " protect_fifos='yes'" ', "protect_fifos":"yes"'
  else
    echo_message "\033[31mDisabled\033[m\n" "Disabled," " protect_fifos='no'" ', "protect_fifos":"no"'
  fi

  echo_message "  Protected regular:                      " "" "" ""
  regular=$(sysctl -n fs.protected_regular)
  if [[ -z "${regular}" ]]; then
    echo_message "\033[33mUnsupported\033[m\n" "Unsupported," " protect_regular='unsupported'" ', "protect_regular":"unsupported"'
  elif [[ "${regular}" == "1" ]]; then
    echo_message "\033[33mPartial\033[m\n" "Partial," " protect_regular='partial'" ', "protect_regular":"partial"'
  elif [[ "${regular}" == "2" ]]; then
    echo_message "\033[32mEnabled\033[m\n" "Enabled," " protect_regular='yes'" ', "protect_regular":"yes"'
  else
    echo_message "\033[31mDisabled\033[m\n" "Disabled," " protect_regular='no'" ', "protect_regular":"no"'
  fi

  echo_message "  Ipv4 reverse path filtering:            " "" "" ""
  ipv4_rpath=$(sysctl -n net.ipv4.conf.all.rp_filter)
  if [[ "${ipv4_rpath}" == "1" ]]; then
    echo_message "\033[32mEnabled\033[m\n" "Enabled," " ipv4_rpath='yes'" ', "ipv4_rpath":"yes"'
  else
    echo_message "\033[31mDisabled\033[m\n" "Disabled," " ipv4_rpath='no'" ', "ipv4_rpath":"no"'
  fi

  echo_message "  Kernel heap randomization:              " "" "" ""
  # NOTE: y means it turns off kernel heap randomization for backwards compatability (libc5)
  if ${kconfig} | grep -qi 'CONFIG_COMPAT_BRK=y'; then
    echo_message "\033[31mDisabled\033[m\n" "Disabled," " kernel_heap_randomization='no'" ', "kernel_heap_randomization":"no"'
  else
    echo_message "\033[32mEnabled\033[m\n" "Enabled," " kernel_heap_randomization='yes'" ', "kernel_heap_randomization":"yes"'
  fi

  if ${kconfig} | grep -qi 'CONFIG_CC_STACKPROTECTOR' || ${kconfig} | grep -qa 'CONFIG_STACKPROTECTOR'; then
    echo_message "  GCC stack protector support:            " "" "" ""
    if ${kconfig} | grep -qi 'CONFIG_CC_STACKPROTECTOR=y' || ${kconfig} | grep -qi 'CONFIG_STACKPROTECTOR=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " gcc_stack_protector='yes'" ', "gcc_stack_protector":"yes"'

      if ${kconfig} | grep -qi 'CONFIG_CC_STACKPROTECTOR_STRONG' || ${kconfig} | grep -qi 'CONFIG_STACKPROTECTOR_STRONG'; then
        echo_message "  GCC stack protector strong:             " "" "" ""
        if ${kconfig} | grep -qi 'CONFIG_CC_STACKPROTECTOR_STRONG=y' || ${kconfig} | grep -qi 'CONFIG_STACKPROTECTOR_STRONG=y'; then
          echo_message "\033[32mEnabled\033[m\n" "Enabled," " gcc_stack_protector_strong='yes'" ', "gcc_stack_protector_strong":"yes"'
        else
          echo_message "\033[31mDisabled\033[m\n" "Disabled," " gcc_stack_protector_strong='no'" ', "gcc_stack_protector_strong":"no"'
        fi
      fi
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " gcc_stack_protector='no'" ', "gcc_stack_protector":"no"'
    fi
  fi

  if ${kconfig} | grep -qi 'CONFIG_GCC_PLUGIN_STRUCTLEAK'; then
    echo_message "  GCC structleak plugin:                  " "" "" ""
    if ${kconfig} | grep -qi 'CONFIG_GCC_PLUGIN_STRUCTLEAK=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " gcc_structleak='yes'" ', "gcc_structleak":"yes"'
      echo_message "  GCC structleak by ref plugin:           " "" "" ""
      if ${kconfig} | grep -qi 'CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL=y'; then
        echo_message "\033[32mEnabled\033[m\n" "Enabled," " gcc_structleak_byref='yes'" ', "gcc_structleak_byref":"yes"'
      else
        echo_message "\033[32mEnabled\033[m\n" "Enabled," " gcc_structleak_byref='no'" ', "gcc_structleak_byref":"no"'
      fi
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " gcc_structleak='no'" ', "gcc_structleak":"no"'
    fi
  fi

  if ${kconfig} | grep -qi 'CONFIG_SLAB_FREELIST_RANDOM'; then
    echo_message "  SLAB freelist randomization:            " "" "" ""
    if ${kconfig} | grep -qi 'CONFIG_SLAB_FREELIST_RANDOM=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " slab_freelist_randomization='yes'" ', "slab_freelist_randomization":"yes"'
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " slab_freelist_randomization='no'" ', "slab_freelist_randomization":"no"'
    fi
  fi

  if ${kconfig} | grep -qi 'CPU_SW_DOMAIN_PAN=y'; then
    echo_message "  Use CPU domains:                        " "" "" ""
    if ${kconfig} | grep -qi 'CPU_SW_DOMAIN_PAN=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " cpu_sw_domain'yes'" ', "cpu_sw_domain":"yes"'
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " cpu_sw_domain='no'" ', "cpu_sw_domain":"no"'
    fi
  fi

  if ${kconfig} | grep -qi 'CONFIG_VMAP_STACK'; then
    echo_message "  Virtually-mapped kernel stack:          " "" "" ""
    if ${kconfig} | grep -qi 'CONFIG_VMAP_STACK=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " virtually_mapped_stack='yes'" ', "virtually_mapped_stack":"yes"'
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " virtually_mapped_stack='no'" ', "virtually_mapped_stack":"no"'
    fi
  fi

  if ${kconfig} | grep -qi 'CONFIG_STRICT_DEVMEM'; then
    echo_message "  Restrict /dev/mem access:               " "" "" ""
    if ${kconfig} | grep -qi 'CONFIG_STRICT_DEVMEM=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " restrict_dev_mem_access='yes'" ', "restrict_dev_mem_access":"yes"'
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " restrict_dev_mem_access='no'" ', "restrict_dev_mem_access":"no"'
    fi
  fi

  if ${kconfig} | grep -qi 'CONFIG_IO_STRICT_DEVMEM'; then
    echo_message "  Restrict I/O access to /dev/mem:        " "" "" ""
    if ${kconfig} | grep -qi 'CONFIG_IO_STRICT_DEVMEM=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " restrict_io_dev_mem_access='yes'" ', "restrict_io_dev_mem_access":"yes"'
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " restrict_io_dev_mem_access='no'" ', "restrict_io_dev_mem_access":"no"'
    fi
  fi

  if ${kconfig} | grep -qi 'CONFIG_REFCOUNT_FULL'; then
    echo_message "  Full reference count validation:        " "" "" ""
    if ${kconfig} | grep -qi 'CONFIG_REFCOUNT_FULL=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " full_refcount_validation='yes'" ', "full_refcount_validation":"yes"'
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " full_refcount_validation='no'" ', "full_refcount_validation":"no"'
    fi
  fi

  echo_message "  Exec Shield:                            " """" ""
  execshield=$(sysctl -n kernel.exec-shield 2> /dev/null)
  if [[ -z "${execshield}" ]]; then
    echo_message '\033[32mUnsupported\033[m\n' '' '' ''
  elif [[ "${execshield}" == "1" ]]; then
    echo_message '\033[32mEnabled\033[m\n' '' '' ''
  else
    echo_message '\033[31mDisabled\033[m\n' '' '' ''
  fi

  echo_message "  YAMA:                                   " """" ""
  yama_ptrace_scope=$(sysctl -n kernel.yama.ptrace_scope 2> /dev/null)
  if [[ -z "${yama_ptrace_scope}" ]]; then
    echo_message "\033[31mDisabled\033[m\n\n" "Disabled," " yama_ptrace_scope='disabled'" ', "yama_ptrace_scope":"disabled"'
  elif [[ "${yama_ptrace_scope}" == "0" ]]; then
    echo_message "\033[31mInactive\033[m\n\n" "Inactive," " yama_ptrace_scope='inactive'" ', "yama_ptrace_scope":"inactive"'
  else
    echo_message "\033[32mActive\033[m\n\n" "Active," " yama_ptrace_scope='active'" ', "yama_ptrace_scope":"active"'
  fi

  if ${kconfig} | grep -qi 'CONFIG_HARDENED_USERCOPY'; then
    echo_message "  Hardened Usercopy:                      " "" "" ""
    if ${kconfig} | grep -qi 'CONFIG_HARDENED_USERCOPY=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " hardened_usercopy='yes'" ', "hardened_usercopy":"yes"'
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " hardened_usercopy='no'" ', "hardened_usercopy":"no"'
    fi
  fi

  if ${kconfig} | grep -qi 'CONFIG_FORTIFY_SOURCE'; then
    echo_message "  Harden str/mem functions:               " "" "" ""
    if ${kconfig} | grep -qi 'CONFIG_FORTIFY_SOURCE=y'; then
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " fortify_source='yes'" ', "fortify_source":"yes"'
    else
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " fortify_source='no'" ', "fortify_source":"no"'
    fi
  fi

  if ${kconfig} | grep -qi 'CONFIG_DEVKMEM'; then
    echo_message "  Restrict /dev/kmem access:              " "" "" ""
    if ${kconfig} | grep -qi 'CONFIG_DEVKMEM=y'; then
      echo_message "\033[31mDisabled\033[m\n" "Disabled," " restrict_dev_kmem_access='no'" ', "restrict_dev_kmem_access":"no"'
    else
      echo_message "\033[32mEnabled\033[m\n" "Enabled," " restrict_dev_kmem_access='yes'" ', "restrict_dev_kmem_access":"yes"'
    fi
  fi

  #x86 only
  if [[ "${arch}" == "32" ]] || [[ "${arch}" == "64" ]]; then
    echo_message "\n" "\n" "" ""
    echo_message "* X86 only:            \n" "" "" ""

    if ! ${kconfig} | grep -qi 'CONFIG_PAX_SIZE_OVERFLOW=y'; then
      if ${kconfig} | grep -qi 'CONFIG_DEBUG_STRICT_USER_COPY_CHECKS'; then
        echo_message "  Strict user copy checks:                " "" "" ""
        if ${kconfig} | grep -qi 'CONFIG_DEBUG_STRICT_USER_COPY_CHECKS=y'; then
          echo_message "\033[32mEnabled\033[m\n" "Enabled," " strict_user_copy_check='yes'" ', "strict_user_copy_check":"yes"'
        else
          echo_message "\033[31mDisabled\033[m\n" "Disabled," " strict_user_copy_check='no'" ', "strict_user_copy_check":"no"'
        fi
      fi
    fi

    if ${kconfig} | grep -qi 'CONFIG_RANDOMIZE_BASE' || ${kconfig} | grep -qi 'CONFIG_PAX_ASLR'; then
      echo_message "  Address space layout randomization:     " "" "" ""
      if ${kconfig} | grep -qi 'CONFIG_RANDOMIZE_BASE=y' || ${kconfig} | grep -qi 'CONFIG_PAX_ASLR=y'; then
        echo_message "\033[32mEnabled\033[m\n" "Enabled," " random_address_space_layout='yes'" ', "random_address_space_layout":"yes"'
      else
        echo_message "\033[31mDisabled\033[m\n" "Disabled," " random_address_space_layout='no'" ', "random_address_space_layout":"no"'
      fi
    fi
  fi

  #ARM only
  if [[ "${arch}" == "arm" ]]; then
    echo_message "\n" "\n" "\n" ""
    echo_message "* ARM only:            \n" "" "" ""

    if ${kconfig} | grep -qi 'CONFIG_ARM_KERNMEM_PERMS'; then
      echo_message "  Restrict kernel memory permissions:     " "" "" ""
      if ${kconfig} | grep -qi 'CONFIG_ARM_KERNMEM_PERMS=y'; then
        echo_message "\033[32mEnabled\033[m\n" "Enabled," " arm_kernmem_perms='yes'" ', "arm_kernmem_perms":"yes"'
      else
        echo_message "\033[31mDisabled\033[m\n" "Disabled," " arm_kernmem_perms='no'" ', "arm_kernmem_perms":"no"'
      fi
    fi

    if ${kconfig} | grep -qi 'CONFIG_DEBUG_ALIGN_RODATA'; then
      echo_message "  Make rodata strictly non-excutable:     " "" "" ""
      if ${kconfig} | grep -qi 'CONFIG_DEBUG_ALIGN_RODATA=y'; then
        echo_message "\033[32mEnabled\033[m\n" "Enabled," " arm_strict_rodata='yes'" ', "arm_strict_rodata":"yes"'
      else
        echo_message "\033[31mDisabled\033[m\n" "Disabled," " arm_strict_rodata='no'" ', "arm_strict_rodata":"no"'
      fi
    fi

  fi

  #ARM64 only
  if [[ "${arch}" == "aarch64" ]]; then
    echo_message "\n" "\n" "\n" ""
    echo_message "* ARM64 only:            \n" "" "" ""

    if ${kconfig} | grep -qi 'CONFIG_UNMAP_KERNEL_AT_EL0'; then
      echo_message "  Unmap kernel in userspace (KAISER):     " "" "" ""
      if ${kconfig} | grep -qi 'CONFIG_UNMAP_KERNEL_AT_EL0=y'; then
        echo_message "\033[32mEnabled\033[m\n" "Enabled," " unmap_kernel_in_userspace='yes'" ', "unmap_kernel_in_userspace":"yes"'
      else
        echo_message "\033[31mDisabled\033[m\n" "Disabled," " unmap_kernel_in_userspace='no'" ', "unmap_kernel_in_userspace":"no"'
      fi
    fi

    if ${kconfig} | grep -qi 'CONFIG_HARDEN_BRANCH_PREDICTOR'; then
      echo_message "  Harden branch predictor:                " "" "" ""
      if ${kconfig} | grep -qi 'CONFIG_HARDEN_BRANCH_PREDICTOR=y'; then
        echo_message "\033[32mEnabled\033[m\n" "Enabled," " harden_branch_predictor='yes'" ', "harden_branch_predictor":"yes"'
      else
        echo_message "\033[31mDisabled\033[m\n" "Disabled," " harden_branch_predictor='no'" ', "harden_branch_predictor":"no"'
      fi
    fi

    if ${kconfig} | grep -qi 'CONFIG_HARDEN_EL2_VECTORS'; then
      echo_message "  Harden EL2 vector mapping:              " "" "" ""
      if ${kconfig} | grep -qi 'CONFIG_HARDEN_EL2_VECTORS=y'; then
        echo_message "\033[32mEnabled\033[m\n" "Enabled," " harden_el2_vector_mapping='yes'" ', "harden_el2_vector_mapping":"yes"'
      else
        echo_message "\033[31mDisabled\033[m\n" "Disabled," " harden_el2_vector_mapping='no'" ', "harden_el2_vector_mapping":"no"'
      fi
    fi

    if ${kconfig} | grep -qi 'CONFIG_ARM64_SSBD'; then
      echo_message "  Speculative store bypass disable:       " "" "" ""
      if ${kconfig} | grep -qi 'CONFIG_ARM64_SSBD=y'; then
        echo_message "\033[32mEnabled\033[m\n" "Enabled," " speculative_store_bypass_disable='yes'" ', "speculative_store_bypass_disable":"yes"'
      else
        echo_message "\033[31mDisabled\033[m\n" "Disabled," " speculative_store_bypass_disable='no'" ', "speculative_store_bypass_disable":"no"'
      fi
    fi

    if ${kconfig} | grep -qi 'CONFIG_ARM64_SW_TTBR0_PAN'; then
      echo_message "  Emulate privileged access never:        " "" "" ""
      if ${kconfig} | grep -qi 'CONFIG_ARM64_SW_TTBR0_PAN=y'; then
        echo_message "\033[32mEnabled\033[m\n" "Enabled," " emulate_privileged_access_never='yes'" ', "emulate_privileged_access_never":"yes"'
      else
        echo_message "\033[31mDisabled\033[m\n" "Disabled," " emulate_privileged_access_never='no'" ', "emulate_privileged_access_never":"no"'
      fi
    fi

    if ${kconfig} | grep -qi 'CONFIG_RANDOMIZE_BASE'; then
      echo_message "  Randomize address of kernel image:      " "" "" ""
      if ${kconfig} | grep -qi 'CONFIG_RANDOMIZE_BASE=y'; then
        echo_message "\033[32mEnabled\033[m\n" "Enabled," " randomize_kernel_address='yes'" ', "randomize_kernel_address":"yes"'
      else
        echo_message "\033[31mDisabled\033[m\n" "Disabled," " randomize_kernel_address='no'" ', "randomize_kernel_address":"no"'
      fi
    fi

    if ${kconfig} | grep -qi 'CONFIG_RANDOMIZE_MODULE_REGION_FULL'; then
      echo_message "  Randomize module region over 4GB:       " "" "" ""
      if ${kconfig} | grep -qi 'CONFIG_RANDOMIZE_MODULE_REGION_FULL=y'; then
        echo_message "\033[32mEnabled\033[m\n" "Enabled," " randomize_module_region_full='yes'" ', "randomize_module_region_full":"yes"'
      else
        echo_message "\033[31mDisabled\033[m\n" "Disabled," " randomize_module_region_full='no'" ', "randomize_module_region_full":"no"'
      fi
    fi
  fi

  echo_message "" "" ">" "},"

  echo_message "\n" "\n" "\n" ""
  echo_message "* SELinux:                                " "" "" ""
  if ${kconfig} | grep -qi 'CONFIG_SECURITY_SELINUX=y'; then
    getsestatus
    sestatus=$?
    if [[ ${sestatus} == 0 ]]; then
      echo_message "\033[31mDisabled\033[m\n" "Disabled,," "    <selinux enabled='no'" '"selinux":{ "enabled":"no"'
      echo_message "\n  SELinux infomation available here: \n" "" "" ""
      echo_message "    http://selinuxproject.org/\n" "" "" ""
    elif [[ ${sestatus} == 1 ]]; then
      echo_message "\033[33mPermissive\033[m\n" "Permissive," "    <selinux enabled='yes' mode='permissive'" '"selinux":{ "enabled":"yes", "mode":"permissive"'
    elif [[ ${sestatus} == 2 ]]; then
      echo_message "\033[32mEnforcing\033[m\n" "Enforcing," "    <selinux enabled='yes' mode='enforcing'" '"selinux":{ "enabled":"yes", "mode":"enforcing"'
    fi
  else
    echo_message "\033[31mNo SELinux\033[m\n" "Disabled,," "    <selinux enabled='no'" '"selinux":{ "enabled":"no"'
    echo_message "\n  SELinux infomation available here: \n" "" "" ""
    echo_message "    http://selinuxproject.org/\n" "" "" ""
  fi

  if [[ ${sestatus} == 1 ]] || [[ ${sestatus} == 2 ]]; then
    echo_message "  Checkreqprot:                         " "" "" ""
    if [[ $(cat /sys/fs/selinux/checkreqprot) == 0 ]]; then
      echo_message "\033[32m  Enabled\033[m\n" "Enabled," " checkreqprot='yes'" ', "checkreqprot":"yes"'
    else
      echo_message "\033[31m  Disabled\033[m\n" "Disabled," " checkreqprot='no'" ', "checkreqprot":"no"'
    fi

    echo_message "  Deny Unknown:                         " "" "" ""
    if [[ $(cat /sys/fs/selinux/deny_unknown) == 1 ]]; then
      echo_message "\033[32m  Enabled\033[m\n" "Enabled" " deny_unknown='yes'" ', "deny_unknown":"yes"'
    else
      echo_message "\033[31m  Disabled\033[m\n" "Disabled" " deny_unknown='no'" ', "deny_unknown":"no"'
    fi
  fi
  echo_message "\n" "\n" " />\n</kernel>\n" " }}"
}
