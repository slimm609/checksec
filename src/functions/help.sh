#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

# help
help() {
  echo "Usage: checksec [--format={cli,csv,xml,json}] [OPTION]"
  echo
  echo
  echo "Options:"
  echo
  echo " ## Checksec Options"
  echo "  --file={file}"
  echo "  --dir={directory}"
  echo "  --libcfile={file or search path for libc}"
  echo "  --listfile={text file with one file per line}"
  echo "  --proc={process name}"
  echo "  --proc-all"
  echo "  --proc-libs={process ID}"
  echo "  --kernel[=kconfig]"
  echo "  --fortify-file={executable-file}"
  echo "  --fortify-proc={process ID}"
  echo "  --version"
  echo "  --help"
  if ! ${pkg_release}; then
    echo "  --update or --upgrade"
  fi
  echo
  echo " ## Modifiers"
  echo "  --debug"
  echo "  --verbose"
  echo "  --format={cli,csv,xml,json}"
  echo "  --output={cli,csv,xml,json}"
  echo "  --extended"
  echo
  echo "For more information, see:"
  echo "  http://github.com/slimm609/checksec.sh"
  echo
}
