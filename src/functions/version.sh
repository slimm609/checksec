#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

# version information
version() {
  echo "checksec v${SCRIPT_MAJOR}.${SCRIPT_MINOR}.${SCRIPT_REVISION}, Brian Davis, github.com/slimm609/checksec.sh, Dec 2015"
  echo "Based off checksec v1.5, Tobias Klein, www.trapkit.de, November 2011"
  echo
}
