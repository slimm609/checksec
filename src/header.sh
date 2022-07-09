#!/usr/bin/env bash
# shellcheck disable=SC2154,SC2034
# these top lines are moved during build

# --- Modified Version ---
# Name    : checksec.sh
# Version : 1.7.0
# Author  : Brian Davis
# Date    : Feburary 2014
# Download: https://github.com/slimm609/checksec.sh
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

# set the common paths
PATH=${PATH}:/sbin/:/usr/sbin/:/usr/bin/:/bin/

# sanitize the environment before run
[[ "$(env | sed -r -e '/^(PWD|SHLVL|_)=/d')" ]] && exec -c "$0" "$@"

export PS4='+(${BASH_SOURCE##*/}:${LINENO}): ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'

# License: BSD License
# https://opensource.org/licenses/bsd-license.php
