#!/bin/bash
# run a quick test of checksec to ensure normal operations. 
DIR=$(cd $(dirname "$0"); pwd)

$DIR/xml-checks.sh || exit 2
$DIR/json-checks.sh || exit 2
