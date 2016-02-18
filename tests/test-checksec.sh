#!/bin/bash
# run a quick test of checksec to ensure normal operations. 

./xml-checks.sh || exit 2
./json-checks.sh || exit 2
