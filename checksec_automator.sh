#!/usr/bin/env bash

# keep checksec executable and checksec_automation file in same directory.

if [ ! -x checksec ]; then
  echo 'checksec file not found or not executable - put it in the same directory and run the script again'
  exit 1
fi

# print a help message if nothing is passed
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 DIRECTORY_TO_SCAN OUTPUT_FILE"
  exit 1
fi

echo "Checksec Output" | tee "$2"

find "$1" -type f -executable -print0 | xargs -r0 file -i -- | grep -e 'application/x-sharedlib; charset=binary' -e 'application/x-pie-executable; charset=binary' -e 'application/x-executable; charset=binary' | cut -d: -f1 | sort |
while read -r i; do
  ./checksec --file="$i"
done | tee -a "$2"

echo 'Use "less -R" to view the output file'
