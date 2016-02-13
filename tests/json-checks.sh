#!/bin/bash

#check json for proc-all
../checksec --format json --proc-all > output.json
jsonlint output.json > /dev/null
if [ $? != 0 ]; then
 echo "proc-all json validation failed"
 exit
fi
#check json for kernel
../checksec --format json --kernel > output.json
jsonlint  output.json
if [ $? != 0 ]; then
 echo "kernel json validation failed"
 exit
fi

#check json against custom kernel config to trigger all checks
../checksec --format json --kernel kernel.config > output.json
jsonlint  output.json
if [ $? != 0 ]; then
 echo "custom kernel json validation failed"
 exit
fi

#check json for file
../checksec --format json --file /bin/ls > output.json
jsonlint  output.json
if [ $? != 0 ]; then
 echo "file json validation failed"
 exit
fi

#check json for fortify file
../checksec --format json --fortify-file /bin/ls > output.json
jsonlint  output.json
if [ $? != 0 ]; then
 echo "fortify-file json validation failed"
 exit
fi
 
#check json for dir 
../checksec --format json --dir /sbin > output.json
jsonlint  output.json
if [ $? != 0 ]; then
 echo "dir json validation failed"
 exit
fi



echo "All XML validation tests passed jsonlint"
rm -f output.json
