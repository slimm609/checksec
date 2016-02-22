#!/bin/bash

#check json for proc-all
echo "starting proc-all check - json"
../checksec --format json --proc-all > output.json
jsonlint output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "proc-all json validation failed"
 exit $RET
fi

#check json for kernel
echo "starting kernel check - json"
../checksec --format json --kernel > output.json
jsonlint  output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "kernel json validation failed"
 exit $RET
fi

#check json against custom kernel config to trigger all checks
echo "starting custom kernel check - json"
../checksec --format json --kernel kernel.config > output.json
jsonlint  output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "custom kernel json validation failed"
 exit $RET
fi

#check json for file
echo "starting file check - json"
../checksec --format json --file /bin/ls > output.json
jsonlint  output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "file json validation failed"
 exit $RET
fi

#check json for fortify file
echo "starting fortify-file check - json"
if [ -f /bin/ls ]; then 
../checksec --format json --fortify-file /bin/ls > output.json
elif [ -f /bin/bash ]; then
../checksec --format json --fortify-file /bin/bash > output.json
elif [ -f /bin/sh ]; then
../checksec --format json --fortify-file /bin/sh > output.json
else
 echo "could not find valid file to test"
 exit 255
fi
jsonlint output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "fortify-file json validation failed"
 exit $RET
fi
 
#check json for dir 
echo "starting dir check - json"
../checksec --format json --dir /sbin > output.json
jsonlint  output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "dir json validation failed"
 exit $RET
fi



echo "All json validation tests passed jsonlint"
rm -f output.json
