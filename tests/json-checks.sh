#!/bin/bash
if [ -f /bin/bash ]; then 
	test_file="/bin/bash"
elif [ -f /bin/sh ]; then
	test_file="/bin/sh"
elif [ -f /bin/ls ]; then
	test_file="/bin/ls"
else
 echo "could not find valid file to test"
 exit 255
fi
DIR=$(cd $(dirname "$0"); pwd)
PARENT=$(cd $(dirname "$0")/..; pwd)

jsonlint=$(which jsonlint || which jsonlint-py)
#check json for proc-all
echo "starting proc-all check - json"
$PARENT/checksec --format=json --proc-all > $DIR/output.json
$jsonlint --allow duplicate-keys $DIR/output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "proc-all json validation failed"
 exit $RET
fi

#check json for kernel
echo "starting kernel check - json"
$PARENT/checksec --format=json --kernel > $DIR/output.json
$jsonlint  $DIR/output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "kernel json validation failed"
 exit $RET
fi

#check json against custom kernel config to trigger all checks
echo "starting custom kernel check - json"
$PARENT/checksec --format=json --kernel=kernel.config > $DIR/output.json
$jsonlint $DIR/output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "custom kernel json validation failed"
 exit $RET
fi

#check json for file
echo "starting file check - json"
$PARENT/checksec --format=json --file=$test_file > $DIR/output.json
$jsonlint $DIR/output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "file json validation failed"
 exit $RET
fi

#check json for fortify file
echo "starting fortify-file check - json"
$PARENT/checksec --format=json --fortify-file=$test_file > $DIR/output.json
$jsonlint --allow duplicate-keys $DIR/output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "fortify-file json validation failed"
 exit $RET
fi
 
#check json for fortify proc
echo "starting fortify-proc check - json"
$PARENT/checksec --format=json --fortify-proc=1 > $DIR/output.json
$jsonlint --allow duplicate-keys $DIR/output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "fortify-file json validation failed"
 exit $RET
fi

#check json for dir 
echo "starting dir check - json"
$PARENT/checksec --format=json --dir=/sbin > $DIR/output.json
$jsonlint $DIR/output.json > /dev/null
RET=$?
if [ $RET != 0 ]; then
 echo "dir json validation failed"
 exit $RET
fi



echo "All json validation tests passed jsonlint"
rm -f $DIR/output.json
