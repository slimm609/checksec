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

#check xml for proc-all
echo "starting proc-all check - xml"
$PARENT/checksec --format=xml --proc-all > $DIR/output.xml
xmllint --noout $DIR/output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "proc-all xml validation failed"
 exit $RET
fi

#check xml for kernel
echo "starting kernel check - xml"
$PARENT/checksec --format=xml --kernel > $DIR/output.xml
xmllint --noout $DIR/output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "kernel xml validation failed"
 exit $RET
fi

#check xml against custom kernel config to trigger all checks
echo "starting custom kernel check - xml"
$PARENT/checksec --format=xml --kernel=kernel.config > $DIR/output.xml
xmllint --noout $DIR/output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "custom kernel xml validation failed"
 exit $RET
fi

#check xml for file
echo "starting file check - xml"
$PARENT/checksec --format=xml --file=$test_file > $DIR/output.xml
xmllint --noout $DIR/output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "file xml validation failed"
 exit $RET
fi

#check xml for fortify file
echo "starting fortify-file check - xml"
$PARENT/checksec --format=xml --fortify-file=$test_file > $DIR/output.xml
xmllint --noout $DIR/output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "fortify-file xml validation failed"
 exit $RET
fi

#check xml for fortify proc
echo "starting fortify-proc check - xml"
$PARENT/checksec --format=xml --fortify-proc=1 > $DIR/output.xml
xmllint --noout $DIR/output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "fortify-proc xml validation failed"
 exit $RET
fi

 
#check xml for dir 
echo "starting dir check - xml"
$PARENT/checksec --format=xml --dir=/sbin > $DIR/output.xml
xmllint --noout $DIR/output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "dir xml validation failed"
 exit $RET
fi



echo "All XML validation tests passed xmllint"
rm -f $DIR/output.xml
