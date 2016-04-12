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

#check xml for proc-all
echo "starting proc-all check - xml"
../checksec --format xml --proc-all > output.xml
xmllint --noout output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "proc-all xml validation failed"
 exit $RET
fi

#check xml for kernel
echo "starting kernel check - xml"
../checksec --format xml --kernel > output.xml
xmllint --noout output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "kernel xml validation failed"
 exit $RET
fi

#check xml against custom kernel config to trigger all checks
echo "starting custom kernel check - xml"
../checksec --format xml --kernel kernel.config > output.xml
xmllint --noout output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "custom kernel xml validation failed"
 exit $RET
fi

#check xml for file
echo "starting file check - xml"
../checksec --format xml --file $test_file > output.xml
xmllint --noout output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "file xml validation failed"
 exit $RET
fi

#check xml for fortify file
echo "starting fortify-file check - xml"
../checksec --format xml --fortify-file $test_file > output.json
xmllint --noout output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "fortify-file xml validation failed"
 exit $RET
fi
 
#check xml for dir 
echo "starting dir check - xml"
../checksec --format xml --dir /sbin > output.xml
xmllint --noout output.xml
RET=$?
if [ $RET != 0 ]; then
 echo "dir xml validation failed"
 exit $RET
fi



echo "All XML validation tests passed xmllint"
rm -f output.xml
