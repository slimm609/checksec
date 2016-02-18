#!/bin/bash

#check xml for proc-all
echo "starting proc-all check - xml"
../checksec --format xml --proc-all > output.xml
xmllint --noout output.xml
if [ $? != 0 ]; then
 echo "proc-all xml validation failed"
 exit
fi

#check xml for kernel
echo "starting kernel check - xml"
../checksec --format xml --kernel > output.xml
xmllint --noout output.xml
if [ $? != 0 ]; then
 echo "kernel xml validation failed"
 exit
fi

#check xml against custom kernel config to trigger all checks
echo "starting custom kernel check - xml"
../checksec --format xml --kernel kernel.config > output.xml
xmllint --noout output.xml
if [ $? != 0 ]; then
 echo "custom kernel xml validation failed"
 exit
fi

#check xml for file
echo "starting file check - xml"
../checksec --format xml --file /bin/ls > output.xml
xmllint --noout output.xml
if [ $? != 0 ]; then
 echo "file xml validation failed"
 exit
fi

#check xml for fortify file
echo "starting fortify-file check - xml"
../checksec --format xml --fortify-file /bin/ls > output.xml
xmllint --noout output.xml
if [ $? != 0 ]; then
 echo "fortify-file xml validation failed"
 exit
fi
 
#check xml for dir 
echo "starting dir check - xml"
../checksec --format xml --dir /sbin > output.xml
xmllint --noout output.xml
if [ $? != 0 ]; then
 echo "dir xml validation failed"
 exit
fi



echo "All XML validation tests passed xmllint"
rm -f output.xml
