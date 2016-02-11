#!/bin/bash

#check xml for proc-all
../checksec --format xml --proc-all > output.xml
xmllint --noout output.xml
if [ $? != 0 ]; then
 echo "proc-all xml validation failed"
 exit
fi
#check xml for kernel
../checksec --format xml --kernel > output.xml
xmllint --noout output.xml
if [ $? != 0 ]; then
 echo "kernel xml validation failed"
 exit
fi

#check xml against custom kernel config to trigger all checks
../checksec --format xml --kernel kernel.config > output.xml
xmllint --noout output.xml
if [ $? != 0 ]; then
 echo "custom kernel xml validation failed"
 exit
fi

#check xml for file
../checksec --format xml --file /bin/ls > output.xml
xmllint --noout output.xml
if [ $? != 0 ]; then
 echo "file xml validation failed"
 exit
fi

#check xml for fortify file
../checksec --format xml --fortify-file /bin/ls > output.xml
xmllint --noout output.xml
if [ $? != 0 ]; then
 echo "fortify-file xml validation failed"
 exit
fi


rm -f output.xml
