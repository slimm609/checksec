#!/usr/bin/env bash

# keep checksec executable and checksec_automation file in same directory.

#sudo find $1 -type f -executable -exec file -i '{}' \; | grep 'x-executable; charset=binary' | cut -c1- | cut -d ':' -f1 > linux_executables.txt

#tree -fi $1 > linux_executables.txt


help() {
                echo "Usage: ./checksec_automation.sh [<dir_to_scan>] [<output_file_name>]"
                        }

                        #run help if nothing is passed
                                if [[ "$#" -lt 1 ]]; then
                                        help
                                        exit 1
                                fi


find "$1" -type f -executable -exec file -i '{}' \; | grep -e 'application/x-sharedlib; charset=binary' -e 'application/x-executable; charset=binary'  | cut -c1- | cut -d ':' -f1 > linux_executables.txt 

echo "Checksec Output" | tee "$2"

for i in $(cat linux_executables.txt)
                do
                        ./checksec &> /dev/null
                        if [ "$?" -eq 127 ]; then
                                    echo "File not Found. Keep checksec in same directory and run the script again."
                                    exit 1
                            else
                        ./checksec -f "$i" | tee -a "$2"
                fi
                done
