#!/bin/bash
# Build all yes kernel config for testing different versions

build_config () {
    cd /root
    if [[ ! -s /root/configs/config-$1.$2.1 ]]; then
      wget https://mirrors.edge.kernel.org/pub/linux/kernel/v$1.x/linux-$1.$2.1.tar.xz 
      tar Jxvf linux-$1.$2.1.tar.xz
      cd linux-$1.$2.1
      make allyesconfig
      cp .config /root/configs/config-$1.$2.1
      cd /root
      rm -rf linux-$1.$2.1.tar.xz linux-$1.$2.1
    fi
}


#build configs for 3.x up to 3.18
for i in {1..18}; do 
  build_config 3 $i
done


#build configs for 4.x up to 4.18
for i in {1..18}; do 
  build_config 4 $i
done
