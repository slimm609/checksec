#!/usr/bin/env bash
# Build all yes kernel config for testing different versions
set -eou pipefail

build_config() {
  folder=${1}
  major=${2}
  minor=${3}
  revision=${4:-1}
  cd /root
  if [[ ! -s /root/configs/config-${major}.${minor}.${revision} ]]; then
    wget --no-check-certificate "https://mirrors.edge.kernel.org/pub/linux/kernel/v${folder}/linux-${major}.${minor}.${revision}.tar.xz"
    tar Jxvf "linux-${major}.${minor}.${revision}.tar.xz"
    cd "linux-${major}.${minor}.${revision}"
    make allyesconfig
    cp .config "/root/configs/config-${major}.${minor}.${revision}"
    cd /root
    rm -rf "linux-${major}.${minor}.${revision}.tar.xz" "linux-${major}.${minor}.${revision}"
  fi
}

#build configs for 3.x up to 3.18
for i in {1..18}; do
  build_config 3.x 3 "$i"
done

#build configs for 4.x up to 4.19
for i in {0..19}; do
  build_config 4.x 4 "$i"
done

#build configs for 5.x up to 5.10
for i in {1..10}; do
  build_config 5.x 5 "$i"
done
