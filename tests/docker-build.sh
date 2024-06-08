#!/usr/bin/env bash
# build the container with a shell script so that it is bash
# Dockerfile syntax is sh not bash so installing gcc-multilib in an
# if condition becomes more difficult.

set -eou pipefail

apt-get update
apt-get -y -q upgrade

DEBIAN_FRONTEND=noninteractive apt-get -y -q install \
  bc bison flex build-essential git file \
  libncurses-dev libssl-dev u-boot-tools wget \
  xz-utils vim libxml2-utils python3 python3-pip jq \
  gcc clang nasm binutils

if [[ "$(uname -m)" == "x86_64" ]]; then
  apt-get -y -q install gcc-multilib
fi

apt-get clean

pip3 install --upgrade pip
pip3 install setuptools demjson3
