FROM ubuntu:24.04

COPY checksec /bin/

RUN apt-get update && apt-get -y -q upgrade && DEBIAN_FRONTEND=noninteractive apt-get -y -q install \
  bc bison flex build-essential ccache git file \
  libncurses-dev libssl-dev u-boot-tools wget \
  xz-utils vim xfce4 libxml2-utils python3 python3-pip jq \
  gcc clang && apt-get clean \
  pip3 install --upgrade pip && pip3 install setuptools && \
  pip3 install demjson3 && \
  chmod +x /bin/checksec
