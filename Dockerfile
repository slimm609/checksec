FROM ubuntu:22.04

COPY checksec /bin/

RUN apt-get update && apt-get -y -q upgrade && DEBIAN_FRONTEND=noninteractive apt-get -y -q install \
  bc bison flex build-essential ccache git file \
  libncurses-dev libssl-dev u-boot-tools wget \
  xz-utils vim xfce4 libxml2-utils python3 python3-pip jq \
  gcc clang && apt-get clean \
  pip3 install --upgrade pip && pip3 install setuptools && \
  pip3 install demjson3 && mkdir -p /zig && \
  wget https://ziglang.org/builds/zig-linux-$(uname -m)-0.12.0-dev.3667+77abd3a96.tar.xz && \
  tar xf zig-linux-$(uname -m)-0.12.0-dev.3667+77abd3a96.tar.xz -C /zig --strip-components=1 && \
  rm -rf zig-linux-$(uname -m)-0.12.0-dev.3667+77abd3a96.tar.xz && \
  chmod +x /bin/checksec

COPY .  /root
WORKDIR /root

COPY dist/linux_linux_arm64/checksec /bin/checksec-go
