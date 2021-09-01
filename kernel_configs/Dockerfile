FROM ubuntu:bionic

# Install dependencies
RUN apt-get update               \
 && apt-get -y -q upgrade        \
 && apt-get -y -q install        \
    bc bison flex build-essential          \
    ccache git libncurses-dev libssl-dev   \
    u-boot-tools wget xz-utils             \
 && apt-get clean

COPY build_kernel_configs.sh /root
