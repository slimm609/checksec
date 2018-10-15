FROM ubuntu:bionic


# Install dependencies
RUN apt-get update  && apt-get -y -q upgrade && DEBIAN_FRONTEND=noninteractive apt-get -y -q install \
  bc bison flex build-essential ccache git \
  libncurses-dev libssl-dev u-boot-tools wget \
  xz-utils vim xfce4 \
 && apt-get clean

COPY .  /root
WORKDIR /root
