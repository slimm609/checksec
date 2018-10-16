FROM archlinux/base:latest

# Install dependencies
RUN pacman -Syu --noconfirm vim base-devel && ln -s $(command -v vim) /bin/vi

COPY .  /root
WORKDIR /root
