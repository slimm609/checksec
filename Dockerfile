FROM photon:3.0

COPY checksec /bin/
RUN tdnf clean all && tdnf remove -y toybox && tdnf upgrade -y && \
    tdnf install -y coreutils util-linux sed tar texinfo procps-ng grep findutils gzip file which awk binutils && \
    chmod +x /bin/checksec
