FROM ubuntu:22.04

LABEL maintainer="Malware Analysis Team"
LABEL description="Malware Analysis Sandbox - Isolated environment for dynamic analysis"

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    ltrace \
    inotify-tools \
    tcpdump \
    net-tools \
    procps \
    iproute2 \
    iputils-ping \
    dnsutils \
    curl \
    wget \
    python3 \
    python3-pip \
    file \
    binutils \
    gdb \
    vim-tiny \
    tshark \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    yara-python \
    pefile \
    && rm -rf /root/.cache/pip

RUN mkdir -p /sandbox /sandbox/sample /sandbox/output /sandbox/logs

WORKDIR /sandbox

RUN echo '#!/bin/bash' > /usr/local/bin/entrypoint.sh && \
    echo 'exec "$@"' >> /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/bin/bash"]
