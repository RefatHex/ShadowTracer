# Wazuh agent (Rocky Linux 9) built from OUR fork's source, plus a pinned
# osqueryd and a throwaway sshd for the Phase 1 capability tests.
#
# Build from the repo root:
#   docker build -f deploy/lab/agent-rocky.Dockerfile -t shadowtracer-lab/agent-rocky:local .

FROM rockylinux:9 AS builder

RUN dnf install -y -q --allowerasing \
        gcc gcc-c++ make automake autoconf libtool cmake \
        curl wget git ca-certificates policycoreutils && \
    dnf clean all

WORKDIR /wazuh
COPY . .
RUN cd src && make deps && make TARGET=agent -j"$(nproc)"

FROM rockylinux:9 AS runtime

RUN dnf install -y -q --allowerasing \
        procps-ng iproute ca-certificates gawk curl \
        openssh-server openssh-clients rsyslog sudo shadow-utils passwd && \
    dnf clean all

# osquery, pinned version (Step 1: "pinned version")
RUN curl -fsSL -o /tmp/osquery.rpm \
        https://github.com/osquery/osquery/releases/download/5.23.1/osquery-5.23.1-1.linux.x86_64.rpm && \
    rpm -ivh /tmp/osquery.rpm && rm /tmp/osquery.rpm

WORKDIR /wazuh
COPY --from=builder /wazuh /wazuh
COPY deploy/lab/preloaded-vars-agent.conf /wazuh/etc/preloaded-vars.conf

RUN cd /wazuh && ./install.sh

# Throwaway sshd, for step 3.5 (brute force) and step 3.10 (active response
# disable-account test uses a throwaway user "sttest")
RUN mkdir -p /run/sshd && ssh-keygen -A && \
    useradd -m -s /bin/bash sttest && echo 'sttest:sttest' | chpasswd && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

COPY deploy/lab/entrypoint-agent.sh /entrypoint.sh
COPY deploy/lab/healthcheck-agent.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh

HEALTHCHECK --interval=10s --timeout=10s --start-period=30s --retries=20 CMD /healthcheck.sh

ENTRYPOINT ["/entrypoint.sh"]
