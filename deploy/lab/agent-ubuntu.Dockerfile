# Wazuh agent (Ubuntu 22.04) built from OUR fork's source, plus a pinned
# osqueryd and a throwaway sshd for the Phase 1 capability tests.
#
# Build from the repo root:
#   docker build -f deploy/lab/agent-ubuntu.Dockerfile -t shadowtracer-lab/agent-ubuntu:local .

FROM ubuntu:22.04 AS builder

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        build-essential automake autoconf libtool cmake \
        curl wget git ca-certificates policycoreutils && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /wazuh
COPY . .
RUN cd src && make deps && make TARGET=agent -j4

FROM ubuntu:22.04 AS runtime

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        procps iproute2 ca-certificates gawk curl \
        openssh-server rsyslog sudo passwd && \
    rm -rf /var/lib/apt/lists/*

# osquery, pinned version (Step 1: "pinned version")
RUN curl -fsSL -o /tmp/osquery.deb \
        https://github.com/osquery/osquery/releases/download/5.23.1/osquery_5.23.1-1.linux_amd64.deb && \
    dpkg -i /tmp/osquery.deb && rm /tmp/osquery.deb

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

# entrypoint.sh / healthcheck.sh are bind-mounted by docker-compose.yml, not
# baked in here - see PHASE1_FINDINGS.md next-session rule 1. This image is
# not meant to be run standalone outside the compose lab.

HEALTHCHECK --interval=10s --timeout=10s --start-period=30s --retries=20 CMD /healthcheck.sh

ENTRYPOINT ["/entrypoint.sh"]
