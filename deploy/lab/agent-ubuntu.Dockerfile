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
        openssh-server rsyslog sudo passwd auditd audispd-plugins && \
    rm -rf /var/lib/apt/lists/*

# Phase 5C-1: auditd itself (GPL-2) and its libaudit library (LGPL-2.1) -
# confirmed directly from the installed package's own copyright file
# (/usr/share/doc/auditd/copyright), source https://github.com/linux-audit/audit-userspace.
# priority_boost 0: the package default (4) calls setpriority() on
# itself, which needs CAP_SYS_NICE - not granted to this container (see
# docker-compose.yml's cap_add for what IS granted: CAP_AUDIT_CONTROL
# only) and not worth the extra capability for a lab container's own
# scheduling priority.
RUN sed -i 's/^priority_boost = 4/priority_boost = 0/' /etc/audit/auditd.conf

# Ubuntu's auditd package registers these example rule files (dpkg -L
# auditd lists them) but ships them empty - /usr/share/doc/* is stripped
# in this base image (space saving, standard for Docker). Fetched
# directly from the upstream audit-userspace repo at the exact tag
# matching the installed package version (3.0.7) instead of writing a
# from-scratch ruleset of unclear provenance - same GPL-2 licence as
# auditd itself (confirmed above), verified at this exact URL:
# https://github.com/linux-audit/audit-userspace/tree/v3.0.7/rules
# 10-base-config (buffers/failure mode), 11-loginuid (auid tracking,
# needed for every other rule's auid field to mean anything),
# 31-privileged (setuid/setgid binary execution - matches several of
# Wazuh's existing auditd ruleset entries), 43-module-load (kernel
# module load/unload), 99-finalize (locks the config, standard last
# rule). Deliberately NOT the full STIG/PCI-DSS/OSPP sets - this is a
# lab coverage-measurement exercise, not a compliance deployment.
RUN mkdir -p /etc/audit/rules.d && \
    for f in 10-base-config 11-loginuid 31-privileged 43-module-load 99-finalize; do \
        curl -fsSL -o "/etc/audit/rules.d/${f}.rules" \
            "https://raw.githubusercontent.com/linux-audit/audit-userspace/v3.0.7/rules/${f}.rules"; \
    done

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
