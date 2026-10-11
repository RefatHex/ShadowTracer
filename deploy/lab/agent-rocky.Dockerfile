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
RUN cd src && make deps && make TARGET=agent -j4

FROM rockylinux:9 AS runtime

RUN dnf install -y -q --allowerasing \
        procps-ng iproute ca-certificates gawk curl \
        openssh-server openssh-clients rsyslog sudo shadow-utils passwd audit && \
    dnf clean all

# Phase 5C-1: same auditd setup as agent-ubuntu.Dockerfile - see that
# file's comments for the licence citation and why priority_boost is
# disabled. RockyLinux's audit package ships its rules.d examples
# un-stripped (unlike the Ubuntu container image), but fetched from the
# same verified upstream tag anyway for one consistent, cited source
# across both agent images rather than trusting two different
# packagers' bundling to have stayed identical.
RUN sed -i 's/^priority_boost = 4/priority_boost = 0/' /etc/audit/auditd.conf && \
    mkdir -p /etc/audit/rules.d && \
    for f in 10-base-config 11-loginuid 31-privileged 43-module-load 99-finalize; do \
        curl -fsSL -o "/etc/audit/rules.d/${f}.rules" \
            "https://raw.githubusercontent.com/linux-audit/audit-userspace/v3.0.7/rules/${f}.rules"; \
    done

# osquery, pinned version (Step 1: "pinned version")
RUN curl -fsSL -o /tmp/osquery.rpm \
        https://github.com/osquery/osquery/releases/download/5.23.1/osquery-5.23.1-1.linux.x86_64.rpm && \
    rpm -ivh /tmp/osquery.rpm && rm /tmp/osquery.rpm

WORKDIR /wazuh
COPY --from=builder /wazuh /wazuh
COPY deploy/lab/preloaded-vars-agent.conf /wazuh/etc/preloaded-vars.conf

RUN cd /wazuh && ./install.sh

# Phase 3 follow-up 4: the builder stage's own `libgcc` package
# (11.5.0-14.el9, pulled in because gcc-c++ depends on it) requires
# GLIBC_2.35, which Rocky 9's own glibc doesn't provide (frozen at 2.34 -
# a real upstream Rocky/RHEL 9 repo defect, not anything in our build or
# Wazuh's: reproduced on a bare `rockylinux:9` + `dnf install gcc-c++`,
# no Wazuh code involved). install.sh bundles whatever `g++
# --print-file-name=libgcc_s.so.1` resolved to in the builder stage into
# /var/ossec/lib, which is this broken one. This runtime stage's own
# system libgcc (11.4.1-2.1.el9, installed before any dev-tool package
# pulls in the newer one) only needs up to GLIBC_2.34 and works fine -
# use it instead of the bundled copy.
RUN cp -f /usr/lib64/libgcc_s.so.1 /var/ossec/lib/libgcc_s.so.1

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
