# Builds the Wazuh manager (classic, non-indexer) from OUR fork's source.
# Used for both the cluster master and workers; role is chosen at container
# start by entrypoint-manager.sh via CLUSTER_NODE_TYPE.
#
# Single stage, not builder+slim-runtime: install.sh's own install step
# (Install() in install.sh, triggered because preloaded-vars-server.conf
# does NOT set USER_BINARYINSTALL) is what stages /var/ossec/framework and
# /var/ossec/api (see src/Makefile's WPYTHON_DIR target) - it needs the
# full build toolchain present, not just a C compiler. A slim runtime
# without `make` silently produces a manager with no framework/API and a
# wazuh-apid that can't start.
#
# Build from the repo root:
#   docker build -f deploy/lab/manager.Dockerfile -t shadowtracer-lab/manager:local .

FROM ubuntu:22.04

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        build-essential automake autoconf libtool cmake \
        curl wget git ca-certificates policycoreutils \
        procps iproute2 gawk && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /wazuh
COPY . .
RUN cd src && make deps && make TARGET=server -j"$(nproc)"

COPY deploy/lab/preloaded-vars-server.conf /wazuh/etc/preloaded-vars.conf

RUN cd /wazuh && sh install.sh

COPY deploy/lab/entrypoint-manager.sh /entrypoint.sh
COPY deploy/lab/healthcheck-manager.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh

EXPOSE 1514/tcp 1515/tcp 1516/tcp 55000/tcp

HEALTHCHECK --interval=10s --timeout=10s --start-period=30s --retries=12 CMD /healthcheck.sh

ENTRYPOINT ["/entrypoint.sh"]
