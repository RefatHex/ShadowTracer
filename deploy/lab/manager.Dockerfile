# Builds the Wazuh manager (classic, non-indexer) from OUR fork's source.
# Used for both the cluster master and workers; role is chosen at container
# start by entrypoint-manager.sh via CLUSTER_NODE_TYPE.
#
# Build from the repo root:
#   docker build -f deploy/lab/manager.Dockerfile -t shadowtracer-lab/manager:local .

FROM ubuntu:22.04 AS builder

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        build-essential automake autoconf libtool cmake \
        curl wget git ca-certificates policycoreutils && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /wazuh
COPY . .
RUN cd src && make deps && make TARGET=server -j"$(nproc)"

FROM ubuntu:22.04 AS runtime

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        procps iproute2 ca-certificates gawk && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /wazuh
COPY --from=builder /wazuh /wazuh
COPY deploy/lab/preloaded-vars-server.conf /wazuh/etc/preloaded-vars.conf

RUN cd /wazuh && ./install.sh

COPY deploy/lab/entrypoint-manager.sh /entrypoint.sh
COPY deploy/lab/healthcheck-manager.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh

EXPOSE 1514/tcp 1515/tcp 1516/tcp 55000/tcp

HEALTHCHECK --interval=10s --timeout=10s --start-period=30s --retries=12 CMD /healthcheck.sh

ENTRYPOINT ["/entrypoint.sh"]
