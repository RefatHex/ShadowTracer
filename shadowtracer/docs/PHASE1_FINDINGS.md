# Phase 1 findings — multi-node cluster proof

Lab: `deploy/lab/`. All images built from this fork's own source (no
published `wazuh/*` images used). Host: WSL2 (Ubuntu 22.04, 12 vCPU, 7.4GiB
RAM), Docker Desktop 4.91.0.

## Step 1 — images built from source

| Image | Size | Build time | Notes |
|---|---|---|---|
| `shadowtracer-lab/manager:local` | 3.16 GB | 13m32s | `make deps && make TARGET=server` in builder stage, `./install.sh` in runtime stage |
| `shadowtracer-lab/agent-ubuntu:local` | 601 MB | not isolated — built concurrently with the Rocky image (~18 min wall clock shared between both); a clean solo rebuild wasn't re-run since the artifact is already verified | `make deps && make TARGET=agent`, osquery 5.23.1 pinned |
| `shadowtracer-lab/agent-rocky:local` | 649 MB | same caveat as above | same, RPM package of osquery 5.23.1 |

**Surprise:** `install.sh`'s runtime stage logs `make: not found` three times
(it unconditionally re-invokes `${MAKEBIN} ... build` at install.sh:114 even
though the builder stage already compiled everything). The runtime image has
no `build-essential`, so those calls fail — but harmlessly: `install.sh`
doesn't `set -e`, and the binaries the builder stage already produced get
staged into `/var/ossec/bin` regardless. Verified by shelling into the built
image: `wazuh-analysisd`, `wazuh-authd`, `wazuh-agentd`, etc. all present
with real sizes and correct timestamps. Not a defect, just log noise —
flagging since a `set -e` upstream change would turn this into a real build
failure.

Verified in both agent images: `osqueryd --version` → `5.23.1` (pinned),
`wazuh-agentd` binary present, `sttest` throwaway user present, `sshd`
present.

## Step 2 — cluster lab

_(pending)_

## Step 3 — capability verdicts

_(pending — table of all 17 items to follow)_

## Step 4 — smoke test

_(pending)_

## Resource usage

_(pending)_

## Surprises

- `install.sh`'s redundant `make ... build` call fails silently in a
  `make`-less runtime image (see Step 1 above) — currently harmless, but
  fragile if upstream ever adds `set -e`.
