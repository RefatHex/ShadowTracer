# Phase 1 findings — multi-node cluster proof

Lab: `deploy/lab/`. All images built from this fork's own source (no
published `wazuh/*` images used). Host: WSL2 (Ubuntu 22.04, 12 vCPU, 7.4GiB
RAM), Docker Desktop 4.91.0.

## Step 1 — images built from source

| Image | Size | Build time | Notes |
|---|---|---|---|
| `shadowtracer-lab/manager:local` | 4.67 GB | ~13 min (full recompile) | single stage, full toolchain kept through install (see below) |
| `shadowtracer-lab/agent-ubuntu:local` | 601 MB | not isolated — built concurrently with the Rocky image (~18 min wall clock shared between both) | multi-stage (slim runtime is fine for agents — no framework/API needed), osquery 5.23.1 pinned |
| `shadowtracer-lab/agent-rocky:local` | 649 MB | same caveat as above | same, RPM package of osquery 5.23.1 |

Verified in both agent images: `osqueryd --version` → `5.23.1` (pinned),
`wazuh-agentd` binary present, `sttest` throwaway user present, `sshd`
present.

### Three real bugs found and fixed while getting the manager to actually run

These weren't cosmetic — each one produced a manager image that *looked*
like it built successfully (exit 0, "Thanks for using Wazuh") but was
non-functional. Root-caused by comparing against Wazuh's own official
integration-test manager Dockerfile
(`api/test/integration/env/base/manager/manager.Dockerfile`), which is a
known-working from-source build.

**1. Missing `/var/ossec/framework` and `/var/ossec/api` (manager wouldn't
start — `wazuh-apid: Configuration error`).**
The original `manager.Dockerfile` used a builder+slim-runtime split, with
`preloaded-vars-server.conf` setting `USER_BINARYINSTALL="y"` on the
assumption that the builder stage's compile already did everything
`install.sh` needed, so re-running the build in `install.sh` would be
redundant. It isn't: `install.sh`'s `Install()` function only skips its own
`make ... build` step when `USER_BINARYINSTALL` is set, but that same `make
build` invocation is what stages the embedded Python framework and the API
(`src/Makefile`'s `WPYTHON_DIR := ${INSTALLDIR}/framework/python`, with a
`pip3 install` from a locally-bundled dependency index). Skipping it left
`/var/ossec/framework` and `/var/ossec/api` never created. The slim runtime
image also had no `make`, so even when this path *did* get exercised it
failed silently (`install.sh` has no `set -e`). Fixed by merging
`manager.Dockerfile` into a single stage that keeps the full build toolchain
through the install step, and removing `USER_BINARYINSTALL` from
`preloaded-vars-server.conf` so `install.sh` does its real install. Costs
~1.5 GB of image size; correctness over slimness for this image.
(An earlier theory blamed shebang-exec (`./install.sh`) vs explicit `sh
install.sh` invocation for this — that correlation was a coincidence from
inconsistent build caching, not the real cause.)

**2. `wazuh-apid` config validation error: "`max_request_per_minute` was
unexpected".**
`entrypoint-manager.sh` appended `max_request_per_minute: 99999` at the
top level of `api.yaml`. The real schema nests it under `access:`. Fixed the
entrypoint to write `access:\n  max_request_per_minute: 99999`.

**3. `wazuh-clusterd not running` — cluster never actually configured.**
`entrypoint-manager.sh` guarded its cluster-config injection on `if !
grep -q "<cluster>" ossec.conf`, intending to add a `<cluster>` block only
if one wasn't already there. But the installed `ossec.conf` *always* ships
a default `<cluster>` block with placeholder values (empty `<key>`,
`node_name=node01`, `<node>NODE_IP</node>`, `<disabled>yes</disabled>`), so
that guard was always false and our real cluster settings never got
applied — nodes ran with cluster disabled and no key. Fixed by patching the
existing placeholders in place (`sed` on `NODE_IP`, the empty `<key>`,
`node01`, and `disabled>yes`) instead of guarding on presence/absence of
the tag.

All three confirmed fixed via a standalone container run: `wazuh-apid`,
`wazuh-clusterd`, and all core daemons report running via
`wazuh-control status`, and `ossec.conf`'s cluster block shows real values
(key, node name, master hostname) instead of placeholders.

## Step 2 — cluster lab

_(pending)_

## Step 3 — capability verdicts

_(pending — table of all 17 items to follow)_

## Step 4 — smoke test

_(pending)_

## Resource usage

_(pending)_

## Surprises

- A from-source `install.sh` run can exit 0 and print "Configuration
  finished properly" while silently producing a non-functional manager
  (missing framework/API, cluster disabled, API rejecting its own config).
  None of these were caught by the build — only by actually starting the
  container and checking `wazuh-control status`. See the three bugs above.
