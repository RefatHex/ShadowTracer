# Phase 2 — Rebrand

ShadowTracer is built on Wazuh. Internal process names (the `wazuh-*`
daemons) and the `wazuh` system user/group keep their upstream names on
purpose, so upstream security patches continue to apply cleanly - see the
Pass C decision in [DECISIONS.md](DECISIONS.md) for the full reasoning.

This document summarizes what changed, what was deliberately kept, and
what's still open. The detailed inventory, every file touched and why, and
the Pass C risk analysis live in [REBRAND_PLAN.md](REBRAND_PLAN.md) and
`UPSTREAM.md`'s change-categories table - this is the readable summary,
not a replacement for either.

## What changed

**Pass A - text users read.** Systemd `Description=` lines, installer
prompts and banners (English templates + `install.sh` + the three control
script sources), API title/description/summary text (by script,
word-boundary matched), 38 rule `<description>` tags across 5 files (by
script), and `src/win32/version.rc`'s `FileDescription`/`ProductName`.
Added `shadowtracer/VERSION` (`1.0.0-dev`) and a composed version string,
`1.0.0-dev (based on Wazuh 4.14.8)`, now shown wherever the control script
reports its own version.

**Pass B - names users type or see.** The systemd units themselves
(`wazuh-manager.service` → `shadowtracer-manager.service`, same for
agent). The control binary, `wazuh-control` → `shadowtracer-control`,
updated everywhere it's invoked - including two C active-response callers
not in the task's own example list, found necessary because leaving them
pointed at the old name would have broken active-response restarts the
moment the binary was renamed. The DEB/RPM packages, renamed with
`Conflicts`/`Replaces` (DEB) and `Conflicts`/`Obsoletes`/`Provides` (RPM)
against the old `wazuh-*` names. Deployment env vars: `SHADOWTRACER_*`
now takes priority, `WAZUH_*` still works as a fallback, verified for all
three priority orderings by sourcing the resolution function directly,
not just by inspection.

**Pass C - decided, not executed.** Daemon names and the system user stay
as upstream ships them. See the decision and full reasoning in
`DECISIONS.md` (166 files, a proven decoder dependency, upstream-patch
compatibility, privilege-drop risk) and the condition for revisiting it
later (before GA, only if asked, and then only as a scripted repeatable
rename, never by hand).

**Checker Additions.** Three checks, each proven to fail on a real
violation and pass once fixed:
1. No `wazuh-control`/`wazuh-manager.service`/`wazuh-agent.service`
   outside an allowlist. Writing this surfaced **real leftover bugs**, not
   style nits: two hardcoded cgroup paths in the control scripts, two
   Python modules (`wodles/utils.py`, `wazuh_logtest.py`) that actually
   execute the old binary path at runtime, a stale install comment, a
   stale API spec example, and the API's own separate test/dev Docker
   scripts. All fixed.
2. A user-visible "Wazuh" text snapshot - fails only on a genuinely new
   occurrence, not on fixing an old one.
3. Healthcheck break/restore testing, done for real (not hypothetically)
   on both a manager and an agent container. This surfaced the "other
   direction" bug: our container's PID 1 (`tail -F ...`) never reaped
   zombie processes, so a killed daemon lingered `<defunct>` and both
   `shadowtracer-control`'s and our healthcheck's PID-existence checks
   reported it as still running - a false positive that silently masks a
   dead daemon, the dangerous direction. Fixed with Docker Compose's
   native `init: true` (injects `tini`) on every manager/agent service;
   verified the full kill → unhealthy → restart → healthy cycle on both
   container types before and after the fix.

## What was kept, and why

- Copyright headers, `LICENSE`, every "Based on OSSEC/Wazuh" line, rule
  IDs, decoder names, and all matching logic - untouched, per the task's
  own NEVER CHANGE list.
- `version.rc`'s `CompanyName`, `LegalCopyright`, and `Info` URL; the
  Debian/RPM `Maintainer`/`Vendor`/`Packager` fields; the installer's
  "root certificate by Wazuh" line (a real Wazuh-issued cert still in
  use, not branding) - all genuine attribution to the real upstream
  project/company, not leftover references. No ShadowTracer-equivalent
  contact info exists yet, so inventing one would have been worse than
  leaving the real one.
- The other 15 installer-template languages (only English was rebranded -
  confirmed `en` is the install default; mistranslating 15 languages we
  can't verify was judged worse than leaving them faithfully Wazuh-worded).
- `WAZUH_HOME_TMP` (a build-time path placeholder substituted by
  packaging scripts, not a deployment var) and `WAZUH_HOME` (a C-level
  `getenv()` install-path fallback, not part of the Docker/OVA deployment
  convention) - both out of scope for the env var rename.
- Daemon names and the system user/group (Pass C decision above).

## VERIFY - what was actually run, with real output

- **Build server and agent in a clean `ubuntu:22.04` container**: done
  twice - once as part of rebuilding all three `deploy/lab` images from a
  freshly-installed Docker Engine (no prior cache), and again via `act`
  running the real `build-agent` CI job end to end (`make deps` +
  `make TARGET=agent -j$(nproc)`, 4m18s, exit 0).
- **Clean install in a systemd-capable environment**: a privileged
  `ubuntu:22.04` container running real `systemd` as PID 1
  (`--privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw`),
  manager compiled and installed via `install.sh`, then the systemd unit
  installed the same way the DEB postinst does (substitute
  `WAZUH_HOME_TMP`, `systemctl daemon-reload && enable && start` - the
  real package-build step for the manager was blocked, see below, so this
  replicates postinst's own steps rather than running it via `dpkg`).
  Every item confirmed with real output: `systemctl status
  shadowtracer-manager` shows `ShadowTracer manager`; `ExecStart` resolved
  to `/usr/bin/env /var/ossec/bin/shadowtracer-control start` with no
  literal `WAZUH_HOME_TMP` token; `systemctl is-active` returns `active`;
  `shadowtracer-control status` lists all 15 daemons by name; and a real
  alert flowed (rule 554, FIM "File added to the system" on a realtime
  watch) - which also happened to confirm, live, that rule 502's
  description now reads "ShadowTracer server started."
- **Build the agent `.deb` with the repo's packaging tooling**: BLOCKED,
  not skipped silently. `packages/generate_package.sh -t agent --system
  deb` builds from `debian:7` (2013-era Wheezy, for glibc
  compatibility) - this host's WSL2 kernel (6.18, no `vsyscall` support)
  segfaults that image's own `apt-get` `http` transport
  (`Sub-process http received a segmentation fault`). Failed identically
  on two attempts, confirming it's deterministic, not transient; root
  cause confirmed (`uname -r`, absence of `/proc/sys/kernel/vsyscall`).
  Per the task's own instruction, stopped rather than patch around it
  (that would mean testing a different Dockerfile than the repo's actual
  tooling) or modify the host kernel.
- **`docker compose up` from clean, `smoke-test.sh` passes**: done, on
  the same freshly-installed Docker Engine (0 prior images/containers) -
  full stack up, cluster formed, both Ubuntu agents enrolled and Active,
  smoke test green.
- **`act` CI green**: all three jobs - `check-project` (4.1s),
  `shellcheck-syntax` (0.5s), `build-agent` (4m18.6s) - genuinely green,
  real `act` output pasted into the session, not reasoned about from
  `ci.yml`'s structure alone.
- **`TARGET=winagent` in a mingw container**: succeeded, after fixing two
  real (not environmental) problems first - a stale `CMakeCache.txt`
  baked with a different absolute path, and ~476 leftover native-Linux
  `.o` files from an earlier host-side build that the Windows link step
  tried to reuse. Produced a real `wazuh-agent-4.14.8.exe` plus
  `agent-auth.exe`/`manage_agents.exe`/etc.; confirmed the compiled binary
  actually contains the Pass A `version.rc` strings (`ShadowTracer Agent`,
  `ShadowTracer Windows Agent`) alongside the deliberately-kept
  `Wazuh Inc.` attribution, by reading the PE resource strings (UTF-16LE)
  directly out of the built `.exe`.

## Still open

- **The agent (and manager) `.deb`/`.rpm` build is untested end-to-end**
  on this host, blocked by the `debian:7`/WSL2-kernel incompatibility
  above. Needs either a host with vsyscall support (older kernel or a
  config that re-enables it) or a VM, not this WSL2 setup. The package
  *content* (names, Conflicts/Replaces, control-binary path) was reviewed
  and edited correctly in Pass B/Checker Additions, but never actually
  built and installed via `dpkg -i` on this host.
- **AIX/Solaris/HP-UX/macOS packaging scripts** were text-edited for the
  control-binary rename (where in scope) but never build- or
  install-tested - no such environment is available. Flagged, not
  guessed at.
- **The other 15 installer-template languages** (`br`, `cn`, `de`, `el`,
  `es`, `fr`, `hu`, `it`, `jp`, `nl`, `pl`, `ru`, `sr`, `tr`) still read
  "Wazuh" throughout. Needs either professional translation of the
  rebranded strings or an explicit decision to drop unsupported
  languages, not a blind find-replace.
- **`Maintainer`/`Vendor`/`Packager` contact fields** in the DEB/RPM specs
  still say "Wazuh <info@wazuh.com>" - needs a real ShadowTracer contact
  before an actual release; inventing one now would be worse than the
  accurate-but-wrong-brand placeholder.
- **Pass C** (daemon names, system user) is a decision to revisit before
  GA only if customers ask - see `DECISIONS.md` for the exact scripted,
  repeatable approach required if it happens.
- **Tests** (`tests/`, `api/test/`, and various `*/tests/`, `*/qa/`
  directories) were never rewritten to expect the new names - a known,
  deliberate consequence of keeping the rename scoped to what's
  user/system-visible, not a gap discovered late. `ci.yml` doesn't run
  these suites, so none of this is masked by a passing CI badge; it's
  simply out of scope and should be remembered as such before anyone
  tries to run Wazuh's own upstream test suite against this fork
  unmodified.
