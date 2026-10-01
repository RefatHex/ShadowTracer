# Rebrand plan — inventory (Phase 2, Step 0)

This is the pre-rename map for Phase 2. Counts are from `git grep` against
the fork point, scoped to inherited paths that are actually candidates for
change — vendored trees (`src/external`, `ruleset/mitre`, `ruleset/sca`),
upstream's own `docs/`, `LICENSE`, and `CHANGELOG.md` are excluded, since
the project's standing rule (and this phase's NEVER CHANGE list) is that
none of those are touched. `shadowtracer/` and `deploy/` are our own code,
not inherited, so they're excluded too — this plan is only about what
Phase 2 might rename in the inherited tree.

No renames have happened yet. This document is the map Pass A/B/C work
from, not a changelog.

## 1. Occurrence counts

**33,799** case-insensitive `wazuh` occurrences across **4,455** files, in
scope as defined above. By top-level directory (occurrences, not files):

| Directory | Occurrences | Notes |
|---|---|---|
| `src` | 10,509 | Daemon source, mostly copyright headers + internal identifiers |
| `framework` | 7,860 | The Python `wazuh` package itself (see §5) |
| `tests` | 6,670 | Unit/integration test code - **out of scope for Pass A/B**, not user-facing; see §7 |
| `packages` | 2,268 | RPM/DEB/AIX packaging specs - Pass B |
| `api` | 1,930 | REST API: spec title, error strings, framework imports |
| `.github` | 1,913 | Mostly the deleted workflow files already recorded in UPSTREAM.md; not re-counted here |
| `ruleset` | 1,046 | Rule/decoder files (excl. `mitre`, `sca`) - mostly rule `id`/group text, see §8 |
| `wodles` | 692 | Module source |
| `etc` | 367 | Shipped config templates |
| `architecture` | 151 | Design docs (not shipped, arguably Pass A-adjacent but low priority) |
| (everything else) | ~400 | `tools/`, `extensions/`, `integrations/`, root scripts |

### Known protected buckets within that total (NEVER CHANGE)

These are **not** rename candidates and should not shrink the "real" count
below — they're carved out by the task's NEVER CHANGE list, not missed:

| Bucket | Count | Why protected |
|---|---|---|
| `Copyright (C) ..., Wazuh Inc.` headers | 3,417 | "every copyright header" |
| `WAZUH_[A-Z_]+` C macros/identifiers | 1,871 | "internal identifiers: C macros (WAZUH_*)" |
| Python `from wazuh` / `import wazuh` | 509 | "the Python package framework/wazuh" |
| "Based on OSSEC/Wazuh" attribution lines | 18 | explicit NEVER CHANGE line |
| `WAZUH_HOME_TMP` template token | (counted above, not separately) | explicit NEVER CHANGE token - see §5, it's an install-time path placeholder, not a deployment env var |

That's **5,815** occurrences already excluded by name. The remainder
(~28,000) is a mix of: more internal identifiers not matching the
`WAZUH_*` macro pattern (lowercase C symbols, struct/function names),
file paths and binary names (counted separately below), and genuine
user-visible text (log/console strings, API text, rule descriptions,
install prompts, systemd units, packaging metadata). **This plan does not
claim to split all ~28,000 by hand** — Pass A and Pass B each do their own
targeted, scripted grep over their specific surface (see NEVER CHANGE's
own instruction to grep `ruleset/` before changing any emitted string).
The breakdown below covers every category the task asked for by name.

## 2. Service file names

| File | Installs as | Notes |
|---|---|---|
| `src/init/templates/wazuh-manager.service` | `wazuh-manager.service` | `Description=Wazuh manager`; `ExecStart=/usr/bin/env WAZUH_HOME_TMP/bin/wazuh-control start` (template token, not literal) |
| `src/init/templates/wazuh-agent.service` | `wazuh-agent.service` | `Description=Wazuh agent`; same `ExecStart` pattern |

Both are Pass B candidates (filename + unit name) and Pass A candidates
(the `Description=` line is user-visible text, independent of the
filename rename).

## 3. Control binary

Not a single source file — built from one of three role-specific sources,
installed as the single name `bin/wazuh-control`:

| Role | Source | Installed as |
|---|---|---|
| manager | `src/init/wazuh-server.sh` | `$INSTALLDIR/bin/wazuh-control` |
| agent | `src/init/wazuh-client.sh` | `$INSTALLDIR/bin/wazuh-control` |
| standalone | `src/init/wazuh-local.sh` | `$INSTALLDIR/bin/wazuh-control` |

Rename wiring is in `src/init/inst-functions.sh` (`OSSEC_CONTROL_SRC=...`,
then `${INSTALL} ... ${OSSEC_CONTROL_SRC} ${INSTALLDIR}/bin/wazuh-control`).
Every caller of the final binary name (`pkg_installer.sh`,
`darwin-init.sh`, `init.sh`, the systemd units above, our own
`deploy/lab/healthcheck-manager.sh`/`entrypoint-manager.sh`) would need
updating together - this is the Pass C item ("daemon names and system
user") in spirit even though the control binary itself is listed under
Pass B; it's the one Pass B rename with the widest blast radius, so flag
it for extra care in Pass B's own verification.

## 4. Package names

| Package | Spec file |
|---|---|
| `wazuh-manager` (RPM) | `packages/rpms/SPECS/wazuh-manager.spec` |
| `wazuh-agent` (RPM) | `packages/rpms/SPECS/wazuh-agent.spec` |
| `wazuh-agent` (AIX) | `packages/aix/SPECS/wazuh-agent-aix.spec` |
| `wazuh-manager` (DEB) | `packages/debs/SPECS/wazuh-manager/debian/control` |
| `wazuh-agent` (DEB) | `packages/debs/SPECS/wazuh-agent/debian/control` |

Pass B: rename to `shadowtracer-manager` / `shadowtracer-agent`, same
install path (`/var/ossec` is unchanged - NEVER CHANGE), so
`Conflicts`/`Replaces` on the `wazuh-*` package names is required or a
machine could end up with both installed over the same files.

## 5. Deployment env vars

Found in `src/init/inst-functions.sh` and the preloaded-vars templates.
**28 vars**, all prefixed `WAZUH_`:

```
WAZUH_AGENT_GROUP        WAZUH_MANAGER_IP          WAZUH_REGISTRATION_PASSWORD
WAZUH_AGENT_NAME         WAZUH_MANAGER_PORT        WAZUH_REGISTRATION_PASSWORD_PATH
WAZUH_AUTHD_PORT         WAZUH_NOTIFY_TIME         WAZUH_REGISTRATION_PORT
WAZUH_AUTHD_SERVER       WAZUH_PASSWORD            WAZUH_REGISTRATION_SERVER
WAZUH_CERTIFICATE        WAZUH_PEM                 WAZUH_REVISION
WAZUH_GROUP              WAZUH_PROTOCOL            WAZUH_TIME_RECONNECT
WAZUH_HOME               WAZUH_REGISTRATION_CA     WAZUH_TYPE
WAZUH_HOME_TMP   <- NEVER CHANGE, see below         WAZUH_USER
WAZUH_KEEP_ALIVE_INTERVAL   WAZUH_REGISTRATION_CERTIFICATE   WAZUH_VERSION
WAZUH_KEY                WAZUH_REGISTRATION_KEY
WAZUH_MACOS_AGENT_DEPLOYMENT_VARS   WAZUH_MANAGER
```

**`WAZUH_HOME_TMP` is explicitly NEVER CHANGE** - it's a literal template
placeholder string inside `wazuh-manager.service`/`wazuh-agent.service`
that `install.sh` text-substitutes for the real install path at install
time (`sed`-style replace, not a shell environment variable a user sets).
It looks like it belongs in this list but it is build/install machinery,
not a deployment knob - do not touch it in Pass B.

The other 27 are genuine deployment-time env vars (used by Docker/OVA
images, cloud-init, and `preloaded-vars.conf` generation) and are Pass B's
`SHADOWTRACER_*` rename candidates, each keeping its `WAZUH_*` name as a
fallback per the task's instruction.

## 6. Daemon binary names and system user/group

**15 daemons**, all `wazuh-*`, defined by `src/Makefile`'s build targets:

```
wazuh-agentd       wazuh-authd        wazuh-integratord   wazuh-remoted
wazuh-agentlessd   wazuh-csyslogd     wazuh-maild          wazuh-reportd
wazuh-analysisd    wazuh-execd        wazuh-modulesd       wazuh-syscheckd
                                       wazuh-monitord
```

(plus `wazuh-db`, `wazuh-clusterd`, `wazuh-apid` referenced elsewhere as
daemons but not standalone `make` targets in the same list - confirmed
running in the Phase 1 lab via `wazuh-control status`).

**System user and group, this version: both literally `wazuh`**
(`src/init/inst-functions.sh`: `WAZUH_USER='wazuh'`, `WAZUH_GROUP='wazuh'`,
passed to `adduser.sh`). Not a legacy `ossec` name - confirms this is a
real Pass C item, not already partially done.

Renaming the daemons and the system user is the single highest-blast-radius
change in this phase - per the task, **Pass C is a plan-and-report only,
no edits**, see `shadowtracer/docs/PHASE2_REBRAND.md` once that report is
written.

## 7. Tests (flagged, not a rename target)

`tests/` carries 6,670 occurrences across 461 files - the single largest
bucket after `src` and `framework`. None of it is user-visible or a
system-visible name; it's internal test code (fixtures, mock daemon names,
assertions on log strings). **Out of scope for Pass A and Pass B** - test
assertions that match real daemon/log output will track whatever Pass A/B
actually renames (e.g. if a systemd Description string changes, any test
asserting on that exact string needs updating too, but that's a
consequence of the Pass A/B rename, not a rename target in its own right).
Called out here so it isn't mistaken for missed scope later.

## 8. API title strings

`api/api/spec/spec.yaml`:

| Field | Value |
|---|---|
| `title` (top-level, line 45) | `'Wazuh API REST'` |
| `title` (error schema, 2 occurrences) | `"Wazuh Error"` |

Pass A: these are rendered in API docs/error responses a user sees
directly. Low count (3), easy, high visibility.

## 9. Rule descriptions containing "Wazuh"

**38 occurrences across 5 files**: `0010-rules_config.xml`,
`0015-ossec_rules.xml`, `0016-wazuh_rules.xml`, and two others matching
`<description>...[Ww]azuh...</description>`. Examples:

```
<description>Wazuh server started.</description>
<description>Wazuh agent disconnected.</description>
<description>Wazuh API: $(endpoint) Bad request.</description>
```

Per NEVER CHANGE: **only the `<description>` text**, never the rule `id`,
`level`, match/decoder logic, or group tags in the same file. The task
already names the method - a script that rewrites only `<description>`
tag contents, with every touched file listed in the Pass A report.

## 10. `src/win32/version.rc`

Mixed file - some fields are Pass A text, one is protected:

| Field | Value | Pass A? |
|---|---|---|
| top comment `Copyright (C) 2015, Wazuh Inc.` | - | **No** - copyright header, NEVER CHANGE |
| `CompanyName` | `"Wazuh Inc."` | Judgment call for Pass A - see note below |
| `FileDescription` | `"Wazuh Agent"` | Yes |
| `LegalCopyright` | `"Copyright (C) Wazuh, Inc."` | **No** - it's a copyright field by name, NEVER CHANGE |
| `ProductName` | `"Wazuh Windows Agent"` | Yes |
| `Info` (URL) | `"https://www.wazuh.com"` | Judgment call - points at the real upstream project, arguably correct to keep as attribution rather than a dead/wrong ShadowTracer URL |

`CompanyName` and the `Info` URL are genuinely ambiguous: they're
user-visible (Pass A's own list names "Windows version.rc fields"
explicitly), but `CompanyName` stating "Wazuh Inc." when the binary isn't
built or distributed by Wazuh Inc. reads differently than
`FileDescription`/`ProductName`. Recommend keeping both as-is alongside
the protected `LegalCopyright` line (true, accurate attribution to the
upstream company) rather than rewriting them - flagged here for a
decision during Pass A rather than decided unilaterally in this
inventory.

## Pass C report — daemon names and system user (plan only, not executed)

Per the task: this is analysis to decide from, not a change. Nothing below
has been edited.

### Scope: how many files

| Dependency | Count | What |
|---|---|---|
| Files mentioning any of the 15 daemon names (`wazuh-agentd`, `wazuh-analysisd`, ... `wazuh-apid`) | **166** | Repo-wide, excluding vendored/tests/docs/shadowtracer (see breakdown below) |
| ...of which in `src/` | 84 | Build system, daemon source, active-response, logging |
| ...of which in `framework/` (Python) | 34 | Cluster code, status reporting |
| ...of which in `api/` | 21 | Daemon status/stats endpoints |
| ...of which in `packages/` | 5 | Service management in postinst/preinst/prerm (control-script calls only - Pass B already renamed the invoking binary) |
| ARGV0 compile-time macro definitions in `src/Makefile` | 34 | One `-DARGV0="wazuh-X"` per compiled object per daemon |
| Total daemon-name occurrences in `src/Makefile` | 68 | Includes `BUILD_SERVER+=`/`BUILD_AGENT+=` target lists and the make targets themselves (`wazuh-remoted: ${remoted_o}`) |
| `ruleset/decoders/*.xml` or `ruleset/rules/*.xml` matching a daemon name | **2** | See "Rule/decoder risk" below - small in file count, but this is the category NEVER CHANGE warns about |
| Files with real `chown`/`-o`/`-g` operations using the `wazuh` user/group | 16 | Install scripts + every platform's packaging postinst |
| C source files calling `Privsep_GetUser(USER)`/`Privsep_GetGroup(GROUPGLOBAL)` | 15 | Every daemon's own privilege-drop-after-bind startup code |

### What depends on these names

- **Build system (`src/Makefile`)**: the daemon name isn't just a label -
  it's the Make target name, the compiled binary's output filename, *and*
  a compile-time `ARGV0` macro baked into the binary that the daemon uses
  for its own log-line prefixes (`merror`/`minfo` etc. print `wazuh-X:
  ...`). Renaming a daemon means renaming the Make target, the binary
  filename, and recompiling with a new ARGV0 - not a text edit, a build
  system change touching every one of that daemon's ~2-4 compile rules.
- **Control script**: `src/init/wazuh-server.sh`/`wazuh-client.sh`/
  `wazuh-local.sh`'s `DAEMONS=`/`OP_DAEMONS=` lists (already identified in
  Pass B, left untouched there on purpose) name every daemon literally,
  used to start/stop/check each one by exact binary name.
- **Cluster code** (`framework/wazuh/core/cluster/`): 10 files reference
  specific daemon names, for things like checking `wazuh-db` or
  `wazuh-clusterd` process state as part of cluster health/sync logic.
- **API status** (`api/api/`, `framework/wazuh/core/`): 27 files - the API
  exposes per-daemon status and stats (`GET /manager/status` etc. return
  `wazuh-analysisd: running` style fields), so renaming daemons changes
  the API's own response field values, which is a breaking API change for
  any client (including our own future console) parsing those names.
- **Logs**: every daemon's own log lines are prefixed with its ARGV0 name
  (`wazuh-remoted: INFO: ...`). This is what the smoke test and Phase 1's
  own healthcheck scripts grep for today (`grep -q "^${d} is running"`) -
  renaming daemons requires updating every such grep, ours included.
- **System user/group (`wazuh`/`wazuh`)**: baked into C via
  `src/headers/defs.h`'s `#define USER "wazuh"` / `#define GROUPGLOBAL
  "wazuh"`, used by ~15 daemon source files to drop root privileges after
  startup (bind to privileged ports / open root-only files, then
  `setuid`/`setgid` to this user). Also used by install scripts to `chown`
  essentially the entire install tree (binaries, configs, logs, queue
  sockets) to `wazuh:wazuh` at install time, and by every platform's
  packaging postinst to create the user/group in the first place
  (`adduser.sh`).

### Rule/decoder risk (the concrete finding, not a hypothetical)

Per NEVER CHANGE's own instruction, `ruleset/` was grepped before writing
this report, not after. It found a real hit:
`ruleset/decoders/0200-ossec_decoders.xml` (the decoder for Wazuh's *own*
internal daemon logs) line 19:

```
<prematch>^\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d ossec-logcollector|^\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d wazuh-logcollector</prematch>
```

This decoder literally pattern-matches the string `wazuh-logcollector` as
part of recognizing that log line's format (note it already carries a
legacy `ossec-logcollector` alternative from the OSSEC->Wazuh rename, so
this isn't a hypothetical risk - it already happened once). Renaming
`wazuh-logcollector` without updating this decoder (adding a third
alternative, the same pattern already used for the OSSEC legacy name)
would silently break recognition of that specific internal log line.
Scope is small (1 real decoder file, this one `<prematch>`; the second
file found, `0320-sudo_decoders.xml`, only has daemon names inside a
comment, not matching logic) - but it proves the risk is real, not
theoretical, and the safe pattern for doing it right already exists in
this exact file (add an alternative, don't replace).

### Risks, summarized

1. **Build system change, not a text edit.** Every daemon's Makefile rules
   (34 ARGV0 definitions, 68 total references) need updating together;
   get one wrong and that daemon silently logs under the old name or fails
   to build.
2. **API is a breaking change for any consumer.** Per-daemon status/stats
   field names in API responses change - any script, dashboard, or our
   own future console parsing `wazuh-analysisd` as a literal API field
   name breaks until updated.
3. **System user/group rename means re-owning the install tree.** Not
   just a C macro change - every file under `/var/ossec` is `chown
   wazuh:wazuh` at install time. A rename needs either (a) a fresh install
   always uses the new name (clean, but means a real migration path is
   needed for upgrades from existing wazuh-user installs), or (b) upgrade
   logic that re-chowns the entire tree and migrates the user/group,
   which is real filesystem work with real failure modes (partial
   re-chown, permission errors) if interrupted.
4. **Decoder/rule risk is real, proven, and has a known-safe pattern.**
   One decoder (`0200-ossec_decoders.xml`) needs a third `prematch`
   alternative, following the exact precedent already in that file for
   the OSSEC->Wazuh transition. Low file count, but gets the NEVER CHANGE
   warning exactly right if missed.
5. **Blast radius is 2-3x Pass B's.** Pass B (control binary, services,
   packages, env vars) touched 45 files. This would touch at minimum the
   166 files found above, likely more once the build-system and API
   response-shape changes ripple into their own callers (tests aren't
   counted here - they're out of scope per the standing decision in §7 of
   this plan, but 6,670 occurrences live there and a daemon rename is the
   one Pass A/B change category most likely to actually break running
   tests, not just need cosmetic updates, since test fixtures assert on
   real daemon names and status field values).

No files touched in writing this report. Waiting on your decision before
doing anything in Pass C.
