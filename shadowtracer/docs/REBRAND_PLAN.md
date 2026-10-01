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
