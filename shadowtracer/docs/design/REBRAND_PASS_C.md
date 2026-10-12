# Rebrand Pass C: remove Wazuh branding from everything a customer can see

Status: **Step 1 (audit) and Step 2 (plan) only - no changes made.** Per instruction,
stopping here for approval before any Step 3 implementation. This builds on, and in
one case (daemon names/system user) partially reopens, a decision already recorded in
`docs/DECISIONS.md` ("Phase 2 Pass C decision: daemon names and the system user are
kept") - that entry's own "if revisited" checklist is reused as the backbone of §2's
plan below, since this task matches its revisit condition almost exactly.

## Step 1: Visibility audit

### 1.0 What Pass A/B already did (context, not re-derived)

Per `docs/PHASE2_REBRAND.md`/`docs/REBRAND_PLAN.md`, already shipped and verified:
systemd `Description=` lines, the control binary (`wazuh-control` ->
`shadowtracer-control`), DEB/RPM package names, deployment env vars
(`SHADOWTRACER_*` with `WAZUH_*` fallback), API title text, 38 rule
`<description>` tags, `version.rc`'s `FileDescription`/`ProductName`. Confirmed
still live today: `docker exec ... shadowtracer-control status` lists daemons;
alert `rule.description` for id 502 reads "ShadowTracer server started." Explicitly
kept on purpose: copyright headers, `LICENSE`, "Based on OSSEC/Wazuh" lines, rule
IDs/decoder names/matching logic, `version.rc`'s `CompanyName`/`LegalCopyright`/`Info`
URL, 15 non-English installer languages, DEB/RPM `Maintainer` fields, and (the Pass C
decision this task reopens) daemon names and the system user.

### 1.1 Live verification, this session (commands + output)

Ran directly against the already-running lab (manager `shadowtracer-lab-wazuh-master-1`,
agent `shadowtracer-lab-agent-ubuntu-1-1`):

- **Process names** (`ps -eo pid,comm`): every process is literally `wazuh-*`
  (`wazuh-authd`, `wazuh-db`, `wazuh-execd`, `wazuh-analysisd`, `wazuh-syscheckd`,
  `wazuh-remoted`, `wazuh-logcollec` [15-char `comm` truncation, confirmed live],
  `wazuh-monitord`, `wazuh-modulesd`) on both manager and agent. **(A)**
- **Control CLI output**: `shadowtracer-control status` prints `wazuh-clusterd is
  running...` etc. for all 16 daemons - the binary name is rebranded, every daemon
  name it reports is not. **(A)**
- **Log lines**: `tail /var/ossec/logs/ossec.log` - every line prefixed
  `wazuh-modulesd: ...` (baked in via the ARGV0 compile macro). **(A)/(B)** - visible
  to anyone tailing logs, which in practice includes customers via the console
  eventually, not just admins.
- **Alert JSON**: rule 502's `description` genuinely reads "ShadowTracer server
  started." (Pass A confirmed live) but `"groups": ["ossec"]` - correctly still
  "ossec" per this task's own "Keep: rule group 'ossec'" instruction.
- **Generated `ossec.conf`'s own header - a real gap, not previously documented**:
  the live config inside the running manager starts with "Wazuh - Manager - Default
  configuration for ubuntu 22.04 / More info at: https://documentation.wazuh.com /
  Mailing list: https://groups.google.com/forum/#!forum/wazuh". Source:
  `etc/templates/config/generic/header-comments.template` (4 lines, substituted via
  `TYPE`/`DISTRIBUTION`/`VERSION` placeholders) - referenced by **both**
  `src/init/inst-functions.sh` (Linux/Unix) and `src/win32/InstallerScripts.vbs`
  (Windows), so this is a cross-platform gap, not a Linux-only one. **Not mentioned
  anywhere in `docs/PHASE2_REBRAND.md`'s Pass A summary** - this looks genuinely
  missed, not a deliberate keep (unlike the already-documented, deliberate
  "root certificate by Wazuh" and `Info` URL keeps). **(A)**
- **Docker container/image names**: `shadowtracer-lab-wazuh-master-1`,
  `-wazuh-worker1-1`, etc. - this is **our own** lab naming convention (compose
  service/hostname choice), zero upstream dependency. **(A)/(B)**, cheap.
- **Frontend**: zero "wazuh"/"Wazuh" anywhere in `shadowtracer/console/frontend/src`
  (grepped directly) - already clean, page `<title>` already "ShadowTracer console".
- **Backend**: two non-user-facing code comments mention "Wazuh" factually (category
  C) - and **one real exception**: `app/routers/attack_coverage.py`'s
  `COVERAGE_LABEL` constant, returned by the attack-coverage API and shown in the
  console UI, reads "...the inherited Wazuh ruleset..." **(A)** - a judgment call
  (see §1.4), not an oversight like the config-header finding above.
- **No About/attribution page exists yet** in the console frontend (checked - no
  `About*.tsx`, no footer component) - there is currently no natural home for the
  "Built on Wazuh open source (GPLv2)" notice this task asks to add.
- **Man pages**: none shipped for Wazuh/ShadowTracer itself (checked repo-wide;
  the only `.1`/`.8` files found belong to vendored third-party tools like
  `libarchive`'s `bsdtar`). Nothing to rebrand in this category.
- **Windows runtime/install testing**: **not possible in this environment** - no
  Wine, no Windows VM, no mingw-based install-testing image found. Phase 2 only ever
  cross-compiled the agent binary (`TARGET=winagent` in a mingw container) and read
  PE resource strings out of the result; it never actually *ran* the installer or
  inspected a live `services.msc`/Add-Remove-Programs entry. This audit's Windows
  findings (below) are from reading the installer/service source directly, not from
  an observed live install - flagged plainly, not glossed over.

### 1.2 Install path (`/var/ossec`) - is it a real build variable, and where is it hardcoded anyway

**Yes, it is a real build-time variable** (`INSTALLDIR`), confirmed at its defaults:
`src/Makefile:215,309` (`INSTALLDIR = /var/ossec`), `src/init/shared.sh:38`
(installer's own runtime default, overridable via `preloaded-vars.conf`),
`framework/Makefile:8` and `api/Makefile:8` (`INSTALLDIR ?= /var/ossec`) - **5
places defining the same default**, which would need updating together, not 1.
Confirmed **no separate C-level fallback constant** exists (`src/headers/defs.h` has
no `DEFAULTDIR`-style define) - one less thing to rebrand than feared.

**Real hardcodes that would NOT follow an `INSTALLDIR` change** (grep counts, `(A)`
or `(B)` per visibility, every count below is a real `grep -rc` run, not estimated):

| Where | Count | Severity |
|---|---|---|
| `api/scripts/wazuh_apid.py:1` - hardcoded shebang `#!/var/ossec/framework/python/bin/python3` | 1 file, the only one matching `^#!/var/ossec` repo-wide | **Critical (C-level, but production-breaking)** - a shebang is resolved by the OS exec loader at run time, not by any Make/install substitution. If `INSTALLDIR` is ever not `/var/ossec`, this script fails to execute, full stop, regardless of how correctly everything else is rewired. |
| `src/init/pkg_installer.sh:32-33` - upgrade guard `if [ "${WAZUH_HOME}" != "/var/ossec" ]; then ... interrupting upgrade` | 1 | **High (B)** - any in-place WPK upgrade of a non-default install silently aborts today, independent of any rebrand; this audit surfaced a real latent bug. |
| Debian maintainer scripts (`packages/debs/SPECS/wazuh-agent/debian/{postinst,preinst,prerm,postrm,rules}`) | 5 files, each with its own local `DIR="/var/ossec"`/`INSTALLATION_DIR="/var/ossec"` literal | **Medium (B)** - **RPM specs are clean by contrast** (`%{_localstatedir}` macro throughout, confirmed at `packages/rpms/SPECS/wazuh-agent.spec:57,86,110`) - DEB packaging alone would need per-script editing. |
| Solaris IPS manifest (`packages/solaris/solaris11/SPECS/template_agent.json`) | 306 (of 339 total "packages/" hits) | **Low customer visibility, high mechanical cost (C)** - a static file-manifest, every installed path listed literally; needs full regeneration, not a targeted edit. |
| Solaris10/AIX/HP-UX scripts | ~12 across several files | **Low (C)**, same pattern as above, smaller scale. |
| **Our own `deploy/lab/`** | **41, across `docker-compose.yml`, both entrypoint scripts, both healthcheck scripts, `smoke-test.sh`, both `preloaded-vars-*.conf`, `agent-rocky.Dockerfile`** | **Entirely within our control, zero upstream dependency** - every one of these is a flat literal (not a variable reference), so an install-path change requires touching all 41 by hand unless we build the rename into the same script that would do it everywhere else. |
| **Our own product code** (`shadowtracer/console`, `correlate`, `ingest`, etc.) | **0** | **Already clean** - confirmed the shipper takes `alerts_path` as a parameter (`shadowtracer/ingest/shadowtracer_ingest/shipper.py`), not a hardcoded path. |

`ossec-agent` as a literal subpath name (distinct from `/var/ossec` itself) is used
consistently as a convention appended to a variable (`$INSTALLDIR/ossec-agent`,
`%{_localstatedir}/...`) everywhere it was checked - it follows an install-prefix
change correctly; it's a directory *name* choice, not an unresolved path.

### 1.3 Daemon names and system user (Pass C's original scope - revisited)

Full prior analysis in `docs/REBRAND_PLAN.md`'s own "Pass C report" section still
holds (166 files, build-system/ARGV0/API-response/privilege-drop dependencies, the
proven `0200-ossec_decoders.xml` decoder risk) - not re-derived here. **New since
that report:**

- **All 16 proposed `st-*` names fit the 15-character Linux `comm` limit** -
  computed directly: longest is `st-integratord` at 14 characters (`wazuh-execd` ->
  `st-execd`, `wazuh-clusterd` -> `st-clusterd`, `wazuh-agentlessd` -> `st-agentlessd`
  at 13, etc.) None exceed 15. **No daemon needs a shortened or different name.**
- **Decoder/rule risk is bigger than the one previously-found hit** (full inventory
  in §1.4).
- **A pre-existing, unrelated bug found while auditing**: `ruleset/rules/0280-attack_rules.xml:11,17`'s
  `SYS_USERS` variable (consumed by rule 40101, "System user successfully logged to
  the system") lists `^ossec$` as a service account that should never interactively
  log in, but **not** `wazuh` - meaning this list was never updated when the system
  user itself was renamed `ossec`->`wazuh` at some point upstream. Independent of
  this rebrand; flagged because it's exactly the kind of thing a scripted daemon/user
  rename must not repeat a third time.

### 1.4 Decoder and rule literal-match inventory (complete, not sampled)

**Daemon names (16) and `/var/ossec` literal paths, in real matching logic
(`<prematch>`/`<regex>`/`<match>`/`<field>`, not comments/descriptions):**

- Only 2 real hits, both in `ruleset/decoders/0200-ossec_decoders.xml`: line 19
  (already known - dual-accept `ossec-logcollector`/`wazuh-logcollector`) and **line
  58, newly found**: `<program_name>^ossec$</program_name>` (decoder `ossec-alert`).
- **Zero** hits for the other 15 daemon names, and **zero** `/var/ossec` literal-path
  hits in matching logic anywhere in `ruleset/decoders/`/`ruleset/rules/` (every
  occurrence checked is inside a comment or sample-log block) - genuinely low risk
  for those two specific categories.

**A larger, previously-uncounted risk category: the product's own internal
self-log-line prefix** (`"ossec: "` / `"wazuh: "`, the format ShadowTracer's own
daemons use for their own log lines - distinct from a daemon's *filename*):
~20 real matches across `ruleset/decoders/0005-wazuh_decoders.xml`,
`0200-ossec_decoders.xml`, `ruleset/rules/0015-ossec_rules.xml`,
`0016-wazuh_rules.xml`, `0340-puppet_rules.xml` (e.g. `<prematch>^wazuh: </prematch>`,
`<match>^wazuh: Agent buffer: </match>`, eleven separate `<match>^ossec: ...`
patterns). **This is the risk that actually matters most for "will self-monitoring
alerts still fire with new names"** - bigger and more load-bearing than the daemon
*binary name* question, since it's about the literal text every renamed daemon would
need to keep emitting (or the decoders need to accept both forms).

**A separate, higher-risk category this audit surfaced that is NOT a cosmetic brand
string at all**: `<category>ossec</category>`, `<type>ossec</type>`, and
`<plugin_decoder>OSSECAlert_Decoder</plugin_decoder>` (~27 occurrences across
`ruleset/rules/0015-ossec_rules.xml` and others, plus `0200-ossec_decoders.xml`) are
**literal keywords `strcmp`-matched against a hardcoded C enum/array**
(`src/analysisd/rules.c:960`, `src/analysisd/decoders/decode-xml.c:505`,
`src/analysisd/decoders/plugin_decoders.h:38`). **Renaming any of these values
requires patching and recompiling analysisd, not editing XML** - a fundamentally
different, more dangerous change than renaming a daemon's filename. Recommend
treating this as explicitly out of scope for any text-only or scripted-XML rename,
separate from the "Keep: decoder names" instruction (which covers decoder `name=`,
not these category/type/plugin_decoder *values*).

**Structural identifiers** (decoder `name=`, `parent=`, `<decoded_as>`, `<group
name=>`) are internally consistent today and have no `<if_group>` cross-dependency on
any of the names in question - renameable as a coordinated set, not independently.

**Narrow, low-risk extra findings**: two integration rules (GitHub rule 91448, Office
365 rule 91648) match the literal field value `wazuh` as an internal sentinel for
that integration's own failure-detection logic - unrelated to daemon/path naming,
small blast radius if ever touched. One osquery rule (24500) matches the literal
osquery pack name `ossec-rootkit` (upstream's own pack file name) - already has a
rebranded `<description>`, would only break if the referenced osquery pack itself
were separately renamed.

**Lab-hostname question, resolved - no dependency found**: grepped every
decoder/rule for `wazuh-master`/`wazuh-worker`/`MANAGER_NAME` - zero hits. Renaming
`deploy/lab/docker-compose.yml`'s own container hostnames away from `wazuh-*` would
not change any decoder/rule behavior.

### 1.5 Windows (source-level findings - no live install test possible, see §1.1)

- **`src/win32/win_service.c`**: the Windows Service's internal name (`WazuhSvc`),
  display name (`"Wazuh"`), and description (`"Wazuh Windows Agent"`) - **not touched
  by Pass A, not mentioned anywhere in `docs/PHASE2_REBRAND.md`**. **(A)** - this is
  exactly what a customer sees in `services.msc`.
- **Two installer definitions exist; only one is actually built.** `wazuh-installer.nsi`
  (NSIS) is wired into `make TARGET=winagent` (`src/Makefile:809`, `makensis
  wazuh-installer.nsi`) - this is the real, shipping installer. `wazuh-installer.wxs`
  (WiX/MSI) is only ever built by hand (`wazuh-installer-build-msi.bat`), not by any
  `make` target or CI job.
- **The NSIS installer that actually ships is fully Wazuh-branded**: `Name "Wazuh
  Windows Agent v4.14.8"`, `BrandingText`, `ProductName "Wazuh"`, `CompanyName "Wazuh
  Inc."`, `FileDescription "Wazuh Agent installer"`, `InternalName "Wazuh Agent"`,
  `Publisher "Wazuh"`, `HelpLink`/`URLInfoAbout` -> `https://wazuh.com`. **(A)** -
  every one of these is what a customer sees during/after install (installer title
  bar, and the Add/Remove Programs entry it writes).
- **Windows install path, hardcoded in both installer definitions independently**:
  `InstallDir "$PROGRAMFILES\ossec-agent"` (NSIS) and `<Directory Id="APPLICATIONFOLDER"
  Name="ossec-agent">` (WiX) - resolves to `C:\Program Files (x86)\ossec-agent` on a
  normal 64-bit Windows install. **(A)** - matches this task's own proposed rename
  target exactly (`C:\Program Files (x86)\ShadowTracer Agent`).
- **Registry keys, not rebranded**: `HKLM\SOFTWARE\OSSEC`, `HKLM\SOFTWARE\ossec`,
  `...\Uninstall\OSSEC\*` (NSIS); `HKLM\SOFTWARE\Wazuh, Inc.\Wazuh Agent` (WiX, read
  only if the MSI path is ever actually used). **(B)** - admin-visible via regedit,
  not typically seen by an end customer. A crash-dump folder name
  (`%LOCALAPPDATA%\WazuhCrashDumps`, `src/win32/InstallerScripts.vbs`) is the one
  Windows item with a *customer-visible path component* rather than just a registry
  key.
- **MSI `UpgradeCode`: confirmed exact value, confirmed already safe.**
  `F495AC57-7BDE-4C4B-92D8-DBE40A9AA5A0` (`wazuh-installer.wxs` line 3), confirmed
  **untouched by the automated version-bump tool** (`tools/repository_bumper.sh:243-252`
  only rewrites the `Version=` attribute via a regex anchored on `Name="Wazuh Agent"`)
  - **this task's "keep the UpgradeCode unchanged" requirement is already satisfied,
    today, with no action needed**, *as long as* any future rebrand of the `Name`
    attribute also updates that regex so the version-bump tool doesn't silently stop
    matching.
- **Icon/branding image files** (`favicon.ico`, `install.ico`, `uninstall.ico`,
  `ui/bannrbmp.jpg`, `ui/dlgbmp.jpg`) still exist under their current (not
  Wazuh-named, just generic) filenames - not inspected visually, only noted as
  present; a real rebrand would need to confirm their *content* is acceptable to use
  (or replace them), which this audit did not check.
- **`version.rc` fully re-verified, matches the existing doc exactly** - nothing
  missed there beyond what `docs/PHASE2_REBRAND.md` already discloses.

## Step 2: Plan (stopping here for approval - nothing below has been executed)

### 2.1 What to rename, and what to leave alone

Per the task's own classification and this audit's evidence:

**Rename fully (A), all customer-visible:**
1. `etc/templates/config/generic/header-comments.template` - the "Wazuh - TYPE -
   Default configuration..." banner (§1.1's missed-item finding). Cheap (1 file, 4
   lines), used on both Linux and Windows.
2. Windows Service display name/description (`win_service.c`) and the entire NSIS
   installer's branding fields (§1.5) - the installer that actually ships is 100%
   unbranded today; this is the single highest-visibility customer-facing gap this
   audit found.
3. Windows install path `ossec-agent` -> `ShadowTracer Agent` (NSIS `InstallDir`,
   §1.5) - matches the task's own proposed name exactly.
4. Our own Docker container/service hostnames (`wazuh-master` etc. in
   `deploy/lab/docker-compose.yml`) - zero upstream dependency, zero ruleset
   dependency (confirmed §1.4), cheap.
5. `COVERAGE_LABEL` in `attack_coverage.py` - reword for consistency with the new
   About-page notice (§2.3), rather than leaving the only other "Wazuh" mention
   scattered in a different part of the UI.

**Rename where cheap (B):**
6. Linux install path `/var/ossec` -> `/opt/shadowtracer` **- recommend NOT doing
   this in the same pass as daemon/user renaming.** It is not cheap: 5 separate
   default-variable definitions to keep synchronized, a critical hardcoded shebang
   (`wazuh_apid.py`) that would silently break regardless of how well everything else
   is rewired, an upgrade-abort guard (`pkg_installer.sh`) that already has a latent
   bug independent of this task, 300+ static Solaris manifest entries, divergent
   DEB-vs-RPM packaging hygiene, and 41 of our own `deploy/lab/` files with no
   variable to hook into. Each of these is individually fixable; doing all of them
   correctly, scripted, and verified is its own project-sized effort, not a line item
   inside the daemon-name rename.
7. The system user/group `wazuh` -> `shadowtracer`, and the 16 daemon binaries
   `wazuh-*` -> `st-*` (all confirmed to fit the 15-char limit, §1.3) - per
   `docs/DECISIONS.md`'s own revisit checklist, do together as one scripted change
   (they share the same blast radius: build system, privilege-drop C macro,
   packaging chown/postinst, API status-field responses).

**Leave alone (C), confirmed by this audit, not just asserted:**
- Rule group names (`ossec`, `wazuh`, `wazuh_api`) - task's own instruction, and
  confirmed no `<if_group>` depends on renaming them anyway, so this is a real
  choice, not a forced one if ever revisited.
- Decoder *names* (`name=`, `parent=`, `<decoded_as>`) - task's own instruction.
- `<category>`/`<type>`/`<plugin_decoder>` **values** (`ossec`, `OSSECAlert_Decoder`)
  - **new finding, recommend explicitly adding to the NEVER CHANGE list** - these are
    C-level hardcoded keywords, not decoder names, and weren't separately named in
    the task's own "Keep" list.
- Internal C identifiers, Python package names (`shadowtracer_ingest`, `wazuh`
  framework package) - task's own instruction.
- `version.rc`'s `CompanyName`/`LegalCopyright`/`Info` URL, DEB/RPM `Maintainer`
  fields, the 15 non-English installer languages - already-made Pass A/B decisions,
  re-affirmed, not re-litigated here.

### 2.2 The decoder dual-accept requirement, in full (not just the one known case)

Per the task's own instruction ("decoders must accept BOTH old and new names, prove
with a test"), the real list - bigger than the one previously-known case - is:

1. `ruleset/decoders/0200-ossec_decoders.xml:19` (`<prematch>`, already has the
   OSSEC->Wazuh precedent) - add a third alternative for the renamed daemon form.
2. `ruleset/decoders/0200-ossec_decoders.xml:58` (`<program_name>`, newly found) -
   needs the same dual/triple-accept treatment if the `ossec` literal it matches is
   ever touched (it currently matches `ossec`, not a daemon name - only relevant if
   the system-user/process-prefix rename ever changes what this field actually
   contains in a real log line; needs its own real-data check, not assumed).
3. The ~20 self-log-prefix matches (`ruleset/decoders/0005-wazuh_decoders.xml`,
   `0200-ossec_decoders.xml`, `ruleset/rules/0015-ossec_rules.xml`,
   `0016-wazuh_rules.xml`, `0340-puppet_rules.xml`) - **this is the real work**, not
   the daemon-filename decoder. Every renamed daemon's own log-line prefix (ARGV0)
   needs its decoder/rule pattern updated to accept both forms, or self-monitoring
   alerts (agent started/stopped/disconnected, buffer warnings, FIM DB issues, etc.)
   silently stop firing for the new name.
4. The stale `SYS_USERS` list (`0280-attack_rules.xml`) - fix as part of the same
   pass (add the new user alongside `ossec`/`wazuh`, closing the already-existing gap
   from the original ossec->wazuh rename, not just adding a third name to a list
   that's already incomplete).

### 2.3 Other plan items the task asked for

- **`deploy/rebrand/rebrand.sh`**: a single script, run against a pristine upstream
  checkout, idempotent/re-runnable after every upstream merge - matches
  `docs/DECISIONS.md`'s own existing requirement for revisiting Pass C, extended to
  cover the install-path and Windows items too if those are approved. No hand edits,
  per the task's own instruction and the project's existing practice (Pass A/B were
  already script-driven, per `docs/PHASE2_REBRAND.md`).
- **"Built on Wazuh open source (GPLv2)" notice**: no About page exists yet (§1.1) -
  needs a small new page/footer component in the frontend, not just a text edit. Low
  effort (new route + static content), but it's new surface, not a find-replace.
- **Effort/upstream-merge cost, by item** (rough, relative - no production timeline
  commitment):
  - Our own hostnames (item 4): hours, trivial merge cost (our own files).
  - `header-comments.template` + `COVERAGE_LABEL` + About page (items 1, 5, 2.3):
    hours to a day, trivial merge cost (1 inherited file + 2 of our own).
  - Windows NSIS/service rename (items 2-3): a day or two - mechanical but touches
    `win_service.c` (recompile + retest) and the installer script together; moderate
    merge cost (upstream does touch `src/win32/` across versions).
  - Daemon names + system user (item 7): the largest single item - per
    `docs/REBRAND_PLAN.md`'s existing estimate, 166+ files, build system changes, a
    privilege-drop migration story, high merge cost (upstream security patches
    frequently touch exactly these identifiers - this is the original reason Pass C
    was deferred, still true).
  - Linux install path (item 6): **recommend deferring**, as its own future item -
    see §2.1's reasoning. If pursued anyway, comparable size to item 7, with the
    added risk of the `wazuh_apid.py` shebang bug and Solaris/DEB packaging divergence
    making it easy to miss something silently.

### 2.4 Recommendation

Do items 1, 4, 5, and the About-page addition now (cheap, zero/low upstream-merge
cost, closes the one genuinely *missed* gap this audit found). Do items 2-3 (Windows
NSIS + service) next, as a contained, mechanical, source-only change. Treat item 7
(daemon names + system user) as its own scripted project per `docs/DECISIONS.md`'s
existing revisit checklist, now extended with this audit's new findings (the
self-log-prefix decoders, the stale `SYS_USERS` list, the C-level
category/type/plugin_decoder exclusion). **Recommend explicitly deferring the Linux
install-path rename** (`/var/ossec` -> `/opt/shadowtracer`) to a later, separate pass
- not because it's undesirable, but because this audit found real, specific reasons
(the shebang bug, the upgrade-abort guard, Solaris/DEB packaging divergence, 41 of our
own hardcoded files) that make it a materially bigger and riskier effort than either
daemon renaming or the Windows items, and bundling it into the same script raises the
chance of a silent miss in any one of those categories.

No files touched in writing this report. Waiting on your decision before any Step 3
implementation.
