# Upstream

ShadowTracer is a fork of [Wazuh](https://github.com/wazuh/wazuh), licensed
under GPLv2 (see [LICENSE](LICENSE)).

## Fork point

- Upstream repo: https://github.com/wazuh/wazuh.git
- Tag: `v4.14.8`
- Commit: `f470ad7db717b18db7feeed568949643698f0f34`
- Date forked: 2026-09-29
- Local marker tag: `st-base-4.14.8`

`VERSION.json` reports `"stage": "rc2"`, but `v4.14.8` has dated public
release notes on the upstream repo, so it is treated as a release, not a
release candidate.

## Boundary

All original ShadowTracer code lives under [`shadowtracer/`](shadowtracer/).
Everything else in this repository is inherited Wazuh code, changed only
when necessary. Every such change is recorded below. `docs/` stays exactly
as upstream ships it; our own project docs live in
[`shadowtracer/docs/`](shadowtracer/docs/) — see
[DECISIONS.md](shadowtracer/docs/DECISIONS.md) and
[DEV_SETUP.md](shadowtracer/docs/DEV_SETUP.md).

## How to pull a security fix from upstream

1. `git fetch upstream`
2. Find the fix commit on the relevant upstream tag/branch.
3. `git cherry-pick <commit>` onto our `main` (resolve conflicts if the file
   has a ShadowTracer-side modification — check the table below first).
4. Re-run `check-project.sh`.
5. Rebuild (`cd src && make deps && make TARGET=server && make TARGET=agent`).
6. Smoke test the affected component before merging.

## Change categories

Every inherited-path change (added/modified/deleted) vs `v4.14.8` is listed
in [`shadowtracer/docs/MODIFIED_FILES.txt`](shadowtracer/docs/MODIFIED_FILES.txt)
(regenerate with `shadowtracer/scripts/gen-modified-files.sh`). Every path
in that file must match at least one `Patterns` entry below — `check-
project.sh` fails otherwise, so a new kind of change means a new row here
before it can land, not a note added after the fact.

| Category | Patterns | Reason |
|------|--------|------|
| CI workflow replacement | `.github/workflows/*` | Upstream's `4_*.yml` workflows need Wazuh's own infrastructure (AWS OIDC roles, self-hosted runners, internal secrets) that doesn't exist in this fork; left in place they'd fire on every push and fail instantly. Deleted all 77 and added one `ci.yml` that actually runs here. `.github/actions/` and `.github/scripts/` were left as-is (inert without a workflow invoking them). |
| gitignore additions | `.gitignore` | Appended ShadowTracer-specific ignore patterns (`__pycache__/`, `node_modules/`, `.env`, etc.) below upstream's list. |
| Repo governance files | `UPSTREAM.md` `check-project.sh` `.dockerignore` `.gitattributes` | New root-level files that track and enforce the fork boundary and build hygiene; they describe the whole repository rather than our own code, so they live at the root, not under `shadowtracer/`. |
| Phase 2 Pass A: systemd unit descriptions | `src/init/templates/wazuh-manager.service` `src/init/templates/wazuh-agent.service` | Rebranded the `Description=` line only (text users see in `systemctl status`); filenames, `ExecStart`/`wazuh-control` references stay until Pass B. |
| Phase 2 Pass A: control script banners | `src/init/wazuh-server.sh` `src/init/wazuh-client.sh` `src/init/wazuh-local.sh` | Rebranded the `Starting`/`Stopped`/`not used by` console banners and the `VERSION=` string shown in them (now `1.0.0-dev (based on Wazuh 4.14.8)`); daemon-name strings (`wazuh-analysisd`, etc.) and the unused `AUTHOR=` var are untouched. |
| Phase 2 Pass A: installer prompts and banners | `etc/templates/en/messages.txt` `etc/templates/en/messages/0x101-initial.txt` `etc/templates/en/messages/0x103-thanksforusing.txt` `etc/templates/en/messages/0x105-noboot.txt` `src/init/pkg_installer.sh` | Rebranded the English (`en`, the install default) prompt/banner text only - the other 15 language directories under `etc/templates/` are unchanged (not translated, flagged as an open item rather than guessed at). `0x109-castore.txt`'s mention of "the root certificate by Wazuh" was deliberately left as-is - it describes a real Wazuh-issued certificate still in use, not branding. |
| Phase 2 Pass A: API title/description text | `api/api/spec/spec.yaml` | Rebranded `title`/`description`/`summary` field text only, by script (`shadowtracer/scripts/rebrand-api-spec.py`), word-boundary matched so compound identifiers like `WazuhDB` (a real socket name) and daemon-name enums/decoder-file references in the same file were left untouched. |
| Phase 2 Pass A: rule descriptions | `ruleset/rules/0010-rules_config.xml` `ruleset/rules/0015-ossec_rules.xml` `ruleset/rules/0016-wazuh_rules.xml` `ruleset/rules/0017-wazuh-api_rules.xml` `ruleset/rules/0545-osquery_rules.xml` | Rebranded only `<description>` tag text, by script (`shadowtracer/scripts/rebrand-rule-descriptions.py`); rule `id`/`level`/`group`/match-decoder logic is untouched - per NEVER CHANGE, ruleset/ was grepped first to confirm no rule matches its own description text. |
| Phase 2 Pass A: Windows version.rc | `src/win32/version.rc` | Rebranded `FileDescription`/`ProductName` only; `CompanyName`, `LegalCopyright`, and the `Info` URL are genuine attribution to the real upstream company/site and were kept, alongside the untouched copyright header. |
| Phase 2 Pass B: systemd unit files renamed | `src/init/templates/wazuh-manager.service` `src/init/templates/wazuh-agent.service` `src/init/templates/shadowtracer-manager.service` `src/init/templates/shadowtracer-agent.service` | Renamed the installed filenames (old names appear as `D` in MODIFIED_FILES.txt, new ones as `A`); `ExecStart`/`ExecStop`/`ExecReload` updated to the renamed control binary. `WAZUH_HOME_TMP` (a build-time path placeholder, not a deployment var) is untouched. |
| Phase 2 Pass B: control binary renamed (wazuh-control -> shadowtracer-control) | `install.sh` `src/init/darwin-init.sh` `src/init/init.sh` `src/init/inst-functions.sh` `src/init/update.sh` `src/init/wazuh-client.sh` `src/init/wazuh-local.sh` `src/init/wazuh-server.sh` `src/init/templates/ossec-hids-aix.init` `src/init/templates/ossec-hids-debian.init` `src/init/templates/ossec-hids-gentoo.init` `src/init/templates/ossec-hids-hpux.init` `src/init/templates/ossec-hids-rh.init` `src/init/templates/ossec-hids-solaris.init` `src/init/templates/ossec-hids-suse.init` `src/init/templates/ossec-hids.init` `src/active-response/restart.sh` `src/active-response/restart-wazuh.c` `src/os_execd/wcom.c` `src/analysisd/compiled_rules/register_rule.sh` `packages/aix/SPECS/wazuh-agent-aix.spec` `packages/solaris/solaris11/SPECS/template_agent.json` | The installed binary name changes everywhere it's invoked, including the two C active-response callers (`restart-wazuh.c`, `wcom.c`) - not in the task's own example list, but functionally required: leaving them pointed at the old name would break active-response restarts the moment the binary is renamed. AIX/Solaris specs were text-edited but not build-tested (no AIX/Solaris environment available) - flagged as an open item. `wazuh-agentd`/`wazuh-agentlessd` daemon-name strings were deliberately left alone (Pass C, not this pass) - caught and fixed one accidental substring match during this edit (`wazuh-agent` matching inside `wazuh-agentd`). |
| Phase 2 Pass B: package names, Conflicts/Replaces | `packages/debs/SPECS/wazuh-manager/debian/control` `packages/debs/SPECS/wazuh-manager/debian/rules` `packages/debs/SPECS/wazuh-manager/debian/postinst` `packages/debs/SPECS/wazuh-manager/debian/preinst` `packages/debs/SPECS/wazuh-manager/debian/prerm` `packages/debs/SPECS/wazuh-agent/debian/control` `packages/debs/SPECS/wazuh-agent/debian/rules` `packages/debs/SPECS/wazuh-agent/debian/postinst` `packages/debs/SPECS/wazuh-agent/debian/preinst` `packages/debs/SPECS/wazuh-agent/debian/prerm` `packages/rpms/SPECS/wazuh-manager.spec` `packages/rpms/SPECS/wazuh-agent.spec` | DEB `Package:`/RPM `Name:` renamed to `shadowtracer-manager`/`shadowtracer-agent`, same install path (`/var/ossec`, unchanged), so `Conflicts`/`Replaces` (DEB) and `Conflicts`/`Obsoletes`/`Provides` (RPM's native equivalent) added against the old `wazuh-*` package names - same install path means they must never coexist. `Maintainer`/`Vendor`/`Packager` fields kept as real upstream contact info (no ShadowTracer equivalent exists yet - open item). The self-signed cert `CN=Wazuh` generated by `wazuh-authd` on manager install was also updated to `CN=ShadowTracer`. |
| Phase 2 Pass B: deployment env vars | `src/init/register_configure_agent.sh` | Added `get_shadowtracer_vars` (new `SHADOWTRACER_*` names, always take priority when set) called right before the existing `get_deprecated_vars` (old `WAZUH_*` names, used only as a fallback) - verified all three priority cases (SHADOWTRACER_* only, WAZUH_* only, both set) by sourcing the functions directly. `WAZUH_HOME_TMP` and `WAZUH_HOME` (the latter a C-level `getenv()` install-path fallback, not a Docker/OVA deployment var) are out of scope for this pass. |
| Phase 2 Checker Additions: more wazuh-control callers the new checker found | `etc/ossec.conf` `framework/scripts/wazuh_logtest.py` `wodles/utils.py` `api/test/integration/env/base/agent/entrypoint.sh` `api/test/integration/env/base/manager/entrypoint.sh` `api/test/integration/env/configurations/manager/manager/healthcheck/healthcheck.py` `api/test/integration/env/configurations/security/manager/healthcheck/healthcheck.py` `api/test/integration/env/tools/healthcheck_utils.py` `api/tools/env/wazuh-agent/entrypoint.sh` `api/tools/env/wazuh-manager/healthcheck.sh` `api/api/spec/spec.yaml` `src/init/wazuh-server.sh` `src/init/wazuh-client.sh` | Writing the "no wazuh-control outside an allowlist" checker (see below) surfaced real leftover references Pass B's own file-by-file scope missed: two `CGROUP_PATH` lookups in `wazuh-server.sh`/`wazuh-client.sh` still hardcoded the old `.service` unit name (would have looked in the wrong cgroup path); `wodles/utils.py` and `wazuh_logtest.py` both construct and execute `bin/wazuh-control` at runtime (genuine functional bugs, not cosmetic); `etc/ossec.conf`'s shipped comment told users to run the old binary name; the API spec's example process-list entry still showed `wazuh-control`; and the API's own test/dev Docker entrypoints/healthchecks (separate from `deploy/lab`) called the old binary name too. This is exactly what the checker is for - not a style nit. |
| Phase 3 follow-up: agent send-failure bug fix | `src/client-agent/buffer.c` | `dispatch_buffer()` freed a message unconditionally after `send_msg()`, regardless of whether the send succeeded - a failed send in the window before `os_wait()`'s connection-loss lock engages was silently dropped (Phase 1 item 15's 1-of-20 loss during a worker failover). Fixed by requeuing via the existing `buffer_append()` on failure instead of dropping. Trade-off recorded in `shadowtracer/docs/DECISIONS.md`: a requeued send whose first attempt actually landed can produce a manager-side duplicate with a different `alert_id`, invisible to Phase 3's `(tenant_id, cluster_node, alert_id)` dedup - accepted, a duplicate beats a loss for a security product. Re-ran Phase 1 item 15 for real: 20/20 delivered (was 19/20). Upstream issue/patch drafted - see `shadowtracer/docs/UPSTREAM_ISSUES/agent-send-failure-drops-message.md`. |
| Phase 3 follow-up: load-balancer NULL-pointer bug fix | `src/shared/validate_op.c` `src/headers/validate_op.h` `src/unit_tests/shared/test_validate_op.c` | `OS_IsValidIP()`'s "any" branch allocated `final_ip->ipv6` but never set `final_ip->is_ipv6 = TRUE` to match (left at its `memset(0)` default of `FALSE`), so `isSingleHost()` (`validate_op.h`) read the never-allocated `final_ip->ipv4` instead - a NULL-pointer dereference for every "any"-registered agent, the real cause of the dynamic-ID `!<id>!` prefix never being sent (Phase 1 Step 2's load-balancer finding). Fixed the root cause (`is_ipv6 = TRUE` in that branch) and hardened `isSingleHost()` with a defensive NULL check on `ipv4` as a second line of defense against the same class of mismatch elsewhere. Updated the one existing unit test that asserted the buggy behavior as correct (`OS_IsValidIP_any_struct`) and added a direct `isSingleHost()` assertion - couldn't be executed in this environment (unrelated `syscollector`/`data_provider` build dependencies, see `shadowtracer/docs/PHASE3_DATA_PLATFORM.md`); live-validated instead by re-running Phase 1 item 15 through the real load balancer (20/20, both agents reaching Active with dynamic IP for the first time) and removing the static-IP-per-worker workaround (`deploy/lab/docker-compose.yml`, `deploy/lab/entrypoint-agent.sh`). Upstream issue/patch drafted - see `shadowtracer/docs/UPSTREAM_ISSUES/load-balancer-null-pointer.md`. |

## Upstream check log

- Last upstream check: 2026-09-29
