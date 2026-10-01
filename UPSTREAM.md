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

## Upstream check log

- Last upstream check: 2026-09-29
