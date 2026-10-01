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

## Upstream check log

- Last upstream check: 2026-09-29
