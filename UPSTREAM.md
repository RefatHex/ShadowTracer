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
when necessary. Every such change is recorded below.

## How to pull a security fix from upstream

1. `git fetch upstream`
2. Find the fix commit on the relevant upstream tag/branch.
3. `git cherry-pick <commit>` onto our `main` (resolve conflicts if the file
   has a ShadowTracer-side modification — check the table below first).
4. Re-run `check-project.sh`.
5. Rebuild (`cd src && make deps && make TARGET=server && make TARGET=agent`).
6. Smoke test the affected component before merging.

## Wazuh files we modified

| File | Reason | Date |
|------|--------|------|
| `docs/README.md` | Appended a ShadowTracer docs section; original Wazuh manager doc intro preserved above it | 2026-09-29 |
| `.github/workflows/*` (all except `ci.yml`) | Deleted (77 files). Upstream CI needs Wazuh's own infrastructure (AWS OIDC roles, self-hosted runners, internal secrets) that doesn't exist in this fork; left in place they'd fire on every push and fail instantly. `.github/actions/` and `.github/scripts/` were left as-is (inert without a workflow invoking them). | 2026-09-29 |

## Upstream check log

- Last upstream check: 2026-09-29
