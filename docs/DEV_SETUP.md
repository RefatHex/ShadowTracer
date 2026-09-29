# Dev setup

## WSL2

Work inside WSL2, on the Linux filesystem — not under `/mnt/c`. Cross-filesystem
access from Windows to `/mnt/c` (and vice versa) is slow and can break file
permissions/line endings.

Repo location: `~/ShadowTracer` (e.g. `/home/<user>/ShadowTracer`).

## Line endings

`core.autocrlf` should be `input` or `false` — never `true` — since this repo
mixes LF (default), CRLF (`*.bat`), and binary files, and `.gitattributes`
already enforces normalization on checkout/commit:

```
git config core.autocrlf input
```

## Docker

Used for clean build verification and eventually for `deploy/`. Install
Docker Desktop with WSL2 integration, or Docker Engine directly inside WSL2.

## Build steps

```
cd src
make deps
make TARGET=server
# or
make TARGET=agent
```

The first build needs network access to fetch external dependencies.

### Build packages needed (Ubuntu 22.04)

See the "Prove it builds" run in this repo's history / CI for the exact
package list and any warnings from a clean-container build.
