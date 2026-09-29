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

Verified in a clean `ubuntu:22.04` container (2026-09-29):

```
apt-get install -y build-essential automake autoconf libtool cmake \
    curl wget git ca-certificates
```

(`policycoreutils`, `gawk`, `python3`, `sudo`, `lsb-release` were also
installed in the verification run but are not required for `TARGET=server`
or `TARGET=agent` — they matter for other targets like `TARGET=winagent`
or SELinux-enabled builds.)

`make deps` downloads prebuilt external-library tarballs from
`packages.wazuh.com` and the `http-request` submodule tarball from GitHub,
so the first build needs outbound HTTPS access.

### Build results (2026-09-29, clean `ubuntu:22.04` container, host: WSL2)

| Step | Time | Result |
|------|------|--------|
| `make deps` (TARGET=server) | 2m17s | OK, prebuilt binary deps fetched, no compilation needed |
| `make TARGET=server -j$(nproc)` | 3m40s | OK — `Done building server`, 35 compiler warnings (all pre-existing upstream code: `-Wstringop-overflow`, `-Wdiscarded-qualifiers`, one OpenSSL 3.0 deprecation, etc.), 0 errors |
| `make TARGET=agent -j$(nproc)` | 2s | OK — `Done building agent` (shares already-built objects with the server build), 4 warnings, 0 errors |

Both `src/wazuh-analysisd` and `src/wazuh-agentd` were produced.

That 2s `TARGET=agent` number is not a real agent build — it reused object
files already compiled for `TARGET=server` moments earlier. The real,
from-clean number is below.

### Real agent build (2026-09-29, fresh `ubuntu:22.04` container, host: WSL2)

`make deps`, then `make clean`, then `make TARGET=agent`, nothing else in
between:

| Step | Time | Result |
|------|------|--------|
| `make deps` | 1m18s | OK |
| `make clean` | 2s | OK |
| `make TARGET=agent -j$(nproc)` | 34s, then **Error 127** | `cd external/dbus/ && ./configure ...` → `./configure: not found` |

**`make clean` breaks a from-scratch build.** `make deps` fetches a
*prebuilt* dbus binary (only `external/dbus/lib/` and `external/dbus/include/`
— no source, no `configure` script). `make clean`'s dbus rule
(`rm -rf external/dbus/lib external/dbus/include`, `Makefile:2676`) assumes a
from-source build and deletes the only two directories that exist, leaving
`external/dbus/` completely empty. `make TARGET=agent` then tries to rebuild
`libdbus-1.a` from source (`Makefile:1290`) and there's nothing there to
configure.

The fix is simply to run `make deps` again before building — its dbus fetch
step is unconditional (unlike its source-fallback path, it isn't guarded by
`test -d external/dbus`), so it always re-populates the directory:

| Step | Time | Result |
|------|------|--------|
| `make deps` (recovers `external/dbus/`) | 1m0s | OK |
| `make TARGET=agent -j$(nproc)` | 1m18s | OK — `Done building agent`, 0 errors |

`src/wazuh-agentd` was produced. **Takeaway:** don't run `make clean` between
`make deps` and the first build in a fresh checkout; if you do, run
`make deps` once more before building.
