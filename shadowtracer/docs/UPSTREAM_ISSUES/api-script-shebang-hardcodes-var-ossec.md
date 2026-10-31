Drafted for submission to github.com/wazuh/wazuh. Not filed - this fork
has no standing to file on the user's behalf. Written so it's ready to
paste in once reviewed.

---

**Title:** `api/scripts/wazuh_apid.py`'s shebang hardcodes `/var/ossec`,
breaking direct execution on any non-default install path

**Component:** `api/scripts/wazuh_apid.py`

**Summary:**

The script's shebang line is a literal, absolute interpreter path:

```python
#!/var/ossec/framework/python/bin/python3
```

This is never substituted at install time - `api/Makefile` only copies the
file (`$(INSTALL_FILE) scripts/wazuh_apid.py ${INSTALLDIR}/api/scripts`),
it does not rewrite the shebang to match `${INSTALLDIR}`. In normal
operation this is masked: the real entry point installed at
`${INSTALLDIR}/bin/wazuh-apid` is `wrappers/generic_wrapper.sh`, which
*does* derive its Python interpreter path correctly, relative to its own
location (`WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"`, then invoking
`${WAZUH_PATH}/framework/python/bin/python3 ${WAZUH_PATH}/api/scripts/wazuh_apid.py`).
The bug only surfaces if `wazuh_apid.py` is ever executed directly -
manually, from an IDE run action, or by any tooling that bypasses the
wrapper - on an install where `INSTALLDIR` was set to anything other than
the default `/var/ossec` (`make INSTALLDIR=/path`, or any packaging that
chooses a different prefix). The direct-execution path then fails with
"No such file or directory" against a `/var/ossec` that was never actually
used for that install.

**Reproduction:**

1. Build and install with a non-default prefix: `make
   INSTALLDIR=/opt/example TARGET=server`, then install.sh with
   `USER_DIR=/opt/example`.
2. Run `/opt/example/api/scripts/wazuh_apid.py --help` directly (not via
   `/opt/example/bin/wazuh-apid`).
3. Observe the shell reports no such file or directory for
   `/var/ossec/framework/python/bin/python3` - the real interpreter at
   `/opt/example/framework/python/bin/python3` is never considered.

**Suggested fix:**

Replace the hardcoded shebang with a self-locating polyglot header, the
same relative-path logic `generic_wrapper.sh` already uses, so the script
is correct however it's invoked:

```python
#!/bin/sh
""":"
_D="$(cd "$(dirname "$0")/../.."; pwd)"
exec "${WAZUH_PATH:-$_D}/framework/python/bin/python3" "$0" "$@"
":"""
```

`sh` executes the `exec` line (locating the interpreter two directories up
from the script's own real location, honoring `WAZUH_PATH` if set, exactly
like the wrapper); Python sees the same lines as a single inert
triple-quoted string literal (verified: `python3 -c
"compile(open(f).read(), f, 'exec')"` raises no error). Verified end to
end against the real embedded CPython distribution and a genuinely
non-default location (not just a syntax check): copied
`framework/python` and the fixed script to a separate path, confirmed the
`exec` line resolved and attempted the correct non-`/var/ossec` interpreter
path (the only remaining failure was an unrelated shared-library RPATH
issue from manually copying prebuilt binaries outside a real install,
not the shebang logic).

**Patch:** see the diff in this fork's `api/scripts/wazuh_apid.py` (search
history for "Rebrand Pass C prep" in the commit log) - happy to open a PR
with the equivalent change against a clean checkout if maintainers want it
in that form instead.
