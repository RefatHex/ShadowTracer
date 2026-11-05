"""Write a Wazuh CDB list text file, then prove it parses back to exactly the intended
keys using the same rules as analysisd's compiler (src/analysisd/lists_make.c:61-140).
THREAT_INTEL.md §4.7: nothing reaches a list file that could add, drop or change an entry.
"""


class UnsafeList(ValueError):
    pass


def _parse_line(line: str):
    """One line as Lists_OP_MakeCDB reads it; returns the key or None if skipped."""
    line = line.split("\r", 1)[0].split("\n", 1)[0]
    key = None
    q = line.find('"')
    colon = line.find(":")
    rest = line
    if q != -1 and colon != -1 and colon > q:           # quoted key (lists_make.c:73-99)
        end = line.find('"', q + 1)
        if end == -1:
            return None                                  # format error -> line skipped
        key = line[q + 1:end]
        rest = line[end + 1:]
    c = rest.find(":")
    if c == -1:
        return None                                      # no ':' -> skipped (:107-113)
    if key is None:
        key = rest[:c]
    return key


def parse(text: bytes) -> list:
    out = []
    for line in text.decode("utf-8").split("\n"):
        if line == "":
            continue
        k = _parse_line(line)
        if k is not None:
            out.append(k)
    return out


def write(keys) -> bytes:
    """keys: already-normalised IOC values (normalise.py). Keys containing ':' (IPv6,
    URLs) are quoted. Values are always empty. Raises UnsafeList if the file would not
    parse back to exactly these keys."""
    keys = sorted(set(keys))
    lines = []
    for k in keys:
        if not k or "\n" in k or "\r" in k or "\0" in k or '"' in k:
            raise UnsafeList(f"unsafe key {k!r}")
        line = f'"{k}":' if ":" in k else f"{k}:"
        if len(line.encode()) >= 65534:                  # fgets(str, OS_MAXSTR - 1) splits longer lines
            raise UnsafeList("line too long")
        lines.append(line)
    data = ("\n".join(lines) + "\n").encode("utf-8") if lines else b""
    if parse(data) != keys:
        raise UnsafeList("list does not parse back to the intended keys")
    return data
