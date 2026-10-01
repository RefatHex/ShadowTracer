#!/usr/bin/env python3
"""Pass A: rewrite "Wazuh" -> "ShadowTracer" only inside <description>...
</description> tag TEXT in ruleset/rules/*.xml. Never touches rule id,
level, group, match/regex/decoded_as or any other matching logic - grepped
ruleset/ first per the NEVER CHANGE rule before running this."""
import glob
import re

DESC_RE = re.compile(r"(<description>)([^<]*)(</description>)")
WAZUH_WORD_RE = re.compile(r"\bWazuh\b|\bwazuh\b")

def rebrand_line(line):
    def sub(m):
        text = m.group(2)
        if WAZUH_WORD_RE.search(text):
            text = WAZUH_WORD_RE.sub("ShadowTracer", text)
        return m.group(1) + text + m.group(3)
    return DESC_RE.sub(sub, line)

touched_files = []
for path in sorted(glob.glob("ruleset/rules/*.xml")):
    with open(path) as f:
        lines = f.readlines()
    changed = False
    out = []
    for line in lines:
        new_line = rebrand_line(line)
        if new_line != line:
            changed = True
        out.append(new_line)
    if changed:
        with open(path, "w") as f:
            f.writelines(out)
        touched_files.append(path)

print(f"touched {len(touched_files)} files:")
for p in touched_files:
    print(" ", p)
