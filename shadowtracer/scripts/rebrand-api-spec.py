#!/usr/bin/env python3
"""Pass A: rewrite the brand word "Wazuh" -> "ShadowTracer" only inside
title/description/summary field VALUES in api/api/spec/spec.yaml - never in
daemon-name enums, decoder file references, schema "format" identifiers,
URLs, or compound identifiers like "WazuhDB" (a real socket name, not
prose - \\b excludes it since nothing but a word character follows "Wazuh"
there). Lines with no match are emitted byte-for-byte unchanged.
"""
import re

PATH = "api/api/spec/spec.yaml"
FIELD_RE = re.compile(r"^(\s*)(title|description|summary):\s*(.*)$")
BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?\s*$")
WAZUH_WORD_RE = re.compile(r"\bWazuh\b")

with open(PATH) as f:
    lines = f.readlines()

out = []
in_block = False
block_indent = -1
touched = 0

for line in lines:
    stripped = line.rstrip("\n")
    m = FIELD_RE.match(stripped)
    if in_block:
        indent = len(stripped) - len(stripped.lstrip(" "))
        if stripped.strip() == "" or indent > block_indent:
            if WAZUH_WORD_RE.search(stripped):
                stripped = WAZUH_WORD_RE.sub("ShadowTracer", stripped)
                touched += 1
                out.append(stripped + "\n")
            else:
                out.append(line)
            continue
        else:
            in_block = False
            # fall through to re-check this line as a normal line

    if m:
        indent, key, value = m.groups()
        if BLOCK_SCALAR_RE.match(value.strip()):
            in_block = True
            block_indent = len(indent)
            out.append(line)
            continue
        if WAZUH_WORD_RE.search(value):
            value = WAZUH_WORD_RE.sub("ShadowTracer", value)
            out.append(f"{indent}{key}: {value}\n")
            touched += 1
        else:
            out.append(line)
        continue

    out.append(line)

with open(PATH, "w") as f:
    f.writelines(out)

print(f"touched {touched} title/description/summary lines")
