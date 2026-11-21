"""Verify step (in code): every sentence of the LLM summary must cite evidence ids whose text
actually contains the hard facts it states (IPs, technique ids, rule/numeric values). A sentence with
no citation, or a cited fact that isn't in the cited evidence, is flagged "unverified" - never dropped
silently. Facts the model invents therefore surface as flagged, not as confident prose.
"""
from __future__ import annotations

import re

_BRACKET = re.compile(r"\[([^\]]*?E\d+[^\]]*?)\]")   # a bracket group that contains evidence ids
_EID = re.compile(r"E\d+")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_NUM = re.compile(r"\b\d{2,}\b")          # multi-digit numbers (counts, levels, rule ids); skip 1-digit noise
# Split on a sentence terminator FOLLOWED BY whitespace, so a '.' inside an IP (203.0.113.9) or a
# decimal never splits a sentence.
_SPLIT = re.compile(r"(?<=[.!?])\s+")


def _facts(sentence: str) -> list[str]:
    s = re.sub(r"\[[^\]]*\]", "", sentence)   # strip citation brackets so their ids aren't read as facts
    facts = set(_IPV4.findall(s)) | set(_TECH.findall(s))
    facts |= {m.group(0) for m in _NUM.finditer(s)}
    return sorted(facts)


def verify(summary: str, evidence: list[dict]) -> list[dict]:
    """-> [{text, cites, verified, unsupported:[facts]}] per sentence, in order."""
    by_id = {e["id"]: e["body"] + " " + e["title"] for e in evidence}
    out = []
    for raw in _SPLIT.split(summary):
        text = raw.strip()
        if not text:
            continue
        cites = [eid for grp in _BRACKET.findall(text) for eid in _EID.findall(grp)]
        cited_text = " ".join(by_id.get(c, "") for c in cites)
        facts = _facts(text)
        # A sentence with no hard facts (e.g. a suggested next step) has nothing to check -> ok.
        # A factual claim must have its facts present in the cited evidence, else it is unsupported.
        unsupported = [f for f in facts if f not in cited_text]
        verified = not unsupported
        out.append({"text": text, "cites": cites, "verified": verified, "unsupported": unsupported})
    return out
