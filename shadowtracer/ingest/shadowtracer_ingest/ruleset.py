"""Parses the real, bundled Wazuh ruleset (ruleset/rules/*.xml) and the
real, bundled MITRE ATT&CK STIX bundle (ruleset/mitre/enterprise-attack.json)
to answer two questions, deterministically, with no model and no network
call: which rule groups can actually appear on a real alert's
rule.groups array, and which rule ids carry which MITRE technique ids
and tactics.

Parsed fresh on each call (not cached to a static file) - 168 small XML
files parse in well under a second, and a pre-generated artifact would be
a SECOND source that could silently drift from the real ruleset if it's
ever upgraded without regenerating it (same reasoning as Phase 5A Step
0's one ClickHouse schema source, not two). The MITRE STIX bundle is the
one exception - it's 27 MB of upstream ATT&CK data unrelated to anything
ShadowTracer changes, so `_load_mitre_tactics` caches it in-process for
the life of whatever imports this module, not per-call.

Shared the same way shadowtracer_ingest.normalizer already is: imported
directly by both shadowtracer_correlate and the console backend via a
sys.path insert, never duplicated.
"""

import functools
import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

# Confirmed directly from src/analysisd/format/json_extended.c
# (add_groupPCI/CIS/GDPR/GPG13/HIPAA/NIST/TSC): any XML <group> token
# starting with one of these prefixes is a compliance-framework mapping
# that analysisd pulls OUT into its own dedicated alert field
# (rule.pci_dss, rule.gdpr, ...) - it never appears in a real alert's
# rule.groups array. Confirmed empirically too, against
# shadowtracer/ingest/fixtures/real_alerts_4.14.8.jsonl: rule 5710's own
# XML <group> tag lists gdpr_IV_35.7.d, gpg13_7.1, nist_800_53_AU.14,
# pci_dss_10.2.4, tsc_CC6.1, ... alongside authentication_failed and
# invalid_login - the real captured alert's rule.groups is exactly
# ["syslog", "sshd", "authentication_failed", "invalid_login"] (the first
# two inherited from the enclosing <group name="syslog,sshd,">): every
# compliance-prefixed token is absent, every other token is present.
_COMPLIANCE_PREFIXES = (
    "pci_dss_", "cis_", "gdpr_", "gpg13_", "hipaa_", "nist_800_53_", "tsc_",
)


@dataclass
class RuleInfo:
    rule_id: str
    level: int
    description: str
    groups: list = field(default_factory=list)      # real alert-visible groups only
    mitre_ids: list = field(default_factory=list)


def _real_groups(raw_tokens: list) -> list:
    seen = []
    for tok in raw_tokens:
        tok = tok.strip()
        if not tok or any(tok.startswith(p) for p in _COMPLIANCE_PREFIXES):
            continue
        if tok not in seen:
            seen.append(tok)
    return seen


def _parse_one_file(path: str) -> list:
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    # A handful of rules embed a literal regex containing backslash-escaped
    # angle brackets (e.g. \<\w+\>) inside a <regex> text node - not valid
    # XML (bare < / > outside a tag). Fixed by swapping them for plain-ASCII
    # placeholders (control characters like \x01 are themselves invalid
    # XML 1.0 character data and just trade one parse error for another -
    # found the hard way) - but ONLY inside <regex>...</regex> spans, found
    # by regex, not a blind whole-file string replace: a blind replace once
    # corrupted an unrelated rule's <field name="...">E:\\</field> value
    # elsewhere in the ruleset, whose text happens to end in two literal
    # backslashes immediately followed by the real closing tag's '<' - the
    # blind replace ate that '<' as if it were an escaped regex bracket,
    # silently breaking that tag's structure (a "mismatched tag" parse
    # error many lines later, nowhere near the real cause - also found the
    # hard way). Scoping the substitution to real <regex> spans only
    # avoids touching any other tag's content.
    def _escape_angle_brackets_in_regex(m):
        return m.group(0).replace("\\<", "ESCAPEDLT").replace("\\>", "ESCAPEDGT")

    text = re.sub(r"<regex\b[^>]*>.*?</regex>", _escape_angle_brackets_in_regex, text, flags=re.DOTALL)
    root = ET.fromstring(f"<root>{text}</root>")

    rules = []

    def walk(node, inherited_groups):
        for child in node:
            if child.tag == "group" and child.get("name") is not None:
                wrapper_groups = inherited_groups + [
                    t.strip() for t in child.get("name").split(",") if t.strip()
                ]
                walk(child, wrapper_groups)
            elif child.tag == "rule":
                own_group_el = child.find("group")
                own_tokens = (
                    [t.strip() for t in (own_group_el.text or "").split(",")]
                    if own_group_el is not None else []
                )
                mitre_ids = [e.text.strip() for e in child.findall("./mitre/id") if e.text]
                desc_el = child.find("description")
                description = (desc_el.text or "").strip() if desc_el is not None else ""
                description = description.replace("ESCAPEDLT", "<").replace("ESCAPEDGT", ">")
                rules.append(RuleInfo(
                    rule_id=child.get("id", ""),
                    level=int(child.get("level") or 0),
                    description=description,
                    groups=_real_groups(inherited_groups + own_tokens),
                    mitre_ids=mitre_ids,
                ))
            else:
                walk(child, inherited_groups)

    walk(root, [])
    return rules


def parse_ruleset(ruleset_dir: str) -> list:
    """One RuleInfo per <rule id=...> found under ruleset_dir/*.xml -
    groups resolved exactly the way analysisd composes them for a real
    alert: every enclosing <group name="..."> wrapper's tokens (outer to
    inner) plus the rule's own direct <group>...</group> tag, with
    compliance-prefixed tokens stripped and order-preserving de-dup."""
    rules = []
    for name in sorted(os.listdir(ruleset_dir)):
        if name.endswith(".xml"):
            rules.extend(_parse_one_file(os.path.join(ruleset_dir, name)))
    return rules


def all_rule_groups(ruleset_dir: str) -> set:
    groups = set()
    for r in parse_ruleset(ruleset_dir):
        groups.update(r.groups)
    return groups


@functools.lru_cache(maxsize=1)
def _load_mitre_tactics(mitre_json_path: str) -> dict:
    """technique_id -> sorted list of tactic names (ATT&CK's
    kill_chain_phases[].phase_name), from the real, bundled MITRE
    ATT&CK STIX bundle. Cached in-process (27 MB of upstream reference
    data unrelated to anything this project changes - unlike the
    ruleset, there's no drift risk in caching this for the process
    lifetime). Revoked/deprecated ATT&CK objects are skipped; a
    technique id the ruleset references that isn't in the active set
    simply gets an empty tactic list, not an error - reported, not
    hidden."""
    with open(mitre_json_path, encoding="utf-8") as f:
        data = json.load(f)
    tactics_by_technique: dict = {}
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break
        if not technique_id:
            continue
        tactics = sorted({p["phase_name"] for p in obj.get("kill_chain_phases", [])})
        tactics_by_technique[technique_id] = tactics
    return tactics_by_technique


_VALID_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def attack_coverage_map(ruleset_dir: str, mitre_json_path: str) -> dict:
    """technique_id -> {"tactics": [...], "rule_ids": [...]} - built from
    the inherited ruleset's own MITRE tags only. This is "rules exist for
    this technique", not a tested-coverage claim - see Step 2's own
    callers for the explicit label.

    Excludes the one rule in the real ruleset
    (0997-maltiverse_rules.xml, rule carrying <id>$(threat.software.id)</id>)
    whose "technique id" is actually a runtime template placeholder for a
    threat-intel feed's MITRE ATT&CK *software* id (format Sxxxx, not a
    technique Txxxx/Txxxx.xxx), not a static technique reference at all -
    found by inspecting the one coverage entry whose tactics never
    resolved against the real MITRE STIX bundle, confirmed in the rule's
    own XML. Never silently dropped - see ruleset_counts() for the
    explicit excluded-id report."""
    tactics_by_technique = _load_mitre_tactics(mitre_json_path)
    coverage: dict = {}
    for r in parse_ruleset(ruleset_dir):
        for tid in r.mitre_ids:
            if not _VALID_TECHNIQUE_ID.match(tid):
                continue
            entry = coverage.setdefault(tid, {"tactics": tactics_by_technique.get(tid, []), "rule_ids": []})
            if r.rule_id not in entry["rule_ids"]:
                entry["rule_ids"].append(r.rule_id)
    return coverage


def ruleset_counts(ruleset_dir: str) -> dict:
    """The exact counts Phase 5B Step 1 requires printed: total rules,
    rules carrying at least one MITRE id, distinct valid technique ids,
    distinct rule groups - plus any non-static/templated "technique id"
    found and excluded from the distinct-technique count, reported
    explicitly rather than silently dropped."""
    rules = parse_ruleset(ruleset_dir)
    with_mitre = [r for r in rules if r.mitre_ids]
    all_ids = {tid for r in with_mitre for tid in r.mitre_ids}
    valid_ids = {tid for tid in all_ids if _VALID_TECHNIQUE_ID.match(tid)}
    excluded_ids = sorted(all_ids - valid_ids)
    return {
        "total_rules": len(rules),
        "rules_with_mitre_ids": len(with_mitre),
        "distinct_techniques": len(valid_ids),
        "distinct_rule_groups": len(all_rule_groups(ruleset_dir)),
        "excluded_non_technique_ids": excluded_ids,
    }
