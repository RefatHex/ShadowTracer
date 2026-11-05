"""Checks a ShadowTracer TI rule file against the order Wazuh loads rule files in.

analysisd loads every file from every <rule_dir>/<rule_include> in one list sorted by
BASENAME with strcmp (src/config/rules-config.c:26-47, qsort at :382), not by directory.
A rule whose if_sid parent is defined in a file that sorts after it loses that parent:
the reload drops the rule and still answers success, with the drop only in `warnings`
(THREAT_INTEL.md §1.4 point 2a, §9.2). Inside one file rules load top to bottom.

Also enforced here (THREAT_INTEL.md §0.1): no ShadowTracer rule may use
lookup="address_match_key_value" - its result is inverted in 4.14.8
(src/analysisd/lists_list.c:308-312, confirmed with wazuh-logtest in §9.2).
"""
import os
import re
import xml.etree.ElementTree as ET

BANNED_LOOKUPS = {"address_match_key_value"}
PARENT_TAGS = ("if_sid", "if_matched_sid")

_COMMENT = re.compile(r"<!--.*?-->", re.S)
_RULE_ID = re.compile(r"<rule\s[^>]*\bid\s*=\s*\"(\d+)\"")


def load_key(path: str) -> bytes:
    """Wazuh's sort key: the basename compared with strcmp (byte order)."""
    return os.path.basename(path).encode()


def rule_ids(xml_text: str) -> list:
    """Rule ids defined in a Wazuh rule file, in file order. Regex, not an XML parser:
    Wazuh's own parser is lenient and at least one shipped file is not well-formed XML
    (0910-ms-exchange-proxylogon_rules.xml). Commented-out rules don't count."""
    return [int(i) for i in _RULE_ID.findall(_COMMENT.sub("", xml_text))]


def parse_ti_rules(xml_text: str) -> list:
    """Strict parse of a ShadowTracer-generated rule file (ours is well-formed)."""
    root = ET.fromstring("<root>" + xml_text + "</root>")
    rules = []
    for rule in root.iter("rule"):
        parents = []
        for tag in PARENT_TAGS:
            for el in rule.findall(tag):
                parents += [int(p) for p in re.split(r"[,\s]+", el.text or "") if p]
        lists = [(el.get("field"), el.get("lookup", "match_key"), (el.text or "").strip())
                 for el in rule.findall("list")]
        rules.append({"id": int(rule.get("id")), "parents": parents, "lists": lists})
    return rules


def check(ruleset_ids: dict, ti_files: dict) -> list:
    """ruleset_ids: {path: [rule ids in file order]} for every OTHER rule file the
    manager loads (rule_exclude already applied; build it with rule_ids()).
    ti_files: {path: xml text} for the ShadowTracer TI files.
    Returns human-readable violations; empty means safe to publish."""
    order = sorted(list(ruleset_ids) + list(ti_files), key=load_key)
    pos = {p: i for i, p in enumerate(order)}
    ids_by_file = dict(ruleset_ids)
    ids_by_file.update({p: rule_ids(t) for p, t in ti_files.items()})
    defined_in = {}  # rule id -> (file position, index within file)
    for path, ids in ids_by_file.items():
        for k, rid in enumerate(ids):
            defined_in.setdefault(rid, (pos[path], k))

    problems = []
    for path, text in ti_files.items():
        for k, rule in enumerate(parse_ti_rules(text)):
            here = (pos[path], k)
            for parent in rule["parents"]:
                where = defined_in.get(parent)
                if where is None:
                    problems.append(f"{os.path.basename(path)}: rule {rule['id']} parent {parent} is not defined anywhere")
                elif where >= here:
                    problems.append(
                        f"{os.path.basename(path)}: rule {rule['id']} parent {parent} is defined in "
                        f"{os.path.basename(order[where[0]])}, which loads after it")
            for field, lookup, name in rule["lists"]:
                if lookup in BANNED_LOOKUPS:
                    problems.append(f"{os.path.basename(path)}: rule {rule['id']} uses lookup=\"{lookup}\" "
                                    f"on {name} (inverted in 4.14.8, never allowed)")
    return problems
