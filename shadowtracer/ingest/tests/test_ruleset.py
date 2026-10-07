"""Phase 5B Step 1: verify against the real, bundled 4.14.8 ruleset
(ruleset/rules/*.xml) and MITRE ATT&CK bundle (ruleset/mitre/enterprise-attack.json)
before any sequence/coverage-map code trusts a rule group or technique id
that doesn't actually exist. No mocks - these are the real files this
ShadowTracer checkout ships."""

import os

from shadowtracer_ingest import ruleset

RULESET_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "ruleset", "rules")
MITRE_JSON = os.path.join(os.path.dirname(__file__), "..", "..", "..", "ruleset", "mitre", "enterprise-attack.json")


def test_real_ruleset_directory_exists_and_has_rule_files():
    assert os.path.isdir(RULESET_DIR), f"expected the real ruleset at {RULESET_DIR}"
    xml_files = [f for f in os.listdir(RULESET_DIR) if f.endswith(".xml")]
    assert len(xml_files) > 100, "expected the full real 4.14.8 ruleset, not a handful of files"


def test_every_rule_file_parses(capsys):
    """Every real rule XML file must parse without error - a failure here
    means the parser (not the ruleset) needs fixing. Found and fixed two
    real parsing bugs building this: a blind backslash-angle-bracket
    substitution for one file's literal regex corrupted an unrelated
    rule's <field> tag elsewhere, and an XML-invalid control-character
    placeholder. Both fixed in ruleset.py; this guards against a
    regression."""
    failures = []
    for name in sorted(os.listdir(RULESET_DIR)):
        if not name.endswith(".xml"):
            continue
        try:
            ruleset._parse_one_file(os.path.join(RULESET_DIR, name))
        except Exception as exc:  # noqa: BLE001 - report every failure, not just the first
            failures.append(f"{name}: {exc}")
    assert not failures, "\n".join(failures)


def test_rule_5710_groups_match_the_real_captured_alert():
    """Regression anchor: fixtures/real_alerts_4.14.8.jsonl's rule 5710
    alert has rule.groups == ["syslog", "sshd", "authentication_failed",
    "invalid_login"] - this is the ground truth the group-resolution
    logic (wrapper <group name> inheritance + own <group> tag, compliance
    prefixes stripped) must reproduce exactly."""
    rules = ruleset.parse_ruleset(RULESET_DIR)
    matches = [r for r in rules if r.rule_id == "5710"]
    assert len(matches) == 1
    assert matches[0].groups == ["syslog", "sshd", "authentication_failed", "invalid_login"]


def test_ruleset_counts_printed(capsys):
    """Phase 5B Step 1's required output: print the counts. Also asserts
    they're sane, not just present, so a parser regression that silently
    returns zero/empty is caught here rather than downstream."""
    counts = ruleset.ruleset_counts(RULESET_DIR)
    print(f"total rules: {counts['total_rules']}")
    print(f"rules with MITRE ids: {counts['rules_with_mitre_ids']}")
    print(f"distinct techniques: {counts['distinct_techniques']}")
    print(f"distinct rule groups: {counts['distinct_rule_groups']}")
    print(f"excluded non-technique ids: {counts['excluded_non_technique_ids']}")

    assert counts["total_rules"] > 3000
    assert counts["rules_with_mitre_ids"] > 500
    assert counts["distinct_techniques"] > 100
    assert counts["distinct_rule_groups"] > 200
    # The one known templated placeholder (0997-maltiverse_rules.xml's
    # $(threat.software.id)) - if this list ever grows, a new one needs
    # the same manual inspection, not a silent widening of the filter.
    assert counts["excluded_non_technique_ids"] == ["$(threat.software.id)"]


def test_no_compliance_prefixed_token_ever_appears_in_resolved_groups():
    """The compliance-prefix filter (pci_dss_/cis_/gdpr_/gpg13_/hipaa_/
    nist_800_53_/tsc_ - confirmed from src/analysisd/format/json_extended.c)
    must actually be filtering something real, not just compiling: if the
    real ruleset ever stops containing compliance-tagged rules, this test
    doesn't fail, but if ANY resolved group ever starts with one of these
    prefixes, that's the filter silently failing to apply."""
    rules = ruleset.parse_ruleset(RULESET_DIR)
    prefixes = ("pci_dss_", "cis_", "gdpr_", "gpg13_", "hipaa_", "nist_800_53_", "tsc_")
    offending = [
        (r.rule_id, g) for r in rules for g in r.groups if g.startswith(prefixes)
    ]
    assert not offending, offending


def test_attack_coverage_map_resolves_tactics_for_a_known_technique():
    coverage = ruleset.attack_coverage_map(RULESET_DIR, MITRE_JSON)
    assert "T1110" in coverage
    assert "credential-access" in coverage["T1110"]["tactics"]
    assert len(coverage["T1110"]["rule_ids"]) > 0
    # the excluded templated placeholder must never appear as a coverage key
    assert "$(threat.software.id)" not in coverage
