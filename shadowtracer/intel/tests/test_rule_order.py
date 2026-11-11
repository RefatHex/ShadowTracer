"""The TI rule file must load after its parents and never use a banned lookup
(THREAT_INTEL.md §1.4 point 2a, §0.1)."""
import glob
import os
import re

from shadowtracer_intel import rule_order, ti_rules

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
LAB_EXCLUDES = {"0215-policy_rules.xml"}   # deploy/lab ossec.conf <rule_exclude>


def repo_ruleset_ids():
    ids = {}
    for f in glob.glob(os.path.join(REPO, "ruleset", "rules", "*.xml")):
        if os.path.basename(f) not in LAB_EXCLUDES:
            ids["ruleset/rules/" + os.path.basename(f)] = rule_order.rule_ids(open(f, encoding="utf-8", errors="replace").read())
    return ids


def ti(xml):
    return f'<group name="t,">{xml}</group>'


def test_generated_rules_load_after_every_parent_in_the_real_ruleset():
    assert rule_order.check(repo_ruleset_ids(), {ti_rules.RULES_FILE: ti_rules.rules_xml()}) == []


def test_load_order_is_basename_strcmp_across_directories():
    files = ["etc/rules/local_rules.xml", "ruleset/rules/0095-sshd_rules.xml",
             "etc/rules/1000-shadowtracer_ti_rules.xml", "etc/x/0001-early.xml"]
    assert sorted(files, key=rule_order.load_key) == [
        "etc/x/0001-early.xml", "ruleset/rules/0095-sshd_rules.xml",
        "etc/rules/1000-shadowtracer_ti_rules.xml", "etc/rules/local_rules.xml"]


def test_ti_file_that_sorts_before_its_parent_is_rejected():
    # The 6.0 spike's mistake: 0001-*.xml loaded before 0095-sshd_rules.xml (§9.2).
    problems = rule_order.check(repo_ruleset_ids(), {"etc/rules/0001-early.xml": ti_rules.rules_xml()})
    assert problems and all("loads after it" in p for p in problems)
    assert any("parent 5700" in p and "0095-sshd_rules.xml" in p for p in problems)


def test_parent_defined_later_in_the_same_file_is_rejected():
    xml = ti('<rule id="110900" level="5"><if_sid>110901</if_sid><description>x</description></rule>'
             '<rule id="110901" level="5"><if_sid>5700</if_sid><description>y</description></rule>')
    problems = rule_order.check(repo_ruleset_ids(), {ti_rules.RULES_FILE: xml})
    assert len(problems) == 1 and "parent 110901" in problems[0]


def test_missing_parent_is_rejected():
    xml = ti('<rule id="110900" level="5"><if_sid>99999999</if_sid><description>x</description></rule>')
    assert "not defined anywhere" in rule_order.check(repo_ruleset_ids(), {ti_rules.RULES_FILE: xml})[0]


def test_address_match_key_value_is_never_allowed():
    xml = ti('<rule id="110900" level="5"><if_sid>5700</if_sid>'
             '<list field="srcip" lookup="address_match_key_value" check_value="x">etc/lists/a</list>'
             '<description>x</description></rule>')
    problems = rule_order.check(repo_ruleset_ids(), {ti_rules.RULES_FILE: xml})
    assert len(problems) == 1 and "address_match_key_value" in problems[0]


def test_generated_rules_shape():
    rules = rule_order.parse_ti_rules(ti_rules.rules_xml())
    assert rules and all(110000 <= r["id"] <= 110999 for r in rules)
    assert all(lookup not in rule_order.BANNED_LOOKUPS for r in rules for _, lookup, _ in r["lists"])
    assert "address_match_key_value" not in ti_rules.rules_xml()
    # every CHILD rule (if_sid) runs after its native siblings (§1.4); the YARA-match rule is a
    # decoded_as-json entry rule, not a child, so it legitimately has neither if_sid nor accuracy.
    xml = ti_rules.rules_xml()
    assert len(re.findall(r'accuracy="0"', xml)) == len(re.findall(r"<if_sid>", xml))
    # every list a rule names is in the bundle
    named = {name for r in rules for _, _, name in r["lists"]}
    assert named <= set(ti_rules.list_paths())


def test_commented_out_rules_do_not_count_as_defined():
    assert rule_order.rule_ids('<!-- <rule id="1"> --><rule id="2" level="0">') == [2]


def test_placeholder_lists_compile_to_one_never_matching_key():
    b = ti_rules.bundle()
    for path in ti_rules.list_paths():
        assert b[path] == f"{ti_rules.EMPTY_LIST_KEY}:\n".encode()
