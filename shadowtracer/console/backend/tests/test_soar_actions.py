"""Phase 9 (a): containment dispatch contract — apply_block/reverse_block call the ShadowTracer AR
script with the add/delete arg that lets SOAR own timed expiry and undo through the manager API."""

from app.soar import actions


def test_apply_and_reverse_use_add_delete_args(monkeypatch):
    calls = []
    monkeypatch.setattr(actions.wazuh_api, "run_command",
                        lambda base, agent, script, args, ip: calls.append((script, args, ip, agent, base)))
    actions.apply_block("https://mgr:55000", "001", "8.8.8.8")
    actions.reverse_block("https://mgr:55000", "001", "8.8.8.8")
    assert calls == [
        ("shadowtracer-fw-drop", ["add"], "8.8.8.8", "001", "https://mgr:55000"),
        ("shadowtracer-fw-drop", ["delete"], "8.8.8.8", "001", "https://mgr:55000"),
    ]


def test_pick_script_defaults_to_fw_drop():
    assert actions.pick_script("ubuntu") == "shadowtracer-fw-drop"
    assert actions.pick_script(None) == "shadowtracer-fw-drop"
