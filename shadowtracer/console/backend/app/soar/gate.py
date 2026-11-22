"""Confidence gate (Phase 9 C): auto containment needs >= 2 INDEPENDENT non-model signals
on the incident. A model score (ml_score / ml_anomaly_score) may ADD confidence to the record
but is never counted toward the threshold and can never be the sole trigger.

An incident row is passed in as a plain mapping (the worker's SELECT). Returns (passed, signals)
where signals is the list shown in the action record; each has counts=True/False.
"""

TI_MIN_CONFIDENCE = 50          # ti-matcher confidence that counts as a confirmed TI hit
MIN_SIGNALS = 2


def evaluate(incident: dict) -> tuple[bool, list[dict]]:
    signals: list[dict] = []

    rule_ids = incident.get("rule_ids") or []
    if rule_ids:
        signals.append({"type": "rule_match", "detail": f"{len(rule_ids)} rule(s): {', '.join(rule_ids[:5])}",
                        "counts": True})

    ti = incident.get("ti_confidence")
    if ti is not None and ti >= TI_MIN_CONFIDENCE:
        signals.append({"type": "ti_hit", "detail": f"threat-intel confidence {ti} (source-backed)",
                        "counts": True})

    prior = incident.get("prior_occurrences")
    if incident.get("fingerprint_key") and prior and prior > 0:
        signals.append({"type": "known_repeat",
                        "detail": f"fingerprint {incident['fingerprint_key'][:12]} seen {prior}x before",
                        "counts": True})

    kev = incident.get("kev_cve_ids") or []
    if kev:
        signals.append({"type": "kev_cve", "detail": f"actively-exploited CVE: {', '.join(kev[:3])}",
                        "counts": True})

    # Model scores are advisory only: recorded, never counted (counts=False).
    for key, label in (("ml_score", "ml risk"), ("ml_anomaly_score", "ml anomaly")):
        v = incident.get(key)
        if v is not None and v > 0:
            signals.append({"type": key, "detail": f"{label} {round(float(v), 3)} (advisory, not counted)",
                            "counts": False})

    passed = sum(1 for s in signals if s["counts"]) >= MIN_SIGNALS
    return passed, signals


if __name__ == "__main__":  # self-check
    # one signal -> no auto; two independent -> auto; model alone -> no auto
    assert evaluate({"rule_ids": ["5710"]})[0] is False
    assert evaluate({"rule_ids": ["5710"], "ti_confidence": 80})[0] is True
    assert evaluate({"rule_ids": ["5710"], "fingerprint_key": "a" * 64, "prior_occurrences": 3})[0] is True
    assert evaluate({"ml_score": 0.99, "ml_anomaly_score": 0.9})[0] is False      # model-only never passes
    assert evaluate({"rule_ids": ["5710"], "ml_score": 0.99})[0] is False          # rule + model = 1 counted
    print("gate self-check ok")
