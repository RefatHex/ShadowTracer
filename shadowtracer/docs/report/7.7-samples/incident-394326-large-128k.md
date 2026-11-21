# Investigation sample — incident 394326 (large-128k)

- model: `gemma4:e4b` · prompt_version: `7.7-v1`
- latency: 10550 ms · tokens: 3269 · num_ctx: 8192
- claims (sentences): 5 · verified: 5 · unverified: 0
- tool calls requested: none

## Summary (LLM, cited)

**SUMMARY:** Incident 394326 is a high-priority alert [E1] related to numerous failed authentication attempts [E2].

**TIMELINE:** The incident first appeared on 2026-11-06 09:04:29.603000+00:00 [E1] and was last seen on 2026-11-06 09:19:23.164000+00:00 [E1].

**TECHNIQUES:** The incident involves T1110.001 Password Guessing and T1021.004 SSH [E1, E6, E7].

**NEXT_STEPS:** Review the 128532 alerts [E1] and the top rule 5710 "sshd: Attempt to login using a non-exist" [E2].

**CONFIDENCE:** Medium, because the incident is based on failed login attempts [E2].

## Per-sentence verification

- [OK ] cites=['E1', 'E2'] — Incident 394326 is a high-priority alert [E1] related to numerous failed authentication attempts [E2].
- [OK ] cites=['E1', 'E1'] — The incident first appeared on 2026-11-06 09:04:29.603000+00:00 [E1] and was last seen on 2026-11-06 09:19:23.164000+00:00 [E1].
- [OK ] cites=['E1', 'E6', 'E7'] — The incident involves T1110.001 Password Guessing and T1021.004 SSH [E1, E6, E7].
- [OK ] cites=['E1', 'E2'] — Review the 128532 alerts [E1] and the top rule 5710 "sshd: Attempt to login using a non-exist" [E2].
- [OK ] cites=['E2'] — Medium, because the incident is based on failed login attempts [E2].

## Evidence pack (gathered in code; what the LLM was given)

### [E1] Incident overview
```
incident 394326, agent 000, state closed, triage new, priority 5, max rule level 5, alert_count 128532, correlation basis: rule_group, rule groups: syslog, sshd, authentication_failed, invalid_login, techniques: T1110.001, T1021.004, first_seen 2026-11-06 09:04:29.603000+00:00, last_seen 2026-11-06 09:19:23.164000+00:00, CVEs: none (KEV: none).
```

### [E2] Alerts summary
```
Summary of the most recent 200 of 128532 alerts:
top rules: rule 5710 "sshd: Attempt to login using a non-exist" x200
rule levels: level 5 x200
top external source IPs: none
```

### [E3] Model assessment
```
historical classifier incident-classifier:4: attack (P=0.73, experimental=True).
```

### [E4] Similar past incidents
```
incident 463505 (score 1.00, basis rule_group, state closed, triage new); incident 463808 (score 1.00, basis rule_group, state closed, triage new); incident 464288 (score 1.00, basis rule_group, state closed, triage new); incident 464695 (score 1.00, basis rule_group, state closed, triage new); incident 483807 (score 1.00, basis rule_group, state closed, triage new)
```

### [E5] Relationship graph
```
nodes 2, edges 1, alerts considered 5000; node kinds: 
```

### [E6] ATT&CK T1110.001
```
T1110.001 Password Guessing (tactics: credential-access)
```

### [E7] ATT&CK T1021.004
```
T1021.004 SSH (tactics: lateral-movement)
```
