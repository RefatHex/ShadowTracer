# Investigation sample — incident 378565 (campaign-member)

- model: `gemma4:e4b` · prompt_version: `7.7-v1`
- latency: 12567 ms · tokens: 3051 · num_ctx: 8192 · max_tokens: 2000 · done_reason: stop
- claims (sentences): 5 · verified: 4 · unverified: 1
- tool calls requested: none

## Summary (LLM, cited)

**SUMMARY:** Incident 378565 is a closed incident involving two alerts related to SSHD failures [E1, E2].

**TIMELINE:** The incident was first seen and last seen on 2026-10-04 12:00:00+00:00 [E1].

**TECHNIQUES:** The incident suggests Brute Force (T1110) due to the repeated "sshd failure" alerts [E2].

**NEXT_STEPS:** Review the source IP 9.9.9.9 for further context regarding the SSHD failures [E2].

**CONFIDENCE:** Medium, because the incident is closed but involves repeated SSHD failures [E1, E2].

## Per-sentence verification

- [OK ] cites=['E1', 'E2'] — Incident 378565 is a closed incident involving two alerts related to SSHD failures [E1, E2].
- [OK ] cites=['E1'] — The incident was first seen and last seen on 2026-10-04 12:00:00+00:00 [E1].
- [UNVERIFIED] cites=['E2'] — The incident suggests Brute Force (T1110) due to the repeated "sshd failure" alerts [E2].  (missing from cited evidence: ['T1110'])
- [OK ] cites=['E2'] — Review the source IP 9.9.9.9 for further context regarding the SSHD failures [E2].
- [OK ] cites=['E1', 'E2'] — Medium, because the incident is closed but involves repeated SSHD failures [E1, E2].

## Evidence pack (gathered in code; what the LLM was given)

### [E1] Incident overview
```
incident 378565, agent hostile-agent-hostile1793913489, state closed, triage new, priority 5, max rule level 5, alert_count 2, correlation basis: source_ip, rule groups: sshd, techniques: none, first_seen 2026-10-04 12:00:00+00:00, last_seen 2026-10-04 12:00:00+00:00, CVEs: none (KEV: none).
```

### [E2] Alerts summary
```
Summary of the most recent 2 of 2 alerts:
top rules: rule 5710 "sshd failure" x2
rule levels: level 5 x2
top external source IPs: 9.9.9.9 x2
```

### [E3] Model assessment
```
not scored by the ML models.
```

### [E4] Relationship graph
```
nodes 3, edges 2, alerts considered 2; node kinds: 
```
