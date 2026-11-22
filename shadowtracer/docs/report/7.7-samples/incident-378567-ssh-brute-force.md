# Investigation sample — incident 378567 (ssh-brute-force)

- model: `gemma4:e4b` · prompt_version: `7.7-v1`
- latency: 14213 ms · tokens: 4074 · num_ctx: 8192 · max_tokens: 2000 · done_reason: stop
- claims (sentences): 5 · verified: 5 · unverified: 0
- tool calls requested: none

## Summary (LLM, cited)

**SUMMARY:** Incident 378567 is a high-priority incident [E1] involving authentication failures [E1] from external source IP 45.33.32.157 [E2].

**TIMELINE:** The incident was first seen on 2026-11-05 21:55:34.577000+00:00 [E1] and last seen on 2026-11-05 22:01:34.605000+00:00 [E1].

**TECHNIQUES:** The activity aligns with T1110.001 Password Guessing [E6] and T1110 Brute Force [E8] due to multiple alerts for "sshd: Attempt to login using a non-exist" [E2].

**NEXT_STEPS:** Review the threat intelligence hits for ipv4 45.33.32.157 [E4] and investigate the relationship graph [E5].

**CONFIDENCE:** Medium, because the evidence only shows failed login attempts [E2].

## Per-sentence verification

- [OK ] cites=['E1', 'E1', 'E2'] — Incident 378567 is a high-priority incident [E1] involving authentication failures [E1] from external source IP 45.33.32.157 [E2].
- [OK ] cites=['E1', 'E1'] — The incident was first seen on 2026-11-05 21:55:34.577000+00:00 [E1] and last seen on 2026-11-05 22:01:34.605000+00:00 [E1].
- [OK ] cites=['E6', 'E8', 'E2'] — The activity aligns with T1110.001 Password Guessing [E6] and T1110 Brute Force [E8] due to multiple alerts for "sshd: Attempt to login using a non-exist" [E2].
- [OK ] cites=['E4', 'E5'] — Review the threat intelligence hits for ipv4 45.33.32.157 [E4] and investigate the relationship graph [E5].
- [OK ] cites=['E2'] — Medium, because the evidence only shows failed login attempts [E2].

## Evidence pack (gathered in code; what the LLM was given)

### [E1] Incident overview
```
incident 378567, agent 002, state closed, triage new, priority 10, max rule level 10, alert_count 70, correlation basis: source_ip, rule groups: syslog, sshd, authentication_failed, invalid_login, authentication_failures, techniques: T1110.001, T1021.004, T1110, first_seen 2026-11-05 21:55:34.577000+00:00, last_seen 2026-11-05 22:01:34.605000+00:00, CVEs: none (KEV: none).
```

### [E2] Alerts summary
```
Summary of the most recent 70 of 70 alerts:
top rules: rule 5710 "sshd: Attempt to login using a non-exist" x69; rule 5712 "sshd: brute force trying to get access t" x1
rule levels: level 10 x1, level 5 x69
top external source IPs: 45.33.32.157 x70
```

### [E3] Model assessment
```
not scored by the ML models.
```

### [E4] Threat-intel hits
```
ipv4 45.33.32.157 (sources otx, conf 55, matcher); ipv4 45.33.32.157 (sources otx, conf 55, matcher); ipv4 45.33.32.157 (sources otx, conf 55, matcher); ipv4 45.33.32.157 (sources otx, conf 55, matcher); ipv4 45.33.32.157 (sources otx, conf 55, matcher); ipv4 45.33.32.157 (sources otx, conf 55, matcher); ipv4 45.33.32.157 (sources otx, conf 55, matcher); ipv4 45.33.32.157 (sources otx, conf 55, matcher)
```

### [E5] Relationship graph
```
nodes 66, edges 125, alerts considered 70; node kinds: 
```

### [E6] ATT&CK T1110.001
```
T1110.001 Password Guessing (tactics: credential-access)
```

### [E7] ATT&CK T1021.004
```
T1021.004 SSH (tactics: lateral-movement)
```

### [E8] ATT&CK T1110
```
T1110 Brute Force (tactics: credential-access)
```
