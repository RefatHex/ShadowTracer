# Phase 6.0 — Threat intelligence: Wazuh alignment audit and design

Status: **design; 6.0 decisions recorded in §0.1** (no feature code in 6.0). Date: 2026-11-05.

Revision 2 (6.0 addendum, same day): added §1.10 observable coverage from real lab
data, §2 source catalogue with abuse.ch and YARA-X, §4.6–§4.16 (normalisation, entry
validation, allowlists and warninglists, poisoning, confidence and aging, multi-source
dedup, feed failure, TLP, analyst context, feed metrics, list version per manager),
a STIX 2.1-compatible store schema in §4.1, updated §7 licences and §8 VERIFY.
Scope: `FEATURE_PLAN.md` §4 / 6.0. Source cited is this repository at the 4.14.8 fork
point plus ShadowTracer changes (`UPSTREAM.md`); line numbers are from `main` at
`bc2c901516`. Spike measurements are in §9 with commands and output.

## 0. Decisions in one page

1. **No network call per event, anywhere.** OTX and MISP are pulled by a periodic
   `ti-sync` job into a Postgres IOC store. VirusTotal is called only for new FIM
   hashes, through a cached and budgeted integratord script, and on demand from the
   console. Wazuh's documented MISP approach (one MISP API call per alert from
   integratord) is not used (§1.9).
2. **Two matchers, each covering what the other cannot** (§3):
   - **Wazuh-native CDB lists + rules** for events that produce **no** alert on their
     own (they never reach Kafka, so only analysisd can see them) and for FIM hashes.
     TI rules are children of a grouping parent with `accuracy="0"`, which Wazuh
     evaluates after every native sibling, so they fire only when no native rule did.
   - **`ti-matcher` side consumer** (own consumer group, O(1) in-process lookups) for
     events that already became alerts. It annotates, never replaces. A CDB TI child
     rule on an alerting parent would *replace* that alert, and hide it from the
     parent's frequency rules (source evidence in §1.4), so ShadowTracer does not use
     that pattern for alerting rules.
3. **One fixed set of list files per tenant manager cluster** (global ∪ that tenant's
   private IOCs), declared once in `ossec.conf`; only their contents change. Files are
   written on the tenant's master with write-temp-then-rename, synced to workers by the
   Wazuh cluster, and loaded by the 4.13+ ruleset hot reload — orchestrated so a worker
   never reloads before its copy matches the master (§4.4).
4. **Hot reload is not loss-free in 4.14.8.** `w_hotreload_drain_queues()` frees
   queued events and not-yet-written alerts instead of processing them
   (`src/analysisd/analysisd.c:2549-2575`). §9.4 measures it. Fixing this is a
   correctness item for 6.1 (inherited-file change, §6), not a backlog item, because
   6.1 makes reloads routine. Measured: 29 of 240,000 events lost over 5 reloads at
   4,000/s, none without reloads (§9.4).
5. **The lab breaks the tenancy model for anything cluster-synced:** the test tenant's
   manager `worker-test` is a worker in the main tenant's cluster (§1.7). Before 6.1
   writes any tenant-private list, `worker-test` must become its own cluster. This is a
   cross-tenant correctness prerequisite, not a deferral.
6. **Licences:** OTX's EULA says free for **non-commercial** use and forbids service-
   bureau use and redistribution; production use needs a LevelBlue agreement (marked
   UNCLEAR). The VirusTotal public API must not be used in commercial products; each
   tenant needs its own premium key. MISP feeds: per-feed terms, mostly unstated (§7).
7. **List size is not a throughput problem.** A 100,000-entry `address_match_key`
   list leaves analysisd's ceiling at the baseline's ~4,000/s and costs no measurable
   CPU at 4–20k/s lookups per second (§9.3). Reload of the whole ruleset takes
   0.36–0.98 s (§9.4).

### 0.1 Owner decisions on 6.0 (2026-11-05)

- Split `worker-test` into its own cluster: **approved** (6.1a).
- analysisd hot-reload fix as an inherited-file change: **approved** (6.1a).
- OTX and VirusTotal: **customer-supplied keys** in the product, under the customer's own
  agreement; ShadowTracer's own keys only for the lab and the report.
- abuse.ch is the default commercial-safe feed family, terms checked in §7: only
  Feodo Tracker, SSL Blacklist and YARAify are CC0; URLhaus, ThreatFox and
  MalwareBazaar need a Spamhaus subscription for commercial use, so they follow the
  customer-key model too.
- `address_match_key_value` is never used; a test fails if any generated or shipped
  ShadowTracer rule uses it (6.1a item 3).
- T10 (many-source invalid-user spray halves analysisd) is an attacker-triggered
  event-loss risk: moved to the security section of `OPTIMIZATION_BACKLOG.md`.
- The reload loss, the fd/mmap leak and the inverted lookup are on the upstream report
  list (backlog U4).

---

## 1. Audit: what Wazuh 4.14.8 provides

### 1.1 CDB list format and compilation

| Property | Behaviour | Source |
|---|---|---|
| Line format | `key:value`, value optional (`key:`); a line with no `:` is skipped silently | `src/analysisd/lists_make.c:107-113` |
| Quoting | a key containing `:` (IPv6, MAC, URL) must be wrapped in `"…"`; values may be quoted too | `lists_make.c:73-99`, `:115-130`; doc "Creating a CDB list" ([cdb-list.html](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html)) |
| Line length | read with `fgets(str, OS_MAXSTR - 1)`, `OS_MAXSTR` = 65,536 | `lists_make.c:61`, `src/headers/defs.h:51` |
| Matching | exact bytes (`cdb_find`), so case-sensitive: hashes and domains must be normalised to one case | `src/analysisd/lists_list.c:146,180` |
| Compile | `<list>.txt` → `<list>.tmp` → `rename()` to `<list>.cdb` (atomic), `chmod 0660` | `lists_make.c:45,52-56,148-156` |
| When compiled | only if the text file's mtime (seconds) is newer than the `.cdb`'s, or forced; at start-up and in every hot reload | `lists_make.c:47-48`; `analysisd.c:692`, `:2681` |
| Size limit | no documented limit. The cdb format uses 32-bit offsets: one `.cdb` file cannot exceed 4 GiB (`posplus` fails with `ENOMEM`). `cdb_make_add`'s return value is ignored, so an overflow would truncate silently | `src/analysisd/cdb/cdb_make.c:36-41`, `:81-86`; `lists_make.c:140` |
| Loading | the `.cdb` is opened and `mmap`ed lazily on the first lookup and kept open | `lists_list.c:121-133`; `cdb/cdb.c:34-46` |
| Declared where | each list needs a `<list>` line in `<ruleset>` of `ossec.conf`; a rule naming an undeclared or missing list is **skipped with a warning**, not fatal | `src/analysisd/lists.c:22-70`; `rules.c:893-905` |

Consequence for list generation: ShadowTracer must validate every IOC value strictly by
type before writing it. A feed value containing a newline, `"` or `:` would otherwise
inject extra list entries (feed content is untrusted input).

### 1.2 Lookup types

Parsed in `src/analysisd/rules.c:149-158` and `:803-822`; constants in
`src/analysisd/lists.h:19-25`; evaluated in `lists_list.c:275-317`.

| `lookup=` | Meaning (from code) |
|---|---|
| `match_key` (default) | field value is a key (`lists_list.c:286-290`) |
| `not_match_key` | field value is not a key (`:291-295`) |
| `match_key_value` + `check_value="regex"` | key found and its value matches the OSMatch pattern (`:135-169`, `:296-300`) |
| `address_match_key` | exact key, then the value is cut one character at a time from the right and every prefix ending in `.` is tried: `1.2.3.4`, `1.2.3.`, `1.2.`, `1.` (`:189-218`). So IPv4 /8, /16, /24 on octet boundaries only; no `/20`; IPv6 exact only |
| `not_address_match_key` | negation of the above (`:303-307`) |
| `address_match_key_value` | **inverted (confirmed):** returns true when `OS_DBSearchKeyAddressValue() == 0`, i.e. when the address is *not* found or the value does not match (`:308-312`). In §9.2 it fired for an IP absent from the list and not for a listed one. ShadowTracer does not use it |

### 1.3 Which decoded fields a rule can check against a list

`<list field="…">` accepts the static fields `srcip`, `srcport`, `dstip`, `dstport`,
`user` (srcuser, else dstuser), `url`, `id`, `hostname`, `program_name`, `status`,
`action`, `protocol`, `system_name`, `data`, `extra_data` (`rules.c:824-856`,
evaluated `:2937-3080`), or **any dynamic field name** (`rules.c:856-861`, looked up
by `FindField()`, case-insensitive, `src/analysisd/decoders/decoder.c:233-241`). If the
field is absent the rule does not match, for every lookup type including the `not_*`
ones (`rules.c:2942-3072`).

FIM events expose `md5`, `sha1`, `sha256` (and `*_before`) as dynamic fields
(`src/analysisd/decoders/syscheck.c:231-244`, keys copied at `:565-567`). The shipped
rule 99901 uses `field="sha256"` (`ruleset/rules/0999-malicious-ioc-rules.xml:12-20`).

Observable coverage with CDB lists:

| Observable | Coverable? | How / limits |
|---|---|---|
| Source IP | yes | `srcip` (most decoders), `win.eventdata.ipAddress`, `src_ip` (Suricata); `address_match_key` for octet-aligned prefixes |
| Destination IP | yes | `dstip`, `dest_ip` (Suricata), `win.eventdata.destinationIp` (Sysmon 3) |
| Domain | partly | only where a decoder extracts a host name: `dns.rrname`, `http.hostname` (Suricata), `win.eventdata.queryName` (Sysmon 22). Exact match only: `address_match_key` cuts from the right, so `a.evil.com` never matches a list key `evil.com` |
| URL | poorly | `url` is whatever the decoder extracted (usually the path only, for web logs); exact match, no normalisation |
| File hash, FIM | yes | `sha256`/`md5`/`sha1` under FIM rules 550/554 |
| File hash, Sysmon | no | `win.eventdata.hashes` is one composite string (`SHA256=…,MD5=…`), so an exact key never matches without a decoder change |

### 1.4 Rule evaluation: how a TI rule can fire, and what it replaces

From `src/analysisd/analysisd.c:2113-2255` and `rules.c:3106-3147`:

1. Root rules are tried in list order (built the same way as child lists, point 2:
   `OS_AddRule` → `_OS_AddRule`, `rules_list.c:272-274`). A root is skipped if its category differs from
   the decoder's type (`analysisd.c:2126-2130`; a rule without `<category>` is
   `SYSLOG`, `rules.c:2101`).
2. In a matching root, children are tried in list order; the **first** matching child
   wins and the search goes depth-first (`rules.c:3120-3133`). The list order is **not**
   load order: at load time a level-0 rule is given level 99 and every level is
   multiplied by 100 unless the rule has `accuracy="0"` (`rules.c:390-404`, attribute
   `rules.c:2246`); a child is inserted before the first sibling with a lower value
   (`rules_list.c:217-269`); `_setlevels` divides back afterwards (`rules.c:2527-2529`).
   So siblings run level-0 rules first, then highest level first, then load order;
   `accuracy="0"` rules run **last**. §9.2 shows a level-10 TI child of 5700 pre-empting
   5710 and 5715 without `accuracy="0"`, and running after them with it.
2a. Rule files from all `<rule_dir>`s are loaded in one global file-name order, not
   directory order: a file named `0001-…` in `etc/…` loaded before
   `ruleset/rules/0095-sshd_rules.xml`, so every `if_sid` in it was dropped. The reload
   still answered `success: True`, listing the dropped rules only under `warnings`
   (§9.2). The distributor must treat any warning as a failure.
3. The first root that returns a rule ends the search: **one alert per event**
   (`analysisd.c:2253`). If the result is level 0, the event produces no alert and the
   search still ends (`:2139-2141`).
4. A `noalert` root (rules 1–7 in `ruleset/rules/0010-rules_config.xml`) whose children
   all fail returns NULL, so the search continues with the next root (`rules.c:3136-3138`).
5. The parent of the firing rule is not in the alert JSON (`lf->prev_rule`,
   `rules.c:3127`, is used only for `ignore` handling; `src/analysisd/format/to_json.c`
   does not write it).
6. Frequency bookkeeping (`if_matched_sid`, `if_matched_group`) records only the rule
   that produced the alert (`analysisd.c:2219-2245`).

Consequences:

- **A TI child of an alerting rule replaces that alert.** This is Wazuh's own pattern
  (`0999-malicious-ioc-rules.xml`, rules 99901-99920, e.g. 99904 under 5716). The
  native rule id is lost, and by point 6 the native rule's frequency rules stop
  counting those events: with a TI child under 5710, a brute force from a listed IP
  would never reach 5712 (`ruleset/rules/0095-sshd_rules.xml:109-117`,
  `frequency="8"`, `if_matched_sid 5710`). The IP most worth correlating is the one
  that disappears from correlation.
- **"Fire on events no other rule matched"** has exactly two shapes:
  - a TI child of a **grouping parent** (for example 5700 "sshd messages grouped")
    **with `accuracy="0"`**, which puts it after every native sibling: it fires only
    when none of them matched. Without `accuracy="0"`, a level-10 TI child sits ahead of
    every native sibling below level 10 and pre-empts them (§9.2: it replaced 5710,
    5715 and 5706);
  - a **root-level** TI rule with `accuracy="0"` fires only when no other root matched
    (without it, a level-10 root sits ahead of every root below level 10). A level-0
    grouping root such as 5700 ends the search (point 3), so a root TI rule never
    sees sshd events.
- Gap: an event whose final match is a **level-0 leaf** (not a grouping parent)
  produces no alert and is reached by neither shape (§9.2: "Connection closed by
  <listed IP>" ended at 5722, level 0). Covering it needs a TI child under
  that leaf; the 6.1 rule generator lists those leaves per decoder family (VERIFY 6.1-8).

### 1.5 Ruleset hot reload (4.13+)

Triggers: analysisd socket command `reload-ruleset` (`src/analysisd/asyscom.c:165-189`);
API `PUT /manager/analysisd/reload` and `PUT /cluster/analysisd/reload`
(`api/api/spec/spec.yaml:13550`, `:11953`). The 4.13 release post says hot reload
covers "decoders, rules, and CDB lists"
([wazuh.com/blog/introducing-wazuh-4-13-0](https://wazuh.com/blog/introducing-wazuh-4-13-0/));
the CDB list docs page still says to restart the manager
([cdb-list.html](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html)).

What `w_hotreload_reload()` does (`analysisd.c:2485-2523`):

1. Builds the whole new ruleset **before** taking any lock: re-reads the `<ruleset>`
   section of `ossec.conf`, parses decoders, compiles lists whose text is newer than
   their `.cdb`, parses rules (`:2630-2722`). Event processing continues meanwhile.
2. Takes the write lock (`:2497`). Input and decoder threads hold the read lock per
   event (`:1230`, `:1798`, …), so they stop; incoming events wait in the queues.
3. `w_hotreload_drain_queues()` (`:2501`, body `:2549-2575`) pops every event in
   `decode_queue_event_output`, `writer_queue_log`, `writer_queue`,
   `writer_queue_log_statistical`, `writer_queue_log_firewall` and **frees** it.
   `writer_queue_log` holds alerts already matched but not yet written to
   `alerts.json`. The comment says these "can refer to the old ruleset".
4. Swaps pointers (`:2577-2628`), unlocks, frees the old ruleset (`:2519`).

Two further findings:
- The rule-matching threads (`w_process_event_thread`, `:1999`) take no lock and keep
  popping `decode_queue_event_output` during the drain, racing with it; the only grace
  period before the old ruleset is freed is `usleep(5000)` (`:2502`). Not measured;
  recorded as an upstream question.
- `os_remove_cdblist()` frees the list names but never calls `cdb_free()` or closes the
  file descriptor (`lists_list.c:319-333`; `cdb_free` is `cdb/cdb.c:19-23`), so each
  reload leaks one fd and one mapping per list. Confirmed in §9.5 (+1 fd and +1
  mapping per looked-up list per reload).

Community reports of 4.14 reloads not taking effect on workers
([groups.google.com/g/wazuh/c/QMTjw-ZXnJw](https://groups.google.com/g/wazuh/c/QMTjw-ZXnJw))
and of analysisd crashing after reloads
([groups.google.com/g/wazuh/c/J1R4pjnQMTs](https://groups.google.com/g/wazuh/c/J1R4pjnQMTs))
are unconfirmed here; the cluster path below explains the first one.

### 1.6 Wazuh API list upload

`PUT /lists/files/{filename}` (`framework/wazuh/cdb_list.py:120-173`) is not usable for
generated IOC lists:
- with `overwrite=true` it **moves the old file away before writing the new one**
  (`:156-160`), so the list is briefly missing; a reload or a cluster integrity check in
  that window drops it (rule skipped; workers told to delete it);
- the validator only accepts quoted keys made of `[\w\-: ]`
  (`framework/wazuh/core/cdb_list.py:230`), so a URL key (`"https://…/…"`) is rejected;
- request bodies are capped at 10 MB (`api/api/configuration.py:42`); 1 M SHA-256
  entries are ~66 MB.

### 1.7 Cluster sync of lists and rules

- `framework/wazuh/core/cluster/cluster.json`: `etc/lists/`, `etc/rules/`,
  `etc/decoders/` are synced recursively from the master, permissions `0o660`;
  `ossec.conf` and `*.tmp`, `*.lock`, `*.swp`, `*~` are excluded. `ruleset/` is not
  synced (it ships with the package).
- Timing (same file, `intervals`): the master recalculates file integrity every 8 s; each
  worker runs an integrity check every 9 s. Files a worker has that the master does not
  are deleted ("Files to delete", `worker.py:727-730`), so a worker cannot hold a
  private list inside a synced directory.
- Workers write each file to a temp name and `rename()` it (`framework/wazuh/core/utils.py:691-711`),
  without preserving the master's mtime (`worker.py:828-831`).
- **Reload on a worker is deferred:** the API on a worker only sets a flag
  (`framework/wazuh/analysis.py:51-60`, `core/cluster/local_server.py:423-439`); the
  worker reloads at the end of its next integrity check, after applying any file
  changes (`worker.py:735-741`) or after "sync not required" (`:400-408`). §9.6 measures
  the delay. The master reloads immediately.
- **Race:** if the flag is set before the master's next integrity recalculation has seen
  the new list, the worker reloads with its old files, clears the flag, and then
  receives the new files with no reload. It keeps matching the old list until the next
  reload. A `.txt` and its `.cdb` can also arrive in different cycles. The distributor
  must confirm each worker's copy before asking it to reload (§4.4).
- **Lab finding:** `worker-test` (the test tenant's dedicated manager) is a worker of
  the main tenant's master:
  ```
  $ docker exec shadowtracer-lab-shadowtracer-master-1 /var/ossec/bin/cluster_control -l
  NAME         TYPE    VERSION  ADDRESS
  master       master  4.14.8   shadowtracer-master
  worker2      worker  4.14.8   172.28.0.12
  worker1      worker  4.14.8   172.28.0.11
  worker-test  worker  4.14.8   172.28.0.14
  ```
  Both nodes' `ossec.conf` have `<name>wazuh</name>`, the same `<key>`, and
  `<node>shadowtracer-master</node>`. Today this already syncs the main tenant's
  `client.keys`, `etc/rules` and `etc/lists` to the test tenant's manager. TENANCY.md
  option (A) assumes one cluster per tenant. Fix before 6.1 (VERIFY 6.1-1).

### 1.8 wazuh-integratord and the VirusTotal integration

integratord (`src/os_integrator/integrator.c`):
- reads `alerts.json` through the JSON file queue (`:44-48`, `:154-158`), off
  analysisd's path, so a slow integration delays only integratord;
- filters each alert by `level`, `group`, `rule_id`, `event_location` (`:183-268`);
- for each match writes the alert to `/tmp/<name>-<time>-<rand>.alert` and
  **fork/execs the script and waits for it** (`:278-460`): one alert at a time, one
  process per alert;
- passes the API key on the command line (`:437-445`), visible in `ps`;
- accepts `slack`, `pagerduty`, `virustotal`, `shuffle`, `maltiverse` and any name
  starting with `custom-` (`:61-135`); the script must exist in the integrations dir.
  Arguments: alert file, api_key, hook_url, `debug`, options file, timeout, retries
  (config keys in `src/config/integrator-config.c:19-30`).
- Results come back as new events: the script writes
  `1:[agent] (name) ip->virustotal:{json}` to analysisd's queue socket
  (`integrations/virustotal.py:309-325`), the JSON decoder decodes them, and rules match
  them, so they become ordinary alerts in `alerts.json` and reach our pipeline.

Built-in VirusTotal (`integrations/virustotal.py`, rules `ruleset/rules/0490-virustotal_rules.xml`):
- Trigger: whatever the `<integration>` block selects; the documented block uses
  `<group>syscheck</group>` ([virus-total-integration.html](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html)).
  The script needs `syscheck.md5_after` (`virustotal.py:196-211`) and looks up the
  **MD5** with the legacy v2 endpoint `GET /vtapi/v2/file/report?apikey=…`
  (`:255-281`). VirusTotal calls v3 the standard and says v2 will be sunset some day
  ([blog.virustotal.com 2023-02](https://blog.virustotal.com/2023/02/upgrading-from-api-v2-to-v3-what-you.html)).
- **No rate limiting, cache or budget** in the script or in integratord. HTTP 204 (rate
  limit) becomes alert 87101 and that hash is never retried (`:288-296`). The public API
  allows 4 requests/min and 500/day
  ([docs.virustotal.com/reference/public-vs-premium-api](https://docs.virustotal.com/reference/public-vs-premium-api));
  one package upgrade changes hundreds of files.
- Output shape (`virustotal.py:193-246`): `data.integration = "virustotal"`,
  `data.virustotal.{found, malicious, source{alert_id, file, md5, sha1}, sha1,
  scan_date, positives, total, permalink}` or `{error, description}`.
- Rules: 87100 base (level 0), 87101 rate limit (204), 87102 credentials (403), 87103
  not in VT, 87104 no positives, **87105 malicious (level 12)**, 87106 timeout (408)
  (`0490-virustotal_rules.xml:12-63`).

### 1.9 Wazuh's documented OTX and MISP approaches

- **OTX:** Wazuh's proof-of-concept guide downloads the AlienVault IP reputation list
  (FireHOL `alienvault_reputation.ipset`), converts it to the CDB list
  `blacklist-alienvault` with `iplist-to-cdblist.py`, adds rule 100100
  (`if_group` web|attack|attacks, `address_match_key` on `srcip`) and restarts the
  manager ([block-malicious-actor-ip-reputation.html](https://documentation.wazuh.com/current/proof-of-concept-guide/block-malicious-actor-ip-reputation.html)).
  No per-event call, but IP reputation only, and no OTX pulses. A Wazuh team member said
  there is no OTX pulse integration
  ([groups.google.com/g/wazuh/c/CW2zcMTsJB0](https://groups.google.com/g/wazuh/c/CW2zcMTsJB0)).
- **MISP:** the MISP project's own guide (2025-10-06) and `MISP/wazuh-integration` run
  `custom-misp_file_hashes.py` from integratord on `syscheck`/rule 554 and query the
  MISP API **once per alert** (the debug log shows one request per alert); results come
  back as rules 100800-100804
  ([misp-project.org/2025/10/06/wazuh-integration.html](https://www.misp-project.org/2025/10/06/wazuh-integration.html),
  [github.com/MISP/wazuh-integration](https://github.com/MISP/wazuh-integration)).
  Community `custom-misp.py` variants do the same for Sysmon events.
- **Why per-event calls break FEATURE_PLAN §2:** they don't block analysisd directly
  (integratord reads `alerts.json` on the side), but integratord is serial fork/exec +
  HTTPS per alert. At tens to hundreds of ms each it handles roughly 3–20 alerts/s
  (**estimate**, not measured), against ~500 alerts/s end to end and ~4,000/s per
  manager. On anything but rare triggers it lags without bound, misses alerts once
  `alerts.json` rotates past it, and turns alert volume into API load on MISP/OTX. §2
  forbids it on the hot path; this design keeps it off every per-alert path.

### 1.10 Observable coverage in the lab today (real data)

Queried from ClickHouse `shadowtracer.events` on 2026-11-05. Main tenant
`eec7135f…`: 18,781 alerts, 2026-10-01 → 2026-11-04. (The test tenant's 4.4 M alerts
are almost all synthetic load-test traffic and are left out.)

```
SELECT decoder_name, location, rule_id, count() n, countIf(src_endpoint_ip!='') with_src,
       uniqExact(src_endpoint_ip) ips
FROM events WHERE tenant_id='eec7135f91067739afe1cd3b3273bb72' GROUP BY 1,2,3 ORDER BY n DESC
 json   osquery            24010 5743     0 | sca  sca  19008 5121 0 | sca sca 19007 4614 0 | sca sca 19009 2156 0
 sshd   /var/log/auth.log   5710  498   498  (5 distinct IPs)
 sshd   /var/log/auth.log   5712    6     6
 syscheck_new_entry syscheck 554    1     0   … (dpkg, adduser, agent start/stop rows omitted)
-- every tenant: dst_endpoint_ip is empty on every row
-- extra_fields keys matching url|domain|host|query|hash|sha|md5|dstip|dest_ip: only
--   data.srcip (sshd), data.osquery.columns.hostname (the agent's own name), syscheck.{md5,sha1,sha256}_after (1 row)
```

Agent log sources (`<localfile>` in each agent's `ossec.conf`): `auth.log` / `secure`,
`dpkg.log`, `audit.log` (auditd, Phase 5C-1), journald (Rocky), command outputs;
FIM `<directories>` on all four agents; osquery and SCA.

| IOC type | Lab source today | Sample (real lab alert) | Can match now? | What would enable it |
|---|---|---|---|---|
| Source IP | sshd via `auth.log`/`secure`, rules 5710/5712 (`data.srcip`) | `Oct  9 18:14:34 agent-ubuntu-1 sshd[120977]: Invalid user smoketest1791569673 from ::1 port 33734` → 5710, `src_endpoint_ip=::1` | **yes** (CDB on 5700 children, `ti-matcher` on 5710/5712) | already there; more sources come with any network log below |
| Destination IP | **none**: no lab decoder emits `dstip` | — | **no** | firewall logs (iptables/nftables `LOG` on agents, `iptables` decoder), Suricata `eve.json` on a lab sensor (`dest_ip`), Sysmon event 3 on the Windows VM (D1) |
| Domain | **none** | — | **no** | DNS query logs: Suricata DNS (`dns.rrname`), Sysmon 22 (`win.eventdata.queryName`, D1), unbound/bind query logs; proxy logs |
| URL | **none** | — | **no** | Squid access log (full URL in `url`), Suricata HTTP (`http.hostname` + `http.url`); web-server logs carry only paths |
| File hash | FIM (syscheck) rules 550/554 | 554 "File added to the system." on agent-ubuntu-1, `syscheck.path=/var/ossec/lab-fim-test/testfile.txt`, `sha256_after=852e5319…95b7` | **yes** (CDB on 550/554, VirusTotal on new hashes) | also Sysmon 1/15 hashes after a decoder split (§1.3) |

**Update 6.1b (2026-11-06):** agent-ubuntu-1 now logs every new outbound connection
(iptables NFLOG → ulogd2 → `/var/log/shadowtracer-netlog.log` with a `kernel: ST-OUT`
prefix that Wazuh's stock `iptables-2` decoder reads; `AGENT_NETLOG=1`, cap `NET_ADMIN`).
Matchable now, with the TI rule that matches:

| IOC type | Source | TI rule parents (`accuracy="0"`) | Proven end to end |
|---|---|---|---|
| source IP | sshd (`auth.log`/`secure`) | 5700, 5722 (`srcip`) | 110000/110001 → ClickHouse → incident |
| destination IP | outbound connection log, agent-ubuntu-1 | 4100 (`dstip`) | 110005 for `45.33.32.156` |
| source IP (inbound) | same log, INPUT side when enabled | 4100 (`srcip`) | rule loads; no inbound rule enabled in the lab |
| file hash | FIM 550/554 | `sha256`, `sha1`, `md5` | 110013 |
| domain, URL | **none yet** | lists are generated (`url-medium` holds the OTX fixture URL), nothing decodes a domain or URL | needs DNS/proxy logs (Suricata, Squid) |

Before 6.1b, only **source IPs** and **FIM hashes** could match. Destination IP, domain and URL
IOCs can be stored, retro-hunted and shown, but they cannot match anything until a
network/DNS/proxy log source is added. The cheapest lab option is iptables `LOG` rules on
the Linux agents (destination IPs). Suricata on one lab sensor would add DNS and HTTP.
6.1 should add one of them so the dst-IP/domain paths are exercised end to end (VERIFY
6.1-13).

---

## 2. Per-source design

| Source | Ingest | Matching | Network calls |
|---|---|---|---|
| **OTX** | `ti-sync` pulls subscribed pulses incrementally (`/api/v1/pulses/subscribed?modified_since=…`, key from a secret), maps indicator types (IPv4, IPv6, domain, hostname, URL, FileHash-MD5/SHA1/SHA256, CIDR) into the IOC store | CDB lists + `ti-matcher` + retro-hunt | periodic only (e.g. every 15 min) |
| **MISP** | feed-only by default: MISP-format feeds (`manifest.json` + event files), attributes with `to_ids=true`; server mode (6.2, separate compose profile) via PyMISP `restSearch(to_ids=True, published=True, timestamp=…)` | same | periodic only |
| **VirusTotal** | not a feed. (a) FIM: integratord runs a new `custom-shadowtracer-virustotal` script (v3, SHA-256, per-tenant key, on-disk cache, token-bucket budget, same output shape so rules 87100-87106 still apply); (b) on demand from the console through the backend with the same cache and budget. Hashes only, never uploads | VT verdicts land in the IOC store (`source=virustotal`) so later sightings hit locally | per **new** FIM hash, capped by budget; per analyst click |

| **abuse.ch Feodo Tracker** | botnet C2 IP blocklist (JSON/CSV download), CC0 | CDB + `ti-matcher` | periodic only |
| **abuse.ch ThreatFox / URLhaus / MalwareBazaar** | REST/export with the customer's Auth-Key (Spamhaus subscription for commercial use); ThreatFox gives IP:port, domains, URLs, hashes with malware family and `confidence_level` | CDB + `ti-matcher` (+ hash context for FIM) | periodic only |

Known-bad hashes from OTX/MISP/abuse.ch are matched locally by CDB on FIM rules before
any VT call is needed.

Keys: OTX, VirusTotal, ThreatFox/URLhaus/MalwareBazaar and MISP servers use **keys the
customer supplies** under their own agreement (§0.1), stored per tenant as secrets;
ShadowTracer's own keys are used only in the lab.

**VirusTotal is per-tenant opt-in** (`ti_tenant_settings.vt_enabled`, default off,
admin-only, audited). With it off, no hash from that tenant is ever sent: integratord
is not configured with the VT script on that tenant's managers, and the console's
"check on VirusTotal" button is disabled. With it on, only SHA-256 hashes are sent,
never files, and never hashes whose IOC or FIM context is TLP:RED or AMBER+STRICT (§4.13).

### 2.1 abuse.ch feeds and YARA-X: include now, later, or drop

| Item | Licence / terms | Proposal | Why |
|---|---|---|---|
| Feodo Tracker (C2 IPs) | CC0, commercial use free (abuse.ch terms §3.4) | **include now** (6.1, default global feed) | the one commercial-safe IP feed; lab sshd source IPs can match |
| SSL Blacklist | CC0 (§3.4) | **later** | needs TLS certificate or JA3 logs, none in the lab |
| YARAify | CC0 (§3.4) | **later** (with YARA-X) | rule/scan service, only useful once files are scanned |
| ThreatFox | commercial use "may require a paid subscription" (§4.1) | **include now** as a customer-key source (6.2), lab/report use under the non-commercial terms | multi-type IOCs with malware family and confidence; best confidence input |
| URLhaus | same as ThreatFox | **later** | no URL or domain log source in the lab yet (§1.10) |
| MalwareBazaar | same as ThreatFox | **later, with 6.3** | hash context for FIM next to VirusTotal; fewer VT calls |
| YARA-X | BSD-3-Clause ([github.com/VirusTotal/yara-x](https://github.com/VirusTotal/yara-x)) | **later** (not in 6.x) | Wazuh FIM gives hashes, not file contents; scanning needs an agent-side or quarantine design of its own, never on the hot path |

## 3. What stays Wazuh-native, what ShadowTracer builds

| Piece | Owner | Why |
|---|---|---|
| IOC lookup inside analysisd (CDB + rules) | Wazuh-native | only analysisd sees events that produce no alert |
| Rule attachment for non-alerting events | ShadowTracer rule file (new) | `accuracy="0"` children run after native siblings (§1.4) |
| FIM hash match (550/554) | Wazuh-native, ShadowTracer lists | replacing "file added" with "known-bad hash" is the intended result |
| List sync master → workers | Wazuh cluster | already syncs `etc/lists` (§1.7) |
| Reload | Wazuh hot reload, orchestrated by ShadowTracer | §4.4 |
| VirusTotal on FIM | integratord + new `custom-` script + inherited 0490 rules | built-in script has no cache/budget and uses v2/MD5 |
| Feed pull, IOC store, list generation, distribution, expiry | ShadowTracer | no Wazuh equivalent |
| Annotating alerts that a native rule produced | ShadowTracer `ti-matcher` | CDB would replace the alert (§1.4) |
| Retro-hunt | ShadowTracer job on ClickHouse | needs stored history |
| Console views, per-tenant source settings | ShadowTracer | |

The inherited demo ruleset `0999-malicious-ioc-rules.xml` (replaces native alerts for
IPs in a 199-entry demo list) is excluded with `<rule_exclude>` in 6.1, without editing
the file; ShadowTracer's lists supersede it.

### 3.1 Is a side consumer still needed? Yes: `ti-matcher`

Needed for cases CDB lists can't cover correctly:
1. **Alerts a native rule already produced.** A CDB TI child would replace the alert and
   hide it from frequency rules (§1.4). `ti-matcher` writes a separate `ti_hits` row and
   the alert stays as it was.
2. **Shapes CDB can't express:** CIDRs that need more than 256 octet-aligned prefixes
   (§4.3), IPv6 prefixes, parent-domain matching (`a.evil.com` vs `evil.com`), URL
   normalisation, composite fields (Sysmon `Hashes`), fields only present in `full_log`.
3. **Exact expiry** between list regenerations.

It is a per-alert side consumer under FEATURE_PLAN §2: own consumer group on the
per-tenant alert topics, one O(1) dict/set lookup per extracted observable (plus a
sorted-range search for CIDRs), no network calls, lag shown in `/health/detail` but not
in `/health/ready`, output idempotent (ReplacingMergeTree keyed on alert identity +
IOC). Its own ceiling must reach ~3,300/s (T9). Tenant scope comes from the topic (set
by the shipper's static `TENANT_ID`), never from alert content.

CDB TI alerts (group `shadowtracer_ti`) also pass through `ti-matcher`; the hit is
recorded once because the `ti_hits` key is the same.

### 3.2 Built in 6.1c (2026-11-06)

`shadowtracer/intel/shadowtracer_intel/matcher.py`, service `ti-matcher`
(`deploy/lab/ti-matcher.Dockerfile`, 128m). Differences from §3.1 and §4.1, by owner
instruction or found while building:

- **Names.** ClickHouse `ti_matches` (not `ti_hits`; ingest CH migration 0002),
  ReplicatedReplacingMergeTree ORDER BY `(tenant_id, cluster_node, alert_id, ioc_id)`,
  version `matched_at`, partitioned by `alert_time` so duplicates always meet. Postgres
  `incident_ti` (ingest migration 7c1e9b2f4a60), UNIQUE `(tenant_key, node, alert_id,
  ioc_id)`. Read ClickHouse with FINAL or uniqExact over the key.
- **CDB TI alerts are skipped** (rule group `shadowtracer_ti`): analysisd already matched
  them, and their CDB alert carries the observable.
- **Kafka identity.** Own SCRAM user `ti-matcher`: Read/Describe on `shadowtracer.t.*`, own
  group `shadowtracer-ti-matcher`, never a producer (`create-kafka-acls.sh`).
- **Same decision as the lists.** `listgen.evaluate()` scores and filters for both the CDB
  lists and the matcher (global + the tenant's private, minus allowlists, TLP rules,
  hard TTL, noisy-OR confidence). The matcher also keeps the low band, every CIDR (one
  dict per prefix length), parent domains (`a.evil.com` matches `evil.com`, never the bare
  TLD) and URLs, and checks each IOC's expiry at lookup time.
- **Observables.** `data.srcip`, `data.dstip`; any field whose name ends in `url` (the URL
  and its host as domain or IP); fields ending in `domain`, `hostname`, `queryname`;
  `syscheck.{sha256,sha1,md5}_after`. Values go through `normalise()` (tenant scope, so
  private addresses can match tenant-private IOCs); an invalid value is skipped, never an
  error.
- **Reload.** `ti_store_version` is bumped by statement triggers on `iocs`,
  `ioc_sightings`, `ti_allowlist` and `ti_sources` (not by list generation's confidence
  write-back). The matcher polls it every `TI_MATCHER_POLL_SECONDS` (60) and reloads every
  tenant set it holds when it moves, and at least hourly because confidence decays. A
  15-minute ti-sync run upserts its feed rows and so bumps the version: one reload per
  sync. An IOC added later matches alerts **processed after the reload**; earlier alerts
  are retro-hunt's job (or a replay of the topic).
- **Incidents.** The matcher writes `incident_ti` and links rows to the incident through
  `incident_alerts` (it may see an alert before the correlator, so unlinked rows are
  retried for a day), then raises `incidents.ti_confidence`. `incidents.priority` is a
  generated column, `GREATEST(max_level, 12 if C >= 75, 8 if C >= 50)` (the CDB bands),
  so the correlator never writes or races it. The incident API returns `ti_confidence`,
  `priority` and `ti_matches` (field, observable, IOC, sources, confidence).
- **Delivery.** Offsets are committed after both writes; both are idempotent on
  (alert, IOC). A failed write is retried in place, never skipped.
- **Health.** `/health/detail.ti_matcher`: consumer lag (same code as the writer's) and
  the store version each instance has loaded per tenant; alerts when a loaded set is
  behind the store for more than 5 minutes. Not in readiness.
- **Memory.** librdkafka's 64 MiB default prefetch OOM-killed the 128m container in a loop
  on a 300,000-message backlog (12 kills, nothing committed, nothing lost); capped at
  `queued.max.messages.kbytes=16384`, peak 77 MiB.

Lab checks (2026-11-06; outputs in the 6.1c commit message):

| check | result |
|---|---|
| SSH brute force from listed IPs | 5710/5712 unchanged; every alert annotated (`otx` 55, `manual:global` 90); incident 378566 `ti_confidence` 90, priority 10 -> 12, 17 matches in the API |
| URL fixture alerts (no lab log source emits URLs yet) | `cdn.evil-c2.example` matched IOC `evil-c2.example` (parent domain), defanged `hxxp://bad[.]example/x` matched URL IOC; benign URL none |
| IOC added mid-stream | added 21:52:36, matcher reloaded 21:53:15, first matched alert 21:53:14 (38 s) |
| replay from 21:50 | ClickHouse FINAL = distinct keys = Postgres rows (43); the 13 new rows were alerts sent before the IOC reload |
| tenant-private IOC (test tenant) | 1/1 matched on the test tenant; 0/3 on the main tenant; not in the main tenant's set |
| matcher stopped 2 min during 300/s | writer and correlator lag 0 throughout, ingestion 9,010 events/30 s flat; matcher lag 37,151, 0 within 77 s of restart; 120/120 listed-IP alerts matched (86 sent while stopped) |
| own ceiling | ~8,500 alerts/s, one instance, ~45% CPU, 77 MiB (backlog T9) |

### 3.3 Built in 6.2 (2026-11-06): MISP feeds and free feeds

**MISP feed-only mode** (`feeds.parse_misp_manifest`, `parse_misp_event`,
`sync.sync_misp_feed`): `manifest.json`, then every event whose timestamp is past the
cursor (first run: the last 365 days, the longest hard TTL), oldest first, **one
transaction per event** with the cursor advanced after each, so memory stays one event
and a failure resumes where it stopped. Imported: `to_ids` attributes of type `ip-src`,
`ip-dst` (and their `|port` forms), `domain`, `hostname`, `url`, `md5`, `sha1`, `sha256`
(and `filename|<hash>`), from the event and its objects; deleted attributes skipped. Kept
per sighting: event uuid (`source_ref`), event link (`reference_url`), event info
(`source_info`, ingest migration a3d5f0c2b8e1), event and attribute tags (`labels`;
MITRE technique ids from galaxy tags go to `mitre`), TLP (attribute tag, else event tag,
else the feed's default), source confidence from `threat_level_id` (high 0.9, medium
0.75, low 0.5, undefined 0.6), and the **attribute's own timestamp** as last seen:
CIRCL republishes old events with fresh event timestamps, and an event timestamp would
keep 2023 indicators "fresh".

**Tenant MISP server connector** (`misp_server.py`, PyMISP 2.5.34.4, BSD-2-Clause): per
tenant URL + API key (`TI_MISP_SERVERS`; the key comes from the env var it names, never
the database), `attributes/restSearch` with `to_ids=1`, the matchable types,
`includeEventTags`, `timestamp >= cursor`, 1,000 per page. Everything it returns is that
tenant's private intel whatever its TLP. **Not tested against a live MISP server**: unit
tests drive the real PyMISP client over mocked HTTP shaped after the MISP REST API; the
lab runs no MISP container (memory).

**Withdrawals** (`to_ids` later false, attribute deleted, event removed from a feed) are
not applied yet; such sightings age out by TTL/decay (backlog D5). Snapshot feeds
(abuse.ch, DROP, CERT Polska, the IP lists) are revoked correctly.

**Store writes are set-based** (6.2): a batched insert into a temp table (`execute_values`), then one
upsert per table, so a 126,000-entry list is a handful of statements and one
`ti_store_version` bump, not ~250,000. List generation streams sightings ordered by IOC
through a server-side cursor and skips IOCs past their hard TTL in SQL (CIRCL brought
235,000 old domains); confidence write-back is one statement. Lab: ti-sync peak 108 MiB
for a full cycle, one tenant's list generation 120 MiB / 18 s, a tenant's matcher set
(~136k IOCs) 142 MiB peak while loading.

**Feeds and licences** (read 2026-11-06; on = enabled by default in the product, only
where commercial use is clearly allowed; off = the customer enables it with
`TI_FEED_<NAME>=1`). Counts are this lab's import on 2026-11-06 after normalisation;
"listed" = in a CDB list now.

| feed | licence / terms (as read) | link | default | IOCs imported |
|---|---|---|---|---|
| abuse.ch Feodo Tracker | CC0 | [feodotracker.abuse.ch](https://feodotracker.abuse.ch/blocklist/) | **on** | 5 ipv4 (all offline for months: expired) |
| Spamhaus DROP v4 / v6 | "The DROP list is free for any use", "at no cost, regardless of size or business type"; downloads at most once a day; keep the © line ([terms](https://www.spamhaus.org/drop/terms/), [page](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)) | `spamhaus.org/drop/drop_v4.json`, `drop_v6.json` | **on** (daily) | 1,762 cidr4 + 90 cidr6 (EDROP merged into DROP 2024-04-10) |
| CERT Polska warning list | "may be used by any user for any purpose, including commercial purposes" ([policy](https://cert.pl/en/warning-list/)) | `hole.cert.pl/domains/v2/domains.txt` | **on** (hourly) | 126,149 domains |
| AlienVault OTX | the customer's own OTX account and key | `otx.alienvault.com` | on when a key is set | 8,241 (first sync: domain 2,398, sha256 2,201, sha1 1,220, md5 1,189, url 826, ipv4 406, ipv6 1) |
| CIRCL OSINT (MISP feed) | **no licence published**; events tagged TLP:CLEAR/WHITE (a sharing marking, not a licence) ([feed](https://www.circl.lu/doc/misp/feed-osint/)) | MISP feed | off (lab: on); D6 asks CIRCL | 312 events, 274,339: domain 261,076, ipv4 12,336, md5 271, sha256 241, ipv6 239, sha1 130, url 46; listed: 289 domains (rest past TTL) |
| Botvrij.eu (MISP feed) | free, but "You cannot resell the data, neither as an individual package or as part of a larger package" ([FAQ](https://www.botvrij.eu/)) | MISP feed | off | 1 event in the last 365 days: 30 (sha256 16, url 8, ipv4 4, domain 2) |
| blocklist.de all | no licence grant; terms page silent on commercial use ([terms](https://www.blocklist.de/en/terms.html)) | `lists.blocklist.de/lists/all.txt` | off | 26,306 (ipv4 26,015, ipv6 291) |
| CINS Army | "use in any way you see fit", no licence ([cinsscore.com](https://cinsscore.com/)) | `cinsscore.com/list/ci-badguys.txt` | off | 15,000 ipv4 |
| Emerging Threats compromised IPs | no terms on the page; "free to download and use via GPL 2.0" per an unofficial forum reply ([thread](https://community.emergingthreats.net/t/licensing-is-the-compromised-ips-list-also-open/676)) | `rules.emergingthreats.net/blockrules/compromised-ips.txt` | off | 511 ipv4 |
| dataplane.org sshpwauth | "All Rights Reserved" ([dataplane.org](https://dataplane.org/)) | `dataplane.org/sshpwauth.txt` | off | 11,222 ipv4 |
| DigitalSide Threat-Intel (MISP feed) | repo LICENSE is MIT with a website-template copyright line: scope unclear; host refused connections 2026-11-06 | MISP feed | not added | — |
| Phishing.Database | MIT (repository) | `phish.co.za` | not added | download returned HTTP 503 on 2026-11-06 |
| abuse.ch URLhaus / ThreatFox / MalwareBazaar | Auth-Key; commercial use via a Spamhaus subscription (§7) | — | off (not added yet) | — |

Not a licence assessment by a lawyer: each "on" rests on the quoted wording.

Lab checks (2026-11-06):

| check | result |
|---|---|
| MISP feed IP -> TI alert | a local MISP-format feed (fresh timestamps, served over HTTP) through `sync_misp_feed`: 2 events, 1 accepted; `Connection closed by 45.33.32.220` -> rule 110001 (level 8) on both tenants. No real CIRCL IP could be used: CIRCL's newest IPv4 was last seen 2026-09-18, past the 30-day IP TTL |
| TLP:RED event | as a global MISP feed event: rejected ("TLP:RED is never global"); as the test tenant's MISP server (PyMISP, mocked REST): accepted as private. 45.33.32.221 is in worker-test's ipv4 lists (1) and not the master's (0); the sshd line alerts 110001 on the test tenant only, nothing on the main tenant |
| CIRCL OSINT import | 312 events, 274,339 IOCs (table above) |
| real OTX | first sync 9,020 received, 8,241 unique (table above); later incremental syncs 598 updates, 0 rejected, no HTTP 429 |

### 3.4 Built in 6.3 (2026-11-06): VirusTotal

**Limits and terms** (docs.virustotal.com/reference/public-vs-premium-api, read
2026-11-06): "The Public API is limited to 500 requests per day and a rate of 4 requests
per minute"; it "must not be used in commercial products or services". So every tenant
brings its own (premium) key; the lab uses ShadowTracer's free key for tests only.
`VT_PER_MINUTE` / `VT_PER_DAY` set a key's limits (default 4 / 500).

**Automatic path (FIM).** integratord (`<integration>` `custom-shadowtracer-virustotal`,
rules 550/554, installed by the manager entrypoint) runs
`shadowtracer/intel/integrations/custom-shadowtracer-virustotal.py` once per new or
changed file. It makes no network call and holds no key: it writes the SHA-256, the
alert identity, path and agent to `var/shadowtracer-vt/` on that manager (atomic rename,
capped at 10,000 files). ti-sync's VirusTotal worker thread (`vt.py`, every 10 s):
1. collects each manager's spool (lab transport: `docker exec`, backlog S10); a tenant
   with VirusTotal **off has its spool deleted unread** - no hash of it is stored or sent;
2. answers each pending hash from the tenant's verdict cache (`vt_verdicts`, 30 days for
   malicious, 7 for clean/unknown) or with one `GET /api/v3/files/{sha256}` when the key's
   per-minute and per-day limits and the tenant's daily budget allow; otherwise the hash
   waits in the queue (`vt_requests`) and `/health/detail.virustotal` reports
   `budget_reached` - never an error. HTTP 429 pauses that key for 65 s. Every call is in
   `vt_calls` (key fingerprint, never the key). A call that times out counts against the
   budget (VirusTotal may have served it) and is retried on the next step;
3. sends a malicious verdict back to the alert's own manager as an analysisd event in the
   exact shape of Wazuh's `integrations/virustotal.py`, so 0490's 87100/87105 decode it and
   ShadowTracer's TI rule **110100** (child of 87105, `virustotal.origin = shadowtracer`,
   level 12) raises the alert: file, malicious/total engines, top labels. It also becomes a
   tenant-private TLP:AMBER sha256 IOC (source `virustotal:<tenant>`; the next list
   deploy turns later sightings into CDB hits, which replace 554, so integratord never asks
   for a known hash again) and is linked to the FIM alert's incident (`incident_ti`,
   ClickHouse `ti_matches` with origin `virustotal`), raising its priority.

Clean and unknown verdicts are cached but raise no alert. Hashes only: no file is ever
uploaded. **Opt-in** is per tenant (`ti_tenant_settings.vt_enabled`, default off, daily
budget default 500), set by `PUT /api/ti/settings` (admin, audited).

**On demand** (analyst+, audited): `POST /api/ti/virustotal/lookups {sha256}` returns the
cached verdict (200) or queues the hash for the same worker, cache and budget (202
`queued` / `budget_reached`); `GET /api/ti/virustotal/{sha256}` polls. The backend never
holds a key or calls VirusTotal. Console button: 6.4.

Lab checks (2026-11-06; test tenant opted in, main tenant not):

| check | result |
|---|---|
| EICAR dropped in agent-ubuntu-1's FIM directory | 554 -> one request -> VirusTotal 62/64 malicious (`virus.eicar/test`, first submitted 2006-05-22, link) -> rule 110100 level 12 on agent-ubuntu-1 (its own incident); the 554 alert's incident 394304 linked (`incident_ti` sources `virustotal`, confidence 90), priority 5 -> 12 |
| same hash again (copy at another path) | `served_from = cache`, second 110100 alert, no call |
| main tenant (opt-in off), new file on agent-ubuntu-2 | 554 on the main tenant; the master's spool discarded unread ("VirusTotal off, discarded 1"), 0 requests, 0 calls |
| daily budget forced to 1 | a new distinct hash stays `pending`, no call; `/health/detail.virustotal.budget_reached` lists the test tenant (calls_today 2, queued 1); the analyst API answers `202 budget_reached` for it and `cached` for EICAR |
| VirusTotal calls during the whole check | **2**: one read timeout (20 s), then the successful lookup |

### 3.5 Built in 6.4 (2026-11-06): console, false positives, retro-hunt

**Console** (React, text-only rendering of every feed and alert value; a source link is an
`<a>` only for http/https, `api.safeHttpUrl`):
- **Incident detail, "Threat intel" section** (`TiSection.tsx`): per match the observable
  and field, IOC type and value, sources with their links and context (pulse/event name),
  confidence, TLP, tags, MITRE, first seen, origin (matcher | virustotal | retro), the
  cached VirusTotal verdict (malicious/total, labels, analysis date, report link), a
  **Check on VirusTotal** button for hashes (analyst+, same cache and budget; shows
  `budget_reached`) and **Mark false positive** (analyst+). The header shows the priority
  raised by threat intel.
- **Mark false positive** (`POST /api/ti/false-positives`, audited): the observable joins
  the tenant's allowlist (`kind fp_marking`, `origin_ref incident_ti:<id>`), so that
  tenant's CDB lists (next deploy) and ti-matcher (next reload, <= 60 s) stop matching it;
  no other tenant is affected. The label goes to `ti_feedback` for the ML phase.
- **IOC browser** (`#/iocs`, `GET /api/ti/iocs`): search and filter by value, type,
  source, scope (global / this tenant), minimum confidence and expiry (hard TTL from the
  newest sighting). A tenant sees global intel and its own private IOCs, never another
  tenant's; global intel is never TLP:AMBER/RED (rejected at import, filtered again).
- **TI settings** (`#/ti-settings`, `GET /api/ti/overview` for every role, `PUT
  /api/ti/settings` admin only, audited): per-tenant use of each global feed
  (`disabled_sources`: those feeds' IOCs leave that tenant's lists and matcher view),
  VirusTotal opt-in and budget, keys configured yes/no (`ti_key_status`, written by ti-sync,
  never a value), last sync, staleness, IOC counts, hits and false-positive rate per source
  over 30 days, last retro-hunt.

**Retro-hunt** (`retro.py`, in ti-sync after each cycle, per tenant, never on the hot
path): IOCs created since the tenant's cursor (one-hour overlap for late commits; the
first run only sets the cursor) are matched against that tenant's ClickHouse events of
the last `TI_RETRO_DAYS` (7). ClickHouse narrows candidates by exact value (source or
destination IP, any field equal to a hash, domain or URL); `matcher.match` decides, so a
retro hit is what the live matcher would have found. New hits go to `incident_ti`
(origin `retro`) and `ti_matches` (`retro = true`) and are linked to their (old)
incidents; an alert already matched to that IOC is left alone. Bounds: one run per tenant
per `TI_RETRO_INTERVAL_SECONDS` (900), at most 5,000 new IOCs per run (the cursor stops at
the last one taken), 20,000 candidate events, 60 s ClickHouse limit. Parent-domain and
CIDR matches are live-only (backlog D7).

**ti-matcher memory (backlog T17, done):** one shared global set (global IOCs minus global
allowlists) plus a small per-tenant view (private IOCs, the tenant's own allowlist and
disabled feeds applied at lookup). Two tenants: 218 -> 140 MiB anonymous, 164 MiB reload
peak; limit 384m -> 256m.

**VirusTotal alert in the FIM incident:** rule 110100 sits in its own wrapper group
`ossec,syscheck,shadowtracer_ti`, so its first rule group is `ossec`, like FIM 550/554. The
correlator keys group-only alerts by (agent, first group), so "file appeared" and
"VirusTotal: malicious" for the same agent within the session gap (600 s) land in one
incident. Fingerprints: an incident's fingerprint hashes its sorted rule groups, so a FIM
incident with a malicious verdict (`shadowtracer_ti`, `ti_high`, `ti_virustotal` added)
fingerprints differently from a plain "file added" incident and never inherits a
benign-FIM suppression. A verdict queued past the session gap (budget reached) starts a new
incident under the same key; `incident_ti` still links the original FIM incident.

**VirusTotal HTTP 429** (2026-11-06): after the budget reset the free key answered every
call with 429 (5 calls, one per 65 s). The back-off is now derived from `vt_calls` (65 s,
doubling per consecutive 429, at most 6 h), so a restarted worker does not retry a refused
key early. VirusTotal is switched off for the test tenant until the owner confirms the key.

Lab checks (2026-11-06):

| check | result |
|---|---|
| incident with an OTX/manual IP match | #378566: 30 matches (`manual:global`, confidence 90), priority 10 -> 12; screenshot `docs/report/6.4-incident-ti-ip-match.png` |
| EICAR incident | #394304: 2 matches, VirusTotal 62/64 (`virus.eicar/test`), report link, priority 5 -> 12; `6.4-incident-eicar-virustotal-cached.png` |
| "Check on VirusTotal" | `cached 62/64` from the tenant's cache, no call (VirusTotal is off for the tenant: a cached verdict is still shown, only new lookups need the opt-in) |
| false positive, tenant only | global IOC 45.33.32.181: before, CDB 110000 + matcher hit on both tenants; marked on the test tenant (allowlist `fp_marking`, `ti_feedback`), list redeployed (ipv4-high 12,644 -> 12,643): test tenant no TI alert and no matcher hit, main tenant still both |
| retro-hunt | tenant-private IOC 203.0.113.77 (seen 2026-11-01..04): 693 retro matches on 184 closed incidents incl. #34008 (2026-11-04), `ti_matches.retro = true`; `6.4-incident-retro-hunt.png` |
| IOC browser, settings | real data (Spamhaus DROP 1,762, CERT Polska 125,967, CIRCL 274,339, ...); viewer `PUT /api/ti/settings` -> 403, page read-only; `6.4-ioc-browser.png`, `6.4-ti-settings-admin.png`, `6.4-ti-settings-viewer-read-only.png` |
| VirusTotal alert joins the FIM incident | 554 and 110100 (synthetic verdict through the worker's delivery path, no API call) in one incident #394323, key `001|rulegroup:ossec` |

---

## 4. Store, generation, distribution, reload

### 4.1 IOC store (Postgres, ShadowTracer database), STIX 2.1-compatible

Field names follow the STIX 2.1 Indicator object (OASIS STIX 2.1, §4.7 Indicator,
[docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html))
so a later TAXII export is a projection, not a migration. One row per **observable per
tenant scope**. Each source's claim about it is a separate `ioc_sightings` row: that is
what makes multi-source dedup (§4.11) and per-source trust (§4.10) possible.

```sql
CREATE TYPE ioc_type AS ENUM ('ipv4','ipv6','cidr4','cidr6','domain','url','md5','sha1','sha256');
CREATE TYPE tlp AS ENUM ('clear','green','amber','amber+strict','red');

CREATE TABLE ti_sources (
  id            bigserial PRIMARY KEY,
  tenant_id     text NULL,              -- NULL = global source
  kind          text NOT NULL,          -- otx | misp_feed | misp_server | abusech_feodo | abusech_threatfox | virustotal | manual
  name          text NOT NULL,
  stix_identity text NOT NULL,          -- created_by_ref: identity--<uuid5(source)>
  trust         real NOT NULL CHECK (trust BETWEEN 0 AND 1),          -- §4.10
  default_tlp   tlp NOT NULL,
  config        jsonb NOT NULL,         -- URLs, filters; secrets only by reference (customer-supplied keys)
  enabled       boolean NOT NULL DEFAULT true,
  sync_cursor   text,
  last_success_at timestamptz, last_attempt_at timestamptz, last_error text,
  last_good_snapshot_sha256 text        -- §4.12
);

CREATE TABLE iocs (                     -- STIX: indicator
  id            bigserial PRIMARY KEY,
  stix_id       text NOT NULL UNIQUE,   -- indicator--<uuid5(tenant scope, type, value)>, stable across syncs
  tenant_id     text NULL,              -- NULL = global; else private to that tenant
  type          ioc_type NOT NULL,
  value         text NOT NULL,          -- normalised (§4.6)
  pattern       text NOT NULL,          -- STIX pattern, e.g. [ipv4-addr:value = '198.51.100.7']
  pattern_type  text NOT NULL DEFAULT 'stix',
  indicator_types text[] NOT NULL,      -- malicious-activity, anomalous-activity, …
  name          text, description text,
  labels        text[] NOT NULL DEFAULT '{}',   -- tags, malware family
  kill_chain_phases jsonb NOT NULL DEFAULT '[]',-- [{kill_chain_name:'mitre-attack', phase_name:…}] + technique ids
  tlp           tlp NOT NULL,           -- most restrictive over its sightings (object_marking_refs on export)
  confidence    smallint NOT NULL,      -- combined, 0-100 (§4.10), recomputed on sighting change
  valid_from    timestamptz NOT NULL,   -- first_seen across sources
  last_seen     timestamptz NOT NULL,
  valid_until   timestamptz NOT NULL,   -- = expiry (§4.10)
  revoked       boolean NOT NULL DEFAULT false,
  created       timestamptz NOT NULL DEFAULT now(),
  modified      timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (tenant_id, type, value)   -- PostgreSQL 15+, lab runs 16
);
CREATE INDEX ON iocs (tenant_id, type) WHERE NOT revoked;
CREATE INDEX ON iocs (created);         -- retro-hunt watermark

CREATE TABLE ioc_sightings (            -- one row per (ioc, source): provenance and analyst context
  ioc_id        bigint NOT NULL REFERENCES iocs(id),
  source_id     bigint NOT NULL REFERENCES ti_sources(id),
  source_ref    text,                   -- OTX pulse id / MISP event+attribute uuid / abuse.ch id
  reference_url text,                   -- external_references[].url
  source_confidence smallint,           -- what the source said, 0-100 or NULL
  tlp           tlp NOT NULL,
  labels        text[] NOT NULL DEFAULT '{}',
  mitre         text[] NOT NULL DEFAULT '{}',
  first_seen    timestamptz NOT NULL, last_seen timestamptz NOT NULL,
  revoked_at    timestamptz NULL,
  PRIMARY KEY (ioc_id, source_id)
);

CREATE TABLE ti_allowlist (             -- §4.8
  id bigserial PRIMARY KEY,
  tenant_id   text NULL,                -- NULL = global
  type        ioc_type NOT NULL, value text NOT NULL,   -- exact value or CIDR
  kind        text NOT NULL,            -- warninglist | manual | fp_marking | protected_asset
  reason      text NOT NULL, origin_ref text,          -- warninglist name / ti_hit id
  created_by  text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NULL
);

CREATE TABLE ti_tenant_settings (
  tenant_id text PRIMARY KEY, vt_enabled boolean NOT NULL DEFAULT false,
  source_trust_overrides jsonb NOT NULL DEFAULT '{}', retro_days smallint NOT NULL DEFAULT 7
);

CREATE TABLE ti_list_versions (         -- §4.16, built in 6.1a (ingest migration 0e5c1aad5005)
  tenant_key text, node text, path text,  -- one row per node and TI file (list, its .cdb, rule file)
  role text, sha256 text, entries integer,
  result text,                            -- ok | unchanged | warnings | errors | sync_timeout | rolled_back | rejected
  detail text, checked_at timestamptz,
  PRIMARY KEY (tenant_key, node, path)
);
```

ClickHouse `ti_hits` (ReplicatedReplacingMergeTree, ORDER BY
`(tenant_id, alert_time, cluster_node, alert_id, ioc_type, ioc_value)`): IOC id,
`sources Array(String)`, combined confidence, `origin` (`cdb` | `matcher` | `retro`),
incident id when known, analyst verdict when marked. Replays and retro-hunt re-runs
collapse to one row. `ti_source_metrics` is described in §4.15.

Upserts: an IOC seen again refreshes its sighting's `last_seen` and the IOC's
`valid_until`; a source that withdraws it (OTX pulse removed, MISP `to_ids` false or
attribute deleted, abuse.ch status removed) sets that sighting's `revoked_at`; the IOC
is revoked when no live sighting remains.

### 4.2 Per-tenant private lists under dedicated managers

Each tenant has its own manager cluster (TENANCY.md option A). For tenant T the
generator writes **one set of files**, `global ∪ private(T)`, to **T's master only**.
Wazuh sync can't carry them to another tenant because no other tenant's node is in T's
cluster (after the lab fix in §1.7). Merging global and private entries into one file
per type keeps one lookup per observable. Provenance stays in the IOC store and
`ti_hits`.

`ti-matcher` keeps one in-memory set per tenant, built from the same query, selected by
the tenant of the topic it is reading.

### 4.3 List generation

Fixed files (declared once per node in `ossec.conf`; `ossec.conf` is not synced):

```
etc/lists/shadowtracer-ti/ipv4-{high,medium}     address_match_key   exact IPs + octet-aligned prefixes "10.1.2."
etc/lists/shadowtracer-ti/ipv6-{high,medium}     match_key           quoted keys
etc/lists/shadowtracer-ti/domain-{high,medium}   match_key
etc/lists/shadowtracer-ti/url-{high,medium}      match_key           quoted keys
etc/lists/shadowtracer-ti/md5-{high,medium}      match_key
etc/lists/shadowtracer-ti/sha1-{high,medium}     match_key
etc/lists/shadowtracer-ti/sha256-{high,medium}   match_key
```
Band lists carry the confidence (§4.10); `low` lives only in `ti-matcher`.

- Select non-revoked IOCs with `valid_until > now() + <one sync interval>` for
  `tenant_id IS NULL OR tenant_id = T` that the TLP rules allow for T (§4.13), minus
  allowlists (§4.8), band by confidence (§4.10), sort, write `key:` lines with the
  writer of §4.7.
- IPv4 CIDRs are expanded into octet-aligned prefixes when that takes ≤ 256 entries
  (any /8, /16, /24 is one entry; a /20 is sixteen `/24` prefixes); larger expansions go
  to `ti-matcher` only.
- An empty list keeps one reserved never-matching key, so the file always exists and its
  rules always load (VERIFY 6.1-4).
- Write `name.tmp` (excluded from cluster sync), `fsync`, `rename()`. Skip the
  distribution if the content hash is unchanged. If the new text file's mtime is not
  newer than the existing `.cdb`'s (same second), bump it with `os.utime` so analysisd
  recompiles (§1.1).

TI rules: one static ShadowTracer rule file (it changes only with ShadowTracer
releases, not with feeds), rule ids in a reserved ShadowTracer range (proposed
110000–110999, recorded in DECISIONS.md in 6.1), group `shadowtracer_ti`:
- children of grouping parents per decoder family (sshd 5700, web access log, Suricata,
  Sysmon network/DNS, firewall …), one rule per (parent, field, list);
- FIM: children of 550/554 on `sha256`/`sha1`/`md5`;
- every TI child of a grouping parent carries `accuracy="0"` (§1.4), so it runs after
  the native siblings; the file name sorts after `0*` so its `if_sid` parents exist
  when it loads (§1.4 point 2a).

### 4.4 Distribution, atomic swap and reload

Per tenant, after generation:
1. A ShadowTracer component that can write the master's `etc/lists/shadowtracer-ti/`
   (lab: the manager container; production: a small pull agent on the master host)
   writes the files with temp + rename. Not through the API upload (§1.6).
2. `PUT /cluster/analysisd/reload?nodes_list=<master>`; check the response.
3. Poll each worker's file checksums for the changed `.txt` **and** `.cdb` until they
   equal the master's (timeout, e.g. 60 s).
4. `PUT /cluster/analysisd/reload?nodes_list=<workers>`; the reload happens at each
   worker's next integrity check (§9.6).
5. Confirm each node logged `Ruleset reloaded successfully` after the request, then
   record `node_status` in `ti_list_versions`.

Reloads are rate-limited (at most one per tenant per sync interval) because each reload
drops queued events until the analysisd fix lands (§9.4, §6).

**Pre-validation on every node (6.1a follow-up).** Before anything is written to `etc/`,
the wrapper loads the candidate rule file and lists on the master and on every worker
with `wazuh-analysisd -t`. It uses that node's own `ossec.conf`, pointed at a staging
directory under `tmp/` (not cluster-synced). Any analysisd warning or error rejects the
bundle. Without this, a rejected file sat in `etc/rules` for ~8 s during a rollback;
the cluster could sync it to a worker, and a worker restarting in that window would
start with it and keep it in memory after sync restored the good file. Lab proof: the
undeclared-list rule file was rejected on master, worker1 and worker2 with nothing
written and no reload. The post-reload check and rollback remain as a second line.

### 4.5 Expiry and retro-hunt

- **Expiry:** `valid_until` from confidence decay and hard TTLs (§4.10). Lists drop
  expired IOCs at the next generation (worst-case staleness = sync interval +
  distribution time, measured in 6.1); `ti-matcher` checks `valid_until` at lookup time,
  so it is exact.
- **Retro-hunt:** a scheduled job (every sync) takes IOCs with
  `created_at > watermark` (or re-activated) per tenant and searches the last N days
  (default 7, cap 30) of that tenant's `events` in ClickHouse: `src_endpoint_ip`,
  `dst_endpoint_ip`, `extra_fields['syscheck.sha256_after']` and the other mapped
  hash/domain keys, `IN` sets of ≤ 10,000 values per query, `max_execution_time` and a
  row cap per query, always filtered by `tenant_id` and the time partition. Hits go to
  `ti_hits` with `origin='retro'` (idempotent), and the watermark advances only after
  the hunt commits. Limit: only alerts are stored; events that produced no alert can't
  be retro-hunted (archives are not shipped).

### 4.6 Normalisation

Applied in `ti-sync` before anything is stored. Feed values are untrusted input.
- **Refang:** `hxxp`/`hxxps` → `http`/`https`, `[.]` `(.)` `{.}` `[dot]` → `.`, `[:]` → `:`,
  `[@]`/`[at]` → `@`; then validate. A value that is still defanged-looking afterwards
  is rejected.
- **Domains:** strip whitespace and a trailing `.`, lower-case, IDNA 2008 to A-labels
  (punycode); labels 1–63 chars of `[a-z0-9-]`, total ≤ 253, at least two labels. Wildcards
  (`*.evil.com`) become a `domain` suffix entry for `ti-matcher` only (CDB can't match
  suffixes, §1.3).
- **IPv4:** canonical dotted quad. Leading zeros are rejected (`010.1.1.1` is ambiguous:
  octal or decimal).
- **IPv6:** compressed lower-case form; IPv4-mapped `::ffff:a.b.c.d` is stored as IPv4.
- **CIDR:** host bits masked off; IPv4 prefixes shorter than /16 and IPv6 shorter than
  /32 are rejected from feeds (a poisoned `0.0.0.0/1` would match half the internet);
  expansion for CDB as in §4.3.
- **Private and special ranges excluded from global IOCs:** loopback, RFC 1918,
  link-local, CGNAT 100.64/10, multicast, reserved, documentation ranges, unspecified,
  and the IPv6 equivalents (`ipaddress` `is_private`/`is_reserved`/… plus 100.64/10). They
  are allowed only in **tenant-private** intel, where a tenant can flag its own
  internal host.
- **URLs:** scheme and host lower-cased, host normalised as a domain, default port
  dropped, fragment dropped, percent-encoding normalised (decode unreserved, upper-case
  hex), length ≤ 2,048.
- **Hashes:** lower-case hex of exactly 32/40/64 characters. Hashes of the empty file
  (`d41d8cd98f00b204e9800998ecf8427e`, `da39a3ee5e6b4b0d3255bfef95601890afd80709`,
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`) are rejected.

### 4.7 Entry validation and escaping before writing a CDB list

What a raw feed value could do to a list file, from `lists_make.c`:

| Crafted value | Effect if written as-is |
|---|---|
| embedded newline, e.g. `evil.com\n10.:` | `fgets` reads a second line (`:61`): **adds an entry**. Here a 10.0.0.0/8 prefix that turns every internal address into a TI hit (alert flood) |
| > 65,534 bytes | `fgets` splits the line; the tail becomes its own entry |
| unquoted `:` (IPv6, URL) | key cut at the first `:` (`:107-113`): `2001` or `http` becomes the key |
| unbalanced `"` | line silently skipped (`:90-91`, `:126-128`): the IOC disappears |
| empty key (`:`) | key `""`: matches an empty field value |
| NUL byte | `strlen` truncation: a shorter key than intended |

Writer rules (one function writes every list; nothing else touches the files):
1. Only normalised values that pass the per-type grammar of §4.6 are written; the
   grammars contain no newline, `"`, NUL, control character or whitespace. Rejects
   are counted per source (`rejected` metric, §4.15) and never written.
2. Keys that contain `:` (IPv6, URLs) are written as `"key":`. A URL can't contain a
   raw `"` because §4.6 percent-encodes it.
3. Values (after the `:`) are empty. Nothing from a feed is ever written after the
   separator.
4. After writing, the file is re-read and parsed with the same rules as
   `Lists_OP_MakeCDB`. The key set must equal the intended set exactly, or nothing is
   published.

Proof required in 6.1 (VERIFY 6.1-5): a fuzz/crafted corpus (the rows above, plus random
bytes) goes through normalise → write → re-parse with the set check (unit test), then
through a real reload on the test manager: the reload response has no warnings, the
expected entries match in logtest, and an injected-looking string (`10.0.0.5`) does not.

### 4.8 Allowlists, warninglists and false-positive marking

Three allowlist layers, all in `ti_allowlist`, applied **at list generation and in
`ti-matcher`**. An allowlisted observable is never written to a list and never
produces a `ti_hits` row:
- **MISP warninglists** (CC0, [github.com/MISP/misp-warninglists](https://github.com/MISP/misp-warninglists)),
  refreshed weekly. *Hard* (suppress): RFC 1918 and other special ranges, public DNS
  resolvers, top-ranked domains (Tranco/Cloudflare Radar lists), the empty-file hashes.
  *Soft* (keep, but cap confidence at 40 and tag `warninglist:<name>`): cloud and CDN
  ranges, URL shorteners, VPN/datacenter ranges. Attackers really do use those, so
  hiding them outright would hide real hits.
- **Global allowlist** (operator, audited).
- **Per-tenant allowlist** (tenant admin, audited), including **protected assets** (§4.9).

**"Mark TI hit as false positive"** (console, analyst role, audited):
1. adds `(type, value)` to **that tenant's** allowlist with `kind='fp_marking'`,
   `origin_ref=<ti_hit id>`, optional expiry;
2. records a **label** (verdict `false_positive`, analyst, time, IOC id, sources, incident
   id) in the 7.0 labels table, so ML training sees it;
3. increments the FP count of every source that listed it (§4.15);
4. regenerates that tenant's lists at the next sync (or immediately if the analyst asks).
It never edits the global IOC or another tenant's view.

### 4.9 Poisoning: protected assets, and no automatic blocking

- **Protected-asset allowlist** per tenant: the tenant's own public IPs and ranges,
  domains, mail and VPN gateways, and known-good software hashes. A feed entry that hits
  a protected asset is **never listed** and raises a `ti_conflict` event in
  `/health/detail` and the console for a human to review. It may be poisoning, or the
  asset may really be compromised; a person decides.
- Feed-level guards: the CIDR breadth limit (§4.6), private ranges never global (§4.6),
  and the change-volume guard of §4.12.
- **TI never triggers automatic blocking.** No active response is bound to the
  `shadowtracer_ti` group or to TI rule ids, and a 6.1 test fails if a generated rule or
  `ossec.conf` binds one. SOAR (later) may propose a block from a TI hit, but only with
  human approval.

### 4.10 Confidence, per-source trust and aging

- **Per-source trust** `trust ∈ [0,1]` (`ti_sources.trust`, per-tenant override in
  `ti_tenant_settings`). Defaults: tenant manual 1.0; tenant's own MISP 0.9; abuse.ch
  Feodo/ThreatFox 0.8; MISP community feeds 0.6; OTX subscribed pulses 0.5; VirusTotal
  verdict 0.8 (≥ 5 engines), 0.4 (1–4).
- **Source confidence** `c ∈ [0,1]`: the source's own value where it has one
  (ThreatFox `confidence_level`, MISP confidence taxonomy), else 0.7.
- **Decay** by type, from the sighting's `last_seen`: half-life IP 7 days, URL 14 days,
  domain 30 days, hash 180 days; `d(t) = 0.5^(age/half_life)`.
- **Combined confidence** (noisy-OR over live sightings):
  `C = 100 · (1 − Π_s (1 − trust_s · c_s · d_s(t)))`, recomputed at each sync.
- **Expiry** (`valid_until`): when C would fall below 20 at the current decay, capped by
  a hard maximum TTL (IP 30 d, URL 30 d, domain 90 d, hash 365 d) and by any source
  `valid_until`.
- **Alert level from confidence.** A CDB rule's level is static and
  `address_match_key_value` is banned (§0.1), so confidence is expressed through
  **band lists**: `…-high` (C ≥ 75 → TI rule level 12), `…-medium` (50 ≤ C < 75 → level
  8). `low` (20 ≤ C < 50) is `ti-matcher`-only: recorded as a hit and shown on incidents,
  but it raises no Wazuh alert. Within the `accuracy="0"` group the higher-level rule
  is tried first (§1.4), so an observable in both bands alerts once at the high level.
  `ti-matcher` stores the exact C.

### 4.11 Multi-source dedup: one alert per observable

- The store holds one `iocs` row per observable per tenant scope; sources are
  `ioc_sightings` rows (§4.1).
- List generation writes each observable **once**, in exactly one band list, from the
  combined confidence. So one event raises **one** TI alert however many feeds list the
  observable.
- `ti_hits` is keyed on alert identity + observable, and `sources` lists every live
  source with its reference. The CDB alert, the `ti-matcher` row and a retro-hunt row for
  the same alert and observable collapse to one row (ReplacingMergeTree).
- Global and tenant-private sightings of the same value merge into the tenant-scope
  view at generation time; the global row is never modified by tenant data.

### 4.12 Feed failure, last good list, staleness

- Each source sync is all-or-nothing: fetch, parse, validate into a staging table, then
  commit in one transaction. A sync that fails (HTTP error, parse error, auth error,
  schema change) changes nothing. The source keeps its last good IOCs, which still age
  and expire normally; `last_error` and `last_attempt_at` are set.
- **Change-volume guard:** if a sync would remove > 30% of a source's live IOCs, or add
  more than 5× its usual daily volume, it is held as `pending_review` instead of committed.
  This covers truncated downloads and poisoning bursts.
- **Never publish an empty or partial list:** list generation refuses to publish a file
  that is empty while the live version is not, or that shrinks by > 30% without matching
  expiries/revocations/allowlist entries. Files are complete before the rename (§4.3).
  The safe reload wrapper (6.1a) keeps the old lists and rules on any reload warning.
- **Staleness in `/health/detail`** (degrades, never fails `/health/ready`): per source
  `last_success_at`, age, `last_error`, held syncs; per tenant and manager the live
  list version and its age (§4.16).

### 4.13 TLP and distribution

Each sighting carries a TLP (OTX pulse TLP, MISP `tlp:*` tags, abuse.ch TLP:CLEAR, manual
entries choose one), and each IOC carries the most restrictive TLP of its live sightings.
- **Tenant-private intel and TLP:RED never leave that tenant:** never in a global list,
  another tenant's lists or `ti-matcher` set, an export (STIX/TAXII later), a
  VirusTotal request, or the 7.7 LLM agent's tool results. TLP:RED is excluded from the
  agent even within its own tenant, because sending it to an external LLM is disclosure.
- **Owner decision 6.2: TLP:RED, AMBER+STRICT and AMBER are never global.** An
  observation from a global source (feed, OTX, global MISP feed) carrying any of them is
  rejected at import (`store.prepare_rows`: "TLP:AMBER is never global"); list generation
  and ti-matcher drop any such global row as a backstop (`listgen.NO_CROSS_TENANT_TLP`).
  The same intel from a tenant's own source (its MISP server, its manual entries) is
  stored with that tenant's key and stays in that tenant's lists and matcher set only.
- **TLP:GREEN / CLEAR** from global sources may be matched for every tenant, subject to
  the source's own terms (§3.3 feed table).
- Enforcement: every read of IOCs goes through one store function that takes a
  `purpose` (`match`, `export`, `external_lookup`, `llm`, `display`) and the caller's
  tenant, and applies these rules in SQL. One test per purpose proves a TLP:RED IOC and
  a tenant-private IOC are invisible to every other tenant and purpose.

### 4.14 Analyst context per IOC

Stored per IOC/sighting and shown on incident detail (TI panel) and in the IOC browser:
- observable (displayed defanged, e.g. `198.51.100[.]7`), type, combined confidence and
  band, TLP;
- per source: name, trust, source confidence, reference (OTX pulse id, MISP event uuid,
  abuse.ch entry id) with a link (`https://otx.alienvault.com/pulse/<id>`, the MISP
  event URL, `https://threatfox.abuse.ch/ioc/<id>/`, the Feodo or MalwareBazaar page),
  first and last seen at the source;
- description, tags and malware family, MITRE ATT&CK technique ids (OTX
  `attack_ids`, MISP galaxies, ThreatFox malware → technique where given);
- local first seen, last seen, `valid_until`, sightings in this tenant (count, last
  alert), false-positive markings and allowlist entries.

### 4.15 Feed metrics

`ti_source_metrics` (ClickHouse SummingMergeTree, per day × tenant × source): active,
added, expired, revoked, rejected (validation), allowlisted, held syncs; hits by origin
(`cdb`, `matcher`, `retro`), distinct observables hit, FP markings, hits reviewed.
Derived: **FP rate** = FP-marked ÷ reviewed hits (also ÷ all hits, both shown), hits
per 1,000 active IOCs, time from first publication to first hit. Shown on the
source-settings page. Trust is tuned by an admin; it is never changed automatically in
6.x.

### 4.16 List version per manager in health

For each tenant and each manager node, `/health/detail` shows each TI list's live
version (content SHA-256 prefix), entry count, `generated_at`, `loaded_at`, whether the
node's `.txt` and `.cdb` checksums match the master's, and the last reload result
(`ok` / `warnings: …` / `held`). The data comes from `ti_list_versions.node_status`,
written by the safe reload wrapper (6.1a item 3). A node whose version lags the
master's for more than two sync intervals shows as degraded.

## 5. Throughput

- CDB lookups add per-event work inside analysisd. With a 100,000-entry list the ceiling
  is unchanged (~4,000/s on the baseline fixture) and CPU per event is unchanged at
  4–20k lookups/s (§9.3). 6.1 re-measures at real list sizes (VERIFY 6.1-4, 6.1-11).
- `ti-matcher` is off the hot path and has its own gate (T9).
- Reload cost is paid only when lists change (§9.4).

## 6. Files that would change

Inherited Wazuh files (each recorded in `UPSTREAM.md` when changed):

| File | Change | When |
|---|---|---|
| `src/analysisd/analysisd.c` (`w_hotreload_drain_queues`, `w_hotreload_reload`) | process or wait out queued events instead of freeing them; fence the rule-matching threads | 6.1, before reloads are automated (correctness) |
| `src/analysisd/lists_list.c` (`os_remove_cdblist`) | `cdb_free()` + `close()` on removal (fd/mmap leak, confirmed §9.5) | 6.1 |
| `etc/templates/config/generic/rules.template`, `etc/ossec-server.conf`, `etc/ossec.conf` | declare the `shadowtracer-ti` lists, `<rule_exclude>0999-malicious-ioc-rules.xml</rule_exclude>` | 6.1 (lab: `deploy/lab/entrypoint-manager.sh`, ours) |
| `src/init/inst-functions.sh` | install `etc/lists/shadowtracer-ti/` placeholders (next to the `malicious-ioc` block at `:1135-1137`) | packaging (BFC) |
| `integrations/virustotal.py`, `ruleset/rules/0490-virustotal_rules.xml` | **unchanged**: the new script keeps their output shape | — |

New files (ShadowTracer names):

| File | Purpose |
|---|---|
| `etc/rules/1000-shadowtracer_ti_rules.xml` | TI rules (§4.3), generated by `shadowtracer_intel/ti_rules.py` and distributed with the lists by the safe reload wrapper (built in 6.1a); `etc/rules/` is cluster-synced, and `1000-` sorts after every `0xxx-*.xml` parent |
| `ruleset/lists/shadowtracer-ti/*` | empty-list placeholders installed into `etc/lists/shadowtracer-ti/` |
| `integrations/custom-shadowtracer-virustotal` (+ `.py`) | VT v3, cache, budget, per-tenant key |
| `shadowtracer/intel/shadowtracer_intel/` | `store.py`, `normalise.py`, `sync_otx.py`, `sync_misp.py`, `listgen.py`, `distribute.py`, `matcher.py` (`ti-matcher`), `retrohunt.py` |
| `shadowtracer/intel/alembic/…` | IOC store migrations |
| `shadowtracer/ingest/schema/…ti_hits.sql` | ClickHouse table |
| `deploy/lab/…` | `ti-sync`, `ti-matcher` services; lab cluster split for `worker-test` |

Upstream issue drafts to add under `shadowtracer/docs/UPSTREAM_ISSUES/`: reload drain
frees events; CDB fd leak on reload; `address_match_key_value` inversion (confirmed
§9.2); API list upload not atomic; reload reports success while dropping rules.

## 7. Licences and terms

| Source | Terms | Status |
|---|---|---|
| AlienVault/LevelBlue OTX | EULA ([levelblue.com/terms/otx-eula](https://www.levelblue.com/terms/otx-eula)): "free to end users for non-commercial use"; §2.3 forbids commercially exploiting OTX or making it available "as a service bureau", and republishing/distributing OTX content; no effective date given | **Decided (§0.1):** customer-supplied key under the customer's own agreement in the product; our key for the lab and the report only |
| VirusTotal | Public API: 4 req/min, 500/day, "must not be used in commercial products or services" or "business workflows that do not contribute new files" ([public-vs-premium-api](https://docs.virustotal.com/reference/public-vs-premium-api)); premium terms per contract | **Decided (§0.1):** customer-supplied key, per-tenant opt-in (§2); our public key for the lab only |
| MISP software | AGPL-3.0 (server). We only call its API / read its feed format; PyMISP is BSD-2-Clause | Licences to recheck when 6.2 adds dependencies |
| MISP default feeds | Per feed. CIRCL OSINT feed: no licence or TLP statement on the feed index ([circl.lu/doc/misp/feed-osint](https://www.circl.lu/doc/misp/feed-osint/)); its training material says it carries TLP:WHITE events. Some default feeds need a licence (e.g. Bambenek) ([misp-project.org/feeds](https://www.misp-project.org/feeds)) | **UNCLEAR per feed:** 6.2 records each enabled feed's terms; enable only feeds with stated terms |
| Wazuh shipped lists/rules | GPLv2 (`0999-malicious-ioc-rules.xml` header) | inherited, fine |
| abuse.ch Feodo Tracker, SSL Blacklist, YARAify | "free to use without limitations according to Creative Commons principles (CC0)", "for both commercial and non-commercial purposes" (abuse.ch Terms of Use §3.4, effective 2025-11-04, updated 2026-10-21, [abuse.ch/terms-of-use](https://abuse.ch/terms-of-use/)); platform access requires authentication at auth.abuse.ch (§2.1) | **default commercial-safe feed** (Feodo now) |
| abuse.ch URLhaus, ThreatFox, MalwareBazaar | use "with commercial or for-profit needs may require a paid subscription", managed by Spamhaus (§4.1); free use limited to not-for-profit with query/export volume limits (§3.1-3.2) | customer-supplied Auth-Key/subscription in the product; lab and report use under the non-profit terms |
| MISP warninglists | "licensed under CC0 1.0 Universal" ([github.com/MISP/misp-warninglists](https://github.com/MISP/misp-warninglists)); X4BNet-derived VPN/datacenter lists keep their MIT notice | fine; keep the MIT notice with those lists |
| YARA-X | BSD-3-Clause ([github.com/VirusTotal/yara-x](https://github.com/VirusTotal/yara-x)) | fine if adopted later (§2.1) |
| STIX 2.1 / TAXII 2.1 | OASIS open standards | field compatibility only (§4.1) |

## 8. VERIFY list

**6.1 (IOC store, lists, distribution, OTX)**
1. `worker-test` is its own cluster (own name/key, or cluster disabled): `cluster_control -l` on the main master no longer lists it; a canary file in the main master's `etc/lists/` never appears on `worker-test`.
2. A known test IOC (OTX test pulse or manual) produces exactly one TI alert end to end on a non-alerting event, and exactly one `ti_hits` row (CDB origin).
3. The same IOC on an alerting event (5710) leaves the native alert unchanged and adds one `matcher` `ti_hits` row; 5712 still fires on a brute force from that IP.
4. Empty list, 1-entry list and 1 M-entry list all load (no "list not loaded" warning); sizes and compile times recorded.
5. Rejected feed values (newline, quote, colon in a domain) never reach a list file; reject count logged.
6. Reload under load loses no events after the analysisd fix (§9.4 method: sent = received = alerts).
7. Worker reload ordering: change the list, run §4.4, check each worker matches the new IOC and not the removed one; repeat 20 times.
8. Rule generator: logtest per decoder family shows the `accuracy="0"` TI child fires for a non-alerting event (not yet shown in 6.0: no probe line reached it) and never pre-empts a native sibling; level-0 leaves inventoried; reload responses with any warning fail the distribution.
9. Expiry: an IOC past `valid_until` stops matching after the next sync (CDB) and immediately (`ti-matcher`).
10. Replay of the same alerts adds no `ti_hits` duplicates.
11. Throughput gate: hot path within 5%; analysisd ceiling with real list sizes; `ti-matcher` ceiling ≥ 3,300/s (T9).
12. OTX licence position recorded; key read from a secret; incremental sync resumes from its cursor after a restart.
13. One network log source (iptables `LOG` or Suricata) added in the lab so a destination-IP (and, with Suricata, domain) IOC matches end to end (§1.10).
14. Normalisation unit tests: every rule of §4.6, including defanged, IDNA, IPv4-mapped IPv6, leading-zero IPv4, too-broad CIDRs, private ranges rejected from global and accepted tenant-private.
15. Allowlists: a warninglisted (hard) value never reaches a list or `ti_hits`; a soft one is capped at 40; FP marking adds a tenant allowlist row and a label, regenerates only that tenant's lists, and never touches the global IOC.
16. Protected asset in a feed → not listed, `ti_conflict` raised; no active response bound to TI rules (test).
17. Confidence: band assignment and decay unit-tested; one event on an observable listed by three sources → one TI alert, one `ti_hits` row with three sources.
18. Feed failure: a truncated or empty download changes nothing and is visible in `/health/detail`; a 40% shrink is held; the live list version on every node is unchanged.
19. TLP: per-purpose test (`match`, `export`, `external_lookup`, `llm`, `display`) proves TLP:RED and tenant-private IOCs never cross the tenant boundary.
20. Feodo Tracker (CC0) as the first default feed; terms re-checked at implementation time.

**6.2 (MISP)**
1. Feed-only mode imports only `to_ids=true` attributes; each enabled feed's terms recorded.
2. Server mode (if RAM allows): incremental `restSearch`, revocation when `to_ids` flips.
3. A tenant-private MISP's IOCs reach only that tenant's lists and matcher set; canary IOC never matches another tenant.

**6.3 (VirusTotal)**
0. Per-tenant opt-in: with `vt_enabled=false` no request leaves for that tenant (request counter stays 0 under FIM churn); toggling is audited.
1. `custom-shadowtracer-virustotal` on FIM 554: known-bad test hash → 87105-shaped alert; unknown hash → 87103; cache hit makes no request (count requests).
2. Budget: a burst of 500 new files stays within the per-minute and per-day budget; overflow is queued or marked, never silently dropped.
3. Per-tenant key isolation; the key is not visible in `ps` (options file instead of argv).
4. Console on-demand lookup uses the same cache and budget; audited.

**6.4 (console, incidents, retro-hunt)**
1. Incident detail shows TI hits with source and pulse/event reference.
2. Retro-hunt: IOC added after the matching alert produces one `retro` hit; bounded query time recorded; tenant filter proven.
3. IOC browser and source settings admin-only and audited.
4. Tenant isolation end to end: tenant-private IOC never appears in another tenant's console, lists or hits.
5. Analyst context (§4.14) shown for a real hit, with working reference links; feed metrics (§4.15) show hits and FP rate per source; list version per manager (§4.16) visible.

## 9. Spike measurements (2026-11-05, test manager only)

Lab as in THROUGHPUT_BASELINE.md §1 (one WSL2 host, 12 vCPU, ~11 GiB). Test manager
`shadowtracer-worker-test` only. The scratch list, fixture, rules and scripts lived in a
session scratch directory outside the repository and were removed from the container
afterwards (§9.7); none are committed. The scripts are described well enough below to
re-create.

### 9.0 Set-up and isolation

- The test manager's shipper was **stopped** for the whole spike, so no spike alert
  reached Kafka, ClickHouse or Postgres. Its offset equalled the file size when stopped:
  ```
  $ docker exec shadowtracer-lab-shipper-worker-test-1 cat /offsets/offsets.json
  {"alerts.json": {"inode": 404993, "offset": 1890789772}}
  $ docker stop shadowtracer-lab-shipper-worker-test-1
  $ docker exec shadowtracer-lab-shadowtracer-worker-test-1 ls -li /var/ossec/logs/alerts/alerts.json
  404993 -rw-r--r-- 2 wazuh wazuh 1890789772 Nov  5 03:04 /var/ossec/logs/alerts/alerts.json
  ```
- Writers and correlators kept running (they serve the main tenant; they received
  nothing from the test manager during the spike). The baseline's §3.3 stopped them,
  so the absolute numbers here carry the idle-pipeline background; the with/without
  comparison is same-session and same-conditions.
- List: 100,000 distinct IPv4 addresses sampled from 198.18.0.0/15, `ip:spike` lines,
  2,014,031 bytes; compiled `.cdb` 4,216,079 bytes. List and rule files were placed
  in `etc/shadowtracer-spike/` (not a cluster-synced directory, §1.7) and declared in
  `ossec.conf` (not synced), backup kept and restored.
- Rules (scratch): `100900` child of 5715 and `100904` child of 5710, both
  `address_match_key` on the 100k list (the costliest miss path: up to four
  `cdb_find` per miss); `100901` child of 5700 (`accuracy="0"` in the ramp runs);
  `100902` root-level; `100903` `address_match_key_value` child of 5710 (logtest only).
- Two fixtures, both through `deploy/load/generate_load.py --target syslog` (paced
  UDP to port 5514, the baseline's tooling):
  - **baseline fixture** `deploy/load/fixtures/alerts_sample.anon.jsonl`, the same
    method and input as THROUGHPUT_BASELINE §3.3/§12.6: its 76 sshd rows are 75× rule
    5710 and 1× 5712 from 5 source IPs. With the list, every event does one lookup
    (`100904` under 5710).
  - **lookup fixture** (scratch): 10,000 `Accepted password for x from <ip> port <n>
    ssh2` lines, every one with a source IP, 1% of them in the list. Every event does
    the 100k lookup (`100900` under 5715) plus the shipped 199-entry `malicious-ip`
    lookup (99903) that also runs without the list.
- Sampler (scratch `ramp.sh`): 120 s per step, analysisd `.state` deltas every 15 s
  (`events_received`, `events_processed`, `events_dropped`, `alerts_written`,
  `event_queue_usage` from `/var/ossec/var/run/wazuh-analysisd.state`) and
  `top -b -n1 -p $(pidof wazuh-analysisd)` %CPU, 25 s drain between steps:
  ```
  python3 deploy/load/generate_load.py --target syslog --host 172.28.0.14 --port 5514 \
     --rate $R --duration 120 --run-id tis-$L-$R --fixture $FIXTURE --seed 42
  ```

### 9.1 A first fixture that measured something else

The first lookup fixture used `Failed password for invalid user x from <unique ip>`
(rule 5710) with a different source IP on almost every line. Without any list loaded:
```
-- nolist 3000/s for 120 s
13:16:34 recv/s  2326 proc/s  1485 drop/s     0 alerts/s  1484 q 0.00
13:16:48 recv/s  3209 proc/s  1714 drop/s    77 alerts/s  1714 q 1.00
13:17:04 recv/s  2548 proc/s  1570 drop/s   979 alerts/s  1570 q 1.00
13:17:18 recv/s  4268 proc/s  2301 drop/s  1968 alerts/s  2300 q 1.00
13:17:33 recv/s  2565 proc/s  1618 drop/s   946 alerts/s  1619 q 1.00
$ docker exec … top -b -n1 -w 200 -p $(pidof wazuh-analysisd)   # sender already stopped
 120339 wazuh  20  0 5621820 159960  2944 S 553.3  1.4 102:34.19 wazuh-analysisd
```
analysisd fell to ~1,500–2,300 processed/s at 3,000/s offered and kept 5½ cores busy
after the sender stopped. The likely cause is frequency rule 5712 (`if_matched_sid
5710`, `same_source_ip`, `frequency="8"`, `timeframe="120"`) scanning its whole
120-second history for each event, because with unique IPs it never finds 8 matches.
That is a property of the native ruleset under a many-source brute force, not of TI.
Recorded as `OPTIMIZATION_BACKLOG.md` S9 (security; first filed as T10) and switched the lookup fixture to rule 5715.

### 9.2 Rule placement and lookup types (`wazuh-logtest` on the test manager)

Declaring the files and reloading (`reload.py`: the framework's
`send_reload_ruleset_msg`, i.e. the analysisd socket command the API uses):
```
reload_wall_s=0.442 response={'success': True, 'message': 'ok', 'warnings': [
 "(7617): Signature ID '5715' was not found and will be ignored in the 'if_sid' option of rule '100900'.",
 "(7619): Empty 'if_sid' value. Rule '100900' will be ignored.",
 "(7617): Signature ID '5700' was not found … rule '100901'.", "(7619): … Rule '100901' will be ignored.",
 "(7611): Category was not found. Invalid 'category'. Rule '100902' will be ignored.",
 "(7617): Signature ID '5710' was not found … rule '100903'.", "(7619): … Rule '100903' will be ignored."], 'errors': []}
```
The file was named `0001-shadowtracer-ti-spike.xml`: loaded before
`0095-sshd_rules.xml` despite sitting in a later `<rule_dir>`, so every parent was
missing, and the reload still reported success (§1.4 point 2a). Renamed to `1000-…`:
`warnings: []`, including for the root rule 100902 (its "Category was not found" was
also a load-order effect).

Logtest, TI child of 5700 **without** `accuracy="0"` (input lines on the left):
```
Accepted password … from 198.18.157.153 (listed)        -> 100901 (TI child of 5700)   pre-empted 5715
Accepted password … from 100.64.0.5 (not listed)        -> 5715
Failed password for invalid user … 198.18.157.153       -> 100901                      pre-empted 5710
Failed password for invalid user … 100.64.0.5           -> 100903 (address_match_key_value fired on an UNLISTED ip)
Connection closed by 198.18.157.153 port 22 [preauth]   -> 5722 level 0, no alert
Received disconnect from 198.18.157.153 port 22:11: …   -> 5721 level 0, no alert
Did not receive identification string from 198.18.157.153 -> 100901                   pre-empted 5706
```
Same lines with `accuracy="0"` on 100901:
```
listed, Accepted              -> 100900 (TI child of 5715, replaces 5715 — the Wazuh 0999 pattern)
unlisted, Accepted            -> 5715
listed, invalid user          -> 5710   (100903 address_match_key_value did not fire for the listed ip)
unlisted, invalid user        -> 100903 (fired: inverted, §1.2)
listed, Connection closed     -> 5722 level 0, no alert   (level-0 leaf gap, §1.4)
listed, Received disconnect   -> 5721 level 0, no alert
listed, no identification     -> 5706   (native sibling now wins)
```
Not shown: a line where the `accuracy="0"` child itself fires (none of the probe lines
reached it; VERIFY 6.1-8).

### 9.3 analysisd ceiling with and without the 100,000-entry list

Per 120 s step: mean of the 15 s samples (the first sample includes generator start-up,
so mean received is slightly under the offered rate) and the analysisd %CPU range.

**Baseline fixture (THROUGHPUT_BASELINE method):**

| offered/s | without list: recv / proc / drop per s | CPU | with list: recv / proc / drop per s | CPU |
|---|---|---|---|---|
| 4,000 | 3,886 / 3,884 / **0** | 287–487% | 3,876 / 3,871 / **0** | 160–487% |
| 5,000 | 4,877 / 3,769 / 838 (queue 1.00) | 387–553% | 4,904 / 4,068 / 577 (queue 1.00) | 333–540% |
| 6,000 | 5,735 / 4,130 / 1,353 | 367–533% | 5,968 / 3,971 / 1,725 | 227–533% |

**Ceiling ~4,000/s with and without the list** (the baseline's number, §3.3/§12.6).
Saturated processing is ~3,770–4,130/s without and ~3,970–4,070/s with: no difference
beyond step-to-step noise.

**Lookup fixture (every event looks up the 100k list):**

| offered/s | without list: proc/s, drops | CPU | with list: proc/s, drops | CPU |
|---|---|---|---|---|
| 3,000 | 2,995, 0 | 47–53% | — | — |
| 4,000 | 3,908, 0 | 53–73% | 3,941, 0 | 53–73% |
| 5,000 | 4,846, 0 | 73–93% | — | — |
| 6,000 | 5,878, 0 | 88–107% | — | — |
| 8,000 | 7,856, 0 | 120–140% | 7,704, 0 | 127–153% |
| 10,000 | 9,903, 0 | 153–200% | — | — |
| 12,000 | 11,726, 0 | 193–213% | 11,778, 0 | 187–227% |
| 16,000 | 15,741, 0 | 273–306% | 15,336, 0 | 267–313% |
| 20,000 | 19,426, 0 | 200–387% | 19,783, 0 | 267–393% |

No analysisd drop at any step, queue usage 0.00 throughout. At 20,000/s the loss is
**before** analysisd, in the kernel UDP buffer (single sender, `/proc/net/snmp`):
```
no list 16k+20k steps: InDatagrams 20449128 -> 24756411, RcvbufErrors 24083 -> 36798 (+12,715)
with list 4k..20k steps: RcvbufErrors 37451 -> 53744 (+16,293)
```
So for this event mix analysisd's own ceiling is above ~19,000/s and could not be
reached with one UDP sender. CPU per event is the same with and without the list
within the sampling noise.

**Result:** a 100,000-entry `address_match_key` list adds no measurable cost to
analysisd on this lab, either at the baseline's 4,000/s ceiling or at 4–20k/s
where every event does a lookup. The `.cdb` is `mmap`ed and a lookup is a few hash
probes in memory; rule evaluation dominates.

### 9.4 Reload time, and events lost during a reload under load

Reload wall time (socket request → response, `reload.py`), whole ruleset:
```
first reload with the new list (compiles the 4.2 MB .cdb):  reload_wall_s=0.978
later reloads, no list change:                               0.364 0.405 0.428 0.442
during 4,000/s load:                                         0.938 0.451 0.416 0.479 0.548
```
The `ossec.log` lines "Reloading ruleset" / "Ruleset reloaded successfully" carry the
same second, so the locked window (drain + switch) is under 1 s; its exact length is not
logged.

Loss test (scratch `reload_under_load.sh`): 60 s of the lookup fixture at 4,000/s
(240,000 events, each producing exactly one alert), control run with no reload, then
the same run with a reload every 10 s; counters before/after plus a count of this
run's alerts in `alerts.json`:
```
== control (0 reloads)
DONE seq=240000 elapsed=60.0s
events_received_delta=240000 events_processed_delta=240000 events_dropped_delta=0 alerts_written_delta=240000 discarded_count_delta=0 udp_rcvbuf_errors_delta=0
alerts_in_file_for_run=240000
== 5 reloads
14:20:42 reload_wall_s=0.938 response={'success': True, 'message': 'ok', 'warnings': [], 'errors': []}
14:20:53 reload_wall_s=0.451 …   14:21:04 reload_wall_s=0.416 …   14:21:15 reload_wall_s=0.479 …   14:21:25 reload_wall_s=0.548 …
DONE seq=240000 elapsed=60.0s
events_received_delta=239981 events_processed_delta=239978 events_dropped_delta=0 alerts_written_delta=239971 discarded_count_delta=0 udp_rcvbuf_errors_delta=28
alerts_in_file_for_run=239971
```

| | sent | received by analysisd | processed | alerts written | lost |
|---|---|---|---|---|---|
| 0 reloads | 240,000 | 240,000 | 240,000 | 240,000 | **0** |
| 5 reloads | 240,000 | 239,981 | 239,978 | 239,971 | **29** (≈6 per reload) |

The 29 split exactly as §1.5 predicts: 19 never reached analysisd (input blocked while the
write lock was held; the container's kernel counted 28 UDP receive-buffer drops in that
run, a counter shared by every UDP socket there), 3 received but never processed
(freed from `decode_queue_event_output`), 7 matched but never written (freed from
`writer_queue_log`). `events_dropped` stayed 0: the drain is not counted as a drop
anywhere. Agent traffic arrives over remoted's TCP/secure channel, not UDP, so its
behaviour while input is blocked differs and is not measured here; the 10 events freed
inside analysisd are lost whatever the transport.

**Result:** reloads are not loss-free in 4.14.8. The loss is small per reload at this
rate and grows with queue depth (a reload near the ceiling frees up to the queue
contents). Fix in 6.1 (§6) before reloads are automated.

### 9.5 File descriptors and mappings leaked per reload

Counted with `docker exec --privileged` (needed to read another uid's `/proc`):
```
before the loss test: pid=120339 total_fds=82 ti_ip_cdb_fds=5  ti_ip_cdb_maps=4
after 5 reloads:      pid=120339 total_fds=92 ti_ip_cdb_fds=10 ti_ip_cdb_maps=9
```
+1 fd and +1 mapping of the 4.2 MB `.cdb` per reload for each list that is looked up
(+10 total: the shipped `malicious-ip` list is also looked up by 99903). Confirms
`os_remove_cdblist()` never closing (§1.5). The fd limit is 458,752
(`/proc/<pid>/limits`), so fds are not the near-term risk. The mappings are: each
reload keeps another full mapping of every list (virtual memory; resident only as pages
are touched). With seven lists of real size and a reload every 15 minutes, that is
~670 stale mappings a day until analysisd restarts.

### 9.6 Worker reload delay (cluster flag path)

On `worker-test`, set the flag the way the API does on a worker
(`set_reload_ruleset_flag(LocalClient())`) and time until `ossec.log` shows
"Ruleset reloaded successfully":
```
08:25:19 flag={'success': True} reload_done_after_s=2.0
08:25:26 flag={'success': True} reload_done_after_s=6.2
08:25:35 flag={'success': True} reload_done_after_s=6.2
08:25:44 flag={'success': True} reload_done_after_s=6.4
08:25:53 flag={'success': True} reload_done_after_s=6.2
2026/11/05 08:25:43 INFO: [Worker worker-test] [Integrity check] Starting.
2026/11/05 08:25:43 INFO: [Worker worker-test] [Integrity check] Finished in 0.011s. Sync not required.
```
2–6.4 s, bounded by the 9 s integrity interval plus the reload itself. File
propagation master → worker was not measured: `worker-test` must not receive test
lists through the main tenant's master (§1.7). It is measured in 6.1 on the split test
cluster (VERIFY 6.1-7).

### 9.7 Clean-up (done)

1. `ossec.conf` restored from the backup taken before the spike; the backup,
   `etc/shadowtracer-spike/` and the scratch scripts in `/tmp` were removed from the
   container.
2. The unread tail of `alerts.json` was checked before rotating: 20,950,633 lines after
   the shipper's offset, all spike lines except one, the hourly analysisd `stats` alert
   (rule 11, 08:00) that the spike's own volume triggered.
3. Rotated with THROUGHPUT_BASELINE §12.6's procedure: manager stopped, day files
   renamed and **kept** (`logs/alerts/2026/Nov/ossec-alerts-05.spike-ti.json`
   24,635,594,592 B and `.log` 11,192,100,003 B), extra links removed, manager started.
4. Shipper started; it switched to the new file by itself:
   ```
   {"alerts.json": {"inode": 45529, "offset": 556}}
   ```
   `cluster_control -l` still lists `worker-test`; both containers healthy.

The renamed spike files (~36 GB) were deleted on the owner's instruction after
revision 2 (see the 6.1a notes).

---

## 10. Phase 6.5 — free default layer, tenant-managed paid sources, selective VirusTotal

Source terms were verified 2026-11-11 and recorded in `LICENSE_INVENTORY.md` §3. Nothing in 6.5
runs on the shipper/writer/correlator hot path; the file-hash work is in ti-sync's worker loop.

### A1 — CIRCL hashlookup free layer (DONE)

The FIM-hash spool (new file hashes from rules 550/554, `custom-shadowtracer-virustotal.py`) is now
a shared funnel queue (`vt_requests`). ti-sync's worker runs a **free CIRCL stage before
VirusTotal** (`vt.VTWorker.free_layer`, `shadowtracer_intel/hashlookup.py`):

- On by default for every tenant (opt out via `ti_tenant_settings.disabled_sources` = `hashlookup`);
  when both the free layer and VirusTotal are off, the spool is discarded unread (nothing leaves).
- Each new hash is bulk-checked against `hashlookup.circl.lu` (`POST /bulk/sha1`, CC-BY). Verdicts
  are cached globally in Postgres `hashlookup_verdicts` (~30-day TTL), so a hash is looked up once.
- A **known-good** file (present, not malicious/low-trust) marks its incident
  (`incidents.known_good` + `known_good_source`, e.g. NSRL). **No TI alert fires and the hash is
  never sent to VirusTotal.** Whether priority is **lowered** depends on the file's location
  (`shadowtracer_intel/paths.py`, shared with the funnel in C): only an **expected install path**
  (`/usr/bin`, `/usr/lib`, `/opt`, … - configurable) with a **non-dual-use name** is down-ranked
  (`known_good_safe`, priority capped at 2). A known-good file in a **high-risk path** (temp, web
  roots, cron/systemd/startup, home downloads) keeps its priority and is labelled "known file in
  unusual location"; a **dual-use tool** (`nc`, `nmap`, `socat`, … - configurable) is never
  down-ranked. `known_good_note` carries the label; the console colours it green (down-ranked) or
  amber (kept). Lab: a known-good file in `/etc/cron.d` kept priority 5 and the unusual-location
  label; the integration test shows the same binary down-ranked in `/usr/bin` and kept in `/tmp`.
- Only hashes CIRCL does not vouch for continue to VirusTotal (opt-in), so known-good OS/software
  files stop dominating the queue and burning VT budget. Attribution (CC-BY) travels with the
  verdict. Lab check: a known-good file → `known_good`, priority 5→2, 0 TI alerts, 0 VT calls.

### A4 — Tor exit node context tag (DONE)

ti-sync refreshes the Tor Project bulk exit list (CC0, `check.torproject.org/torbulkexitlist`,
`tor_exit.refresh`) into `tor_exit_nodes` (hourly; whole-feed rejection if implausibly small; nodes
absent 3 days are dropped). A tagging pass (`tor_exit.tag_incidents`, each ti-sync cycle, bounded to
a 7-day window) sets `incidents.tor_exit_ips` = the incident's source IPs that are Tor exit nodes.
This is **context only**: shown as "Tor exit node: <ip>", low severity, **never an alert on its own
and it does not change priority**. Default on; disable with `TI_TOR_EXIT=0`. Lab: 1252 exit nodes
loaded; an incident with a Tor exit source IP tagged, priority unchanged.

### A2 — local YARA-X scanning (in progress)

**Trigger — native Wazuh active response, no API, no Docker socket.** The scan fires through
Wazuh's own rule-bound active response. A ShadowTracer child of the FIM rules, **rule 110200**
(`<if_sid>550,554</if_sid>`, level 0), matches only when the changed file's path is in a high-risk
location — the `pcre2` from `paths.high_risk_pcre2()`, the same `HIGH_RISK_PATHS` the funnel uses, so
they never drift. `ossec.conf` on the manager binds `<active-response><command>shadowtracer-yara-scan
</command><location>local</location><rules_id>110200</rules_id></active-response>`, so analysisd tells
the alert-generating agent's own `execd` to run the scan. CIRCL known-good no longer gates the scan
(it still sets priority/labels, A1); every high-risk change is scanned — local scans are ~0.31 s.
The script is hardened: stdin JSON, FIM-path confinement with symlink resolution, re-hash-before-
report, no shell, nice + `RLIMIT_CPU` + yr `--cpu-limit`/`-z` size cap/`-a` timeout. The scan writes
one flat JSON line per match to `logs/shadowtracer-yara.log`; the agent's logcollector ships it;
**rule 110201** (`<decoded_as>json</decoded_as>`, `integration ^shadowtracer-yara$`) turns a match
into a level-12 TI alert carrying the YARA rule name, author and tags (DRL 1.1 / GPL-2 attribution).
A YARA match is also a signal into the VirusTotal funnel (C). The analyst-initiated "scan this file"
over the Wazuh API is backlog-only (never the internal ORM) — see OPTIMIZATION_BACKLOG.

**Verification (deterministic, through Wazuh's own components).**
- Scan script, real signature-base match: EICAR in a FIM dir → `yr` match **`SUSP_Just_EICAR` by
  Florian Roth (Nextron Systems)** (signature-base, DRL 1.1), emitted with author/tags/attribution.
- Rule 110201: feeding that exact scan line to `wazuh-logtest` on the worker yields **id 110201,
  level 12**, description "Threat intel (YARA-X): rule SUSP_Just_EICAR by Florian Roth … matched
  /tmp/eicar-scan", groups `ti_high,ti_yara`.
- Rule 110200 predicate: `high_risk_pcre2()` matches every high-risk path (`/tmp/…`, `/var/www/…`,
  `/etc/cron.d/…`, `/root/downloads/…`, `/home/<u>/downloads/…`) and rejects benign paths
  (`/usr/bin/ls`, `/etc/hostname`, …) — asserted in `tests/test_paths.py`.
- Wiring: the agent's merged `ar.conf` carries the `shadowtracer-yara-scan` command, the scan
  binary + `yr` + the 6.78 MB compiled `.yarc` are on the agent, and the manager binds the command
  to rule 110200.

**Lab caveat — realtime FIM delivery.** The live 554→110200→execd→110201 chain could not be shown
end-to-end **in this WSL2+Docker lab** because Wazuh `syscheckd` realtime delivery is selective here:
raw kernel `inotify` delivers `IN_CREATE` for every monitored dir (verified by a `ctypes` probe on
`/tmp`,`/root`,`/var/www`,…), and every dir arms its watch, but `syscheckd` only emits 554 for files
directly in top-level, unshadowed dirs (`/root`,`/home`,`/var/ossec/lab-fim-test`). It does **not**
emit for the `/tmp` family, for `/etc/*` subdirs shadowed by the non-realtime `/etc` in the base
`<syscheck>`, or for subdirs (`/root/downloads`) — exactly the high-risk paths 110200 targets.
This is a lab-environment quirk (kernel inotify works; a normal host delivers these), not a pipeline
defect: each link is verified above. Closing it needs a clean agent recreate on the current image +
a settled baseline (no restarts), or a run on a non-WSL host. Burst test and `image-cache.sh save`
are tracked with it in OPTIMIZATION_BACKLOG.

**Shared-file distribution (check 2).** Compiled rules are distributed to agents via Wazuh
**agent-group shared files**; the agent image holds only the YARA-X binary. 4.14.8 limits:
`MAX_SHARED_PATH = 200` (path length, `src/remoted/remoted.h:28`); **no per-file byte cap** (the
merged file is chunked over the secure channel). Sync: the manager re-merges group files every
`remoted.shared_reload = 10 s` (`etc/internal_options.conf:185`, `src/remoted/config.c:88`) and
pushes the changed merged file on the agent's keepalive, `NOTIFY_TIME = 20 s`
(`src/headers/defs.h:95`) - so a rule update reaches an agent in **≤ ~30 s**. Measured: the FULL
signature-base compiles to a **6.5 MB `.yarc`** (externals `filename/filepath/filetype/extension/
owner` defined at compile, `--ignore-invalid-rules`); a scan is **~0.31 s** with **74 MB peak RSS**;
the agent's own processes use ~58 MB, so a scan peaks ~132 MB, **within the 176 MB agent limit - the
full set fits, no curated subset needed**.

### A3 CISA KEV + EPSS vuln prioritisation — planned

A3 depends on a Wazuh vulnerability-detector finding stream, which ShadowTracer does not yet ingest
(no CVE field in `events`); that ingestion is a prerequisite and is tracked for A3.

### B tenant-managed paid keys · C selective VirusTotal funnel · D throughput gate — planned

The funnel queue (`vt_requests.known_good` / `funnel_reason`) and the free stage are the first two
stages of the selective-VirusTotal funnel (C).
