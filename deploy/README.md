# deploy/

Deployment configuration and infrastructure for ShadowTracer (containers,
compose/orchestration manifests, environment configs).

## Syslog sources: use TCP

Point network devices and syslog relays at the manager over **TCP**, not UDP.
UDP has no back-pressure: when the manager falls behind, the kernel drops datagrams
before Wazuh sees them, and nothing in ShadowTracer counts them as lost. Measured on
the lab (2026-11-05, `shadowtracer/docs/OPTIMIZATION_BACKLOG.md` T12): 4,561 of 240,000
events lost at 4,000/s over UDP with no reloads; 0 lost over TCP in every run. Agents
are unaffected (they use their own TCP channel).

Manager `ossec.conf`, one block per protocol (Wazuh refuses `tcp,udp` on a syslog
block):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>10.0.0.0/8</allowed-ips>   <!-- only the senders you expect -->
</remote>
```

remoted frames TCP syslog on newlines (one message per line, `src/remoted/syslogtcp.c`).
Keep a UDP block only for devices that cannot send TCP, and size the host so the
manager stays below its measured ceiling. In the lab, the test manager listens on
5514/udp and 5515/tcp (`LOAD_TEST_SYSLOG_PORT`, `LOAD_TEST_SYSLOG_TCP_PORT`).
