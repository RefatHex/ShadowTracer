"""Anti-spoof by provenance (Phase 9 follow-up A4). An IP is blockable only if it reached us through a
NETWORK-LAYER decoder field — the normalized src_endpoint_ip of a trusted decoder — not because it was
parsed out of user-controllable text (a username, URL, message body). A log-injection line such as
`Failed password for invalid user "x from 10.0.0.5 port 22"` puts 10.0.0.5 in the username field, never
in src_endpoint_ip of a trusted decoder, so it is never blockable here. The count check (anti_spoof_ok)
stays as an extra condition on top of this.

TRUSTED_DECODERS is the explicit (decoder -> its src_endpoint_ip is network-layer) allowlist. Our
pipeline only ever fills src_endpoint_ip from the decoder's own srcip field, so the discriminator is the
decoder name. Extend the set as new network decoders are deployed.
"""

TRUSTED_DECODERS = frozenset({
    "sshd", "pam", "sudo", "dropbear", "telnetd",
    "vsftpd", "pure-ftpd", "proftpd",
    "web-accesslog", "apache-errorlog", "nginx", "apache",
    "iptables", "firewalld", "pf", "netscreenfw", "cisco-asa", "sonicwall", "pix",
    "postfix", "sendmail", "sasl", "dovecot",
    "windows", "win-security",
})


def blockable_ips(ch_client, tenant_key: str, alert_ids: list[str]) -> set[str]:
    """IPs that appear as src_endpoint_ip under a trusted decoder among the incident's alerts."""
    if not alert_ids:
        return set()
    rows = ch_client.query(
        "SELECT DISTINCT src_endpoint_ip FROM events "
        "WHERE tenant_id = {t:String} AND alert_id IN {ids:Array(String)} "
        "AND decoder_name IN {dec:Array(String)} AND src_endpoint_ip != ''",
        parameters={"t": tenant_key, "ids": alert_ids, "dec": list(TRUSTED_DECODERS)},
    ).result_rows
    return {r[0] for r in rows}


def make_default_fn(settings):
    """Build the live provenance lookup (tenant_key, alert_ids) -> set[ip] from a ClickHouse client.
    Best-effort: on any ClickHouse error, returns an empty set (nothing is blockable rather than
    wrongly blocking) — containment then needs TI/approval, never a silent over-block."""
    import clickhouse_connect

    def fn(tenant_key: str, alert_ids: list[str]) -> set[str]:
        try:
            client = clickhouse_connect.get_client(
                host=settings.clickhouse_host, port=settings.clickhouse_port,
                username=settings.clickhouse_user, password=settings.clickhouse_password,
                database=settings.clickhouse_database)
            return blockable_ips(client, tenant_key, alert_ids)
        except Exception:                                    # noqa: BLE001
            return set()
    return fn
