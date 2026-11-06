"""Scheduled NORMAL activity on the test tenant's Linux lab agent (Phase 7.0): ordinary
administration that looks like attack techniques (benign look-alikes), so models must learn
the difference. Every run is recorded in attack_runs (tool normal, label benign, technique =
the ATT&CK id it resembles) and undone afterwards. Runs through `docker exec` (lab only).

  python -m shadowtracer_ml.normal_activity once [--action NAME]
  python -m shadowtracer_ml.normal_activity loop          # NORMAL_INTERVAL_SECONDS (1200) +- 30%
"""
import argparse
import datetime as dt
import logging
import os
import random
import subprocess
import sys
import time

from sqlalchemy import text

from . import db, recorder

log = logging.getLogger("normal-activity")
AGENT = os.environ.get("NORMAL_AGENT", "agent-ubuntu-1")
CONTAINER = os.environ.get("NORMAL_CONTAINER", "shadowtracer-lab-agent-ubuntu-1-1")
SETTLE_SECONDS = 20          # let logs/FIM reach the manager inside the recorded window

# name -> (look-alike ATT&CK id, description, [commands], [undo commands]). Benign admin only.
ACTIONS = {
    "service-account": ("T1136.001", "create and remove a system service account",
                        ["useradd -r -M -s /usr/sbin/nologin -c 'backup service' svc-backup"],
                        ["userdel svc-backup"]),
    "cron-maintenance": ("T1053.003", "add and remove a log-rotation cron job",
                         ["printf '17 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf\\n' > /etc/cron.d/st-logrotate"],
                         ["rm -f /etc/cron.d/st-logrotate"]),
    "sudo-admin": ("T1548.003", "an admin runs a package query through sudo",
                   ["id stadmin >/dev/null 2>&1 || useradd -m -s /bin/bash stadmin",
                    "printf 'stadmin ALL=(root) NOPASSWD: /usr/bin/apt-cache\\n' > /etc/sudoers.d/stadmin && chmod 440 /etc/sudoers.d/stadmin",
                    "su - stadmin -c 'sudo -n /usr/bin/apt-cache policy bash' >/dev/null"],
                   []),
    "ssh-typo": ("T1110.001", "a user mistypes their login name once or twice",
                 ["ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 rooot@localhost true || true",
                  "sleep 3; ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 stadmn@localhost true || true"],
                 []),
    "package-install": ("T1105", "install and remove a small package",
                        ["DEBIAN_FRONTEND=noninteractive apt-get install -y -q tree >/dev/null 2>&1 || true"],
                        ["DEBIAN_FRONTEND=noninteractive apt-get purge -y -q tree >/dev/null 2>&1 || true"]),
    "bashrc-alias": ("T1546.004", "an admin adds a shell alias",
                     ["printf \"alias ll='ls -alF'  # st-normal\\n\" >> /root/.bashrc"],
                     ["sed -i '/# st-normal$/d' /root/.bashrc"]),
    "key-rotation": ("T1098.004", "an admin rotates their own SSH key",
                     ["id stadmin >/dev/null 2>&1 || useradd -m -s /bin/bash stadmin",
                      "su - stadmin -c 'mkdir -p ~/.ssh && rm -f ~/.ssh/id_st ~/.ssh/id_st.pub && ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_st "
                      "&& cat ~/.ssh/id_st.pub > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'"],
                     []),
    "sudoers-dropin": ("T1548.003", "an admin delegates package queries to an ops group",
                       ["getent group ops >/dev/null || groupadd ops",
                        "printf '%%ops ALL=(root) /usr/bin/apt-cache\\n' > /etc/sudoers.d/ops && chmod 440 /etc/sudoers.d/ops"],
                       ["rm -f /etc/sudoers.d/ops"]),
}


def run_in_agent(cmd: str, container: str = CONTAINER) -> int:
    return subprocess.run(["docker", "exec", container, "sh", "-c", cmd], capture_output=True, timeout=300).returncode


def run_action(engine, name: str, settle: float = SETTLE_SECONDS, execute=run_in_agent) -> str:
    technique, desc, cmds, undo = ACTIONS[name]
    with engine.begin() as conn:
        run_id = recorder.start(conn, db.test_tenant(), "normal", AGENT, technique=technique, test_name=name,
                                recorded_by="normal-activity", details={"description": desc})
    rcs = [execute(c) for c in cmds]
    time.sleep(settle / 2)
    rcs += [execute(c) for c in undo]
    time.sleep(settle)
    with engine.begin() as conn:
        recorder.stop(conn, run_id)
        conn.execute(text("UPDATE attack_runs SET details = details || CAST(:d AS jsonb) WHERE run_id = :r"),
                     {"d": f'{{"exit_codes": {rcs}}}', "r": run_id})
    log.info("normal activity %s (%s): run %s exit codes %s", name, technique, run_id, rcs)
    return run_id


def recover(engine, execute=run_in_agent) -> int:
    """After a restart: a run cut off mid-action is marked aborted (never labelled) and every undo
    runs, so no look-alike change is left behind on the agent."""
    with engine.begin() as conn:
        n = conn.execute(text("UPDATE attack_runs SET status = 'aborted', ended_at = now() WHERE tool = 'normal' "
                              "AND status = 'running' AND agent = :a"), {"a": AGENT}).rowcount
    for _, _, _, undo in ACTIONS.values():
        for c in undo:
            execute(c)
    return n


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("mode", choices=["once", "loop"])
    p.add_argument("--action", choices=sorted(ACTIONS))
    a = p.parse_args(argv)
    engine = db.engine()
    if a.mode == "once":
        print(run_action(engine, a.action or random.choice(sorted(ACTIONS))))
        return 0
    recover(engine)
    interval = float(os.environ.get("NORMAL_INTERVAL_SECONDS", "1200"))
    names = sorted(ACTIONS)
    i = 0
    while True:
        try:
            run_action(engine, names[i % len(names)])
        except Exception:  # noqa: BLE001 - one failed action never stops the schedule
            log.exception("normal activity failed")
        i += 1
        time.sleep(interval * random.uniform(0.7, 1.3))


if __name__ == "__main__":
    sys.exit(main())
