# ShadowTracer demo runbook (Phase 7.8)

A scripted, repeatable demo of the live pipeline for a recorded screen presentation. Everything
runs against the **TEST tenant** (`shadowtracer-lab-test`) and its lab agent `agent-ubuntu-1`
(id 060) on the test manager `shadowtracer-worker-test`. The attacker, the scenario steps, the fast
incident close, and the big-screen **Live view** are all built for this.

> Atomic Red Team steps are run by the owner's own `st-record` script and are **not** part of this
> runbook. The `replay` step below replays a *recorded* public dataset, which is different.

## 0. One-time setup

```bash
cd deploy/lab
# a console admin for the TEST tenant (prompts for a password):
docker exec -it shadowtracer-lab-console-backend-1-1 python cli.py create-admin \
    --tenant shadowtracer-lab-test --email demo@test.lab
# the attacker box (compose "demo" profile - not part of a normal bring-up):
docker compose --profile demo up -d demo-attacker
```

Open the console at <https://localhost:8443>, sign in as `demo@test.lab`, click **Live** (or go to
`#/live`). Put that on the big screen. It polls every 3 s.

## 1. Reset (start of every take)

```bash
deploy/demo/demo-reset.sh
```

- Removes demo-tagged events and closes the TEST tenant's open incidents so the Live view starts
  calm (it never touches another tenant, and leaves real history intact).
- Prints a **container health table** - every row should be `running` / `healthy`. If any row has
  `<--`, fix that container before recording (`docker compose up -d <svc>`).
- Writes a fresh **run-id** (`deploy/demo/.demo_run_id`) that every later step tags its data with.

**Expected:** "all containers running / healthy" and "READY · new run-id demo-YYYYMMDD-HHMMSS".

## 2. Warm up the model (optional, background)

```bash
deploy/demo/demo-warmup.sh          # ~25 ev/s benign traffic for 10 min, backgrounded
# later: deploy/demo/demo-warmup.sh stop
```

Gives the anomaly model a recent baseline so the attack bursts stand out. **Expected:** Live view's
*Events / min* rises to ~25 and *Stored* climbs. Leave it running during the demo.

## 3. (Optional) turn on fast incident close

In the console Live view, as an admin, click **fast close (60s)**. The badge changes to
`Demo mode: fast close 60s`. Incidents now close ~1 min after they go quiet, so the audience sees
them open **and** close within the demo. Default is off (global 10-min gap). Turn it off again with
the same button.

## 4. Scenario steps

Run each when you want it; each prints a big banner and confirms it fired.

| Step | Command | What the audience sees | Expected result |
|------|---------|------------------------|-----------------|
| **Brute force** | `deploy/demo/demo-scenario.sh brute` | *Live alerts* fill with `sshd: Attempt to login using a non-existent user` (rule 5710); an incident appears on agent 060 | ">= 10 events for the run-id" + an incident (`graph →`) |
| **EICAR → TI** | `deploy/demo/demo-scenario.sh eicar` | a red **Threat intel (high confidence)** hit: `FIM file sha256 275a021b… is a known indicator` (rule 110012) | ">= 1 event for `<run-id>-eicar`" within ~60 s |
| **Replay** | `deploy/demo/demo-scenario.sh replay` | ~700 Windows EVTX events land as a dedicated replay agent; a new incident | "replay finished" with an event count |
| **Load** | `deploy/demo/demo-scenario.sh load` | *Events / min* jumps toward 500×60; *Stored* climbs fast; the pipeline counters all move | ">= 100 events for `load-<run-id>`" |

Click any incident's **graph →** in the Live view to open its attack graph.

## 5. End

Turn off fast close (step 3), stop the warmup (`deploy/demo/demo-warmup.sh stop`), and optionally
`deploy/demo/demo-reset.sh` again to leave the tenant clean. Stop the attacker box with
`docker compose --profile demo stop demo-attacker` if you want it gone.

## If a step doesn't fire

- **Brute force — no alerts.** Is the attacker box up? `docker compose --profile demo up -d
  demo-attacker`. Confirm the victim logs it: `docker exec shadowtracer-lab-agent-ubuntu-1-1 tail
  /var/log/auth.log` (expect `Invalid user demo-… from …`). The agent forwards `auth.log`; the
  alert is rule 5710.
- **EICAR — no TI hit.** FIM realtime is unreliable in WSL, so the step forces a scan with
  `agent_control -r -u 060` (no restart). If nothing fires, re-run the step; confirm the EICAR
  sha256 is still in `etc/lists/shadowtracer-ti/sha256-high` on the manager.
- **Replay — nothing.** The recorded datasets must be present under `ST_DATA`
  (`/home/refat/st-data/datasets`); list them with
  `cd shadowtracer/ml && .venv/bin/python -m shadowtracer_ml.replay --plan`.
- **Load — no climb.** The generator runs in a throwaway container on the lab network (the host
  can't write the root-owned `alerts.json`); check Docker can pull `python:3.12-slim`. The mem guard
  aborts (exit 3) if the host drops below ~1.5 GB free.
- **Live view stages show "—" for Agent events / Alerts.** `LIVE_SHIPPER_METRICS_URL` must point at
  the test shipper's metrics (`http://shipper-worker-test:9101/`); *Stored* and *Incidents* come
  straight from the stores and are always correct.
- **General.** `deploy/demo/demo-reset.sh` prints the container health table - start there.
