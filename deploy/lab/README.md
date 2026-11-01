# Lab compose stack

Bring-up: `cp .env.example .env`, fill it in, `docker compose up -d`.

## VM step override (Phase 5C-1, Hyper-V/WSL2)

`docker-compose.yml` keeps the manager's enrollment port (1515) and the dedicated
test worker's event port (1514) internal to the lab network by default - a real
external VM (not a lab container) can't reach them that way.

If you have a Hyper-V VM on the host's Default Switch enrolling against this lab:

```
cp docker-compose.vm.yml.example docker-compose.vm.yml
docker compose -f docker-compose.yml -f docker-compose.vm.yml up -d
```

This publishes those two ports on `0.0.0.0` instead of staying internal, so the VM
can reach them via the Windows host's own IP (WSL2's localhostForwarding relays it
in). `docker-compose.vm.yml` is gitignored - it's host-specific (binds to every
interface, not just loopback) and should never be the default for anyone who
doesn't actually have a VM in the picture.

**Enrollment is already password-protected regardless of this override**:
`entrypoint-manager.sh` unconditionally flips authd's `use_password` to `yes` and
writes `authd.pass` from `ENROLL_PASSWORD` (`.env`). Exposing the port more broadly
does not relax that - a VM enrolling through this override still needs the same
`ENROLL_PASSWORD` value, passed to `agent-auth -P` the same way every lab agent
container already does it.

Re-check `netsh int ipv4 show excludedportrange protocol=tcp` on the Windows host
before trusting 1514/1515 are free, if the override ever stops binding - Hyper-V has
intermittently reserved these exact ports before via Windows's own dynamic-port
exclusion behavior, not a config mistake in this repo.
