# Phase 7.8 demo: a clearly-labelled "attacker" box for the recorded demo only.
# It holds an SSH client and nothing else; the brute-force loop lives in
# deploy/demo/demo-scenario.sh (docker exec), so what it does is visible in the
# script, not baked into an image. Only ever runs under the compose "demo" profile
# against the TEST tenant's lab agent. Not an attack tool: a loop of failed SSH
# logins, exactly what deploy/lab/smoke-test.sh already does, to light up the pipeline.
FROM alpine:3.20
RUN apk add --no-cache openssh-client
LABEL org.shadowtracer.role="demo-attacker" \
      org.shadowtracer.purpose="recorded-demo SSH brute-force against the TEST lab agent only"
# idle; driven by demo-scenario.sh via `docker exec`
CMD ["sleep", "infinity"]
