Drafted for submission to github.com/wazuh/wazuh. Not filed - this fork
has no standing to file on the user's behalf. Written so it's ready to
paste in once reviewed.

---

**Title:** Agent silently drops a queued message when `send_msg()` fails
in `dispatch_buffer()`

**Component:** `src/client-agent/buffer.c`

**Summary:**

`dispatch_buffer()` pops a message off the agent's internal anti-flooding
buffer and attempts to send it, but discards the message unconditionally
afterward, regardless of whether `send_msg()` actually succeeded:

```c
if (msg_output != NULL) {
    send_msg(msg_output, -1);
    os_free(msg_output);
    buffer[original_j_for_nulling] = NULL;
}
```

`send_msg()`'s return value (0 on success, non-zero on failure - see
`src/client-agent/sendmsg.c`) is never checked. A send that fails here -
for example, because the agent's connection to its current server has
already died but `os_wait()`'s connection-loss lock (set by a *separate*
code path, `receiver.c`'s `receive_msg()` noticing the read side fail)
hasn't engaged yet - is silently lost. The event this message represents
never reaches any manager.

**Reproduction:**

1. Connect an agent to a manager with a second `<server>` entry configured
   for failover.
2. Stop the primary manager (`docker stop`/equivalent) while the agent has
   several events in flight.
3. Generate a steady stream of events (e.g. repeated failed SSH logins) for
   the duration of the failover.
4. Compare events generated vs. events that arrive at the fallback server.

We measured 19 of 20 events delivered in this scenario (1 silently lost)
before the fix below, and 20 of 20 after.

**Suggested fix:**

Requeue the message via the existing `buffer_append()` instead of
unconditionally freeing it:

```c
if (msg_output != NULL) {
    if (send_msg(msg_output, -1) != 0) {
        buffer_append(msg_output);
    }
    os_free(msg_output);
    buffer[original_j_for_nulling] = NULL;
}
```

`buffer_append()` copies the message internally (`strdup`), so freeing
`msg_output` afterward is safe either way.

**Trade-off to flag in review:** a message whose `send_msg()` call failed
but whose data had, in some edge case, already reached the manager (e.g. a
response-read failure after a successful write) will now be resent. The
manager treats this as a new event with a new `id` - there is no
application-level idempotency key on this path today. We believe a
possible duplicate is clearly preferable to a silent loss for a security
product, but flagging it since it changes observable behavior (occasional
duplicate alerts after a flaky connection) that wasn't present before.

**Patch:** see the diff in this fork's `src/client-agent/buffer.c` (search
history for "Phase 3 follow-up" in the commit log) - happy to open a PR
with the equivalent change against a clean checkout if maintainers want it
in that form instead.
