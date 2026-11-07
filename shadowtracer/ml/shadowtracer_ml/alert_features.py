"""Per-ALERT streaming features for the 7.1 anomaly scorer (ml-scorer). ONE shared module -
the scorer computes them live and the offline evaluation recomputes them the same way.

Every value is in [0, 1] (HalfSpaceTrees needs a bounded space). No source-revealing field: no
agent id/name, tenant, node, manager, location, decoder, dataset or raw IP string. Unlike the
7.0 incident features, time-of-day IS a feature here - a live stream's clock is real behaviour,
not a replay artefact - so the forbidden list below allows it while still banning identity.

State is per agent and BOUNDED: an EWMA alert rate, and two capped LRU sets (seen users, seen
source IPs) for the first-seen flags. The number of agents tracked is capped too, so memory has
a hard ceiling (MAX_AGENTS * (2 * LRU_CAP) entries). Bump ALERT_FEATURE_VERSION on any change.
"""
import datetime as dt
import ipaddress
import math
from collections import OrderedDict

ALERT_FEATURE_VERSION = "a1"
GROUP_BUCKETS = 12            # rule groups feature-hashed into this many presence features
LRU_CAP = 512                # distinct users / source IPs remembered per agent
MAX_AGENTS = 4096            # agents tracked at once (LRU); bounds total memory
RATE_HALFLIFE = 60.0         # seconds; EWMA alert-rate half-life per agent

FEATURE_NAMES = tuple(["level", "clock_sin", "clock_cos", "week_sin", "week_cos", "local_rate",
                       "ip_none", "ip_private", "ip_public", "first_seen_user", "first_seen_srcip"]
                      + [f"g{i}" for i in range(GROUP_BUCKETS)])
# A feature name containing any of these would leak where the alert came from.
FORBIDDEN_SUBSTRINGS = ("agent", "tenant", "dataset", "replay", "node", "manager", "cluster",
                        "decoder", "host", "name", "location", "addr")


def _as_dt(v) -> dt.datetime:
    if isinstance(v, dt.datetime):
        d = v
    else:
        d = dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def _ip_class(ip: str) -> str:
    if not ip or ip in ("-", "0.0.0.0", "::"):
        return "none"
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "none"
    return "private" if (a.is_private or a.is_loopback or a.is_link_local) else "public"


class AgentState:
    """Bounded per-agent memory: EWMA alert rate + LRU seen-sets."""
    __slots__ = ("last_t", "rate", "users", "ips")

    def __init__(self):
        self.last_t = None
        self.rate = 0.0
        self.users = OrderedDict()
        self.ips = OrderedDict()

    def _seen(self, store: OrderedDict, key: str) -> bool:
        """True if key was already present; records it (LRU, capped). Empty key is never 'new'."""
        if not key or key == "-":
            return True
        new = key not in store
        store[key] = None
        store.move_to_end(key)
        if len(store) > LRU_CAP:
            store.popitem(last=False)
        return not new

    def update(self, t: dt.datetime) -> float:
        """Advance the EWMA rate (alerts/sec) to time t and return it."""
        if self.last_t is not None:
            gap = max((t - self.last_t).total_seconds(), 0.0)
            self.rate *= 0.5 ** (gap / RATE_HALFLIFE)
        self.last_t = t
        self.rate += 1.0 / RATE_HALFLIFE
        return self.rate


class StreamState:
    """Per-tenant: a bounded LRU of AgentState. One per model/tenant in the scorer."""
    def __init__(self):
        self.agents = OrderedDict()

    def get(self, agent_id: str) -> AgentState:
        st = self.agents.get(agent_id)
        if st is None:
            st = self.agents[agent_id] = AgentState()
        self.agents.move_to_end(agent_id)
        if len(self.agents) > MAX_AGENTS:
            self.agents.popitem(last=False)
        return st


def compute(event, state: StreamState) -> dict:
    """event: a NormalizedEvent (or any object with rule_level, rule_groups, time, agent_id,
    src_endpoint_ip, actor_user, target_user). Mutates `state` (first-seen, rate). -> {name: [0,1]}."""
    st = state.get(event.agent_id)
    t = _as_dt(event.time)
    rate = st.update(t)
    user = event.actor_user or event.target_user or ""
    ipc = _ip_class(event.src_endpoint_ip)
    seen_user = st._seen(st.users, user)
    seen_ip = st._seen(st.ips, event.src_endpoint_ip)
    secs = t.hour * 3600 + t.minute * 60 + t.second
    f = {
        "level": min(max(int(event.rule_level or 0), 0), 15) / 15.0,
        "clock_sin": (math.sin(2 * math.pi * secs / 86400) + 1) / 2,
        "clock_cos": (math.cos(2 * math.pi * secs / 86400) + 1) / 2,
        "week_sin": (math.sin(2 * math.pi * t.weekday() / 7) + 1) / 2,
        "week_cos": (math.cos(2 * math.pi * t.weekday() / 7) + 1) / 2,
        "local_rate": rate / (rate + 1.0),                 # (0,1), saturating
        "ip_none": 1.0 if ipc == "none" else 0.0,
        "ip_private": 1.0 if ipc == "private" else 0.0,
        "ip_public": 1.0 if ipc == "public" else 0.0,
        "first_seen_user": 0.0 if seen_user else 1.0,
        "first_seen_srcip": 0.0 if seen_ip else 1.0,
    }
    for i in range(GROUP_BUCKETS):
        f[f"g{i}"] = 0.0
    for g in (event.rule_groups or []):
        f[f"g{hash_group(g)}"] = 1.0
    assert set(f) == set(FEATURE_NAMES)
    return f


def hash_group(group: str) -> int:
    """Stable (cross-process) feature hash of a rule-group name into [0, GROUP_BUCKETS)."""
    import hashlib
    return int(hashlib.md5(group.encode()).hexdigest(), 16) % GROUP_BUCKETS


_leaks = [n for n in FEATURE_NAMES if any(s in n for s in FORBIDDEN_SUBSTRINGS)]
if _leaks:
    raise ImportError(f"source-revealing alert-feature names: {_leaks}")
