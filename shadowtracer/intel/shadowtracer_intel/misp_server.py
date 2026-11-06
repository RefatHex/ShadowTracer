"""Tenant MISP server connector (6.2): one tenant's own MISP instance, URL + API key per
tenant, pulled by ti-sync with PyMISP. Only to_ids attributes of the matchable types.
Everything it imports is that tenant's private intel (tenant_key set), whatever its TLP,
so TLP:AMBER/RED never leaves the tenant (store.apply_observations, listgen).

NOT TESTED AGAINST A LIVE MISP SERVER: tests drive the real PyMISP client against HTTP
responses written from the MISP REST API documentation (attributes/restSearch), not
recorded from a running instance - the lab runs no MISP container (memory).
"""

from .feeds import MISP_TYPES, FeedError, misp_attributes_to_observations

PAGE_SIZE = 1000
MAX_PAGES = 100


def fetch(url: str, key: str, since: int = None, verify_tls: bool = True, client=None,
          page_size: int = PAGE_SIZE, max_pages: int = MAX_PAGES) -> tuple:
    """-> (observations, new cursor). since: attribute timestamp (epoch seconds) of the
    last sync; MISP returns attributes with timestamp >= since, so the newest one is
    seen again next time (idempotent upsert) and nothing in the same second is missed."""
    try:
        if client is None:
            from pymisp import PyMISP
            client = PyMISP(url, key, ssl=verify_tls, timeout=60)
        obs, newest = [], since
        for page in range(1, max_pages + 1):
            res = client.search(controller="attributes", to_ids=1, type_attribute=sorted(MISP_TYPES),
                                timestamp=since, include_event_tags=True, deleted=False,
                                limit=page_size, page=page, pythonify=False)
            if isinstance(res, dict) and res.get("errors"):
                raise FeedError(f"misp server: {str(res['errors'])[:300]}")
            attrs = res.get("Attribute") if isinstance(res, dict) else None
            if not isinstance(attrs, list):
                raise FeedError("misp server: expected {Attribute: [...]} from attributes/restSearch")
            for a in attrs:
                ev = a.get("Event") or {}
                ev_url = f"{url.rstrip('/')}/events/view/{ev.get('id', a.get('event_id', ''))}"
                obs += misp_attributes_to_observations([a], {"uuid": ev.get("uuid"), "info": ev.get("info"),
                                                             "threat_level_id": ev.get("threat_level_id")},
                                                       ev_url, default_tlp="amber")
                ts = int(a.get("timestamp") or 0)
                newest = max(newest or 0, ts) or None
            if len(attrs) < page_size:
                return obs, (str(newest) if newest else None)
        raise FeedError(f"misp server: more than {max_pages} pages of {page_size}")
    except FeedError:
        raise
    except Exception as exc:  # noqa: BLE001 - PyMISP/requests errors are feed failures: keep the last good data
        raise FeedError(f"misp server {url}: {type(exc).__name__}: {str(exc)[:300]}") from exc
