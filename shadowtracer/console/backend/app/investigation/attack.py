"""ATT&CK technique id -> name + tactics, from a compact precomputed map (data/techniques.json,
derived once from the bundled MITRE STIX). Loaded lazily and cached, so the 160m console container
never parses the 28 MB STIX at request time."""
from __future__ import annotations

import functools
import json
import os

_DATA = os.path.join(os.path.dirname(__file__), "data", "techniques.json")


@functools.lru_cache(maxsize=1)
def _index() -> dict:
    try:
        with open(_DATA, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def technique_info(technique_id: str) -> dict | None:
    """-> {"id","name","tactics"} or None. Falls back to the parent technique for a sub-technique."""
    idx = _index()
    hit = idx.get(technique_id) or idx.get(technique_id.split(".", 1)[0])
    if not hit:
        return None
    return {"id": technique_id, "name": hit["name"], "tactics": hit.get("tactics", [])}
