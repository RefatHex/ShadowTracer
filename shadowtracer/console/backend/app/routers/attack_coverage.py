"""Phase 5B Step 2: ATT&CK static coverage map - technique -> rule ids ->
tactic, built from the inherited ruleset's own MITRE tags only (see
shadowtracer_ingest.ruleset, imported the same way
shadowtracer_correlate/consumer.py already imports .normalizer - a
sys.path insert, never duplicated).

This is explicitly "rules that EXIST for a technique", never "attacks we
DETECT" - no claim of tested coverage is made or implied anywhere in this
response. Tested coverage (Atomic Red Team, firing real techniques
against real agents and confirming a real alert) is Phase 5D's job, not
this one. The label field below is not decoration - every console/API
consumer of this endpoint should surface it verbatim.
"""

import functools
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "ingest"))
from shadowtracer_ingest.ruleset import attack_coverage_map  # noqa: E402

from fastapi import APIRouter, Depends

from ..deps import get_settings
from ..rbac import ALL_ROLES

router = APIRouter(prefix="/api", tags=["attack-coverage"])

COVERAGE_LABEL = (
    "Rules that exist for this technique in the inherited Wazuh ruleset - "
    "NOT a claim that ShadowTracer detects this technique in practice. "
    "Tested detection coverage is validated separately (Phase 5D, Atomic Red Team)."
)


@functools.lru_cache(maxsize=1)
def _cached_coverage_map(ruleset_dir: str, mitre_json_path: str) -> dict:
    # ruleset_dir/mitre_json_path are fixed per process (Settings, loaded
    # once at startup) - caching here avoids re-parsing 168 XML files and
    # re-walking the 27 MB MITRE bundle on every request to a read-only
    # reference endpoint that can't change without a process restart.
    return attack_coverage_map(ruleset_dir, mitre_json_path)


@router.get("/attack-coverage")
def get_attack_coverage(settings=Depends(get_settings), current_user=Depends(ALL_ROLES)):
    coverage = _cached_coverage_map(settings.ruleset_dir, settings.mitre_json_path)
    return {
        "label": COVERAGE_LABEL,
        "technique_count": len(coverage),
        "techniques": coverage,
    }
