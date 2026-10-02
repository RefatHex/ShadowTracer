"""Step 3's required test: enumerate EVERY route automatically and fail
if any lacks a role assertion. A route passes only if its dependency tree
contains a RequireRole instance (real enforcement) or the explicit
mark_public marker (a deliberate, visible opt-out) - there is no third,
silent way to be exempt.
"""

from fastapi.routing import APIRoute

from app.main import create_app
from app.rbac import RequireRole, mark_public


def _route_dependency_calls(route: APIRoute):
    """Flattens a route's full dependant tree (FastAPI/Starlette nests
    sub-dependencies under dependant.dependencies) into the list of
    callables actually used as dependencies."""
    calls = []

    def walk(dependant):
        calls.append(dependant.call)
        for sub in dependant.dependencies:
            walk(sub)

    walk(route.dependant)
    return calls


def _is_compliant(route: APIRoute) -> bool:
    calls = _route_dependency_calls(route)
    has_role_check = any(isinstance(c, RequireRole) for c in calls)
    has_public_marker = any(c is mark_public for c in calls)
    return has_role_check or has_public_marker


def test_every_route_has_a_role_assertion_or_an_explicit_public_marker():
    app = create_app()
    api_routes = [r for r in app.routes if isinstance(r, APIRoute)]
    assert api_routes, "no routes registered - this test would pass vacuously, which defeats its purpose"

    violations = [r.path for r in api_routes if not _is_compliant(r)]
    assert not violations, (
        f"these routes have neither a RequireRole dependency nor an explicit "
        f"Depends(mark_public) marker: {violations}"
    )


def test_enumeration_test_actually_catches_a_missing_role_assertion():
    """Proves the test above isn't vacuous: build a throwaway app with one
    deliberately non-compliant route and confirm the SAME compliance logic
    flags it. This is what "fails when a role is removed, then passes
    when restored" looks like without mutating the real app's routes."""
    from fastapi import FastAPI

    app = FastAPI()

    @app.get("/deliberately-unprotected")
    def unprotected():
        return {"oops": "no role check and no mark_public"}

    api_routes = [r for r in app.routes if isinstance(r, APIRoute)]
    violations = [r.path for r in api_routes if not _is_compliant(r)]
    assert violations == ["/deliberately-unprotected"]

    # Now "restore" it with an explicit public marker and confirm it passes.
    from fastapi import Depends

    app2 = FastAPI()

    @app2.get("/now-marked-public", dependencies=[Depends(mark_public)])
    def now_public():
        return {"ok": True}

    api_routes2 = [r for r in app2.routes if isinstance(r, APIRoute)]
    violations2 = [r.path for r in api_routes2 if not _is_compliant(r)]
    assert violations2 == []
