from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from .config import load_settings
from .version import VERSION
from .db import make_session_factory
from .logging_redact import register_secret, setup_logging
from .routers import agents as agents_router
from .routers import alerts as alerts_router
from .routers import attack_coverage as attack_coverage_router
from .routers import auth as auth_router
from .routers import fingerprints as fingerprints_router
from .routers import health as health_router
from .routers import graph as graph_router
from .routers import incidents as incidents_router
from .routers import ip_lookups as ip_lookups_router
from .routers import campaigns as campaigns_router
from .routers import live as live_router
from .routers import model_assessment as model_assessment_router
from .routers import similar as similar_router
from .routers import paid_sources as paid_sources_router
from .routers import vulnerabilities as vulnerabilities_router
from .routers import ti as ti_router
from .routers import investigation as investigation_router
from .routers import forecast as forecast_router
from .routers import soar as soar_router
from .security_headers import SecurityHeadersMiddleware, install_generic_error_handler


def create_app() -> FastAPI:
    setup_logging()
    settings = load_settings()
    register_secret(settings.jwt_secret)

    app = FastAPI(title="ShadowTracer console API", version=VERSION)
    app.state.settings = settings
    app.state.session_factory = make_session_factory(settings)

    install_generic_error_handler(app)
    app.add_middleware(SecurityHeadersMiddleware)
    # Explicit CORS - no wildcard, no default-allow. Empty list means no
    # cross-origin access at all until deploy/lab (Step 7) sets
    # CORS_ALLOW_ORIGINS to the real console origin.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.include_router(auth_router.router)
    app.include_router(health_router.router)
    app.include_router(alerts_router.router)
    app.include_router(incidents_router.router)
    app.include_router(ti_router.router)
    app.include_router(paid_sources_router.router)
    app.include_router(ip_lookups_router.router)
    app.include_router(graph_router.router)
    app.include_router(fingerprints_router.router)
    app.include_router(agents_router.router)
    app.include_router(attack_coverage_router.router)
    app.include_router(vulnerabilities_router.router)
    app.include_router(live_router.router)
    app.include_router(campaigns_router.router)
    app.include_router(investigation_router.router)
    app.include_router(forecast_router.router)
    app.include_router(soar_router.router)
    app.include_router(similar_router.router)
    app.include_router(model_assessment_router.router)

    @app.on_event("startup")
    def _warm_llm() -> None:
        # Best-effort: load the investigation model into VRAM at startup (same options real calls use)
        # so the first investigation doesn't pay the cold load_duration. Non-blocking; a down LLM is fine.
        import threading
        from .investigation.llm import LLMClient

        def _go():
            try:
                LLMClient(base_url=settings.llm_base_url, model=settings.llm_model,
                          api_key=settings.llm_api_key, timeout_seconds=settings.llm_timeout_seconds,
                          num_ctx=settings.llm_num_ctx, max_tokens=settings.llm_max_tokens,
                          keep_alive=settings.llm_keep_alive).warmup()
            except Exception:                        # noqa: BLE001 - warm-up is advisory, never fatal
                pass
        threading.Thread(target=_go, daemon=True).start()

    return app


app = create_app()
