from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from .config import load_settings
from .db import make_session_factory
from .logging_redact import register_secret, setup_logging
from .routers import agents as agents_router
from .routers import alerts as alerts_router
from .routers import auth as auth_router
from .routers import fingerprints as fingerprints_router
from .routers import health as health_router
from .routers import incidents as incidents_router
from .security_headers import SecurityHeadersMiddleware, install_generic_error_handler


def create_app() -> FastAPI:
    setup_logging()
    settings = load_settings()
    register_secret(settings.jwt_secret)

    app = FastAPI(title="ShadowTracer console API")
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
    app.include_router(fingerprints_router.router)
    app.include_router(agents_router.router)

    return app


app = create_app()
