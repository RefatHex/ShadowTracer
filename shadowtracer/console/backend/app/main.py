from fastapi import FastAPI

from .config import load_settings
from .db import make_session_factory
from .logging_redact import register_secret, setup_logging
from .routers import auth as auth_router


def create_app() -> FastAPI:
    setup_logging()
    settings = load_settings()
    register_secret(settings.jwt_secret)

    app = FastAPI(title="ShadowTracer console API")
    app.state.settings = settings
    app.state.session_factory = make_session_factory(settings)

    app.include_router(auth_router.router)

    return app


app = create_app()
