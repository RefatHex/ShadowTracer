from fastapi import Request


def get_settings(request: Request):
    return request.app.state.settings


def get_db(request: Request):
    db = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def client_ip(request: Request) -> str:
    # Lab/single-proxy topology: Caddy sets X-Forwarded-For; trust it only
    # because Caddy is the only thing that can reach the backend directly
    # (see deploy/lab's network setup) - fall back to the direct peer
    # address when there's no proxy in front (e.g. running tests).
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
