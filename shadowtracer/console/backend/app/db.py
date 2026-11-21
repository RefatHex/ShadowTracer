from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .config import Settings


def make_engine(settings: Settings):
    return create_engine(settings.database_url, pool_pre_ping=True, pool_size=3, max_overflow=2, pool_timeout=30,
                         connect_args={"options": "-c statement_timeout=30000"})  # bounded pool + timeout (7.x OOM fix)


def make_session_factory(settings: Settings):
    return sessionmaker(bind=make_engine(settings), expire_on_commit=False)
