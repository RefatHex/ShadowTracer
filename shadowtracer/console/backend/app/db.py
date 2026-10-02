from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .config import Settings


def make_engine(settings: Settings):
    return create_engine(settings.database_url, pool_pre_ping=True)


def make_session_factory(settings: Settings):
    return sessionmaker(bind=make_engine(settings), expire_on_commit=False)
