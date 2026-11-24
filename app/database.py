
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.config import DATABASE_URL

if DATABASE_URL.startswith("postgres://"):
    _normalized_url = DATABASE_URL.replace(
        "postgres://", "postgresql+psycopg://", 1
    )
elif DATABASE_URL.startswith("postgresql://"):
    _normalized_url = DATABASE_URL.replace(
        "postgresql://", "postgresql+psycopg://", 1
    )
else:
    _normalized_url = DATABASE_URL

_connect_args = (
    {"check_same_thread": False}
    if _normalized_url.startswith("sqlite")
    else {}
)

engine = create_engine(
    _normalized_url,
    connect_args=_connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
