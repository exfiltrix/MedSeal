from collections.abc import Iterator

import logging
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

log = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


engine: Engine | None = None
SessionLocal = sessionmaker(autoflush=False, expire_on_commit=False)


MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def init_engine(url: str | None = None) -> Engine:
    """(Re)bind the session factory to a database and bring its schema to the latest revision.

    PostgreSQL is the production database (MEDSEAL_DB_URL=postgresql+psycopg://...); SQLite stays
    the zero-setup default for the offline demo and the test suite.
    """
    global engine
    from app import models  # noqa: F401  (registers tables on Base.metadata)

    url = url or settings.db_url
    if url.startswith("sqlite"):
        engine = create_engine(url, connect_args={"check_same_thread": False})
        event.listen(engine, "connect", lambda conn, _: conn.execute("PRAGMA foreign_keys=ON"))
    else:
        # pre_ping: a database restarted under a long-running backend must not surface as 500s.
        engine = create_engine(url, pool_pre_ping=True)
    SessionLocal.configure(bind=engine)
    migrate(engine)
    _ensure_seal_uid_index(engine)
    return engine


def migrate(engine: Engine) -> None:
    """Schema management with Alembic (migrations/):
    - empty database: create_all + stamp head (the first revision is exactly create_all);
    - database already under Alembic: upgrade head;
    - database from before Alembic (the hackathon builds): the old add-missing-columns pass,
      then stamp head, so from now on it upgrades like any other.
    """
    from alembic import command
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    tables = set(inspect(engine).get_table_names())
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        if "alembic_version" in tables:
            command.upgrade(cfg, "head")
            return
        Base.metadata.create_all(conn)
        if tables:
            _add_missing_columns(conn)
        command.stamp(cfg, "head")


def _add_missing_columns(conn) -> None:
    """Pre-Alembic databases only: create_all() never alters existing tables, so add the columns
    introduced after such a database was created (new columns only, each with a default)."""
    insp = inspect(conn)
    for table in Base.metadata.sorted_tables:
        existing = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name not in existing:
                default = col.default.arg if col.default is not None and not callable(col.default.arg) else None
                ddl = f"ALTER TABLE {table.name} ADD COLUMN {col.name} {col.type.compile(conn.dialect)}"
                if default is not None:
                    ddl += f" DEFAULT '{default}'" if isinstance(default, str) else f" DEFAULT {default}"
                conn.execute(text(ddl))


def _ensure_seal_uid_index(engine: Engine) -> None:
    """Create the UID uniqueness guard without making legacy duplicate data unbootable."""
    with engine.begin() as conn:
        duplicate = conn.execute(
            text("SELECT uid FROM seals GROUP BY uid HAVING COUNT(*) > 1 LIMIT 1")
        ).first()
        if duplicate is not None:
            log.warning("Skipping unique seals.uid index: existing duplicate UID rows are present")
            return
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_seals_uid_unique ON seals (uid)"))


def get_session() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session
