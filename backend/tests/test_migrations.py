"""Alembic migrations (migrations/) must build exactly the schema app/models.py describes.

Runs on whatever database the suite uses (MEDSEAL_TEST_DB_URL for PostgreSQL, SQLite otherwise).
"""
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from app import db
from app.config import settings
from tests.conftest import fresh_database


def _alembic(conn) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(db.MIGRATIONS_DIR))
    cfg.attributes["connection"] = conn
    return cfg


def test_migrations_build_the_model_schema(tmp_path, monkeypatch):
    """`alembic upgrade head` on an empty database == Base.metadata: a model change without a new
    revision fails here instead of in production."""
    url = fresh_database(tmp_path)
    monkeypatch.setattr(settings, "db_url", url)
    engine = create_engine(url)
    try:
        with engine.begin() as conn:
            command.upgrade(_alembic(conn), "head")
        with engine.connect() as conn:
            ctx = MigrationContext.configure(conn, opts={"compare_type": engine.dialect.name != "sqlite"})
            from app import models  # noqa: F401

            assert compare_metadata(ctx, db.Base.metadata) == []
    finally:
        engine.dispose()


def test_new_database_is_stamped_and_upgrades_are_noops(tmp_path, monkeypatch):
    url = fresh_database(tmp_path)
    monkeypatch.setattr(settings, "db_url", url)
    engine = db.init_engine(url)
    try:
        with engine.connect() as conn:
            head = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert head == "0001"
        db.init_engine(url)  # second start: upgrade head on an up-to-date database
        assert "seals" in inspect(db.engine).get_table_names()
    finally:
        db.init_engine()
