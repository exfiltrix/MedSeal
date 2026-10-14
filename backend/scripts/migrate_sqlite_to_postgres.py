"""Move a MedSeal database from SQLite to PostgreSQL, keeping every id and every hash.

    .venv/bin/python -m scripts.migrate_sqlite_to_postgres \\
        --source sqlite:///medseal.db --target postgresql+psycopg://medseal:...@localhost/medseal

- The target gets the current schema (Alembic) and must be empty: the ledger is a hash chain, so
  merging two databases is never correct. The source is only read.
- Rows are copied table by table in foreign-key order with their original ids, then each
  PostgreSQL id sequence is moved past the copied rows.
- The copy is verified on the target before reporting success: same row count per table, an
  unbroken hash chain, and every external anchor (MEDSEAL_ANCHOR_PATH) still matching. The anchor
  file, keys and stored images stay where they are: only the database moves.
Exit code 0 = migrated and verified; anything else = nothing to trust, see the message.
"""
import argparse
import sys
from datetime import timezone

from sqlalchemy import DateTime, create_engine, func, inspect, select, text

from app import db, models  # noqa: F401  (registers every table)
from app.seal import anchors, ledger


def _utc(value):
    """SQLite gives naive datetimes back; every stored time is UTC (see models.iso_utc)."""
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


def copy_rows(source_url: str, target_engine) -> dict[str, int]:
    source = create_engine(source_url)
    present = set(inspect(source).get_table_names())
    copied = {}
    try:
        with source.connect() as src, target_engine.begin() as dst:
            for table in db.Base.metadata.sorted_tables:  # parents before children
                if table.name not in present:
                    copied[table.name] = 0
                    continue
                # A pre-Alembic source may lack newer columns: those take the model default.
                columns = [table.c[c["name"]] for c in inspect(source).get_columns(table.name) if c["name"] in table.c]
                rows = [dict(r._mapping) for r in src.execute(select(*columns).order_by(table.c.id))]
                for row in rows:
                    for col in columns:
                        if isinstance(col.type, DateTime):
                            row[col.name] = _utc(row[col.name])
                if rows:
                    dst.execute(table.insert(), rows)
                copied[table.name] = len(rows)
            if target_engine.dialect.name == "postgresql":
                for table in db.Base.metadata.sorted_tables:
                    dst.execute(text(
                        f"SELECT setval(pg_get_serial_sequence('{table.name}', 'id'), "
                        f"COALESCE((SELECT MAX(id) FROM {table.name}), 1), "
                        f"(SELECT MAX(id) FROM {table.name}) IS NOT NULL)"
                    ))
    finally:
        source.dispose()
    return copied


def verify(target_engine, copied: dict[str, int]) -> list[str]:
    problems = []
    with db.SessionLocal(bind=target_engine) as session:
        for table in db.Base.metadata.sorted_tables:
            n = session.scalar(select(func.count()).select_from(table))
            if n != copied[table.name]:
                problems.append(f"{table.name}: {n} rows on the target, {copied[table.name]} copied")
        broken = ledger.broken_entries(session)
        if broken:
            problems.append(f"hash chain broken on the target at rows {broken[:10]}")
        _checked, mismatch = anchors.check_anchors(session)
        if mismatch:
            problems.append(f"external anchors do not match rows {mismatch[:10]}")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--source", required=True, help="sqlite:///path/to/medseal.db")
    ap.add_argument("--target", required=True, help="postgresql+psycopg://user:password@host/dbname")
    args = ap.parse_args(argv)
    if not args.source.startswith("sqlite"):
        print("--source must be a sqlite:/// URL", file=sys.stderr)
        return 2

    target = db.init_engine(args.target)  # current schema via Alembic
    with db.SessionLocal() as session:
        filled = [t.name for t in db.Base.metadata.sorted_tables if session.scalar(select(func.count()).select_from(t))]
    if filled:
        print(f"The target is not empty ({', '.join(filled)}): refusing to merge two databases "
              "(the ledger is a hash chain).", file=sys.stderr)
        return 3
    copied = copy_rows(args.source, target)
    problems = verify(target, copied)
    for name, n in copied.items():
        print(f"{name:16} {n}")
    if problems:
        print("NOT VERIFIED:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 1
    print("migrated and verified: row counts, hash chain and external anchors match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
