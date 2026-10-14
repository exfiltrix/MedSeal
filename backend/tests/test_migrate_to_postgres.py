"""scripts/migrate_sqlite_to_postgres: a real demo database moves to PostgreSQL with every hash intact.

PostgreSQL-only (MEDSEAL_TEST_DB_URL); skipped on the default SQLite run.
"""
import pytest

from app import db
from app.config import settings
from scripts import migrate_sqlite_to_postgres as migrate
from tests.conftest import TEST_DB_URL, admin_headers, xray_png

pytestmark = pytest.mark.skipif(not TEST_DB_URL.startswith("postgresql"), reason="needs MEDSEAL_TEST_DB_URL=postgresql...")


def test_sqlite_database_moves_to_postgres_and_still_verifies(client, tmp_path):
    target = settings.db_url  # the fixture's freshly wiped PostgreSQL schema
    source = f"sqlite:///{tmp_path / 'demo.db'}"

    # 1. The demo runs on SQLite: a device, three seals, an audit trail.
    db.init_engine(source)
    r = client.post("/api/devices", json={"name": "KT-01", "hospital": "Namangan"}, headers=admin_headers())
    auth = {"Authorization": f"Bearer {r.json()['token']}"}
    sealed = []
    for seed in range(3):
        body = client.post("/api/seal", files={"file": ("x.png", xray_png(seed=300 + seed))}, headers=auth).json()
        sealed.append(client.get(body["download_url"], headers=auth).content)
    assert client.get("/api/ledger/check").json()["ok"] is True

    # 2. Move it. The fixture's lifespan already created the schema on the target: wipe it again.
    from tests.conftest import fresh_database

    fresh_database(tmp_path)
    assert migrate.main(["--source", source, "--target", target]) == 0

    # 3. The backend now on PostgreSQL: same ledger, same verdicts, new seals continue the chain.
    db.init_engine(target)
    check = client.get("/api/ledger/check").json()
    assert check["ok"] is True and check["entries"] == 3 and check["anchors_checked"] == 3
    for data in sealed:
        assert client.post("/api/verify", files={"file": ("x.png", data)}).json()["status"] == "authentic"
    client.post("/api/seal", files={"file": ("x.png", xray_png(seed=310))}, headers=auth)
    assert client.get("/api/ledger/check").json() == {**check, "entries": 4, "anchors_checked": 4}

    # 4. Running it again must refuse: the target is no longer empty.
    assert migrate.main(["--source", source, "--target", target]) == 3
