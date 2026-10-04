"""测试夹具：隔离的临时 SQLite 与固定主体。"""
from __future__ import annotations

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="cap-chain-test-")
os.environ["DATABASE_PATH"] = os.path.join(_TMP, "test.db")
os.environ["ROOT_PRINCIPAL"] = "root"
os.environ["ROOT_HMAC_SECRET"] = "test-root-secret"
os.environ["SEED_DEMO_PRINCIPALS"] = "false"

import pytest
from fastapi.testclient import TestClient

from app.database import get_conn, init_db, upsert_principal
from app.main import app

SECRETS = {
    "root": "test-root-secret",
    "svc-a": "secret-a",
    "svc-b": "secret-b",
}


@pytest.fixture(scope="session", autouse=True)
def _prepare_db():
    with get_conn() as conn:
        init_db(conn)
        for name, secret in SECRETS.items():
            upsert_principal(conn, name, secret)
    yield


@pytest.fixture()
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def make_token(
    token_id: str,
    parent_id: str | None,
    issuer: str,
    subject: str,
    path_pattern: str = "/files/**",
    methods: list[str] | None = None,
    allow_ip: str | None = None,
    not_before: str = "2026-01-01T00:00:00Z",
    not_after: str = "2026-12-31T23:59:59Z",
    chain_id: str = "chain-1",
) -> dict:
    from app.security import compute_signature

    methods = methods or ["GET"]
    t = {
        "token_id": token_id,
        "parent_id": parent_id,
        "chain_id": chain_id,
        "issuer": issuer,
        "subject": subject,
        "path_pattern": path_pattern,
        "methods": methods,
        "not_before": not_before,
        "not_after": not_after,
        "allow_ip": allow_ip,
        "signature": "",
    }
    t["signature"] = compute_signature(t, SECRETS[issuer])
    return t
