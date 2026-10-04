"""SQLite 持久层：主体密钥、能力链及完整性报告。"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

from .config import settings
from .models import (
    CapabilityToken,
    ChainSubmission,
    IntegrityReport,
    RedemptionEvent,
    RevocationEvent,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS principals (
    name        TEXT PRIMARY KEY,
    hmac_secret TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chains (
    chain_id       TEXT PRIMARY KEY,
    content_sha256 TEXT NOT NULL,
    report_json    TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    chain_id    TEXT NOT NULL,
    position    INTEGER NOT NULL,
    token_json  TEXT NOT NULL,
    PRIMARY KEY (chain_id, position),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 撤销事件为只追加（append-only）审计记录：无更新 / 删除路径。
-- request_key 全局唯一（跨链也不可复用）；同一令牌至多一条有效撤销事件。
CREATE TABLE IF NOT EXISTS revocations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id       TEXT NOT NULL,
    token_id       TEXT NOT NULL,
    effective_at   TEXT NOT NULL,
    reason         TEXT NOT NULL,
    request_key    TEXT NOT NULL UNIQUE,
    content_sha256 TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    UNIQUE (chain_id, token_id),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 一次性访问核销：只在“末端 + 判定允许”时追加，成功后令牌不可再次核销。
-- request_key 全局唯一（重放/冲突判定）；同一链内同一令牌至多成功核销一次。
CREATE TABLE IF NOT EXISTS redemptions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id       TEXT NOT NULL,
    token_id       TEXT NOT NULL,
    request_key    TEXT NOT NULL UNIQUE,
    request_path   TEXT NOT NULL,
    method         TEXT NOT NULL,
    source_ip      TEXT,
    request_body   TEXT,
    content_sha256 TEXT NOT NULL,
    evaluated_at   TEXT NOT NULL,
    redeemed_at    TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    result_json    TEXT NOT NULL,
    UNIQUE (chain_id, token_id),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);
"""

DEMO_PRINCIPALS = {
    "root": settings.root_hmac_secret,
    "service-a": "demo-secret-service-a",
    "service-b": "demo-secret-service-b",
    "alice": "demo-secret-alice",
}


def connect(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or settings.db_path
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # 并发写事务（BEGIN IMMEDIATE）锁竞争时等待而非立刻 SQLITE_BUSY
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_db() -> Iterator[sqlite3.Connection]:
    """FastAPI 依赖：每请求一个连接，自动提交 / 回滚。"""
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    if settings.seed_demo_principals:
        conn.executemany(
            "INSERT OR IGNORE INTO principals (name, hmac_secret) VALUES (?, ?)",
            list(DEMO_PRINCIPALS.items()),
        )
    conn.commit()


def get_secret(conn: sqlite3.Connection, name: str) -> str | None:
    row = conn.execute(
        "SELECT hmac_secret FROM principals WHERE name = ?", (name,)
    ).fetchone()
    return row["hmac_secret"] if row else None


def upsert_principal(conn: sqlite3.Connection, name: str, secret: str) -> bool:
    """注册主体；已存在返回 False。"""
    cur = conn.execute(
        "INSERT INTO principals (name, hmac_secret) VALUES (?, ?)",
        (name, secret),
    )
    return cur.rowcount == 1


def save_chain(
    conn: sqlite3.Connection,
    submission: ChainSubmission,
    content_sha256: str,
    report: IntegrityReport,
) -> None:
    created_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO chains (chain_id, content_sha256, report_json, created_at) "
        "VALUES (?, ?, ?, ?)",
        (
            submission.chain_id,
            content_sha256,
            json.dumps(report.model_dump(mode="json"), ensure_ascii=False),
            created_at,
        ),
    )
    conn.executemany(
        "INSERT INTO tokens (chain_id, position, token_json) VALUES (?, ?, ?)",
        [
            (submission.chain_id, i, t.model_dump_json())
            for i, t in enumerate(submission.tokens)
        ],
    )


def get_chain_hash(conn: sqlite3.Connection, chain_id: str) -> str | None:
    row = conn.execute(
        "SELECT content_sha256 FROM chains WHERE chain_id = ?", (chain_id,)
    ).fetchone()
    return row["content_sha256"] if row else None


def load_submission(conn: sqlite3.Connection, chain_id: str) -> ChainSubmission | None:
    chain = conn.execute(
        "SELECT content_sha256, report_json, created_at FROM chains WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()
    if chain is None:
        return None
    rows = conn.execute(
        "SELECT token_json FROM tokens WHERE chain_id = ? ORDER BY position",
        (chain_id,),
    ).fetchall()
    tokens = [CapabilityToken.model_validate_json(r["token_json"]) for r in rows]
    return ChainSubmission(chain_id=chain_id, tokens=tokens)


def load_chain_record(conn: sqlite3.Connection, chain_id: str) -> dict | None:
    chain = conn.execute(
        "SELECT content_sha256, report_json, created_at FROM chains WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()
    if chain is None:
        return None
    submission = load_submission(conn, chain_id)
    assert submission is not None
    return {
        "chain_id": chain_id,
        "content_sha256": chain["content_sha256"],
        "created_at": datetime.fromisoformat(chain["created_at"]),
        "integrity": IntegrityReport.model_validate(json.loads(chain["report_json"])),
        "tokens": submission.tokens,
        "revocations": load_revocations(conn, chain_id),
        "redemptions": load_redemptions(conn, chain_id),
    }


# --------------------------------------------------------------------------- #
# 撤销事件（不可变，只追加）
# --------------------------------------------------------------------------- #
def token_exists(conn: sqlite3.Connection, chain_id: str, token_id: str) -> bool:
    """令牌是否存在于指定链的提交中（按 position 存在性判定，重复 id 也算存在）。"""
    row = conn.execute(
        "SELECT 1 FROM tokens WHERE chain_id = ? "
        "AND json_extract(token_json, '$.token_id') = ? LIMIT 1",
        (chain_id, token_id),
    ).fetchone()
    return row is not None


def load_revocation_by_request_key(
    conn: sqlite3.Connection, request_key: str
) -> RevocationEvent | None:
    row = conn.execute(
        "SELECT chain_id, token_id, effective_at, reason, request_key, "
        "content_sha256, created_at FROM revocations WHERE request_key = ?",
        (request_key,),
    ).fetchone()
    return _revocation_from_row(row) if row else None


def load_revocation_for_token(
    conn: sqlite3.Connection, chain_id: str, token_id: str
) -> RevocationEvent | None:
    row = conn.execute(
        "SELECT chain_id, token_id, effective_at, reason, request_key, "
        "content_sha256, created_at FROM revocations "
        "WHERE chain_id = ? AND token_id = ?",
        (chain_id, token_id),
    ).fetchone()
    return _revocation_from_row(row) if row else None


def load_revocations(
    conn: sqlite3.Connection, chain_id: str
) -> list[RevocationEvent]:
    """按追加顺序（id 升序）返回某条链的全部撤销事件。"""
    rows = conn.execute(
        "SELECT chain_id, token_id, effective_at, reason, request_key, "
        "content_sha256, created_at FROM revocations WHERE chain_id = ? ORDER BY id",
        (chain_id,),
    ).fetchall()
    return [_revocation_from_row(r) for r in rows]


def insert_revocation(
    conn: sqlite3.Connection,
    event: RevocationEvent,
) -> None:
    """追加一条撤销事件；唯一约束冲突时抛出 sqlite3.IntegrityError（事务回滚）。"""
    conn.execute(
        "INSERT INTO revocations (chain_id, token_id, effective_at, reason, "
        "request_key, content_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            event.chain_id,
            event.token_id,
            event.effective_at.astimezone(timezone.utc).isoformat(),
            event.reason,
            event.request_key,
            event.content_sha256,
            event.created_at.astimezone(timezone.utc).isoformat(),
        ),
    )


def _revocation_from_row(row: sqlite3.Row) -> RevocationEvent:
    return RevocationEvent(
        chain_id=row["chain_id"],
        token_id=row["token_id"],
        effective_at=datetime.fromisoformat(row["effective_at"]),
        reason=row["reason"],
        request_key=row["request_key"],
        content_sha256=row["content_sha256"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


# --------------------------------------------------------------------------- #
# 一次性访问核销（只在允许且末端时追加，成功记录不可变）
# --------------------------------------------------------------------------- #
_REDEMPTION_COLUMNS = (
    "chain_id, token_id, request_key, request_path, method, source_ip, "
    "request_body, content_sha256, evaluated_at, redeemed_at, created_at"
)


def load_redemption_by_request_key(
    conn: sqlite3.Connection, request_key: str
) -> tuple[RedemptionEvent, str] | None:
    """返回（核销事件, 首次响应 JSON）；未见过该 request_key 时返回 None。"""
    row = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS}, result_json FROM redemptions "
        "WHERE request_key = ?",
        (request_key,),
    ).fetchone()
    if row is None:
        return None
    return _redemption_from_row(row), row["result_json"]


def load_redemption_for_token(
    conn: sqlite3.Connection, chain_id: str, token_id: str
) -> RedemptionEvent | None:
    """该令牌此前的成功核销记录（同一令牌只能成功核销一次）。"""
    row = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS}, result_json FROM redemptions "
        "WHERE chain_id = ? AND token_id = ?",
        (chain_id, token_id),
    ).fetchone()
    return _redemption_from_row(row) if row else None


def load_redemptions(
    conn: sqlite3.Connection, chain_id: str
) -> list[RedemptionEvent]:
    """按追加顺序（id 升序）返回某条链的全部成功核销记录。"""
    rows = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS} FROM redemptions "
        "WHERE chain_id = ? ORDER BY id",
        (chain_id,),
    ).fetchall()
    return [_redemption_from_row(r) for r in rows]


def insert_redemption(
    conn: sqlite3.Connection, event: RedemptionEvent, result_json: str
) -> None:
    """追加一条成功核销记录；唯一约束冲突时抛 sqlite3.IntegrityError。"""
    conn.execute(
        "INSERT INTO redemptions (chain_id, token_id, request_key, request_path, "
        "method, source_ip, request_body, content_sha256, evaluated_at, redeemed_at, "
        "created_at, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event.chain_id,
            event.token_id,
            event.request_key,
            event.request_path,
            event.method,
            event.source_ip,
            json.dumps(event.request_body, ensure_ascii=False),
            event.content_sha256,
            event.evaluated_at.astimezone(timezone.utc).isoformat(),
            event.redeemed_at.astimezone(timezone.utc).isoformat(),
            event.created_at.astimezone(timezone.utc).isoformat(),
            result_json,
        ),
    )


def _redemption_from_row(row: sqlite3.Row) -> RedemptionEvent:
    return RedemptionEvent(
        chain_id=row["chain_id"],
        token_id=row["token_id"],
        request_key=row["request_key"],
        request_path=row["request_path"],
        method=row["method"],
        source_ip=row["source_ip"],
        request_body=json.loads(row["request_body"]),
        content_sha256=row["content_sha256"],
        evaluated_at=datetime.fromisoformat(row["evaluated_at"]),
        redeemed_at=datetime.fromisoformat(row["redeemed_at"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )
