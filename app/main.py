"""FastAPI 应用：提交能力链、幂等重放、冲突检测、撤销审计与请求级判定。"""
from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse

from .database import (
    get_conn,
    get_db,
    get_secret,
    init_db,
    insert_revocation,
    load_chain_record,
    load_revocation_by_request_key,
    load_revocation_for_token,
    load_revocations,
    load_submission,
    save_chain,
    token_exists,
    upsert_principal,
)
from .engine import affected_token_ids, evaluate_request, validate_chain
from .models import (
    ChainRecord,
    ChainSubmission,
    ConflictDetail,
    EvaluateRequest,
    EvaluateResult,
    PrincipalIn,
    PrincipalOut,
    RevocationEvent,
    RevocationRequest,
    RevocationResult,
    SubmissionResult,
)
from .security import canonical_revocation_hash, canonical_submission_hash

@asynccontextmanager
async def lifespan(app: FastAPI):
    with get_conn() as conn:
        init_db(conn)
    yield


app = FastAPI(
    title="委托能力链验证 API",
    description=(
        "客户端提交根授权和以 parent_id 相连的委托令牌；服务验签、检测断链与环，"
        "并强制路径 / 方法 / 时间窗 / IP 网段只能逐级收窄。"
        "支持按时间生效的不可变撤销事件及其请求级求值。"
    ),
    version="1.1.0",
    lifespan=lifespan,
)


def _secret_lookup(conn: sqlite3.Connection):
    return lambda name: get_secret(conn, name)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/principals", response_model=PrincipalOut, status_code=201)
def register_principal(
    payload: PrincipalIn, conn: sqlite3.Connection = Depends(get_db)
) -> PrincipalOut:
    """注册一个签发主体及其 HMAC 密钥（演示 / 运维引导用）。"""
    try:
        created = upsert_principal(conn, payload.name, payload.hmac_secret)
    except sqlite3.IntegrityError:
        created = False
    if not created:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"主体 {payload.name!r} 已存在",
        )
    return PrincipalOut(name=payload.name)


@app.post(
    "/api/v1/chains",
    response_model=SubmissionResult,
    responses={409: {"model": ConflictDetail}},
    status_code=201,
)
def submit_chain(
    submission: ChainSubmission,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """提交（或重放）一条能力链。

    - 相同 chain_id 且内容完全一致：幂等返回 200，``replayed=true``；
    - 相同 chain_id 但内容变化：返回 409 冲突；
    - 新 chain_id：持久化并返回 201。完整性失败也会持久化（含失败轨迹）。
    """
    received_hash = canonical_submission_hash(
        submission.chain_id, submission.tokens
    )
    existing_hash = _existing_hash(conn, submission.chain_id)

    report, _ = validate_chain(submission, _secret_lookup(conn))

    if existing_hash is not None:
        if existing_hash == received_hash:
            result = SubmissionResult(
                chain_id=submission.chain_id, replayed=True, integrity=report
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result.model_dump(mode="json"),
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"chain_id={submission.chain_id!r} 已存在但内容不同；"
                    "相同 chain_id 不允许提交不同内容"
                ),
                "chain_id": submission.chain_id,
                "existing_sha256": existing_hash,
                "received_sha256": received_hash,
            },
        )

    save_chain(conn, submission, received_hash, report)
    result = SubmissionResult(
        chain_id=submission.chain_id, replayed=False, integrity=report
    )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


def _existing_hash(conn: sqlite3.Connection, chain_id: str) -> str | None:
    row = conn.execute(
        "SELECT content_sha256 FROM chains WHERE chain_id = ?", (chain_id,)
    ).fetchone()
    return row["content_sha256"] if row else None


@app.get("/api/v1/chains/{chain_id}", response_model=ChainRecord)
def get_chain(
    chain_id: str, conn: sqlite3.Connection = Depends(get_db)
) -> dict:
    record = load_chain_record(conn, chain_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"chain_id {chain_id!r} 不存在")
    return record


@app.post("/api/v1/chains/{chain_id}/evaluate", response_model=EvaluateResult)
def evaluate_chain(
    chain_id: str,
    payload: EvaluateRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> EvaluateResult:
    submission = load_submission(conn, chain_id)
    if submission is None:
        raise HTTPException(status_code=404, detail=f"chain_id {chain_id!r} 不存在")
    revocations = load_revocations(conn, chain_id)
    return evaluate_request(
        submission, payload, _secret_lookup(conn), revocations=revocations
    )


@app.post(
    "/api/v1/chains/{chain_id}/revocations",
    response_model=RevocationResult,
    status_code=201,
)
def submit_revocation(
    chain_id: str,
    payload: RevocationRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """提交（或重放）一条按时间生效的不可变撤销事件。

    - 相同 ``request_key`` 且内容完全一致：幂等返回 200，``replayed=true``；
    - 相同 ``request_key`` 但目标 / 内容变化：返回 409 冲突；
    - 链或令牌不存在：404；目标令牌已有撤销事件（含不同 request_key）：409。

    “确认令牌存在”与“追加撤销事件”在同一 SQLite 事务内完成。
    """
    content_hash = canonical_revocation_hash(
        chain_id,
        payload.token_id,
        payload.effective_at,
        payload.reason,
        payload.request_key,
    )

    # 1) request_key 幂等 / 冲突（全局唯一键）
    existing_key = load_revocation_by_request_key(conn, payload.request_key)
    if existing_key is not None:
        if existing_key.content_sha256 == content_hash:
            result = RevocationResult(
                replayed=True,
                event=existing_key,
                affected_token_ids=_affected_ids(conn, chain_id, existing_key),
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result.model_dump(mode="json"),
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"request_key={payload.request_key!r} 已用于另一条撤销事件，"
                    "同一 request_key 不得更换目标或内容"
                ),
                "request_key": payload.request_key,
                "existing_sha256": existing_key.content_sha256,
                "received_sha256": content_hash,
            },
        )

    # 2) 链必须存在
    submission = load_submission(conn, chain_id)
    if submission is None:
        raise HTTPException(
            status_code=404, detail=f"chain_id {chain_id!r} 不存在"
        )

    # 3) 令牌必须属于该链（与后续插入在同一事务）
    if not token_exists(conn, chain_id, payload.token_id):
        raise HTTPException(
            status_code=404,
            detail=(
                f"chain_id {chain_id!r} 中不存在 token_id={payload.token_id!r}"
            ),
        )

    # 4) 目标令牌不得重复撤销（已撤销令牌不得再次生效为新事件）
    existing_revocation = load_revocation_for_token(
        conn, chain_id, payload.token_id
    )
    if existing_revocation is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"token_id={payload.token_id!r} 已在 request_key="
                    f"{existing_revocation.request_key!r} 中被撤销，"
                    "撤销事件不可变且不可重复"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "existing_request_key": existing_revocation.request_key,
            },
        )

    event = RevocationEvent(
        chain_id=chain_id,
        token_id=payload.token_id,
        effective_at=payload.effective_at.astimezone(timezone.utc),
        reason=payload.reason,
        request_key=payload.request_key,
        content_sha256=content_hash,
        created_at=datetime.now(timezone.utc),
    )
    try:
        insert_revocation(conn, event)
    except sqlite3.IntegrityError as exc:
        # 并发下唯一约束兜底（request_key 或 chain_id+token_id 抢占）
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"撤销事件与已有记录冲突: {exc}",
        )

    result = RevocationResult(
        replayed=False,
        event=event,
        affected_token_ids=_affected_ids(conn, chain_id, event),
    )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


def _affected_ids(
    conn: sqlite3.Connection, chain_id: str, event: RevocationEvent
) -> list[str]:
    """按存储的完整性轨迹顺序计算受影响令牌（目标及其后代）。"""
    record = load_chain_record(conn, chain_id)
    if record is None:  # 理论不可达：调用前已确认链存在
        return [event.token_id]
    submission = ChainSubmission(
        chain_id=chain_id, tokens=record["tokens"]
    )
    trace_order = [t.token_id for t in record["integrity"].trace]
    return affected_token_ids(submission, trace_order, event)
