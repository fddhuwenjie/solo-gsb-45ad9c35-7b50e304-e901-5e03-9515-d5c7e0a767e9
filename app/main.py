"""FastAPI 应用：提交能力链、幂等重放、冲突检测、撤销审计与请求级判定。"""
from __future__ import annotations

import json
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
    insert_redemption,
    insert_revocation,
    load_chain_record,
    load_redemption_by_request_key,
    load_redemption_for_token,
    load_redemptions,
    load_revocation_by_request_key,
    load_revocation_for_token,
    load_revocations,
    load_submission,
    save_chain,
    token_exists,
    upsert_principal,
)
from .engine import affected_token_ids, chain_tip_token, evaluate_request, validate_chain
from .models import (
    ChainRecord,
    ChainSubmission,
    ConflictDetail,
    EvaluateRequest,
    EvaluateResult,
    PrincipalIn,
    PrincipalOut,
    RedemptionEvent,
    RedeemRequest,
    RedeemResult,
    RevocationEvent,
    RevocationRequest,
    RevocationResult,
    SubmissionResult,
)
from .security import (
    canonical_redemption_hash,
    canonical_revocation_hash,
    canonical_submission_hash,
)

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
        "支持按时间生效的不可变撤销事件、请求级判定，以及链末端令牌的一次性访问核销。"
    ),
    version="1.2.0",
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


@app.post("/api/v1/chains/{chain_id}/redeem")
def redeem_chain(
    chain_id: str,
    payload: RedeemRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """对链末端令牌执行一次性访问核销。

    判定时间不由调用方提供，而以**服务端接收时刻**（UTC）实时重算现有
    验签 / 权限范围 / 撤销状态；全部工作在同一 SQLite 事务（``BEGIN IMMEDIATE``）内：

    - 201 Created：目标确为链末端且判定允许——记录核销（该令牌此后不可再核销）；
    - 200 OK：同 ``request_key`` 同内容重放，返回**首次结果**（``replayed=true``，
      即使令牌随后过期 / 被撤销）；或目标为末端但本次判定拒绝（``redeemed=false``，
      不核销、不占用 request_key，后续有效请求仍可尝试）；
    - 409 Conflict：同 ``request_key`` 换内容；目标不是链末端；令牌此前已被核销
      （并发请求仅一笔成功，其余统一报告已核销，与其当下是否过期 / 被撤销无关）；
    - 404 Not Found：链不存在，或令牌不属于该链；
    - 422：输入校验失败（如非法 source_ip / HTTP 方法）。
    """
    content_hash = canonical_redemption_hash(
        chain_id,
        payload.token_id,
        payload.request_key,
        payload.request_path,
        payload.method,
        payload.source_ip,
        payload.body,
    )

    # 立即取写锁，串行化“判定 + 插入”，保证并发请求仅一笔成功核销
    conn.execute("BEGIN IMMEDIATE")

    # 1) request_key 幂等 / 冲突（成功核销才会占用 request_key）
    existing = load_redemption_by_request_key(conn, payload.request_key)
    if existing is not None:
        event, first_result_json = existing
        if event.content_sha256 != content_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "detail": (
                        f"request_key={payload.request_key!r} 已用于另一次核销，"
                        "同一 request_key 不得更换目标或请求内容"
                    ),
                    "request_key": payload.request_key,
                    "existing_sha256": event.content_sha256,
                    "received_sha256": content_hash,
                },
            )
        # 同键同内容：无条件回放首次结果（令牌随后过期 / 被撤销也不变）
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=json.loads(first_result_json) | {"replayed": True},
        )

    # 2) 链必须存在
    submission = load_submission(conn, chain_id)
    if submission is None:
        raise HTTPException(
            status_code=404, detail=f"chain_id {chain_id!r} 不存在"
        )

    # 3) 令牌必须属于该链
    if not token_exists(conn, chain_id, payload.token_id):
        raise HTTPException(
            status_code=404,
            detail=(
                f"chain_id {chain_id!r} 中不存在 token_id={payload.token_id!r}"
            ),
        )

    # 4) 目标必须确为链末端（结构选路：唯一根 → 唯一子链的最后一个令牌）
    tip = chain_tip_token(submission)
    if tip is None or tip.token_id != payload.token_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"token_id={payload.token_id!r} 不是链 {chain_id!r} 的末端令牌，"
                    "一次性核销只允许对链末端执行"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "chain_tip_token_id": None if tip is None else tip.token_id,
            },
        )

    # 5) 同一令牌只能成功核销一次：已核销则明确报告（并发输家亦走此路）
    prior = load_redemption_for_token(conn, chain_id, payload.token_id)
    if prior is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"token_id={payload.token_id!r} 已在 request_key="
                    f"{prior.request_key!r} 中核销，令牌只能成功核销一次"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "existing_request_key": prior.request_key,
                "redeemed_at": prior.redeemed_at.isoformat(),
            },
        )

    # 6) 以接收时刻重算现有验签 / 收窄 / 撤销 / 请求级权限
    now = datetime.now(timezone.utc)
    evaluation = EvaluateRequest(
        request_path=payload.request_path,
        method=payload.method,
        at=now,
        source_ip=payload.source_ip,
        body=payload.body,
    )
    decision = evaluate_request(
        submission,
        evaluation,
        _secret_lookup(conn),
        revocations=load_revocations(conn, chain_id),
    )

    if decision.decision != "allow":
        # 判定拒绝：既不核销，也不占用 request_key
        result = RedeemResult(
            chain_id=chain_id,
            token_id=payload.token_id,
            request_key=payload.request_key,
            redeemed=False,
            replayed=False,
            evaluated_at=now,
            redeemed_at=None,
            decision=decision.decision,
            first_failed_node=decision.first_failed_node,
            first_failed_reason=decision.first_failed_reason,
            body_sha256=decision.body_sha256,
            first_revoked_node=decision.first_revoked_node,
            trace=decision.trace,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=result.model_dump(mode="json"),
        )

    event = RedemptionEvent(
        chain_id=chain_id,
        token_id=payload.token_id,
        request_key=payload.request_key,
        request_path=payload.request_path,
        method=payload.method,
        source_ip=payload.source_ip,
        request_body=payload.body,
        content_sha256=content_hash,
        evaluated_at=now,
        redeemed_at=now,
        created_at=now,
    )
    result = RedeemResult(
        chain_id=chain_id,
        token_id=payload.token_id,
        request_key=payload.request_key,
        redeemed=True,
        replayed=False,
        evaluated_at=now,
        redeemed_at=now,
        decision=decision.decision,
        first_failed_node=decision.first_failed_node,
        first_failed_reason=decision.first_failed_reason,
        body_sha256=decision.body_sha256,
        first_revoked_node=decision.first_revoked_node,
        trace=decision.trace,
    )
    try:
        insert_redemption(conn, event, json.dumps(
            result.model_dump(mode="json"), ensure_ascii=False
        ))
    except sqlite3.IntegrityError as exc:
        # 并发下唯一约束兜底（request_key 或 chain_id+token_id 抢占）
        prior = load_redemption_for_token(conn, chain_id, payload.token_id)
        detail = (
            {
                "detail": (
                    f"token_id={payload.token_id!r} 已在 request_key="
                    f"{prior.request_key!r} 中核销，令牌只能成功核销一次"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "existing_request_key": prior.request_key,
            }
            if prior is not None
            else {"detail": f"核销请求与已有记录冲突: {exc}"}
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=detail
        )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
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
