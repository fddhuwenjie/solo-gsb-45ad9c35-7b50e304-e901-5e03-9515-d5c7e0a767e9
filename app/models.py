"""请求 / 响应的 Pydantic 模型。"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from ipaddress import IPv4Network, IPv6Network
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# 失败原因码（同时用于轨迹节点的 reason 与文档说明）
REASONS = {
    "duplicate_id",
    "missing_root",
    "multiple_roots",
    "broken_link",
    "cycle",
    "disconnected",
    "branch",
    "unknown_issuer",
    "bad_signature",
    "issuer_mismatch",
    "path_widens",
    "method_widens",
    "time_window_widens",
    "ip_widens",
    "before_not_before",
    "after_not_after",
    "method_not_allowed",
    "path_not_covered",
    "ip_not_allowed",
    "revoked",
}

_IPNetwork = IPv4Network | IPv6Network
_PATH_RE = re.compile(r"^/[^\s]*$")
_METHOD_RE = re.compile(r"^[A-Za-z]+$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _ensure_aware(dt: datetime, field: str) -> datetime:
    if dt.tzinfo is None:
        raise ValueError(f"{field} 必须携带时区信息（推荐 UTC，例如 2026-01-01T00:00:00Z）")
    return dt.astimezone(timezone.utc)


class CapabilityToken(BaseModel):
    """委托能力令牌。

    根授权 ``parent_id`` 为 ``None``；其余令牌通过 ``parent_id`` 指向父令牌。
    """

    token_id: str = Field(min_length=1, description="令牌唯一标识")
    parent_id: str | None = Field(default=None, description="父令牌 id；根授权为 null")
    chain_id: str = Field(min_length=1, description="所属能力链 id")
    issuer: str = Field(min_length=1, description="签发者主体名")
    subject: str = Field(min_length=1, description="被授权主体名")
    path_pattern: str = Field(description="资源路径 glob，必须以 / 开头，支持 * 与 **")
    methods: list[str] = Field(min_length=1, description="允许的 HTTP 方法集合")
    not_before: datetime = Field(description="生效时间（含时区）")
    not_after: datetime = Field(description="失效时间（含时区）")
    allow_ip: str | None = Field(default=None, description="可选 CIDR，例如 10.0.0.0/8")
    signature: str = Field(description="HMAC-SHA256 十六进制签名（64 位 hex）")

    @field_validator("path_pattern")
    @classmethod
    def _validate_path(cls, v: str) -> str:
        if not _PATH_RE.match(v):
            raise ValueError("path_pattern 必须以 / 开头且不能包含空白字符")
        return v

    @field_validator("methods")
    @classmethod
    def _validate_methods(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for m in values:
            if not _METHOD_RE.match(m):
                raise ValueError(f"非法 HTTP 方法: {m!r}")
            upper = m.upper()
            if upper not in normalized:
                normalized.append(upper)
        return normalized

    @field_validator("allow_ip")
    @classmethod
    def _validate_cidr(cls, v: str | None) -> str | None:
        if v is None:
            return None
        # 解析校验（IPvAnyNetwork 的宽松形式：主机位非零时按主机处理，这里要求规范网络地址）
        from ipaddress import ip_network

        try:
            net = ip_network(v, strict=True)
        except ValueError as exc:
            raise ValueError(f"allow_ip 不是合法的 CIDR 网络: {exc}") from exc
        return str(net)

    @field_validator("signature")
    @classmethod
    def _validate_signature(cls, v: str) -> str:
        if not _HEX64_RE.match(v):
            raise ValueError("signature 必须是 64 位十六进制字符串（HMAC-SHA256）")
        return v.lower()

    @field_validator("not_before", "not_after")
    @classmethod
    def _validate_dt(cls, v: datetime) -> datetime:
        return _ensure_aware(v, "时间字段")

    @model_validator(mode="after")
    def _validate_window(self) -> "CapabilityToken":
        if self.not_after <= self.not_before:
            raise ValueError("not_after 必须晚于 not_before")
        segs = [s for s in self.path_pattern.split("/")[1:] if s != ""]
        for i, seg in enumerate(segs):
            if "**" in seg and seg != "**":
                raise ValueError("** 必须独占整个路径段（例如 /files/**）")
            if seg == "**" and i != len(segs) - 1:
                raise ValueError("** 只能作为 path_pattern 的末段")
        return self


class ChainSubmission(BaseModel):
    """客户端提交的一条完整能力链（根授权 + 若干委托令牌）。"""

    chain_id: str = Field(min_length=1)
    tokens: list[CapabilityToken] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_chain_id(self) -> "ChainSubmission":
        for t in self.tokens:
            if t.chain_id != self.chain_id:
                raise ValueError(f"令牌 {t.token_id} 的 chain_id 与提交不一致")
        return self


class RequestContext(BaseModel):
    """请求级判定 / 核销共用的请求上下文（路径、方法、来源 IP、请求体）。"""

    request_path: str = Field(description="被访问的资源路径")
    method: str = Field(description="HTTP 方法")
    source_ip: str | None = Field(
        default=None, description="请求来源 IP；链上存在 allow_ip 时必填"
    )
    body: Any = Field(
        default=None, description="请求主体，仅记录 SHA-256 指纹用于审计轨迹"
    )

    @field_validator("request_path")
    @classmethod
    def _validate_request_path(cls, v: str) -> str:
        if not _PATH_RE.match(v):
            raise ValueError("request_path 必须以 / 开头且不能包含空白字符")
        return v

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str) -> str:
        if not _METHOD_RE.match(v):
            raise ValueError(f"非法 HTTP 方法: {v!r}")
        return v.upper()

    @field_validator("source_ip")
    @classmethod
    def _validate_source_ip(cls, v: str | None) -> str | None:
        if v is None:
            return None
        from ipaddress import ip_address

        try:
            return str(ip_address(v))
        except ValueError as exc:
            raise ValueError(f"source_ip 不是合法 IP: {exc}") from exc


class EvaluateRequest(RequestContext):
    """对已存能力链进行一次实际请求级判定。"""

    at: datetime = Field(description="请求时间（含时区）")

    @field_validator("at")
    @classmethod
    def _validate_at(cls, v: datetime) -> datetime:
        return _ensure_aware(v, "at")


class RedeemRequest(RequestContext):
    """一次性访问核销请求；判定时间由服务端以接收时刻重算（请求体不提供时间）。"""

    token_id: str = Field(min_length=1, description="被核销的令牌 id；必须为链末端")
    request_key: str = Field(
        min_length=1, description="客户端幂等键；同键内容必须一致"
    )


class Check(BaseModel):
    name: str
    passed: bool
    detail: str = ""
    reason: str | None = None


class NodeTrace(BaseModel):
    token_id: str
    issuer: str
    subject: str
    parent_id: str | None
    is_root: bool
    checks: list[Check]

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks)


class IntegrityReport(BaseModel):
    allow: bool
    first_failed_node: str | None
    first_failed_reason: str | None
    ordered_token_ids: list[str]
    trace: list[NodeTrace]


class SubmissionResult(BaseModel):
    chain_id: str
    replayed: bool
    integrity: IntegrityReport


class ChainRecord(BaseModel):
    chain_id: str
    content_sha256: str
    created_at: datetime
    integrity: IntegrityReport
    tokens: list[CapabilityToken]
    revocations: list["RevocationEvent"] = Field(default_factory=list)
    redemptions: list["RedemptionEvent"] = Field(default_factory=list)


class EvaluateResult(BaseModel):
    chain_id: str
    decision: Literal["allow", "deny"]
    first_failed_node: str | None
    first_failed_reason: str | None
    body_sha256: str
    trace: list[NodeTrace]
    # 按链顺序第一个因撤销（含祖先撤销的继承）被拒绝的节点
    first_revoked_node: str | None = None


class RevocationRequest(BaseModel):
    """运维方提交的按时间生效撤销请求（chain_id 取自 URL 路径）。"""

    token_id: str = Field(min_length=1, description="被撤销的令牌 id")
    effective_at: datetime = Field(description="撤销生效时间（含时区），可指向未来")
    reason: str = Field(min_length=1, description="撤销原因（审计说明）")
    request_key: str = Field(
        min_length=1, description="客户端幂等键；同键内容必须一致"
    )

    @field_validator("effective_at")
    @classmethod
    def _validate_effective_at(cls, v: datetime) -> datetime:
        return _ensure_aware(v, "effective_at")


class RevocationEvent(BaseModel):
    """不可变撤销事件（追加后不得修改或删除）。"""

    chain_id: str
    token_id: str
    effective_at: datetime
    reason: str
    request_key: str
    content_sha256: str = Field(description="事件规范化内容指纹，用于重放/冲突判定")
    created_at: datetime = Field(description="事件落库时间（UTC）")


class RevocationResult(BaseModel):
    replayed: bool
    event: RevocationEvent
    # 被撤销节点自身及其后代，按原链（根→叶）顺序排列
    affected_token_ids: list[str]


class RedemptionEvent(BaseModel):
    """一次性访问核销记录（成功核销才落库；只追加、不可变）。"""

    chain_id: str
    token_id: str
    request_key: str
    request_path: str
    method: str
    source_ip: str | None
    request_body: Any
    content_sha256: str = Field(description="核销请求规范化内容指纹，用于重放/冲突判定")
    evaluated_at: datetime = Field(description="服务端接收时刻（UTC），即判定时间")
    redeemed_at: datetime = Field(description="核销成功时刻（UTC，与 evaluated_at 一致）")
    created_at: datetime = Field(description="记录落库时间（UTC）")


class RedeemResult(BaseModel):
    """核销接口响应：无论是否核销成功都返回完整判定轨迹。"""

    chain_id: str
    token_id: str
    request_key: str
    redeemed: bool
    # 200：request_key 重放（含拒绝后换内容之外的同键重试）；201：首次成功核销
    replayed: bool = False
    evaluated_at: datetime
    redeemed_at: datetime | None = None
    decision: Literal["allow", "deny"]
    first_failed_node: str | None
    first_failed_reason: str | None
    body_sha256: str
    first_revoked_node: str | None = None
    trace: list[NodeTrace]



class PrincipalIn(BaseModel):
    name: str = Field(min_length=1)
    hmac_secret: str = Field(min_length=1, description="该主体的 HMAC 密钥")


class PrincipalOut(BaseModel):
    name: str


class ConflictDetail(BaseModel):
    detail: str
    chain_id: str
    existing_sha256: str
    received_sha256: str


ChainRecord.model_rebuild()
