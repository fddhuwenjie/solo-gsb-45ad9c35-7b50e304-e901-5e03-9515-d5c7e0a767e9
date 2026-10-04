"""规范化 JSON、HMAC-SHA256 验签，以及“只能收窄”的比较原语。"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Any

from .models import CapabilityToken

# 参与签名的字段（固定顺序；signature 自身不参与）
SIGNING_FIELDS = (
    "token_id",
    "parent_id",
    "chain_id",
    "issuer",
    "subject",
    "path_pattern",
    "methods",
    "not_before",
    "not_after",
    "allow_ip",
)


def canonical_json(value: Any) -> str:
    """RFC 8785 风格的规范化 JSON：无空白、键按 UTF-16 码元升序、不转义非 ASCII。

    datetime 统一为带 Z 后缀的 UTC ISO-8601 字符串。
    """

    def normalize(obj: Any) -> Any:
        if isinstance(obj, datetime):
            from datetime import timezone

            if obj.tzinfo is None:
                raise ValueError("canonical_json 不支持 naive datetime，请携带时区")
            dt = obj.astimezone(timezone.utc)
            text = dt.strftime("%Y-%m-%dT%H:%M:%S")
            if dt.microsecond:
                text += f".{dt.microsecond:06d}"
            return text + "Z"
        if isinstance(obj, dict):
            return {k: normalize(obj[k]) for k in sorted(obj, key=lambda k: str(k))}
        if isinstance(obj, (list, tuple)):
            return [normalize(v) for v in obj]
        return obj

    return json.dumps(
        normalize(value),
        separators=(",", ":"),
        ensure_ascii=False,
        sort_keys=False,
    )


def signing_payload(token: CapabilityToken | dict[str, Any]) -> dict[str, Any]:
    """从令牌中抽取参与签名的字段（methods 排序，保证集合顺序无关）。"""
    if isinstance(token, CapabilityToken):
        data = token.model_dump()
    else:
        data = dict(token)
    payload = {k: data.get(k) for k in SIGNING_FIELDS}
    payload["methods"] = sorted(payload["methods"])
    return payload


def canonical_for_signing(token: CapabilityToken | dict[str, Any]) -> str:
    return canonical_json(signing_payload(token))


def compute_signature(token: CapabilityToken | dict[str, Any], secret: str) -> str:
    msg = canonical_for_signing(token).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_signature(token: CapabilityToken, secret: str) -> bool:
    expected = compute_signature(token, secret)
    return hmac.compare_digest(expected, token.signature)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_submission_hash(chain_id: str, tokens: list[CapabilityToken]) -> str:
    """整链内容指纹：用于重放幂等与“内容变化即冲突”的判定。"""
    payload = {
        "chain_id": chain_id,
        "tokens": [json.loads(t.model_dump_json()) for t in tokens],
    }
    return sha256_hex(canonical_json(payload).encode("utf-8"))


def canonical_revocation_hash(
    chain_id: str,
    token_id: str,
    effective_at: datetime,
    reason: str,
    request_key: str,
) -> str:
    """撤销事件内容指纹：同一 request_key 的重放与换目标冲突均据此判定。"""
    payload = {
        "chain_id": chain_id,
        "token_id": token_id,
        "effective_at": effective_at,
        "reason": reason,
        "request_key": request_key,
    }
    return sha256_hex(canonical_json(payload).encode("utf-8"))


def canonical_redemption_hash(
    chain_id: str,
    token_id: str,
    request_key: str,
    request_path: str,
    method: str,
    source_ip: str | None,
    body: Any,
) -> str:
    """核销请求内容指纹：同 request_key 同内容重放、换内容冲突均据此判定。

    判定时间（服务端接收时刻）不参与指纹——重放时一律返回首次结果。
    """
    payload = {
        "chain_id": chain_id,
        "token_id": token_id,
        "request_key": request_key,
        "request_path": request_path,
        "method": method,
        "source_ip": source_ip,
        "body": body,
    }
    return sha256_hex(canonical_json(payload).encode("utf-8"))


# --------------------------------------------------------------------------- #
# 路径 glob
# --------------------------------------------------------------------------- #
def _segments(pattern: str) -> list[str]:
    return [s for s in pattern.split("/")[1:] if s != ""]


def path_to_regex(pattern: str) -> str:
    """把 /a/*/c/** 形式的 glob 转成完整匹配的正则。

    *  匹配单个路径段；** 匹配任意数量路径段（含 0 段，因此 /a/** 也匹配 /a）。
    """
    segs = _segments(pattern)
    if not segs:
        return r"^/$"
    out = "^/"
    for i, seg in enumerate(segs):
        if seg == "**":
            # 去掉刚写入的 '/'，使 ** 可匹配零段（/a/** 等价于 /a 或 /a/<任意段>）
            if out.endswith("/"):
                out = out[:-1]
            out += r"(?:/[^/]*)*"
        elif seg == "*":
            out += r"[^/]+"
        else:
            out += re_escape(seg)
        if i < len(segs) - 1 and segs[i + 1] != "**":
            out += "/"
        elif i < len(segs) - 1:
            out += "/"
    return out + "$"


def re_escape(seg: str) -> str:
    import re

    return re.escape(seg).replace(r"\*", "[^/]*")


def request_path_matches(pattern: str, request_path: str) -> bool:
    import re

    return re.match(path_to_regex(pattern), request_path) is not None


def pattern_covers(child_pattern: str, parent_pattern: str) -> bool:
    """子模式是否是父模式的收窄（子允许的每条具体路径都被父允许）。

    约定 ** 只能作为末段（在模型层强制），且 /a/** 同时覆盖 /a 本身。段级判定：
      父 ** 可吸收子的任意后续段；
      父 *  要求子对应段存在，可以是 *（相等）或字面量（更窄），但不能是 **；
      父字面量要求子为相同字面量，* 或 ** 都构成放大；
      父段耗尽后子不得仍有剩余段；
      子恰好在父的 ** 前结束（/a 收窄自 /a/**）视为合法。
    """
    p = _segments(parent_pattern)
    c = _segments(child_pattern)
    i = 0
    while i < len(p):
        ps = p[i]
        if ps == "**":
            return True
        if i >= len(c):
            # 子提前结束：仅当父剩余部分为单个 **（/a 对 /a/**）时合法
            return p[i:] == ["**"]
        cs = c[i]
        if ps == "*":
            if cs == "**":
                return False
        else:
            if cs == "*" or cs == "**":
                return False
            if cs != ps:
                return False
        i += 1
    return i == len(c)


# --------------------------------------------------------------------------- #
# 方法 / 时间窗 / IP 收窄
# --------------------------------------------------------------------------- #
def methods_narrow(child: set[str], parent: set[str]) -> bool:
    return child <= parent


def time_window_narrows(
    child_nb: datetime,
    child_na: datetime,
    parent_nb: datetime,
    parent_na: datetime,
) -> bool:
    """[child_nb, child_na) 必须包含于 [parent_nb, parent_na)。"""
    from datetime import timezone

    cnb = child_nb.astimezone(timezone.utc)
    cna = child_na.astimezone(timezone.utc)
    pnb = parent_nb.astimezone(timezone.utc)
    pna = parent_na.astimezone(timezone.utc)
    return cnb >= pnb and cna <= pna


def _as_network(value: str) -> IPv4Network | IPv6Network:
    return ip_network(value, strict=True)


def ip_range_narrows(child_cidr: str | None, parent_cidr: str | None) -> bool:
    """父无限制 -> 子可任意；父有限制而子取消 -> 放大，拒绝；都有 -> 子网包含。"""
    if parent_cidr is None:
        return True
    if child_cidr is None:
        return False
    child = _as_network(child_cidr)
    parent = _as_network(parent_cidr)
    if child.version != parent.version:
        return False
    return child.subnet_of(parent)  # type: ignore[arg-type]


def ip_in_network(ip: str, cidr: str) -> bool:
    return ip_address(ip) in _as_network(cidr)
