"""构造并演示一条合法委托能力链：root -> service-a -> service-b。

用法：
    # 仅打印已签名的提交报文（不依赖服务运行）
    python scripts/demo_chain.py print

    # 提交到本机服务并执行一次求值（默认 http://127.0.0.1:8000）
    python scripts/demo_chain.py submit
    BASE_URL=http://localhost:8000 python scripts/demo_chain.py submit
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from app.security import compute_signature

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000")

# 与 app.database.DEMO_PRINCIPALS 保持一致的演示密钥
SECRETS = {
    "root": os.getenv("ROOT_HMAC_SECRET", "dev-root-secret-change-me"),
    "service-a": "demo-secret-service-a",
    "service-b": "demo-secret-service-b",
}

CHAIN_ID = os.getenv("DEMO_CHAIN_ID", "demo-chain-0001")
# 演示一次性核销：核销末端 token-b（必须在撤销之前，撤销后将判定拒绝）
REDEEM_REQUEST_KEY = os.getenv("DEMO_REDEEM_KEY", "access-redeem-2026-0001")
# 演示撤销：撤销 token-a，使其及后代 token-b 自该时刻起失效
REVOKE_TOKEN_ID = "token-a"
REVOKE_REQUEST_KEY = os.getenv("DEMO_REVOKE_KEY", "ops-revoke-2026-0001")
REVOKE_REASON = "运维安全事件：演示撤销 token-a 及其下游委托"


def _token(
    token_id: str,
    parent_id: str | None,
    issuer: str,
    subject: str,
    path_pattern: str,
    methods: list[str],
    not_before: datetime,
    not_after: datetime,
    allow_ip: str | None,
) -> dict:
    t = {
        "token_id": token_id,
        "parent_id": parent_id,
        "chain_id": CHAIN_ID,
        "issuer": issuer,
        "subject": subject,
        "path_pattern": path_pattern,
        "methods": methods,
        "not_before": not_before.isoformat().replace("+00:00", "Z"),
        "not_after": not_after.isoformat().replace("+00:00", "Z"),
        "allow_ip": allow_ip,
        "signature": "",
    }
    t["signature"] = compute_signature(t, SECRETS[issuer])
    return t


def build_submission() -> dict:
    now = datetime.now(timezone.utc)
    nb = now - timedelta(days=1)
    na = now + timedelta(days=30)
    root = _token(
        "token-root",
        None,
        "root",
        "service-a",
        "/files/**",
        ["GET", "POST", "PUT"],
        nb,
        na,
        None,
    )
    delegated_a = _token(
        "token-a",
        "token-root",
        "service-a",
        "service-b",
        "/files/reports/**",
        ["GET", "POST"],
        nb + timedelta(hours=1),
        na - timedelta(days=1),
        "10.0.0.0/8",
    )
    delegated_b = _token(
        "token-b",
        "token-a",
        "service-b",
        "service-b-worker",
        "/files/reports/2026/q1.pdf",
        ["GET"],
        nb + timedelta(hours=2),
        na - timedelta(days=2),
        "10.1.0.0/16",
    )
    return {"chain_id": CHAIN_ID, "tokens": [root, delegated_a, delegated_b]}


def build_evaluation(at: datetime | None = None) -> dict:
    return {
        "request_path": "/files/reports/2026/q1.pdf",
        "method": "GET",
        "at": (at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z"),
        "source_ip": "10.1.2.3",
        "body": {"q": "demo"},
    }


def build_revocation(effective_at: datetime | None = None) -> dict:
    return {
        "token_id": REVOKE_TOKEN_ID,
        "effective_at": (
            effective_at or datetime.now(timezone.utc)
        ).isoformat().replace("+00:00", "Z"),
        "reason": REVOKE_REASON,
        "request_key": REVOKE_REQUEST_KEY,
    }


def build_redemption() -> dict:
    """一次性核销请求：目标为链末端 token-b；判定时间由服务端取接收时刻。"""
    eval_request = build_evaluation()
    eval_request.pop("at", None)  # 核销接口不接受客户端时间
    return {"token_id": "token-b", "request_key": REDEEM_REQUEST_KEY, **eval_request}


def _post(url: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "print"
    submission = build_submission()
    if mode == "print":
        print(json.dumps(submission, ensure_ascii=False, indent=2))
        return 0

    if mode != "submit":
        print(__doc__)
        return 2

    status_code, body = _post(f"{BASE_URL}/api/v1/chains", submission)
    print(f"[submit] HTTP {status_code}")
    print(json.dumps(body, ensure_ascii=False, indent=2))

    # 幂等重放：同样内容再来一次
    status_code, body = _post(f"{BASE_URL}/api/v1/chains", submission)
    print(f"[replay] HTTP {status_code} (replayed={body.get('replayed')})")

    status_code, body = _post(
        f"{BASE_URL}/api/v1/chains/{CHAIN_ID}/evaluate", build_evaluation()
    )
    print(f"[evaluate-before-revocation] HTTP {status_code}")
    print(json.dumps(body, ensure_ascii=False, indent=2))

    # 一次性访问核销：对链末端 token-b 成功核销（201，返回判定轨迹与核销时间）
    redemption = build_redemption()
    status_code, body = _post(
        f"{BASE_URL}/api/v1/chains/{CHAIN_ID}/redeem", redemption
    )
    print(f"[redeem] HTTP {status_code}")
    print(json.dumps(body, ensure_ascii=False, indent=2))

    # 同 request_key 同内容重放：返回首次结果（200，replayed=true）
    status_code, body = _post(
        f"{BASE_URL}/api/v1/chains/{CHAIN_ID}/redeem", redemption
    )
    print(f"[redeem-replay] HTTP {status_code} (replayed={body.get('replayed')})")

    # 再次尝试核销同一令牌（换 request_key）：409，明确报告已核销
    status_code, body = _post(
        f"{BASE_URL}/api/v1/chains/{CHAIN_ID}/redeem",
        {**redemption, "request_key": "access-redeem-2026-0002"},
    )
    print(f"[redeem-again] HTTP {status_code} {body.get('detail', body)}")

    # 提交按时间生效的撤销（effective_at 取“现在”，立即生效）
    effective = datetime.now(timezone.utc)
    status_code, body = _post(
        f"{BASE_URL}/api/v1/chains/{CHAIN_ID}/revocations",
        build_revocation(effective),
    )
    print(f"[revoke] HTTP {status_code}")
    print(json.dumps(body, ensure_ascii=False, indent=2))

    # 幂等重放：同 request_key 同内容，应返回 200 + replayed=true
    status_code, body = _post(
        f"{BASE_URL}/api/v1/chains/{CHAIN_ID}/revocations",
        build_revocation(effective),
    )
    print(f"[revoke-replay] HTTP {status_code} (replayed={body.get('replayed')})")

    # 生效后的求值：token-a 及其后代 token-b 应被拒绝
    status_code, body = _post(
        f"{BASE_URL}/api/v1/chains/{CHAIN_ID}/evaluate", build_evaluation()
    )
    print(f"[evaluate-after-revocation] HTTP {status_code}")
    print(json.dumps(body, ensure_ascii=False, indent=2))

    # 生效前一刻的历史请求：撤销不解释，仍按原链判定
    before = effective - timedelta(seconds=1)
    status_code, body = _post(
        f"{BASE_URL}/api/v1/chains/{CHAIN_ID}/evaluate", build_evaluation(before)
    )
    print(f"[evaluate-before-effective-at] HTTP {status_code}")
    print(json.dumps(body, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
