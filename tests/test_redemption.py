"""链末端一次性访问核销：成功核销、幂等重放、并发唯一、拒绝不占键、撤销参与。"""
from __future__ import annotations

import itertools
import threading
from datetime import datetime, timedelta, timezone

from tests.conftest import make_token

_chain_seq = itertools.count(1)

# 足够宽的时间窗，覆盖测试运行时的服务器时间（2026 年内）
NB = "2020-01-01T00:00:00Z"
NA = "2030-01-01T00:00:00Z"


def _chain3(chain_id: str, leaf_ip: str | None = None,
            not_before: str = NB, not_after: str = NA) -> dict:
    """root -> a -> b 的合法三级链，末端 b 覆盖 GET /files/reports/x。"""
    root = make_token(
        "root", None, "root", "svc-a",
        "/files/**", ["GET", "POST"],
        not_before=not_before, not_after=not_after, chain_id=chain_id,
    )
    a = make_token(
        "a", "root", "svc-a", "svc-b",
        "/files/reports/**", ["GET"],
        not_before=not_before, not_after=not_after, chain_id=chain_id,
    )
    b = make_token(
        "b", "a", "svc-b", "svc-b",
        "/files/reports/x", ["GET"], allow_ip=leaf_ip,
        not_before=not_before, not_after=not_after, chain_id=chain_id,
    )
    return {"chain_id": chain_id, "tokens": [root, a, b]}


def _setup(client, leaf_ip=None, not_before=NB, not_after=NA) -> str:
    chain_id = f"chain-redm-{next(_chain_seq)}"
    resp = client.post(
        "/api/v1/chains",
        json=_chain3(chain_id, leaf_ip, not_before, not_after),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["integrity"]["allow"] is True
    return chain_id


def _redeem(client, chain_id, token_id="b", request_key="rk-1", *,
            path="/files/reports/x", method="GET", source_ip=None, body=None):
    payload = {
        "token_id": token_id,
        "request_key": request_key,
        "request_path": path,
        "method": method,
    }
    if source_ip is not None:
        payload["source_ip"] = source_ip
    if body is not None:
        payload["body"] = body
    return client.post(f"/api/v1/chains/{chain_id}/redeem", json=payload)


def test_redeem_leaf_success_returns_201_with_trace(client):
    chain_id = _setup(client)
    resp = _redeem(client, chain_id, request_key="rk-ok")
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["redeemed"] is True
    assert data["replayed"] is False
    assert data["decision"] == "allow"
    assert data["not_redeemed_reason"] is None
    assert data["chain_id"] == chain_id
    assert data["token_id"] == "b"
    assert data["request_key"] == "rk-ok"
    assert data["redeemed_at"]
    assert data["evaluated_at"]
    assert len(data["content_sha256"]) == 64
    ev = data["evaluation"]
    assert ev["decision"] == "allow"
    assert [n["token_id"] for n in ev["trace"]] == ["root", "a", "b"]
    assert ev["first_failed_node"] is None


def test_redeem_same_key_same_content_replays_first_result(client):
    chain_id = _setup(client)
    first = _redeem(client, chain_id, request_key="rk-replay", body={"q": 1})
    assert first.status_code == 201
    second = _redeem(client, chain_id, request_key="rk-replay", body={"q": 1})
    assert second.status_code == 200
    a, b = first.json(), second.json()
    assert b["replayed"] is True
    assert b["redeemed"] is True
    # 首次结果原样返回（replayed 标志除外）
    assert b["redeemed_at"] == a["redeemed_at"]
    assert b["evaluated_at"] == a["evaluated_at"]
    assert b["evaluation"] == a["evaluation"]
    assert b["decision"] == "allow"


def test_redeem_same_key_different_body_conflicts(client):
    chain_id = _setup(client)
    assert _redeem(client, chain_id, request_key="rk-body", body={"q": 1}).status_code == 201
    resp = _redeem(client, chain_id, request_key="rk-body", body={"q": 2})
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["request_key"] == "rk-body"
    assert detail["existing_sha256"] != detail["received_sha256"]


def test_redeem_same_key_different_path_or_method_conflicts(client):
    chain_id = _setup(client)
    assert _redeem(client, chain_id, request_key="rk-pm").status_code == 201
    resp = _redeem(
        client, chain_id, request_key="rk-pm",
        path="/files/reports/x", method="POST",
    )
    assert resp.status_code == 409


def test_redeem_same_key_different_token_conflicts(client):
    chain_id = _setup(client)
    assert _redeem(client, chain_id, token_id="b", request_key="rk-tok").status_code == 201
    resp = _redeem(client, chain_id, token_id="a", request_key="rk-tok")
    assert resp.status_code == 409


def test_redeem_concurrent_only_one_wins(client):
    chain_id = _setup(client)
    results: list = []
    barrier = threading.Barrier(8)

    def worker(i: int) -> None:
        barrier.wait()
        results.append(_redeem(client, chain_id, request_key=f"rk-conc-{i}"))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    codes = sorted(r.status_code for r in results)
    assert codes.count(201) == 1
    assert codes.count(409) == 7
    # 落败者明确报告“已核销”
    loser = next(r for r in results if r.status_code == 409)
    detail = loser.json()["detail"]
    assert detail["token_id"] == "b"
    assert detail["existing_request_key"] is not None
    assert detail["redeemed_at"]


def test_redeem_non_tip_token_not_redeemed_and_key_not_consumed(client):
    chain_id = _setup(client)
    # 中间节点 a 不是链末端
    mid = _redeem(client, chain_id, token_id="a", request_key="rk-mid")
    assert mid.status_code == 200
    data = mid.json()
    assert data["redeemed"] is False
    assert data["decision"] == "allow"  # 判定本身允许，但目标不符
    assert data["not_redeemed_reason"] == "target_not_chain_tip"
    assert data["redeemed_at"] is None

    # 不占 request_key：同键随后用于成功核销
    ok = _redeem(client, chain_id, token_id="b", request_key="rk-mid")
    assert ok.status_code == 201
    assert ok.json()["redeemed"] is True

    # 根同样不是末端
    root = _redeem(client, chain_id, token_id="root", request_key="rk-root-try")
    assert root.status_code == 200
    assert root.json()["not_redeemed_reason"] == "target_not_chain_tip"


def test_redeem_decision_denied_not_redeemed_and_key_not_consumed(client):
    chain_id = _setup(client)
    bad = _redeem(client, chain_id, request_key="rk-deny", method="POST")
    assert bad.status_code == 200
    data = bad.json()
    assert data["redeemed"] is False
    assert data["decision"] == "deny"
    assert data["not_redeemed_reason"] == "decision_denied"
    assert data["evaluation"]["first_failed_reason"] == "method_not_allowed"

    # 不核销、不占键：同键改为合法请求后成功
    ok = _redeem(client, chain_id, request_key="rk-deny")
    assert ok.status_code == 201
    assert ok.json()["redeemed"] is True


def test_redeem_wrong_path_denied_then_valid_retry_succeeds(client):
    chain_id = _setup(client)
    bad = _redeem(
        client, chain_id, request_key="rk-path",
        path="/files/reports/other",
    )
    assert bad.status_code == 200
    assert bad.json()["not_redeemed_reason"] == "decision_denied"
    ok = _redeem(client, chain_id, request_key="rk-path")
    assert ok.status_code == 201


def test_redeem_ip_restriction_enforced_and_retryable(client):
    chain_id = _setup(client, leaf_ip="10.0.0.0/8")
    bad = _redeem(client, chain_id, request_key="rk-ip", source_ip="192.168.1.1")
    assert bad.status_code == 200
    data = bad.json()
    assert data["redeemed"] is False
    assert data["not_redeemed_reason"] == "decision_denied"
    assert data["evaluation"]["first_failed_reason"] == "ip_not_allowed"

    ok = _redeem(client, chain_id, request_key="rk-ip", source_ip="10.2.3.4")
    assert ok.status_code == 201


def test_redeem_unknown_chain_404(client):
    resp = _redeem(client, "chain-nope", request_key="rk-404c")
    assert resp.status_code == 404


def test_redeem_unknown_token_404(client):
    chain_id = _setup(client)
    resp = _redeem(client, chain_id, token_id="ghost", request_key="rk-404t")
    assert resp.status_code == 404


def test_redeem_twice_different_keys_second_reports_already_redeemed(client):
    chain_id = _setup(client)
    assert _redeem(client, chain_id, request_key="rk-one").status_code == 201
    resp = _redeem(client, chain_id, request_key="rk-two")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert "只能核销一次" in detail["detail"]
    assert detail["existing_request_key"] == "rk-one"


def test_replay_returns_first_allow_even_after_token_later_expires(client):
    # 末端令牌在 3 秒后过期：先成功核销，再等其过期，同键同内容重放仍返回首次 allow
    now = datetime.now(timezone.utc)
    na = (now + timedelta(seconds=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    chain_id = _setup(client, not_after=na)
    first = _redeem(client, chain_id, request_key="rk-exp")
    assert first.status_code == 201

    # 换键在过期后再核销：明确 409（已核销），而非 decision_denied
    import time

    time.sleep(4)
    replay = _redeem(client, chain_id, request_key="rk-exp")
    assert replay.status_code == 200
    data = replay.json()
    assert data["replayed"] is True
    assert data["decision"] == "allow"
    assert data["redeemed"] is True
    assert data["evaluation"] == first.json()["evaluation"]

    other = _redeem(client, chain_id, request_key="rk-exp-other")
    assert other.status_code == 409
    assert other.json()["detail"]["existing_request_key"] == "rk-exp"


def test_redeem_denied_when_revocation_active_at_server_time(client):
    chain_id = _setup(client)
    # 过去生效的撤销：实时判定必拒，不核销
    resp = client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "b",
            "effective_at": "2020-06-01T00:00:00Z",
            "reason": "末端泄露",
            "request_key": "rk-rev-past",
        },
    )
    assert resp.status_code == 201
    denied = _redeem(client, chain_id, request_key="rk-after-rev")
    assert denied.status_code == 200
    data = denied.json()
    assert data["redeemed"] is False
    assert data["decision"] == "deny"
    assert data["not_redeemed_reason"] == "decision_denied"
    assert data["evaluation"]["first_failed_reason"] == "revoked"

    # 不占键，但撤销仍在——同键换内容也不会冲突（键从未被记录）；
    # 这里直接换一个新键验证：仍然判定拒绝而非“已核销”
    again = _redeem(client, chain_id, request_key="rk-never")
    assert again.status_code == 200
    assert again.json()["redeemed"] is False
    assert again.json()["not_redeemed_reason"] == "decision_denied"


def test_redeem_succeeds_with_future_revocation_then_replay_after_it_active(
    client,
):
    chain_id = _setup(client)
    # 未来才生效的撤销：核销时不应解释
    client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "b",
            "effective_at": "2030-06-01T00:00:00Z",
            "reason": "未来轮换",
            "request_key": "rk-rev-future",
        },
    )
    first = _redeem(client, chain_id, request_key="rk-before-rev")
    assert first.status_code == 201
    assert first.json()["decision"] == "allow"

    # 同键重放：返回首次结果
    replay = _redeem(client, chain_id, request_key="rk-before-rev")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True


def test_replay_after_revocation_becomes_active_still_returns_first_result(
    client,
):
    chain_id = _setup(client)
    first = _redeem(client, chain_id, request_key="rk-then-revoke")
    assert first.status_code == 201
    # 核销之后再撤销末端
    rev = client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "b",
            "effective_at": "2020-01-01T00:00:00Z",
            "reason": "事后撤销",
            "request_key": "rk-revoke-after",
        },
    )
    assert rev.status_code == 201
    # 同键同内容重放：返回首次 allow，不被事后撤销影响
    replay = _redeem(client, chain_id, request_key="rk-then-revoke")
    assert replay.status_code == 200
    data = replay.json()
    assert data["replayed"] is True
    assert data["decision"] == "allow"
    assert data["evaluation"]["first_failed_node"] is None
    # 换键重试：已核销 409（撤销状态已无关）
    other = _redeem(client, chain_id, request_key="rk-then-revoke-x")
    assert other.status_code == 409


def test_redeem_request_body_changes_hash_but_denial_does_not_consume(client):
    chain_id = _setup(client)
    # 先用不合法方法 + body 试一次（被拒），再以同键同 body 合法核销
    first = _redeem(
        client, chain_id, request_key="rk-deny-body",
        method="POST", body={"v": 1},
    )
    assert first.status_code == 200
    assert first.json()["redeemed"] is False
    ok = _redeem(
        client, chain_id, request_key="rk-deny-body", body={"v": 1}
    )
    assert ok.status_code == 201


def test_redeem_invalid_input_422(client):
    chain_id = _setup(client)
    resp = client.post(
        f"/api/v1/chains/{chain_id}/redeem",
        json={
            "token_id": "b",
            "request_key": "rk-bad",
            "request_path": "no-leading-slash",
            "method": "GET",
        },
    )
    assert resp.status_code == 422


def test_redeem_method_case_insensitive(client):
    chain_id = _setup(client)
    resp = _redeem(client, chain_id, request_key="rk-case", method="get")
    assert resp.status_code == 201, resp.text
    # 内容指纹按大写方法规范化；用 GET 同键重放视为同一请求
    replay = _redeem(client, chain_id, request_key="rk-case", method="GET")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True


def test_redeem_does_not_affect_readonly_evaluate(client):
    chain_id = _setup(client)
    assert _redeem(client, chain_id, request_key="rk-ro").status_code == 201
    # 核销不落撤销，只读求值行为不变
    ev = client.post(
        f"/api/v1/chains/{chain_id}/evaluate",
        json={
            "request_path": "/files/reports/x",
            "method": "GET",
            "at": "2026-06-01T00:00:00Z",
        },
    ).json()
    assert ev["decision"] == "allow"
    assert ev["first_revoked_node"] is None
