"""按时间生效的撤销审计：提交幂等 / 冲突、求值时间解释、链 GET 事件。"""
from __future__ import annotations

import itertools

from tests.conftest import make_token

_chain_seq = itertools.count(1)


def _chain3(chain_id: str) -> dict:
    """root -> a -> b 的合法三级链。"""
    root = make_token(
        "root", None, "root", "svc-a",
        "/files/**", ["GET", "POST"], chain_id=chain_id,
    )
    a = make_token(
        "a", "root", "svc-a", "svc-b",
        "/files/reports/*", ["GET"], chain_id=chain_id,
    )
    b = make_token(
        "b", "a", "svc-b", "svc-b",
        "/files/reports/x", ["GET"], chain_id=chain_id,
    )
    return {"chain_id": chain_id, "tokens": [root, a, b]}


def _setup_chain(client) -> str:
    chain_id = f"chain-rev-{next(_chain_seq)}"
    resp = client.post("/api/v1/chains", json=_chain3(chain_id))
    assert resp.status_code == 201, resp.text
    return chain_id


def _revoke(client, chain_id, token_id, effective_at, request_key, reason="安全事件"):
    return client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": token_id,
            "effective_at": effective_at,
            "reason": reason,
            "request_key": request_key,
        },
    )


def _evaluate(client, chain_id, at="2026-06-01T00:00:00Z", **over):
    payload = {
        "request_path": "/files/reports/x",
        "method": "GET",
        "at": at,
    }
    payload.update(over)
    return client.post(f"/api/v1/chains/{chain_id}/evaluate", json=payload)


def test_revoke_created_returns_event_and_affected_chain_order(client):
    chain_id = _setup_chain(client)

    resp = _revoke(client, chain_id, "a", "2026-03-01T00:00:00Z", "rk-1")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["replayed"] is False
    event = body["event"]
    assert event["chain_id"] == chain_id
    assert event["token_id"] == "a"
    assert event["request_key"] == "rk-1"
    assert event["reason"] == "安全事件"
    assert event["effective_at"].startswith("2026-03-01T00:00:00")
    assert len(event["content_sha256"]) == 64
    assert event["created_at"]
    # a 及其后代 b，按原链顺序；root 不受影响
    assert body["affected_token_ids"] == ["a", "b"]


def test_revoke_same_request_key_same_content_replays(client):
    chain_id = _setup_chain(client)
    first = _revoke(client, chain_id, "a", "2026-03-01T00:00:00Z", "rk-replay")
    assert first.status_code == 201
    second = _revoke(client, chain_id, "a", "2026-03-01T00:00:00Z", "rk-replay")
    assert second.status_code == 200
    body = second.json()
    assert body["replayed"] is True
    assert body["event"] == first.json()["event"]
    assert body["affected_token_ids"] == ["a", "b"]


def test_revoke_same_request_key_different_target_conflicts(client):
    chain_id = _setup_chain(client)
    assert _revoke(client, chain_id, "a", "2026-03-01T00:00:00Z", "rk-x").status_code == 201
    # 换目标 token
    resp = _revoke(client, chain_id, "b", "2026-03-01T00:00:00Z", "rk-x")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["request_key"] == "rk-x"
    assert detail["existing_sha256"] != detail["received_sha256"]


def test_revoke_same_request_key_different_effective_at_conflicts(client):
    chain_id = _setup_chain(client)
    assert _revoke(client, chain_id, "a", "2026-03-01T00:00:00Z", "rk-y").status_code == 201
    resp = _revoke(client, chain_id, "a", "2026-04-01T00:00:00Z", "rk-y")
    assert resp.status_code == 409


def test_revoke_already_revoked_token_conflicts(client):
    chain_id = _setup_chain(client)
    assert _revoke(client, chain_id, "a", "2026-03-01T00:00:00Z", "rk-a1").status_code == 201
    # 即使换 request_key，也不得对同一令牌再追加撤销事件
    resp = _revoke(client, chain_id, "a", "2026-05-01T00:00:00Z", "rk-a2")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["token_id"] == "a"
    assert detail["existing_request_key"] == "rk-a1"


def test_revoke_unknown_chain_404(client):
    resp = _revoke(client, "chain-does-not-exist", "a", "2026-03-01T00:00:00Z", "rk-404")
    assert resp.status_code == 404


def test_revoke_unknown_token_404(client):
    chain_id = _setup_chain(client)
    resp = _revoke(client, chain_id, "ghost", "2026-03-01T00:00:00Z", "rk-ghost")
    assert resp.status_code == 404


def test_revoke_root_affects_whole_chain(client):
    chain_id = _setup_chain(client)
    resp = _revoke(client, chain_id, "root", "2026-03-01T00:00:00Z", "rk-root")
    assert resp.status_code == 201
    assert resp.json()["affected_token_ids"] == ["root", "a", "b"]


def test_revoke_leaf_affects_only_itself(client):
    chain_id = _setup_chain(client)
    resp = _revoke(client, chain_id, "b", "2026-03-01T00:00:00Z", "rk-leaf")
    assert resp.status_code == 201
    assert resp.json()["affected_token_ids"] == ["b"]


def test_evaluate_after_effective_at_denies_node_and_descendants(client):
    chain_id = _setup_chain(client)
    _revoke(client, chain_id, "a", "2026-03-01T00:00:00Z", "rk-eval")

    result = _evaluate(client, chain_id, at="2026-06-01T00:00:00Z").json()
    assert result["decision"] == "deny"
    # 最先受撤销影响的是 a 自身
    assert result["first_revoked_node"] == "a"
    assert result["first_failed_node"] == "a"
    assert result["first_failed_reason"] == "revoked"

    by_id = {n["token_id"]: n for n in result["trace"]}
    root_checks = {c["name"]: c for c in by_id["root"]["checks"]}
    assert root_checks["revocation_active"]["passed"] is True
    for tid in ("a", "b"):
        rev = {c["name"]: c for c in by_id[tid]["checks"]}["revocation_active"]
        assert rev["passed"] is False
        assert rev["reason"] == "revoked"
    # b 的轨迹说明应体现祖先撤销
    b_rev = {c["name"]: c for c in by_id["b"]["checks"]}["revocation_active"]
    assert "a" in b_rev["detail"] and "祖先" in b_rev["detail"]


def test_evaluate_boundary_at_equals_effective_at_is_active(client):
    chain_id = _setup_chain(client)
    _revoke(client, chain_id, "a", "2026-03-01T00:00:00Z", "rk-boundary")
    result = _evaluate(client, chain_id, at="2026-03-01T00:00:00Z").json()
    assert result["decision"] == "deny"
    assert result["first_revoked_node"] == "a"


def test_evaluate_before_effective_at_uses_original_chain(client):
    chain_id = _setup_chain(client)
    _revoke(client, chain_id, "a", "2026-03-01T00:00:00Z", "rk-future")
    # 生效前一刻：撤销不解释，原链放行
    result = _evaluate(client, chain_id, at="2026-02-28T23:59:59Z").json()
    assert result["decision"] == "allow"
    assert result["first_revoked_node"] is None
    for node in result["trace"]:
        rev = {c["name"]: c for c in node["checks"]}["revocation_active"]
        assert rev["passed"] is True


def test_evaluate_revoked_leaf_only_denies_at_leaf(client):
    chain_id = _setup_chain(client)
    _revoke(client, chain_id, "b", "2026-03-01T00:00:00Z", "rk-eval-leaf")
    result = _evaluate(client, chain_id, at="2026-06-01T00:00:00Z").json()
    assert result["decision"] == "deny"
    assert result["first_revoked_node"] == "b"
    by_id = {n["token_id"]: n for n in result["trace"]}
    for tid in ("root", "a"):
        assert {c["name"]: c for c in by_id[tid]["checks"]}[
            "revocation_active"
        ]["passed"] is True
    assert {c["name"]: c for c in by_id["b"]["checks"]}[
        "revocation_active"
    ]["passed"] is False


def test_chain_get_includes_revocations_in_append_order(client):
    chain_id = _setup_chain(client)
    _revoke(client, chain_id, "b", "2026-05-01T00:00:00Z", "rk-g1")
    _revoke(client, chain_id, "a", "2026-03-01T00:00:00Z", "rk-g2")

    got = client.get(f"/api/v1/chains/{chain_id}").json()
    events = got["revocations"]
    assert [e["token_id"] for e in events] == ["b", "a"]  # 追加顺序，不按生效时间
    assert events[1]["request_key"] == "rk-g2"


def test_chain_get_without_revocations_lists_empty(client):
    chain_id = _setup_chain(client)
    got = client.get(f"/api/v1/chains/{chain_id}").json()
    assert got["revocations"] == []


def test_revocation_naive_effective_at_rejected(client):
    chain_id = _setup_chain(client)
    resp = client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "a",
            "effective_at": "2026-03-01T00:00:00",
            "reason": "x",
            "request_key": "rk-naive",
        },
    )
    assert resp.status_code == 422


def test_revocation_future_effective_at_accepted_but_not_yet_active(client):
    chain_id = _setup_chain(client)
    resp = _revoke(client, chain_id, "a", "2030-01-01T00:00:00Z", f"rk-far-{chain_id}")
    assert resp.status_code == 201
    # 事件已存在（不可变审计），但 2026 年的求值不受影响
    assert _evaluate(client, chain_id, at="2026-06-01T00:00:00Z").json()[
        "decision"
    ] == "allow"
    # 到生效点后拒绝
    assert _evaluate(client, chain_id, at="2030-01-01T00:00:00Z").json()[
        "decision"
    ] == "deny"


def test_revocation_does_not_change_integrity_report(client):
    chain_id = _setup_chain(client)
    _revoke(client, chain_id, "a", "2026-03-01T00:00:00Z", f"rk-int-{chain_id}")
    # 完整性仍实时重算且与撤销无关：GET 中 integrity.allow 仍为 True
    integrity = client.get(f"/api/v1/chains/{chain_id}").json()["integrity"]
    assert integrity["allow"] is True
    assert integrity["ordered_token_ids"] == ["root", "a", "b"]


def test_request_key_reused_on_another_chain_conflicts(client):
    c1 = _setup_chain(client)
    c2 = _setup_chain(client)
    assert _revoke(client, c1, "a", "2026-03-01T00:00:00Z", "rk-shared").status_code == 201
    resp = _revoke(client, c2, "a", "2026-03-01T00:00:00Z", "rk-shared")
    assert resp.status_code == 409


def test_revocation_trace_reason_listed_as_revoked(client):
    chain_id = _setup_chain(client)
    _revoke(client, chain_id, "a", "2026-03-01T00:00:00Z", f"rk-reasons-{chain_id}")
    result = _evaluate(client, chain_id, at="2026-06-01T00:00:00Z").json()
    reasons = {c["reason"] for n in result["trace"] for c in n["checks"]}
    assert "revoked" in reasons
