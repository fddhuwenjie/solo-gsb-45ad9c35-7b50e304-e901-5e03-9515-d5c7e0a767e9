"""一次性访问核销：末端限制、服务端时刻判定、幂等与并发唯一成功。"""
from __future__ import annotations

import itertools
import threading
from datetime import datetime, timedelta, timezone

from tests.conftest import make_token

_chain_seq = itertools.count(1)


def _now_window(**offsets) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    nb = now + timedelta(seconds=offsets.get("nb", -3600))
    na = now + timedelta(seconds=offsets.get("na", 3600))
    return (
        nb.isoformat().replace("+00:00", "Z"),
        na.isoformat().replace("+00:00", "Z"),
    )


def _chain3(chain_id: str, **leaf_over) -> dict:
    """root -> a -> b 的合法三级链（默认对服务端当前时刻有效）。"""
    nb, na = _now_window()
    root = make_token(
        "root", None, "root", "svc-a",
        "/files/**", ["GET", "POST"], not_before=nb, not_after=na,
        chain_id=chain_id,
    )
    a = make_token(
        "a", "root", "svc-a", "svc-b",
        "/files/reports/*", ["GET"], allow_ip="10.0.0.0/8",
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    b_kwargs = dict(
        parent_id="a", issuer="svc-b", subject="svc-b",
        path_pattern="/files/reports/x", methods=["GET"],
        allow_ip="10.1.0.0/16",
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    b_kwargs.update(leaf_over)
    b = make_token("b", **b_kwargs)
    return {"chain_id": chain_id, "tokens": [root, a, b]}


def _setup(client, **leaf_over) -> str:
    chain_id = f"chain-redeem-{next(_chain_seq)}"
    resp = client.post("/api/v1/chains", json=_chain3(chain_id, **leaf_over))
    assert resp.status_code == 201, resp.text
    return chain_id


def _redeem(
    client,
    chain_id,
    *,
    token_id="b",
    request_key="rk",
    request_path="/files/reports/x",
    method="GET",
    source_ip="10.1.2.3",
    body=None,
):
    payload = {
        "token_id": token_id,
        "request_key": request_key,
        "request_path": request_path,
        "method": method,
    }
    if source_ip is not None:
        payload["source_ip"] = source_ip
    if body is not None:
        payload["body"] = body
    return client.post(f"/api/v1/chains/{chain_id}/redeem", json=payload)


# --------------------------------------------------------------------------- #
# 成功核销
# --------------------------------------------------------------------------- #
def test_redeem_leaf_success_records_redemption(client):
    chain_id = _setup(client)
    resp = _redeem(client, chain_id, request_key="rk-ok", body={"k": "v"})
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["redeemed"] is True
    assert data["replayed"] is False
    assert data["decision"] == "allow"
    assert data["chain_id"] == chain_id
    assert data["token_id"] == "b"
    assert data["request_key"] == "rk-ok"
    assert data["first_failed_node"] is None
    assert data["first_failed_reason"] is None
    assert data["first_revoked_node"] is None
    assert data["redeemed_at"] is not None
    assert data["evaluated_at"] is not None
    assert len(data["body_sha256"]) == 64
    # 返回完整判定轨迹（完整性 + 请求级）
    by_id = {n["token_id"]: n for n in data["trace"]}
    assert set(by_id) == {"root", "a", "b"}
    assert {c["name"] for c in by_id["b"]["checks"]} >= {
        "signature",
        "revocation_active",
        "time_valid",
        "method_allowed",
        "path_covered",
        "ip_allowed",
    }


def test_redeem_evaluated_at_is_server_time_not_client_input(client):
    chain_id = _setup(client)
    before = datetime.now(timezone.utc)
    resp = _redeem(client, chain_id, request_key="rk-time")
    after = datetime.now(timezone.utc)
    assert resp.status_code == 201
    evaluated = datetime.fromisoformat(resp.json()["evaluated_at"])
    assert before <= evaluated <= after + timedelta(seconds=1)


# --------------------------------------------------------------------------- #
# 一次性 / 并发
# --------------------------------------------------------------------------- #
def test_token_can_only_be_redeemed_once_different_key_conflicts(client):
    chain_id = _setup(client)
    assert _redeem(client, chain_id, request_key="rk-one").status_code == 201
    resp = _redeem(client, chain_id, request_key="rk-two")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["token_id"] == "b"
    assert detail["existing_request_key"] == "rk-one"
    assert "只能成功核销一次" in detail["detail"]


def test_concurrent_redeems_only_one_wins(client):
    chain_id = _setup(client)
    results: list[tuple[int, dict]] = []
    barrier = threading.Barrier(8)

    def worker(i: int) -> None:
        barrier.wait()
        resp = _redeem(client, chain_id, request_key=f"rk-conc-{i}")
        results.append((resp.status_code, resp.json()))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    created = [r for r in results if r[0] == 201]
    conflicts = [r for r in results if r[0] == 409]
    assert len(created) == 1
    assert len(conflicts) == 7
    assert created[0][1]["redeemed"] is True
    for _, body in conflicts:
        detail = body["detail"]
        assert "核销" in detail["detail"]
        # 输家明确得知令牌已被核销及赢家的 request_key
        assert detail["existing_request_key"] == created[0][1]["request_key"]


# --------------------------------------------------------------------------- #
# 幂等：同键同内容回放首次结果
# --------------------------------------------------------------------------- #
def test_same_key_same_content_replays_first_result(client):
    chain_id = _setup(client)
    payload = dict(
        token_id="b", request_key="rk-replay",
        request_path="/files/reports/x", method="GET",
        source_ip="10.1.2.3", body={"q": 1},
    )
    first = client.post(f"/api/v1/chains/{chain_id}/redeem", json=payload)
    assert first.status_code == 201
    second = client.post(f"/api/v1/chains/{chain_id}/redeem", json=payload)
    assert second.status_code == 200
    f, s = first.json(), second.json()
    assert s["replayed"] is True
    assert s["redeemed"] is True
    assert s["redeemed_at"] == f["redeemed_at"]
    assert s["evaluated_at"] == f["evaluated_at"]
    assert s["decision"] == f["decision"]
    assert s["body_sha256"] == f["body_sha256"]
    assert s["trace"] == f["trace"]


def test_replay_returns_first_result_even_after_revocation(client):
    chain_id = _setup(client)
    first = _redeem(client, chain_id, request_key="rk-rev")
    assert first.status_code == 201
    # 核销成功后令牌（末端 b）被撤销
    revoked = client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "b",
            "effective_at": datetime.now(timezone.utc)
            .isoformat().replace("+00:00", "Z"),
            "reason": "事后撤销",
            "request_key": "ops-revoke-b",
        },
    )
    assert revoked.status_code == 201
    # 同键重放：仍返回首次的 allow 结果，而非当下的 deny
    replay = _redeem(client, chain_id, request_key="rk-rev")
    assert replay.status_code == 200
    body = replay.json()
    assert body["replayed"] is True
    assert body["decision"] == "allow"
    assert body["redeemed"] is True
    assert body["redeemed_at"] == first.json()["redeemed_at"]


def test_replay_returns_first_result_even_after_expiry(client):
    # 令牌在一秒后过期：成功核销后，同键重放仍是首次的 allow
    nb, na = _now_window(nb=-3600, na=1)
    chain_id = f"chain-redeem-{next(_chain_seq)}"
    root = make_token(
        "root", None, "root", "svc-a", "/files/**", ["GET"],
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    leaf = make_token(
        "b", "root", "svc-a", "svc-b", "/files/x", ["GET"],
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    assert client.post(
        "/api/v1/chains", json={"chain_id": chain_id, "tokens": [root, leaf]}
    ).status_code == 201
    first = _redeem(client, chain_id, request_key="rk-exp", request_path="/files/x")
    assert first.status_code == 201
    assert first.json()["decision"] == "allow"

    import time as _time

    _time.sleep(1.1)
    replay = _redeem(client, chain_id, request_key="rk-exp", request_path="/files/x")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["decision"] == "allow"
    assert replay.json()["redeemed_at"] == first.json()["redeemed_at"]


def test_same_key_changed_content_conflicts(client):
    chain_id = _setup(client)
    assert _redeem(
        client, chain_id, request_key="rk-change", source_ip="10.1.2.3"
    ).status_code == 201
    # 同键换来源 IP（换内容）
    resp = _redeem(
        client, chain_id, request_key="rk-change", source_ip="10.9.9.9"
    )
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["request_key"] == "rk-change"
    assert detail["existing_sha256"] != detail["received_sha256"]
    # 换路径 / 方法 / 请求体同样冲突
    for kw in (
        {"request_path": "/files/reports/y"},
        {"method": "POST"},
        {"body": {"other": 1}},
    ):
        assert _redeem(client, chain_id, request_key="rk-change", **kw).status_code == 409


def test_same_key_changed_target_token_conflicts(client):
    chain_id = _setup(client)
    assert _redeem(client, chain_id, request_key="rk-move").status_code == 201
    resp = _redeem(client, chain_id, token_id="a", request_key="rk-move")
    assert resp.status_code == 409
    assert resp.json()["detail"]["request_key"] == "rk-move"


def test_already_redeemed_conflicts_even_if_token_since_revoked(client):
    chain_id = _setup(client)
    assert _redeem(client, chain_id, request_key="rk-once").status_code == 201
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    assert client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "b", "effective_at": now,
            "reason": "事后撤销", "request_key": "ops-after",
        },
    ).status_code == 201
    # 换 key 再来：即便此刻实时判定本会 deny，也统一明确报告“已核销”
    resp = _redeem(client, chain_id, request_key="rk-once-2")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["existing_request_key"] == "rk-once"
    assert "只能成功核销一次" in detail["detail"]


# --------------------------------------------------------------------------- #
# 目标限制
# --------------------------------------------------------------------------- #
def test_non_tip_target_conflicts_and_does_not_redeem(client):
    chain_id = _setup(client)
    resp = _redeem(client, chain_id, token_id="a", request_key="rk-mid")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["chain_tip_token_id"] == "b"
    assert detail["token_id"] == "a"
    # 未核销：末端 b 仍可被（另一把钥匙）核销
    assert _redeem(client, chain_id, token_id="b", request_key="rk-leaf").status_code == 201


def test_redeem_root_target_conflicts(client):
    chain_id = _setup(client)
    resp = _redeem(
        client, chain_id, token_id="root", request_key="rk-root",
        request_path="/files/reports/x",
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["chain_tip_token_id"] == "b"


def test_redeem_unknown_chain_404(client):
    resp = _redeem(client, "chain-missing", request_key="rk-404")
    assert resp.status_code == 404


def test_redeem_unknown_token_404(client):
    chain_id = _setup(client)
    resp = _redeem(client, chain_id, token_id="ghost", request_key="rk-ghost")
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# 判定拒绝：不核销、不占用 request_key
# --------------------------------------------------------------------------- #
def test_denied_redeem_returns_trace_without_redeeming(client):
    chain_id = _setup(client)
    # 方法不在末端集合 -> deny
    resp = _redeem(client, chain_id, method="POST", request_key="rk-deny")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["redeemed"] is False
    assert data["replayed"] is False
    assert data["redeemed_at"] is None
    assert data["decision"] == "deny"
    assert data["first_failed_reason"] == "method_not_allowed"
    assert data["evaluated_at"] is not None
    assert len(data["trace"]) == 3


def test_denied_redeem_does_not_consume_token(client):
    chain_id = _setup(client)
    assert _redeem(client, chain_id, method="POST", request_key="rk-x").status_code == 200
    # 同一令牌随后的有效请求成功核销
    ok = _redeem(client, chain_id, method="GET", request_key="rk-y")
    assert ok.status_code == 201
    assert ok.json()["redeemed"] is True


def test_denied_redeem_does_not_consume_request_key(client):
    chain_id = _setup(client)
    # 第一次：路径不匹配，拒绝（不占用 request_key）
    bad = _redeem(
        client, chain_id, request_path="/elsewhere", request_key="rk-reuse"
    )
    assert bad.status_code == 200
    assert bad.json()["redeemed"] is False
    # 同一 request_key 换为有效请求：正常成功（不构成冲突）
    ok = _redeem(
        client, chain_id, request_path="/files/reports/x", request_key="rk-reuse"
    )
    assert ok.status_code == 201
    assert ok.json()["redeemed"] is True


def test_redeem_denied_then_same_key_replays_after_success(client):
    chain_id = _setup(client)
    bad = _redeem(client, chain_id, method="POST", request_key="rk-seq")
    assert bad.status_code == 200 and bad.json()["redeemed"] is False
    ok = _redeem(client, chain_id, method="GET", request_key="rk-seq")
    assert ok.status_code == 201 and ok.json()["redeemed"] is True
    # 再以同键同内容（GET 版）重放 -> 首次成功结果
    replay = _redeem(client, chain_id, method="GET", request_key="rk-seq")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["decision"] == "allow"


def test_redeem_wrong_ip_denied(client):
    chain_id = _setup(client)
    resp = _redeem(client, chain_id, source_ip="192.168.0.1", request_key="rk-ip")
    assert resp.status_code == 200
    data = resp.json()
    assert data["redeemed"] is False
    assert data["decision"] == "deny"
    assert data["first_failed_reason"] == "ip_not_allowed"


def test_redeem_after_revocation_denied_and_not_consumed(client):
    chain_id = _setup(client)
    # 撤销末端 b，立即生效
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    revoked = client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "b", "effective_at": now,
            "reason": "泄露", "request_key": "ops-1",
        },
    )
    assert revoked.status_code == 201
    resp = _redeem(client, chain_id, request_key="rk-after-rev")
    assert resp.status_code == 200
    data = resp.json()
    assert data["redeemed"] is False
    assert data["decision"] == "deny"
    assert data["first_revoked_node"] == "b"
    assert data["first_failed_reason"] == "revoked"
    # 撤销后无法再成功核销：令牌已废（此例没有“恢复”路径，验证拒绝幂等不占键）
    again = _redeem(client, chain_id, request_key="rk-after-rev")
    assert again.status_code == 200
    assert again.json()["redeemed"] is False


def test_redeem_expired_token_denied_and_key_reusable_elsewhere(client):
    # 一条已过期链：核销拒绝；request_key 可用于另一条有效链
    nb, na = _now_window(nb=-7200, na=-3600)
    expired_id = f"chain-redeem-{next(_chain_seq)}"
    expired = {
        "chain_id": expired_id,
        "tokens": [
            make_token(
                "root", None, "root", "svc-a", "/files/**", ["GET"],
                not_before=nb, not_after=na, chain_id=expired_id,
            ),
            make_token(
                "b", "root", "svc-a", "svc-b", "/files/x", ["GET"],
                not_before=nb, not_after=na, chain_id=expired_id,
            ),
        ],
    }
    assert client.post("/api/v1/chains", json=expired).status_code == 201
    resp = _redeem(
        client, expired_id, request_key="rk-shared", request_path="/files/x"
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "deny"
    assert resp.json()["first_failed_reason"] == "after_not_after"

    fresh = _setup(client)
    ok = _redeem(client, fresh, request_key="rk-shared")
    assert ok.status_code == 201
    assert ok.json()["redeemed"] is True


# --------------------------------------------------------------------------- #
# 与既有只读求值 / 撤销行为共存
# --------------------------------------------------------------------------- #
def test_readonly_evaluate_still_works_after_redemption(client):
    chain_id = _setup(client)
    assert _redeem(client, chain_id, request_key="rk-ro").status_code == 201
    # 核销不改变链：只读求值照常实时判定（当前时刻仍 allow）
    at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    resp = client.post(
        f"/api/v1/chains/{chain_id}/evaluate",
        json={
            "request_path": "/files/reports/x", "method": "GET",
            "at": at, "source_ip": "10.1.2.3",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "allow"


def test_revocation_still_works_after_denied_redeem(client):
    chain_id = _setup(client)
    assert _redeem(client, chain_id, method="POST", request_key="rk-d").status_code == 200
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    resp = client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "b", "effective_at": now,
            "reason": "x", "request_key": "ops-2",
        },
    )
    assert resp.status_code == 201


def test_chain_get_lists_redemptions_in_append_order(client):
    c1 = _setup(client)
    c2 = _setup(client)
    assert _redeem(client, c1, request_key="rk-list-1").status_code == 201
    assert _redeem(client, c2, request_key="rk-list-2").status_code == 201

    got = client.get(f"/api/v1/chains/{c1}").json()
    assert [e["request_key"] for e in got["redemptions"]] == ["rk-list-1"]
    event = got["redemptions"][0]
    assert event["chain_id"] == c1
    assert event["token_id"] == "b"
    assert event["request_path"] == "/files/reports/x"
    assert event["method"] == "GET"
    assert event["source_ip"] == "10.1.2.3"
    assert event["request_body"] is None
    assert len(event["content_sha256"]) == 64
    assert event["redeemed_at"]

    assert client.get(f"/api/v1/chains/{c2}").json()["redemptions"][0][
        "request_key"
    ] == "rk-list-2"


def test_chain_get_without_redemptions_lists_empty(client):
    chain_id = _setup(client)
    got = client.get(f"/api/v1/chains/{chain_id}").json()
    assert got["redemptions"] == []


def test_redeem_invalid_method_rejected_by_validation(client):
    chain_id = _setup(client)
    resp = client.post(
        f"/api/v1/chains/{chain_id}/redeem",
        json={
            "token_id": "b", "request_key": "rk-bad",
            "request_path": "/x", "method": "GET POST",
        },
    )
    assert resp.status_code == 422


def test_redeem_method_normalized_uppercase(client):
    chain_id = _setup(client)
    resp = _redeem(client, chain_id, method="get", request_key="rk-upper")
    assert resp.status_code == 201
    assert resp.json()["decision"] == "allow"
    assert client.get(f"/api/v1/chains/{chain_id}").json()["redemptions"][0][
        "method"
    ] == "GET"
