"""端到端 API 行为测试。"""
from __future__ import annotations

from tests.conftest import make_token


def _valid_chain(chain_id="chain-ok") -> dict:
    root = make_token(
        "root",
        None,
        "root",
        "svc-a",
        "/files/**",
        ["GET", "POST"],
        chain_id=chain_id,
    )
    child = make_token(
        "child",
        "root",
        "svc-a",
        "svc-b",
        "/files/reports/*",
        ["GET"],
        allow_ip="10.0.0.0/8",
        chain_id=chain_id,
    )
    return {"chain_id": chain_id, "tokens": [root, child]}


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_valid_chain_submit_and_get(client):
    resp = client.post("/api/v1/chains", json=_valid_chain())
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["replayed"] is False
    assert body["integrity"]["allow"] is True
    assert body["integrity"]["first_failed_node"] is None
    assert body["integrity"]["ordered_token_ids"] == ["root", "child"]

    got = client.get("/api/v1/chains/chain-ok")
    assert got.status_code == 200
    assert len(got.json()["tokens"]) == 2


def test_replay_is_idempotent(client):
    payload = _valid_chain("chain-replay")
    first = client.post("/api/v1/chains", json=payload)
    assert first.status_code == 201
    second = client.post("/api/v1/chains", json=payload)
    assert second.status_code == 200
    assert second.json()["replayed"] is True


def test_content_change_conflicts(client):
    payload = _valid_chain("chain-conflict")
    assert client.post("/api/v1/chains", json=payload).status_code == 201

    # 改子令牌方法集（重新签名后内容仍不同）
    changed = _valid_chain("chain-conflict")
    changed["tokens"][1] = make_token(
        "child",
        "root",
        "svc-a",
        "svc-b",
        "/files/reports/*",
        ["GET", "POST"],
        allow_ip="10.0.0.0/8",
        chain_id="chain-conflict",
    )
    resp = client.post("/api/v1/chains", json=changed)
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["chain_id"] == "chain-conflict"
    assert detail["existing_sha256"] != detail["received_sha256"]


def test_bad_signature_denies_with_first_failure(client):
    payload = _valid_chain("chain-badsig")
    payload["tokens"][1]["signature"] = "0" * 64
    resp = client.post("/api/v1/chains", json=payload)
    assert resp.status_code == 201  # 失败结果同样持久化
    body = resp.json()
    assert body["integrity"]["allow"] is False
    assert body["integrity"]["first_failed_node"] == "child"
    assert body["integrity"]["first_failed_reason"] == "bad_signature"


def test_unknown_issuer(client):
    rogue = make_token(
        "rogue",
        "root",
        "svc-a",
        "svc-b",
        "/files/x",
        ["GET"],
        chain_id="chain-unknown",
    )
    rogue["issuer"] = "nobody"
    # 重新用不存在的密钥无法验签；直接构造提交体
    payload = {
        "chain_id": "chain-unknown",
        "tokens": [
            make_token("root", None, "root", "svc-a", chain_id="chain-unknown"),
            rogue,
        ],
    }
    resp = client.post("/api/v1/chains", json=payload)
    integrity = resp.json()["integrity"]
    assert integrity["allow"] is False
    assert integrity["first_failed_reason"] == "unknown_issuer"


def test_broken_link_and_missing_root(client):
    broken = {
        "chain_id": "chain-broken",
        "tokens": [
            make_token("c1", "ghost", "svc-a", "svc-b", chain_id="chain-broken")
        ],
    }
    body = client.post("/api/v1/chains", json=broken).json()["integrity"]
    assert body["allow"] is False
    assert body["first_failed_reason"] == "missing_root"
    assert any(
        c["reason"] == "broken_link"
        for n in body["trace"]
        for c in n["checks"]
    )


def test_cycle_detected(client):
    payload = {
        "chain_id": "chain-cycle",
        "tokens": [
            make_token("r", None, "root", "svc-a", chain_id="chain-cycle"),
            make_token("a", "r", "svc-a", "svc-b", chain_id="chain-cycle"),
            make_token("b", "c", "svc-b", "svc-a", chain_id="chain-cycle"),
            make_token("c", "b", "svc-a", "svc-b", chain_id="chain-cycle"),
        ],
    }
    body = client.post("/api/v1/chains", json=payload).json()["integrity"]
    assert body["allow"] is False
    reasons = {c["reason"] for n in body["trace"] for c in n["checks"]}
    assert "cycle" in reasons


def test_path_method_time_ip_narrowing(client):
    cases = [
        # 路径放大
        ("/elsewhere/x", ["GET"], None, None, None, "path_widens"),
        # 方法放大
        ("/files/*", ["DELETE"], None, None, None, "method_widens"),
        # 时间窗放大（早于父起点）
        ("/files/*", ["GET"], None, "2025-12-31T00:00:00Z", None, "time_window_widens"),
        # 父有 IP 限制、子取消限制 => 放大
        ("/files/*", ["GET"], None, None, "10.0.0.0/8", "ip_widens"),
    ]
    for i, (path, methods, ip, nb, parent_ip, reason) in enumerate(cases):
        chain_id = f"chain-narrow-{i}"
        root = make_token(
            "root",
            None,
            "root",
            "svc-a",
            "/files/**",
            ["GET", "POST"],
            allow_ip=parent_ip,
            chain_id=chain_id,
        )
        child = make_token(
            "child",
            "root",
            "svc-a",
            "svc-b",
            path,
            methods,
            allow_ip=ip,
            not_before=nb or "2026-01-01T00:00:00Z",
            chain_id=chain_id,
        )
        body = client.post(
            "/api/v1/chains",
            json={"chain_id": chain_id, "tokens": [root, child]},
        ).json()["integrity"]
        assert body["first_failed_node"] == "child"
        assert body["first_failed_reason"] == reason


def test_ip_narrowing_subnet(client):
    chain_id = "chain-ip-ok"
    root = make_token(
        "root", None, "root", "svc-a",
        "/files/**", ["GET"], allow_ip="10.0.0.0/8", chain_id=chain_id,
    )
    child = make_token(
        "child", "root", "svc-a", "svc-b",
        "/files/x", ["GET"], allow_ip="10.1.0.0/16", chain_id=chain_id,
    )
    body = client.post(
        "/api/v1/chains", json={"chain_id": chain_id, "tokens": [root, child]}
    ).json()["integrity"]
    assert body["allow"] is True


def test_evaluate_allow_and_deny(client):
    client.post("/api/v1/chains", json=_valid_chain("chain-eval"))

    ok = client.post(
        "/api/v1/chains/chain-eval/evaluate",
        json={
            "request_path": "/files/reports/q1.pdf",
            "method": "get",  # 小写会被规范化
            "at": "2026-06-01T00:00:00Z",
            "source_ip": "10.2.3.4",
            "body": {"k": "v"},
        },
    )
    assert ok.status_code == 200
    data = ok.json()
    assert data["decision"] == "allow"
    assert len(data["body_sha256"]) == 64
    assert data["first_failed_node"] is None

    denied = client.post(
        "/api/v1/chains/chain-eval/evaluate",
        json={
            "request_path": "/files/reports/q1.pdf",
            "method": "POST",
            "at": "2026-06-01T00:00:00Z",
            "source_ip": "10.2.3.4",
        },
    ).json()
    assert denied["decision"] == "deny"
    assert denied["first_failed_reason"] == "method_not_allowed"

    wrong_ip = client.post(
        "/api/v1/chains/chain-eval/evaluate",
        json={
            "request_path": "/files/reports/q1.pdf",
            "method": "GET",
            "at": "2026-06-01T00:00:00Z",
            "source_ip": "192.168.1.1",
        },
    ).json()
    assert wrong_ip["decision"] == "deny"
    assert wrong_ip["first_failed_reason"] == "ip_not_allowed"

    expired = client.post(
        "/api/v1/chains/chain-eval/evaluate",
        json={
            "request_path": "/files/reports/q1.pdf",
            "method": "GET",
            "at": "2027-01-01T00:00:00Z",
        },
    ).json()
    assert expired["first_failed_reason"] == "after_not_after"


def test_evaluate_unknown_chain_404(client):
    resp = client.post(
        "/api/v1/chains/nope/evaluate",
        json={
            "request_path": "/x",
            "method": "GET",
            "at": "2026-06-01T00:00:00Z",
        },
    )
    assert resp.status_code == 404


def test_naive_datetime_rejected(client):
    resp = client.post(
        "/api/v1/chains/chain-eval/evaluate",
        json={
            "request_path": "/x",
            "method": "GET",
            "at": "2026-06-01T00:00:00",
        },
    )
    assert resp.status_code == 422


def test_duplicate_id_rejected(client):
    payload = {
        "chain_id": "chain-dup",
        "tokens": [
            make_token("same", None, "root", "svc-a", chain_id="chain-dup"),
            make_token("same", None, "root", "svc-b", chain_id="chain-dup"),
        ],
    }
    body = client.post("/api/v1/chains", json=payload).json()["integrity"]
    assert body["first_failed_reason"] == "duplicate_id"


def test_multiple_roots_rejected(client):
    payload = {
        "chain_id": "chain-multiroot",
        "tokens": [
            make_token("r1", None, "root", "svc-a", chain_id="chain-multiroot"),
            make_token("r2", None, "root", "svc-b", chain_id="chain-multiroot"),
        ],
    }
    body = client.post("/api/v1/chains", json=payload).json()["integrity"]
    assert body["first_failed_reason"] == "multiple_roots"
    assert body["first_failed_node"] == "r2"
