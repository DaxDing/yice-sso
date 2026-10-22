import json
import urllib.parse

import pytest

from sso_service.access_log import AccessLog
from sso_service.api import create_app, state_cookie_name
from sso_service.service import token_hash
from sso_service.store import Member
from tests.support import PARTNER_TENANT, FakeOAuth, FakeStore, make_service, make_settings, peer_client, token

TASK_PEER = "10.0.0.50"


@pytest.fixture
def env(tmp_path):
    store, oauth = FakeStore(), FakeOAuth()
    store.members["ou_member"] = Member("ou_member", "张三", "", "投放部")
    oauth.users["c-member"] = {"open_id": "ou_member", "name": "张三"}
    oauth.users["c-stranger"] = {"open_id": "ou_stranger", "name": "路人"}
    oauth.users["c-partner"] = {"open_id": "ou_q1", "name": "合作企业甲", "tenant_key": PARTNER_TENANT}
    settings = make_settings(tmp_path)
    service = make_service(tmp_path, store=store, oauth=oauth, settings=settings)
    log = AccessLog(tmp_path / "access.jsonl")
    app = create_app(settings=settings, service=service, access_log=log)
    return app, store, tmp_path / "access.jsonl"


def _query(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}


def _cookies(response) -> list[str]:
    return response.headers.get_list("set-cookie")


def _browser_login(
    client, caller="task", code="c-member", next_url="https://task.example.com/warehouse", provider="default"
):
    login = client.get("/sso/login", params={"caller": caller, "next": next_url})
    if login.status_code == 303:
        authorize_url = login.headers["location"]
    else:
        # Multi-provider page: follow the link of the requested provider.
        hrefs = [chunk.split('"', 1)[0].replace("&amp;", "&") for chunk in login.text.split('href="')[1:]]
        authorize_url = next(h for h in hrefs if f"provider={provider}" in h)
    path = urllib.parse.urlsplit(authorize_url)
    authorize = client.get(path.path, params=_query(authorize_url))
    assert authorize.status_code == 302
    state = _query(authorize.headers["location"])["state"]
    name = state_cookie_name(state)
    state_cookie = next(c for c in _cookies(authorize) if c.startswith(f"{name}="))
    assert "Path=/sso" in state_cookie and "HttpOnly" in state_cookie and "Domain" not in state_cookie
    return client.get(
        "/sso/callback", params={"code": code, "state": state}, headers={"Cookie": f"{name}={state}"}
    )


def _session_token(response) -> str:
    cookie = next(c for c in _cookies(response) if c.startswith("yice_sso="))
    return cookie.split(";", 1)[0].split("=", 1)[1]


def test_single_provider_caller_goes_straight_to_feishu(env):
    app, _, _ = env
    client = peer_client(app)
    response = client.get("/sso/login", params={"caller": "task", "next": "/warehouse"})
    assert response.status_code == 303
    assert response.headers["location"].startswith("https://example.com/sso/authorize?")
    assert _query(response.headers["location"])["next"] == "https://task.example.com/warehouse"


def test_multi_provider_caller_gets_a_choice_page_with_strict_headers(env):
    app, _, _ = env
    response = peer_client(app).get("/sso/login", params={"caller": "info"})
    assert response.status_code == 200
    assert "示例主企业" in response.text and "示例合作企业" in response.text
    assert "form-action 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert "<script" not in response.text


def test_full_login_sets_parent_domain_session_cookie(env):
    app, store, _ = env
    response = _browser_login(peer_client(app))
    assert response.status_code == 303
    assert response.headers["location"] == "https://task.example.com/warehouse"
    cookies = _cookies(response)
    session = next(c for c in cookies if c.startswith("yice_sso="))
    for part in ("Domain=example.com", "Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age=34560000"):
        assert part in session
    assert any(c.startswith("yice_sso_state_") and "=;" in c and "Max-Age=0" in c for c in cookies)
    assert token_hash(_session_token(response)) in store.sessions


def test_open_redirects_fall_back_to_the_caller_origin(env):
    app, _, _ = env
    client = peer_client(app)
    for evil in ("https://evil.example/", "//evil.example/x", "https://example.com/", "https://u:p@task.example.com/"):
        response = client.get("/sso/login", params={"caller": "task", "next": evil})
        assert _query(response.headers["location"])["next"] == "https://task.example.com/"


def test_logged_in_user_skips_the_login_page(env):
    app, _, _ = env
    client = peer_client(app)
    session = _session_token(_browser_login(client))
    response = client.get(
        "/sso/login", params={"caller": "task", "next": "/x"}, headers={"Cookie": f"yice_sso={session}"}
    )
    assert response.status_code == 303 and response.headers["location"] == "https://task.example.com/x"


def test_denied_login_returns_to_the_caller_login_page_with_code(env):
    app, store, _ = env
    response = _browser_login(peer_client(app), code="c-stranger")
    assert response.status_code == 303
    assert _query(response.headers["location"]) == {"caller": "task", "error": "member_not_allowed"}
    assert not store.sessions
    page = peer_client(app).get(response.headers["location"])
    assert page.status_code == 200 and "在职名单" in page.text


def test_callback_without_valid_state_shows_error_page(env):
    app, _, _ = env
    response = peer_client(app).get("/sso/callback", params={"code": "c", "state": "s"})
    assert response.status_code == 400 and "登录状态" in response.text


def test_tenant_user_on_member_only_caller_is_offered_logout(env):
    app, _, _ = env
    client = peer_client(app)
    session = _session_token(_browser_login(client, caller="info", code="c-partner", next_url="https://example.com/", provider="partner"))
    page = client.get("/sso/login", params={"caller": "task"}, headers={"Cookie": f"yice_sso={session}"})
    assert page.status_code == 200 and "无权访问" in page.text and "/sso/logout?caller=task" in page.text


def _logout(client, session, origin="https://example.com", **form):
    headers = {"Cookie": f"yice_sso={session}", "Content-Type": "application/x-www-form-urlencoded"}
    if origin:
        headers["Origin"] = origin
    return client.post("/sso/logout", content=urllib.parse.urlencode({"caller": "task", **form}), headers=headers)


def test_logout_get_only_shows_a_same_origin_form(env):
    app, store, _ = env
    client = peer_client(app)
    session = _session_token(_browser_login(client))
    page = client.get("/sso/logout", params={"caller": "task"}, headers={"Cookie": f"yice_sso={session}"})
    assert page.status_code == 200 and '<form method="post" action="https://example.com/sso/logout">' in page.text
    assert "form-action 'self'" in page.headers["content-security-policy"]
    # With no-referrer the browser would post "Origin: null" and the same-origin check would refuse it.
    assert page.headers["referrer-policy"] == "same-origin"
    assert store.sessions and not any(c.startswith("yice_sso=") for c in _cookies(page))


def test_cross_site_logout_post_is_refused(env):
    app, store, _ = env
    client = peer_client(app)
    session = _session_token(_browser_login(client))
    assert _logout(client, session, origin="https://evil.example").status_code == 403
    assert _logout(client, session, origin=None).status_code == 403
    assert _logout(client, session, origin="null").status_code == 403
    cross = {"Cookie": f"yice_sso={session}", "Origin": "null", "Sec-Fetch-Site": "cross-site"}
    assert client.post("/sso/logout", content="caller=task", headers=cross).status_code == 403
    assert store.sessions


def test_logout_with_an_opaque_origin_falls_back_to_fetch_metadata(env):
    app, store, _ = env
    client = peer_client(app)
    session = _session_token(_browser_login(client))
    headers = {"Cookie": f"yice_sso={session}", "Origin": "null", "Sec-Fetch-Site": "same-origin"}
    response = client.post("/sso/logout", content="caller=task", headers=headers)
    assert response.status_code == 303 and not store.sessions


def test_logout_revokes_and_clears_the_parent_domain_cookie(env):
    app, store, _ = env
    client = peer_client(app)
    session = _session_token(_browser_login(client))
    response = _logout(client, session)
    assert response.status_code == 303
    assert _query(response.headers["location"]) == {"caller": "task", "error": "logged_out"}
    cleared = next(c for c in _cookies(response) if c.startswith("yice_sso="))
    assert "Max-Age=0" in cleared and "Domain=example.com" in cleared
    assert not store.sessions
    assert store.events[-1].event_type == "logout"


def test_logout_follows_safe_next_and_accepts_fetch_metadata(env):
    app, _, _ = env
    client = peer_client(app)
    session = _session_token(_browser_login(client))
    headers = {"Cookie": f"yice_sso={session}", "Sec-Fetch-Site": "same-origin"}
    response = client.post("/sso/logout", content="caller=task&next=%2Flogin", headers=headers)
    assert response.status_code == 303 and response.headers["location"] == "https://task.example.com/login"


def test_logout_keeps_the_cookie_when_storage_is_down(env):
    app, store, _ = env
    client = peer_client(app)
    session = _session_token(_browser_login(client))
    store.down = True
    response = _logout(client, session)
    assert response.status_code == 503
    assert not any(c.startswith("yice_sso=") for c in _cookies(response))


def test_me_reports_the_current_session_without_secrets(env):
    app, _, _ = env
    client = peer_client(app)
    session = _session_token(_browser_login(client))
    body = client.get("/sso/me", headers={"Cookie": f"yice_sso={session}"}).json()
    assert body["session"]["subject_id"] == "ou_member" and session not in json.dumps(body)
    assert client.get("/sso/me").status_code == 401


def test_verify_requires_caller_token_and_declared_source(env):
    app, _, _ = env
    session = _session_token(_browser_login(peer_client(app)))
    body = {"token_hash": token_hash(session)}
    task = peer_client(app, TASK_PEER)
    assert task.post("/v1/sessions/verify", json=body).status_code == 401
    bad = task.post("/v1/sessions/verify", json=body, headers={"Authorization": "Bearer " + "n" * 40})
    assert bad.status_code == 401
    wrong_source = peer_client(app, "10.9.9.9").post(
        "/v1/sessions/verify", json=body, headers={"Authorization": f"Bearer {token('task')}"}
    )
    assert wrong_source.status_code == 403 and wrong_source.json()["detail"]["code"] == "source_forbidden"
    ok = task.post("/v1/sessions/verify", json=body, headers={"Authorization": f"Bearer {token('task')}"})
    assert ok.status_code == 200
    assert ok.json()["session"] == {
        "subject_id": "ou_member",
        "open_id": "ou_member",
        "provider_id": "default",
        "company": "示例主企业",
        "directory": True,
        "app_id": "cli_default0001",
        "tenant_key": "",
        "name": "张三",
        "avatar": "",
        "dept": "投放部",
    }


def test_verify_error_contract(env):
    app, store, _ = env
    headers = {"Authorization": f"Bearer {token('task')}"}
    task = peer_client(app, TASK_PEER)
    missing = task.post("/v1/sessions/verify", json={"token_hash": "0" * 64}, headers=headers)
    assert missing.status_code == 401 and missing.json()["detail"]["code"] == "session_invalid"
    assert task.post("/v1/sessions/verify", json={"token_hash": "x"}, headers=headers).status_code == 422
    assert (
        task.post("/v1/sessions/verify", json={"token_hash": "0" * 64, "x": 1}, headers=headers).status_code == 422
    )
    partner = _session_token(_browser_login(peer_client(app), caller="info", code="c-partner", next_url="/", provider="partner"))
    forbidden = task.post("/v1/sessions/verify", json={"token_hash": token_hash(partner)}, headers=headers)
    assert forbidden.status_code == 403 and forbidden.json()["detail"]["code"] == "provider_not_allowed"
    store.down = True
    down = task.post("/v1/sessions/verify", json={"token_hash": "0" * 64}, headers=headers)
    assert down.status_code == 503 and down.json()["detail"]["code"] == "auth_unavailable"


def test_revoke_is_idempotent(env):
    app, _, _ = env
    session = _session_token(_browser_login(peer_client(app)))
    info = peer_client(app, "127.0.0.1")
    headers = {"Authorization": f"Bearer {token('info')}"}
    first = info.post("/v1/sessions/revoke", json={"token_hash": token_hash(session)}, headers=headers)
    second = info.post("/v1/sessions/revoke", json={"token_hash": token_hash(session)}, headers=headers)
    assert (first.json()["revoked"], second.json()["revoked"]) == (True, False)


def test_health_reports_storage_and_returns_503_when_down(env):
    app, store, _ = env
    client = peer_client(app)
    body = client.get("/health").json()
    assert body["ok"] is True and body["callers"]["task"]["token_configured"] is True
    assert body["providers"]["partner"] == {"configured": True, "directory": False}
    store.down = True
    assert client.get("/health").status_code == 503


def test_browser_routes_answer_only_through_local_nginx(env):
    app, _, _ = env
    assert peer_client(app, TASK_PEER).get("/sso/login", params={"caller": "task"}).status_code == 404


def test_unknown_routes_and_callers(env):
    app, _, _ = env
    client = peer_client(app)
    assert client.get("/v1/nothing").status_code == 404
    assert client.get("/api/auth/login").status_code == 404
    assert client.get("/sso/login", params={"caller": "nobody"}).status_code == 400


def test_access_log_never_contains_tokens_codes_or_states(env):
    app, _, log_path = env
    client = peer_client(app)
    session = _session_token(_browser_login(client))
    client.get("/sso/me", headers={"Cookie": f"yice_sso={session}", "X-Forwarded-For": "203.0.113.7"})
    peer_client(app, TASK_PEER).post(
        "/v1/sessions/verify",
        json={"token_hash": "0" * 64},
        headers={"Authorization": f"Bearer {token('task')}"},
    )
    text = log_path.read_text(encoding="utf-8")
    lines = [json.loads(line) for line in text.splitlines()]
    assert session not in text and token_hash(session) not in text and "c-member" not in text
    assert token("task") not in text
    callback = next(line for line in lines if line["path"] == "/sso/callback")
    assert callback["query"] is None and callback["caller"] == "task"
    assert any(line["client_ip"] == "203.0.113.7" for line in lines)
    failed_verify = next(line for line in lines if line["path"] == "/v1/sessions/verify")
    assert failed_verify["status"] == 401 and failed_verify["caller"] == "task"


def _authorize(client, caller="task", provider="default"):
    response = client.get("/sso/authorize", params={"caller": caller, "provider": provider, "next": "/"})
    state = _query(response.headers["location"])["state"]
    [cookie] = [c for c in _cookies(response) if c.startswith(state_cookie_name(state) + "=")]
    return state, cookie.split(";", 1)[0]


def test_two_logins_in_one_browser_keep_separate_states(env):
    """Tab A starts, tab B starts, then A and B finish: both succeed (one shared cookie made A fail)."""
    app, store, _ = env
    client = peer_client(app)
    state_a, cookie_a = _authorize(client, caller="task")
    state_b, cookie_b = _authorize(client, caller="info")
    assert cookie_a.split("=", 1)[0] != cookie_b.split("=", 1)[0]
    jar = f"{cookie_a}; {cookie_b}"
    first = client.get("/sso/callback", params={"code": "c-member", "state": state_a}, headers={"Cookie": jar})
    second = client.get("/sso/callback", params={"code": "c-member", "state": state_b}, headers={"Cookie": jar})
    assert first.status_code == 303 and first.headers["location"] == "https://task.example.com/"
    assert second.status_code == 303 and second.headers["location"] == "https://example.com/"
    assert len(store.sessions) == 2
    # Each callback clears only its own flow cookie.
    assert any(c.startswith(cookie_a.split("=", 1)[0] + "=;") for c in _cookies(first))
    assert not any(c.startswith(cookie_b.split("=", 1)[0] + "=;") for c in _cookies(first))


def test_a_state_presented_under_another_flows_cookie_is_rejected(env):
    app, store, _ = env
    client = peer_client(app)
    state_a, _ = _authorize(client)
    state_b, cookie_b = _authorize(client)
    forged = f"{state_cookie_name(state_a)}={state_b}; {cookie_b}"
    response = client.get("/sso/callback", params={"code": "c-member", "state": state_a}, headers={"Cookie": forged})
    assert response.status_code == 400 and not store.sessions
