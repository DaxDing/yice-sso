import urllib.parse

import pytest

from sso_service.config import RECHECK_AFTER_SECONDS, SESSION_TTL_SECONDS, STATE_TTL_SECONDS
from sso_service.feishu import OAuthError
from sso_service.providers import identity_id
from sso_service.service import LoginFailure, ProviderNotAllowed, RequestMeta, SessionInvalid, token_hash
from sso_service.store import Member, StoreUnavailable
from tests.support import APP_PARTNER, PARTNER_TENANT, FakeOAuth, FakeStore, make_service

META = RequestMeta("r" * 32, "10.0.0.1", "pytest")
MEMBER = Member("ou_member", "张三", "https://avatar/member", "投放部")


def _state_from(url: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["state"][0]


@pytest.fixture
def world(tmp_path):
    store, oauth = FakeStore(), FakeOAuth()
    store.members[MEMBER.open_id] = MEMBER
    oauth.users["c-member"] = {"open_id": "ou_member", "name": "张三", "avatar_url": "https://avatar/feishu"}
    oauth.users["c-stranger"] = {"open_id": "ou_stranger", "name": "路人"}
    oauth.users["c-partner"] = {"open_id": "ou_q1", "name": "合作企业甲", "tenant_key": PARTNER_TENANT}
    oauth.users["c-other-tenant"] = {"open_id": "ou_q2", "name": "外人", "tenant_key": "elsewhere"}
    service = make_service(tmp_path, store=store, oauth=oauth)
    return service, store, oauth


def _login(service, caller_id="task", provider="default", code="c-member", next_url="/warehouse"):
    caller = service.callers.get(caller_id)
    start = service.begin_login(caller, provider, next_url)
    state = _state_from(start.authorize_url)
    return service.complete_login(code, state, state, META)


def test_directory_member_login_creates_session_and_one_audited_event(world):
    service, store, _ = world
    result = _login(service)
    assert result.next_url == "https://task.example.com/warehouse"
    assert result.caller_id == "task"
    assert result.view.subject_id == "ou_member"
    assert result.view.directory is True and result.view.company == "示例主企业"
    # Feishu's own avatar wins at login; department always comes from the directory.
    assert (result.view.avatar, result.view.dept) == ("https://avatar/feishu", "投放部")
    stored = store.sessions[token_hash(result.session_token)]["session"]
    assert stored.caller_id == "task" and result.session_token not in str(stored)
    [event] = store.events
    assert (event.event_type, event.outcome, event.subject_id, event.caller_id) == (
        "login",
        "accepted",
        "ou_member",
        "task",
    )


def test_state_is_single_use_and_bound_to_its_cookie(world):
    service, store, _ = world
    caller = service.callers.get("task")
    state = _state_from(service.begin_login(caller, "default", "/").authorize_url)
    with pytest.raises(LoginFailure) as wrong_cookie:
        service.complete_login("c-member", state, "other", META)
    assert wrong_cookie.value.code == "oauth_state_invalid" and wrong_cookie.value.caller_id is None
    service.complete_login("c-member", state, state, META)
    with pytest.raises(LoginFailure) as replay:
        service.complete_login("c-member", state, state, META)
    assert replay.value.code == "oauth_state_invalid"


def test_expired_state_is_rejected(world):
    service, store, _ = world
    state = _state_from(service.begin_login(service.callers.get("task"), "default", "/").authorize_url)
    store.advance(STATE_TTL_SECONDS)
    with pytest.raises(LoginFailure) as exc:
        service.complete_login("c-member", state, state, META)
    assert exc.value.code == "oauth_state_invalid"


def test_non_member_is_denied_and_audited_with_caller(world):
    service, store, _ = world
    with pytest.raises(LoginFailure) as exc:
        _login(service, code="c-stranger")
    assert (exc.value.code, exc.value.caller_id, exc.value.recorded) == ("member_not_allowed", "task", True)
    assert not store.sessions
    assert (store.events[-1].event_type, store.events[-1].outcome) == ("login", "denied")


def test_cancelled_authorization_consumes_state_and_returns_to_caller(world):
    service, store, _ = world
    state = _state_from(service.begin_login(service.callers.get("info"), "default", "/").authorize_url)
    with pytest.raises(LoginFailure) as exc:
        service.complete_login("", state, state, META, denied=True)
    assert (exc.value.code, exc.value.caller_id) == ("oauth_denied", "info")
    assert not store.states


def test_tenant_provider_uses_info_identity_key_and_rejects_other_tenants(world):
    service, _, _ = world
    result = _login(service, caller_id="info", provider="partner", code="c-partner")
    assert result.view.subject_id == identity_id(APP_PARTNER, PARTNER_TENANT, "ou_q1")
    assert (result.view.open_id, result.view.app_id, result.view.tenant_key) == ("ou_q1", APP_PARTNER, PARTNER_TENANT)
    assert result.view.directory is False and result.view.dept == ""
    with pytest.raises(LoginFailure) as exc:
        _login(service, caller_id="info", provider="partner", code="c-other-tenant")
    assert exc.value.code == "tenant_not_allowed"


def test_caller_cannot_start_a_provider_it_does_not_allow(world):
    service, _, _ = world
    with pytest.raises(LoginFailure) as exc:
        service.begin_login(service.callers.get("task"), "partner", "/")
    assert exc.value.code == "provider_unavailable"


def test_provider_config_change_between_authorize_and_callback_is_rejected(world, tmp_path):
    service, store, oauth = world
    state = _state_from(service.begin_login(service.callers.get("task"), "default", "/").authorize_url)
    changed = make_service(tmp_path, store=store, oauth=oauth)
    object.__setattr__(changed.providers.providers["default"], "app_id", "cli_rotated0001")
    with pytest.raises(LoginFailure) as exc:
        changed.complete_login("c-member", state, state, META)
    assert exc.value.code == "oauth_provider_changed"


def test_upstream_oauth_failure_keeps_its_code(world):
    service, _, oauth = world
    oauth.fail = OAuthError("oauth_token_exchange_failed", "boom")
    with pytest.raises(LoginFailure) as exc:
        _login(service)
    assert exc.value.code == "oauth_token_exchange_failed"


def test_failed_audit_write_is_reported_but_login_still_fails_closed(world):
    service, store, _ = world
    state = _state_from(service.begin_login(service.callers.get("task"), "default", "/").authorize_url)
    store.down = True
    with pytest.raises(StoreUnavailable):
        service.complete_login("c-member", state, state, META)
    store.down = False
    original = store.append_event

    def broken(event):
        raise StoreUnavailable("audit down")

    store.append_event = broken
    with pytest.raises(LoginFailure) as exc:
        service.complete_login("c-member", "missing", "missing", META)
    assert exc.value.recorded is False
    store.append_event = original


def test_verify_rechecks_members_hourly_or_when_fresh(world):
    service, store, _ = world
    digest = token_hash(_login(service).session_token)
    task = service.callers.get("task")
    service.verify(task, digest, fresh=False, meta=META)
    assert store.renewals == 0
    service.verify(task, digest, fresh=True, meta=META)
    assert store.renewals == 1
    store.advance(RECHECK_AFTER_SECONDS)
    store.members[MEMBER.open_id] = Member("ou_member", "张三丰", "", "数据部")
    view = service.verify(task, digest, fresh=False, meta=META)
    assert (view.name, view.dept, store.renewals) == ("张三丰", "数据部", 2)
    # The renewal slides the 30-day expiry from the re-check time.
    store.advance(SESSION_TTL_SECONDS - 1)
    assert service.verify(task, digest, fresh=False, meta=META).subject_id == "ou_member"


def test_departed_member_session_is_revoked_with_reason(world):
    service, store, _ = world
    digest = token_hash(_login(service).session_token)
    del store.members[MEMBER.open_id]
    with pytest.raises(SessionInvalid):
        service.verify(service.callers.get("task"), digest, fresh=True, meta=META)
    assert digest not in store.sessions
    event = store.events[-1]
    assert (event.event_type, event.error_code, event.caller_id, event.subject_id) == (
        "session_revoked",
        "member_inactive",
        "task",
        "ou_member",
    )


def test_session_from_disallowed_provider_is_forbidden_not_invalid(world):
    service, store, _ = world
    digest = token_hash(_login(service, caller_id="info", provider="partner", code="c-partner").session_token)
    with pytest.raises(ProviderNotAllowed):
        service.verify(service.callers.get("task"), digest, fresh=False, meta=META)
    assert digest in store.sessions
    assert service.verify(service.callers.get("info"), digest, fresh=False, meta=META).provider_id == "partner"


def test_expired_unknown_and_malformed_sessions_are_invalid(world):
    service, store, _ = world
    digest = token_hash(_login(service).session_token)
    task = service.callers.get("task")
    for value in ("", "zz", "0" * 64):
        with pytest.raises(SessionInvalid):
            service.verify(task, value, fresh=False, meta=META)
    store.advance(SESSION_TTL_SECONDS)
    with pytest.raises(SessionInvalid):
        service.verify(task, digest, fresh=False, meta=META)


def test_revoke_records_logout_for_the_calling_app(world):
    service, store, _ = world
    digest = token_hash(_login(service).session_token)
    assert service.revoke(digest, caller_id="info", meta=META) is True
    assert service.revoke(digest, caller_id="info", meta=META) is False
    event = store.events[-1]
    assert (event.event_type, event.caller_id, event.subject_id) == ("logout", "info", "ou_member")


def test_provider_config_change_revokes_existing_sessions(world, tmp_path):
    service, store, oauth = world
    digest = token_hash(_login(service, caller_id="info", provider="partner", code="c-partner").session_token)
    changed = make_service(tmp_path, store=store, oauth=oauth)
    object.__setattr__(changed.providers.providers["partner"], "tenant_key", "another-tenant")
    with pytest.raises(SessionInvalid):
        changed.verify(changed.callers.get("info"), digest, fresh=False, meta=META)
    assert digest not in store.sessions
    assert (store.events[-1].event_type, store.events[-1].error_code) == ("session_revoked", "provider_changed")


def test_session_revoked_between_read_and_renewal_is_not_reported_valid(world):
    service, store, _ = world
    digest = token_hash(_login(service).session_token)
    store.before_renew = lambda: store.sessions.pop(digest, None)
    with pytest.raises(SessionInvalid):
        service.verify(service.callers.get("task"), digest, fresh=True, meta=META)
