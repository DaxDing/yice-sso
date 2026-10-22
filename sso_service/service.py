"""Login, session and logout rules. Pure apart from the injected store and OAuth ports.

Authentication only: a session says who the person is and which enterprise vouched for them.
Whether that person may use a given app (roles, grants, disabled accounts) stays in the app.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Any, Callable

from .callers import Caller, CallerRegistry
from .config import RECHECK_AFTER_SECONDS, SESSION_TTL_SECONDS, STATE_TTL_SECONDS, Settings
from .feishu import OAuthClient, OAuthError
from .providers import Provider, ProviderRegistry
from .store import LoginEvent, NewSession, SessionRow, StateRow, Store, StoreUnavailable

TOKEN_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
OPEN_ID_MAX = 64


def token_hash(token: str) -> str:
    """The only form in which a session token or OAuth state is stored or sent between services."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


class LoginFailure(Exception):
    """A browser login that cannot continue; ``caller_id`` is set once the state proved which app asked."""

    def __init__(self, code: str, message: str, *, caller_id: str | None = None, recorded: bool = True) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.caller_id = caller_id
        self.recorded = recorded


class SessionInvalid(Exception):
    code = "session_invalid"


class ProviderNotAllowed(Exception):
    code = "provider_not_allowed"


@dataclass(frozen=True)
class RequestMeta:
    request_id: str
    client_ip: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True)
class SessionView:
    """``app_id`` / ``tenant_key`` / ``open_id`` let an app keep its own per-identity records (Info auth_identity)."""

    subject_id: str
    open_id: str
    provider_id: str
    company: str
    directory: bool
    app_id: str
    tenant_key: str
    name: str
    avatar: str
    dept: str

    def public(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "open_id": self.open_id,
            "provider_id": self.provider_id,
            "company": self.company,
            "directory": self.directory,
            "app_id": self.app_id,
            "tenant_key": self.tenant_key,
            "name": self.name,
            "avatar": self.avatar,
            "dept": self.dept,
        }


@dataclass(frozen=True)
class LoginStart:
    authorize_url: str
    state: str


@dataclass(frozen=True)
class LoginResult:
    session_token: str
    next_url: str
    caller_id: str
    view: SessionView


class SsoService:
    def __init__(
        self,
        *,
        settings: Settings,
        providers: ProviderRegistry,
        callers: CallerRegistry,
        store: Store,
        oauth: OAuthClient,
        new_token: Callable[[int], str] = secrets.token_urlsafe,
    ) -> None:
        callers.check_cookie_domain(settings.cookie_domain)
        self.settings = settings
        self.providers = providers
        self.callers = callers
        self.store = store
        self.oauth = oauth
        self.new_token = new_token

    def login_providers(self, caller: Caller) -> list[Provider]:
        """Providers this caller allows that are fully configured, in the caller's declared order."""
        return [p for pid in caller.providers if (p := self.providers.get(pid)) is not None and p.configured]

    def begin_login(self, caller: Caller, provider_id: str, next_url: str) -> LoginStart:
        provider = self.providers.get(provider_id)
        if provider is None or provider_id not in caller.providers or not provider.configured:
            raise LoginFailure("provider_unavailable", "该企业登录入口未启用", caller_id=caller.id, recorded=False)
        state = self.new_token(24)
        self.store.issue_state(
            token_hash(state),
            StateRow(provider.id, caller.id, caller.safe_next(next_url), provider.digest),
            STATE_TTL_SECONDS,
        )
        return LoginStart(self.oauth.authorize_url(provider, self.settings.redirect_uri, state), state)

    def complete_login(
        self, code: str, state: str, state_cookie: str, meta: RequestMeta, *, denied: bool = False
    ) -> LoginResult:
        """``denied`` is Feishu's redirect after the user cancelled; the state is still consumed once."""
        if not state or not state_cookie or not secrets.compare_digest(state_cookie, state):
            raise self._failure(meta, "error", "oauth_state_invalid", "登录状态校验失败，请重新登录")
        pending = self.store.consume_state(token_hash(state))
        if pending is None:
            raise self._failure(meta, "error", "oauth_state_invalid", "登录状态已失效，请重新登录")
        caller = self.callers.get(pending.caller_id)
        if caller is None:
            raise self._failure(meta, "error", "caller_unavailable", "发起登录的应用已停用")
        context = {"caller_id": caller.id, "provider_id": pending.provider_id}
        if denied or not code:
            raise self._failure(meta, "error", "oauth_denied", "已取消飞书授权", **context)
        provider = self.providers.get(pending.provider_id)
        if provider is None or not provider.configured or provider.digest != pending.provider_digest:
            raise self._failure(meta, "error", "oauth_provider_changed", "企业登录配置已变化，请重新登录", **context)
        try:
            access_token = self.oauth.exchange_code(provider, code, self.settings.redirect_uri)
            info = self.oauth.user_info(access_token)
        except OAuthError as exc:
            raise self._failure(meta, "error", exc.code, exc.message, **context) from exc
        open_id = info.get("open_id")
        feishu_name = str(info.get("name") or "")[:64]
        if not isinstance(open_id, str) or not open_id or len(open_id) > OPEN_ID_MAX:
            raise self._failure(meta, "error", "oauth_user_info_failed", "飞书用户标识无效", **context)
        if provider.directory:
            member = self.store.active_member(open_id)
            if member is None:
                raise self._failure(
                    meta,
                    "denied",
                    "member_not_allowed",
                    f"{feishu_name or open_id} 不在公司在职名单内",
                    subject_id=open_id,
                    name=feishu_name,
                    **context,
                )
            name = feishu_name or member.name
            avatar = str(info.get("avatar_url") or member.avatar or "")[:512]
            dept = member.dept
        else:
            if info.get("tenant_key") != provider.tenant_key:
                raise self._failure(
                    meta, "denied", "tenant_not_allowed", "飞书授权企业与登录入口不一致", name=feishu_name, **context
                )
            name, avatar, dept = feishu_name, str(info.get("avatar_url") or "")[:512], ""
        view = _view(provider, provider.subject_id(open_id), open_id, name, avatar, dept)
        session_token = self.new_token(32)
        self.store.create_session(
            NewSession(
                token_hash(session_token), view.subject_id, open_id, provider.id, provider.digest, caller.id, name,
                avatar, dept,
            ),
            SESSION_TTL_SECONDS,
            self._event(meta, "login", "accepted", subject_id=view.subject_id, name=name, **context),
        )
        return LoginResult(session_token, pending.next_url, caller.id, view)

    def verify(self, caller: Caller, digest: str, *, fresh: bool, meta: RequestMeta) -> SessionView:
        """Resolve a session for ``caller``; directory members are re-checked hourly, or now when ``fresh``."""
        return self._resolve(digest, allowed=caller.providers, fresh=fresh, meta=meta)

    def current(self, digest: str, meta: RequestMeta, *, allowed: tuple[str, ...] | None = None) -> SessionView:
        return self._resolve(digest, allowed=allowed, fresh=False, meta=meta)

    def revoke(self, digest: str, *, caller_id: str, meta: RequestMeta) -> bool:
        removed = self.store.delete_session(digest, self._event(meta, "logout", "accepted", caller_id=caller_id))
        return removed is not None

    def _resolve(
        self, digest: str, *, allowed: tuple[str, ...] | None, fresh: bool, meta: RequestMeta
    ) -> SessionView:
        if not TOKEN_HASH_RE.fullmatch(digest or ""):
            raise SessionInvalid()
        row = self.store.get_session(digest)
        if row is None:
            raise SessionInvalid()
        provider = self.providers.get(row.provider_id)
        if provider is None or not provider.configured:
            self._revoke(row, meta, "provider_removed")
            raise SessionInvalid()
        if provider.digest != row.provider_digest:
            # app_id / tenant_key changed: the vouching enterprise is no longer the one that signed this person in.
            self._revoke(row, meta, "provider_changed")
            raise SessionInvalid()
        if allowed is not None and row.provider_id not in allowed:
            raise ProviderNotAllowed()
        name, avatar, dept = row.name, row.avatar, row.dept
        if fresh or row.checked_age_seconds >= RECHECK_AFTER_SECONDS:
            if provider.directory:
                member = self.store.active_member(row.subject_id)
                if member is None:
                    self._revoke(row, meta, "member_inactive")
                    raise SessionInvalid()
                name, avatar, dept = member.name or row.name, member.avatar or row.avatar, member.dept
            if not self.store.renew_session(row.token_hash, name, avatar, dept, SESSION_TTL_SECONDS):
                # Revoked or expired between the read and the renewal: never report it as valid.
                raise SessionInvalid()
        return _view(provider, row.subject_id, row.open_id, name, avatar, dept)

    def _revoke(self, row: SessionRow, meta: RequestMeta, reason: str) -> None:
        self.store.delete_session(
            row.token_hash, self._event(meta, "session_revoked", "accepted", error_code=reason, caller_id=row.caller_id)
        )

    def _event(self, meta: RequestMeta, event_type: str, outcome: str, **fields: Any) -> LoginEvent:
        # Every path writes at most one event per request, so the access-log request id is its unique key.
        return LoginEvent(
            request_id=meta.request_id,
            event_type=event_type,
            outcome=outcome,
            client_ip=meta.client_ip,
            user_agent=meta.user_agent,
            **fields,
        )

    def _failure(self, meta: RequestMeta, outcome: str, code: str, message: str, **fields: Any) -> LoginFailure:
        try:
            self.store.append_event(self._event(meta, "login", outcome, error_code=code, **fields))
            recorded = True
        except StoreUnavailable:
            # The login still fails closed; the API logs the missing audit row as degraded.
            recorded = False
        return LoginFailure(code, message, caller_id=fields.get("caller_id"), recorded=recorded)


def _view(provider: Provider, subject_id: str, open_id: str, name: str, avatar: str, dept: str) -> SessionView:
    return SessionView(
        subject_id, open_id, provider.id, provider.label, provider.directory, provider.app_id, provider.tenant_key,
        name, avatar, dept,
    )
