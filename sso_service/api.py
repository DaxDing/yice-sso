"""HTTP edge: browser routes under /sso (behind nginx) and the internal /v1 API for declared callers."""

from __future__ import annotations

import time
import urllib.parse
import uuid
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from .access_log import AccessLog
from .callers import Caller, CallerRegistry
from .config import COOKIE_MAX_AGE_SECONDS, SESSION_COOKIE, STATE_COOKIE, STATE_TTL_SECONDS, Settings, load_environment
from .feishu import FeishuOAuthClient
from .pages import LOGOUT_FORM_POLICY, PAGE_HEADERS, error_page, login_page, logout_page
from .providers import ProviderRegistry
from .service import LoginFailure, ProviderNotAllowed, RequestMeta, SessionInvalid, SsoService, token_hash
from .store import MysqlStore, StoreUnavailable

MAX_REQUEST_BYTES = 16_384
LOOPBACK = frozenset({"127.0.0.1", "::1"})
# Successful verifies are the hot path (every app request past its cache); only failures are logged.
QUIET_PATHS = frozenset({"/health", "/v1/sessions/verify"})
SECRET_QUERY_PATHS = frozenset({"/sso/callback"})


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    fresh: bool = False


class RevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            event = await receive()
            if event["type"] == "http.disconnect":
                return
            size += len(event.get("body", b""))
            if size > MAX_REQUEST_BYTES:
                _log_entry(scope)["error_code"] = "request_too_large"
                response = JSONResponse(status_code=413, content=_error("request_too_large", "请求超过大小限制"))
                return await response(scope, receive, send)
            chunks.append(event)
            if not event.get("more_body", False):
                break
        iterator = iter(chunks)

        async def buffered_receive():
            event = next(iterator, None)
            return event if event is not None else await receive()

        await self.app(scope, buffered_receive, send)


class AccessLogMiddleware:
    """Outermost layer: one JSONL line per request (except quiet successes), plus X-Request-Id."""

    def __init__(self, app, log: AccessLog):
        self.app, self.log = app, log

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = time.monotonic()
        request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        entry = _log_entry(scope)
        response: dict[str, int] = {}

        async def send_with_request_id(message):
            if message["type"] == "http.response.start":
                response["status"] = message["status"]
                message = {**message, "headers": [*message.get("headers", []), (b"x-request-id", request_id.encode())]}
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            status = response.get("status", 500)
            path = scope.get("path") or ""
            if not (path in QUIET_PATHS and status == 200):
                headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
                query = "" if path in SECRET_QUERY_PATHS else scope.get("query_string", b"").decode("latin-1")
                self.log.write(
                    {
                        "request_id": request_id,
                        "caller": entry.pop("caller", None),
                        "peer_ip": (scope.get("client") or ("", 0))[0],
                        "client_ip": _browser_ip(scope),
                        "method": scope.get("method"),
                        "path": path,
                        "query": query[:300] or None,
                        "status": status,
                        "duration_ms": round((time.monotonic() - started) * 1000, 1),
                        "user_agent": headers.get("user-agent", "")[:200] or None,
                        **({"outcome": "unhandled_exception"} if "status" not in response else {}),
                        **entry,
                    }
                )


def _log_entry(scope) -> dict[str, Any]:
    return scope.setdefault("state", {}).setdefault("access", {})


def _browser_ip(scope) -> str:
    """nginx on this host overwrites X-Forwarded-For with $remote_addr; trusted only from a loopback peer."""
    peer = (scope.get("client") or ("", 0))[0]
    if peer in LOOPBACK:
        for key, value in scope.get("headers", []):
            if key == b"x-forwarded-for":
                return value.decode("latin-1").split(",")[0].strip()[:45]
    return peer


def state_cookie_name(state: str) -> str:
    """Per-flow cookie name: concurrent logins in one browser keep separate states."""
    return f"{STATE_COOKIE}_{token_hash(state)[:16]}"


def _error(code: str, message: str) -> dict[str, Any]:
    return {"ok": False, "detail": {"code": code, "message": message}}


def create_app(
    *,
    settings: Settings | None = None,
    service: SsoService | None = None,
    access_log: AccessLog | None = None,
) -> FastAPI:
    if settings is None:
        load_environment()
        settings = Settings.from_environment()
    if service is None:
        providers = ProviderRegistry.load(settings.providers_path)
        service = SsoService(
            settings=settings,
            providers=providers,
            callers=CallerRegistry.load(settings.callers_path, providers=set(providers.declared)),
            store=MysqlStore(settings.mysql),
            oauth=FeishuOAuthClient(settings.timeout_seconds),
        )
    if access_log is None:
        access_log = AccessLog(settings.access_log_path)
    callers = service.callers
    base = settings.base
    web_origin = f"{urllib.parse.urlsplit(base).scheme}://{urllib.parse.urlsplit(base).netloc}"
    application = FastAPI(title="YICE SSO", version="1.0.0", docs_url=None, redoc_url=None, openapi_url=None)
    application.add_middleware(BodyLimit)
    application.add_middleware(AccessLogMiddleware, log=access_log)

    def meta(request: Request) -> RequestMeta:
        return RequestMeta(
            request_id=request.scope["state"]["request_id"],
            client_ip=_browser_ip(request.scope) or None,
            user_agent=request.headers.get("user-agent"),
        )

    def note(request: Request, **fields: Any) -> None:
        _log_entry(request.scope).update(fields)

    def page(request: Request, status: int, body: str) -> HTMLResponse:
        return HTMLResponse(body, status_code=status, headers=PAGE_HEADERS)

    def cookie(name: str, value: str, *, max_age: int, path: str, domain: bool) -> str:
        parts = [f"{name}={value}", f"Path={path}", f"Max-Age={max_age}", "HttpOnly", "SameSite=Lax"]
        if domain and settings.cookie_domain:
            parts.append(f"Domain={settings.cookie_domain}")
        if settings.secure:
            parts.append("Secure")
        return "; ".join(parts)

    def redirect(location: str, *cookies: str, status: int = 303) -> RedirectResponse:
        response = RedirectResponse(location, status_code=status, headers={"Cache-Control": "no-store"})
        for value in cookies:
            response.headers.append("Set-Cookie", value)
        return response

    def login_url(caller_id: str, next_url: str | None = None, error: str | None = None) -> str:
        query = {"caller": caller_id, **({"next": next_url} if next_url else {}), **({"error": error} if error else {})}
        return f"{base}/login?{urllib.parse.urlencode(query)}"

    clear_session = cookie(SESSION_COOKIE, "", max_age=0, path="/", domain=True)

    @application.exception_handler(StoreUnavailable)
    async def store_unavailable(request: Request, exc: StoreUnavailable):
        note(request, error_code="auth_unavailable")
        if request.url.path.startswith("/sso/") and request.url.path != "/sso/me":
            return page(request, 503, error_page("auth_unavailable"))
        return JSONResponse(status_code=503, content=_error("auth_unavailable", "认证存储暂不可用"))

    @application.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        note(request, error_code="invalid_request")
        return JSONResponse(status_code=422, content=_error("invalid_request", "请求字段不符合 API 契约"))

    def reject(request: Request, status: int, code: str, message: str) -> HTTPException:
        note(request, error_code=code)
        return HTTPException(status_code=status, detail={"code": code, "message": message})

    def authenticate(request: Request, authorization: str | None = Header(default=None)) -> Caller:
        provided = authorization[7:].strip() if authorization and authorization.startswith("Bearer ") else ""
        if not provided:
            raise reject(request, 401, "token_required", "缺少调用方 token")
        caller = callers.authenticate(provided)
        if caller is None:
            raise reject(request, 401, "unauthorized", "SSO API 未授权")
        note(request, caller=caller.id)
        peer = request.client.host if request.client else ""
        if not caller.allows_source(peer):
            # A valid token from an undeclared network is likely leaked; the peer is in the access log.
            raise reject(request, 403, "source_forbidden", f"调用方 {caller.id} 不允许从该来源调用")
        return caller

    def via_nginx(request: Request) -> None:
        # /sso is served only through the local nginx; other VPC hosts reach the /v1 API alone.
        if (request.client.host if request.client else "") not in LOOPBACK:
            raise reject(request, 404, "not_found", "not found")

    browser = [Depends(via_nginx)]

    # ---------------- browser routes (nginx: location ^~ /sso/) ----------------

    @application.get("/sso/login", dependencies=browser)
    def sso_login(request: Request, caller: str = "", next: str = "", error: str = ""):
        target = callers.get(caller)
        if target is None:
            note(request, error_code="caller_unavailable")
            return page(request, 400, error_page("caller_unavailable"))
        note(request, caller=target.id)
        next_url = target.safe_next(next)
        token = request.cookies.get(SESSION_COOKIE, "")
        if token and not error:
            try:
                service.current(token_hash(token), meta(request), allowed=target.providers)
                return redirect(next_url)
            except SessionInvalid:
                pass
            except ProviderNotAllowed:
                error = "provider_not_allowed"
        providers = service.login_providers(target)
        if not providers:
            note(request, error_code="provider_unavailable")
            return page(request, 503, error_page("provider_unavailable"))
        if not error and len(providers) == 1:
            query = urllib.parse.urlencode({"caller": target.id, "provider": providers[0].id, "next": next_url})
            return redirect(f"{base}/authorize?{query}")
        body = login_page(
            base=base,
            caller_id=target.id,
            caller_label=target.label,
            next_url=next_url,
            providers=providers,
            error=error or None,
        )
        return page(request, 200, body)

    @application.get("/sso/authorize", dependencies=browser)
    def sso_authorize(request: Request, caller: str = "", provider: str = "", next: str = ""):
        target = callers.get(caller)
        if target is None:
            note(request, error_code="caller_unavailable")
            return page(request, 400, error_page("caller_unavailable"))
        note(request, caller=target.id, provider=provider)
        try:
            start = service.begin_login(target, provider, next)
        except LoginFailure as exc:
            note(request, error_code=exc.code)
            return redirect(login_url(target.id, target.safe_next(next), exc.code))
        state = cookie(
            state_cookie_name(start.state), start.state, max_age=STATE_TTL_SECONDS, path="/sso", domain=False
        )
        return redirect(start.authorize_url, state, status=302)

    @application.get("/sso/callback", dependencies=browser)
    def sso_callback(request: Request):
        codes = request.query_params.getlist("code")
        states = request.query_params.getlist("state")
        if len(codes) > 1 or len(states) != 1:
            note(request, error_code="oauth_state_invalid")
            return page(request, 400, error_page("oauth_state_invalid"))
        flow_cookie = state_cookie_name(states[0])
        clear_state = cookie(flow_cookie, "", max_age=0, path="/sso", domain=False)
        try:
            result = service.complete_login(
                codes[0] if codes else "",
                states[0],
                request.cookies.get(flow_cookie, ""),
                meta(request),
                denied=bool(request.query_params.get("error")),
            )
        except LoginFailure as exc:
            note(request, caller=exc.caller_id, error_code=exc.code, **({} if exc.recorded else {"event": "unrecorded"}))
            if exc.caller_id is None:
                response = page(request, 400, error_page(exc.code))
                response.headers.append("Set-Cookie", clear_state)
                return response
            return redirect(login_url(exc.caller_id, error=exc.code), clear_state)
        note(request, caller=result.caller_id, subject=result.view.subject_id, provider=result.view.provider_id)
        session = cookie(SESSION_COOKIE, result.session_token, max_age=COOKIE_MAX_AGE_SECONDS, path="/", domain=True)
        return redirect(result.next_url, session, clear_state)

    @application.get("/sso/logout", dependencies=browser)
    def sso_logout_confirm(request: Request, caller: str = "", next: str = ""):
        target = callers.get(caller)
        if target is None:
            note(request, error_code="caller_unavailable")
            return page(request, 400, error_page("caller_unavailable"))
        note(request, caller=target.id)
        body = logout_page(base=base, caller_id=target.id, caller_label=target.label, next_url=next)
        # no-referrer would make the browser send "Origin: null" on this form's POST and fail the check below.
        headers = {**PAGE_HEADERS, "Content-Security-Policy": LOGOUT_FORM_POLICY, "Referrer-Policy": "same-origin"}
        return HTMLResponse(body, headers=headers)

    @application.post("/sso/logout", dependencies=browser)
    async def sso_logout(request: Request):
        # Same-origin form posts only: the shared session must not end from another site's navigation.
        # An opaque "null" Origin (privacy settings, no-referrer) falls back to the browser-set Sec-Fetch-Site.
        origin = request.headers.get("origin")
        if origin and origin != "null":
            same_origin = origin == web_origin
        else:
            same_origin = request.headers.get("sec-fetch-site") == "same-origin"
        if not same_origin:
            note(request, error_code="logout_forbidden")
            return page(request, 403, error_page("logout_forbidden"))
        form = urllib.parse.parse_qs((await request.body()).decode("utf-8", "replace"), max_num_fields=4)
        target = callers.get((form.get("caller") or [""])[0])
        if target is None:
            note(request, error_code="caller_unavailable")
            return page(request, 400, error_page("caller_unavailable"))
        note(request, caller=target.id)
        token = request.cookies.get(SESSION_COOKIE, "")
        if token:
            # A storage failure raises before the cookie is cleared: never pretend a live session ended.
            await run_in_threadpool(service.revoke, token_hash(token), caller_id=target.id, meta=meta(request))
        next_url = (form.get("next") or [""])[0]
        location = target.safe_next(next_url) if next_url else login_url(target.id, error="logged_out")
        return redirect(location, clear_session)

    @application.get("/sso/me", dependencies=browser)
    def sso_me(request: Request):
        token = request.cookies.get(SESSION_COOKIE, "")
        try:
            view = service.current(token_hash(token), meta(request)) if token else None
        except SessionInvalid:
            view = None
        if view is None:
            note(request, error_code="session_invalid")
            return JSONResponse(status_code=401, content=_error("session_invalid", "未登录"), headers=PAGE_HEADERS)
        return JSONResponse({"ok": True, "session": view.public()}, headers=PAGE_HEADERS)

    # ---------------- internal API (VPC / loopback; never proxied by nginx) ----------------

    @application.get("/health")
    def health():
        try:
            storage = service.store.health()
            storage_ok = storage["tables_ok"] and storage["schema_ok"]
        except StoreUnavailable:
            storage, storage_ok = {"tables_ok": False, "schema_ok": False}, False
        body = {
            "ok": storage_ok,
            "service": "yice-sso",
            "storage": "ok" if storage_ok else "unavailable",
            "schema_version": storage.get("schema_version"),
            "providers": service.providers.status(),
            "callers": callers.status(),
            "access_log": "ok" if access_log.healthy else "degraded",
        }
        return JSONResponse(status_code=200 if storage_ok else 503, content=body)

    @application.get("/v1/whoami")
    def whoami(caller: Caller = Depends(authenticate)):
        return {"ok": True, **caller.public()}

    @application.post("/v1/sessions/verify")
    def verify(request: Request, body: VerifyRequest, caller: Caller = Depends(authenticate)):
        try:
            view = service.verify(caller, body.token_hash, fresh=body.fresh, meta=meta(request))
        except SessionInvalid:
            raise reject(request, 401, "session_invalid", "会话无效或已过期")
        except ProviderNotAllowed:
            raise reject(request, 403, "provider_not_allowed", f"该企业账号无权访问 {caller.id}")
        return {"ok": True, "session": view.public()}

    @application.post("/v1/sessions/revoke")
    def revoke(request: Request, body: RevokeRequest, caller: Caller = Depends(authenticate)):
        revoked = service.revoke(body.token_hash, caller_id=caller.id, meta=meta(request))
        note(request, revoked=revoked)
        return {"ok": True, "revoked": revoked}

    @application.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"])
    def not_found(request: Request, path: str):
        note(request, error_code="not_found")
        return Response(status_code=404, headers={"Cache-Control": "no-store"})

    return application
