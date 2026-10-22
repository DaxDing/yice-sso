"""yice-sso CLI: serve, self-check, and read-only probes. JSON output; exit 0 ok · 1 failed · 2 usage · 3 blocked."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.metadata
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

from .callers import CallerError, CallerRegistry
from .config import Settings, load_environment
from .providers import ProviderError, ProviderRegistry
from .store import MysqlStore, StoreUnavailable

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_BLOCKED = 0, 1, 2, 3
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
# Feishu / Lark group custom-bot webhooks; anything else is refused rather than posted to.
WEBHOOK_HOSTS = frozenset({"open.feishu.cn", "open.larksuite.com"})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="yice-sso", description="Shared Feishu SSO for sibling web apps under one parent domain")
    parser.add_argument("--json", action="store_true", help="machine-readable JSON output (always on)")
    parser.add_argument("--self-check", action="store_true", help="check config, provider/caller secrets and MySQL")
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="start the service (single process)")
    serve.add_argument("--host", default=os.environ.get("SSO_HOST", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("SSO_PORT", "8773")))
    sub.add_parser("health", help="GET $SSO_API_URL/health")
    verify = sub.add_parser("verify", help="POST /v1/sessions/verify as the caller of $SSO_API_TOKEN")
    verify.add_argument("--token-hash", required=True, help="SHA-256 hex of the yice_sso cookie value")
    verify.add_argument("--fresh", action="store_true", help="force the hourly member re-check now")
    events = sub.add_parser("events", help="read login_event rows from MySQL (runs where the service runs)")
    events.add_argument("--since", required=True, help="YYYY-MM-DD or ISO datetime, server local time")
    events.add_argument("--subject", help="subject_id filter")
    events.add_argument("--limit", type=int, default=50)
    probe = sub.add_parser(
        "probe", help="check local /health; on failure alert at most once per hour (notification service and/or webhook)"
    )
    probe.add_argument("--url", default="http://127.0.0.1:8773/health")
    return parser


def _print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, default=str, sort_keys=True))


def self_check() -> dict[str, Any]:
    checks: dict[str, dict[str, Any]] = {}
    for package in ("fastapi", "pydantic", "uvicorn", "python-dotenv", "pymysql"):
        try:
            checks[package] = {"ok": True, "version": importlib.metadata.version(package)}
        except importlib.metadata.PackageNotFoundError:
            checks[package] = {"ok": False}
    try:
        settings = Settings.from_environment()
        providers = ProviderRegistry.load(settings.providers_path)
        callers = CallerRegistry.load(settings.callers_path, providers=set(providers.declared))
        callers.check_cookie_domain(settings.cookie_domain)
        checks["web_url"] = {"ok": True, "secure": settings.secure, "cookie_domain": settings.cookie_domain or None}
        for pid, status in providers.status().items():
            checks[f"provider:{pid}"] = {"ok": status["configured"], **status}
        for cid, status in callers.status().items():
            # A caller without a token cannot authenticate; every enabled caller needs one in production.
            checks[f"caller:{cid}"] = {"ok": status["token_configured"] or not status["enabled"], **status}
        host = os.environ.get("SSO_HOST", "127.0.0.1")
        checks["bind"] = {"ok": host in LOOPBACK_HOSTS or bool(callers.tokens), "host": host}
        store = MysqlStore(settings.mysql)
        try:
            health = store.health()
            checks["mysql_schema"] = {"ok": health["tables_ok"] and health["schema_ok"], **health}
            if any(status["directory"] for status in providers.status().values()):
                store.active_member("ou_self_check_probe")
                checks["member_directory"] = {"ok": True}
            else:
                checks["member_directory"] = {"ok": True, "skipped": "no provider declares a directory"}
        except StoreUnavailable:
            checks["mysql"] = {"ok": False, "message": "MySQL 不可用或权限不足"}
    except (ValueError, OSError, ProviderError, CallerError) as exc:
        checks["configuration"] = {"ok": False, "message": str(exc)}
    ok = all(item["ok"] for item in checks.values())
    return {"ok": ok, "verdict": "PASS" if ok else "FAIL", "checks": checks, "scope": "local config + MySQL read"}


def _api(method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    base = os.environ.get("SSO_API_URL", "").rstrip("/")
    if not base:
        raise RuntimeError("SSO_API_URL is not set")
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("SSO_API_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except ValueError:
            return exc.code, {"ok": False}


def main(argv: list[str] | None = None) -> int:
    load_environment()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_check:
        if args.command:
            parser.error("--self-check cannot be combined with a command")
        result = self_check()
        _print(result)
        return EXIT_OK if result["ok"] else EXIT_FAILED
    if args.command == "serve":
        return _serve(args.host, args.port)
    try:
        if args.command == "health":
            status, payload = _api("GET", "/health")
            _print({"status": status, **payload})
            return EXIT_OK if status == 200 else EXIT_FAILED
        if args.command == "verify":
            status, payload = _api("POST", "/v1/sessions/verify", {"token_hash": args.token_hash, "fresh": args.fresh})
            _print({"status": status, **payload})
            return EXIT_OK if status == 200 else EXIT_FAILED
        if args.command == "probe":
            return _probe(args.url)
        if args.command == "events":
            if not 1 <= args.limit <= 500:
                parser.error("--limit must be 1-500")
            since = datetime.fromisoformat(args.since)
            rows = MysqlStore(Settings.from_environment().mysql).list_events(since, args.subject, args.limit)
            _print({"ok": True, "events": rows})
            return EXIT_OK
    except (RuntimeError, urllib.error.URLError, ValueError, StoreUnavailable) as exc:
        _print({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        return EXIT_BLOCKED if isinstance(exc, RuntimeError) else EXIT_FAILED
    parser.print_help(sys.stderr)
    return EXIT_USAGE


def _probe(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            body = json.loads(response.read() or b"{}")
            if response.status == 200 and body.get("ok") is True:
                return EXIT_OK
            reason = f"health status {response.status}"
    except urllib.error.HTTPError as exc:
        reason = f"health status {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = f"health unreachable: {type(exc).__name__}"
    hour = datetime.now().strftime("%Y%m%d%H")
    text = f"yice-sso 健康检查失败：{reason}。登录可能不可用，请检查所在主机上的 yice-sso 服务。"
    alerts: dict[str, str] = {}
    api = os.environ.get("NOTIFICATION_API_URL", "").rstrip("/")
    token = os.environ.get("NOTIFICATION_API_TOKEN", "").strip()
    target = os.environ.get("SSO_ALERT_TARGET", "").strip()
    if api and token and target:
        alerts["notification"] = _alert_notification(api, token, target, text, hour)
    webhook = os.environ.get("SSO_ALERT_WEBHOOK", "").strip()
    if webhook:
        alerts["webhook"] = _alert_webhook(webhook, os.environ.get("SSO_ALERT_WEBHOOK_SECRET", "").strip(), text, hour)
    if not alerts:
        _print({"ok": False, "verdict": "BLOCKED", "reason": reason, "alerts": "not configured"})
        return EXIT_BLOCKED
    _print({"ok": False, "verdict": "FAIL", "reason": reason, "alerts": alerts})
    return EXIT_FAILED


def _alert_notification(api: str, token: str, target: str, text: str, hour: str) -> str:
    payload = {
        "template": "ops.text.v1",
        "target": {"ref": target},
        "data": {"body": text},
        # One alert per hour: the notification service replays the same key instead of resending.
        "idempotency_key": f"yice-sso-health-{hour}",
    }
    request = urllib.request.Request(
        f"{api}/v1/notifications",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return str(json.loads(response.read() or b"{}").get("status"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f"failed: {type(exc).__name__}"


def _alert_webhook(url: str, secret: str, text: str, hour: str) -> str:
    """Feishu group custom bot. The URL is itself a credential: it never appears in output.

    A webhook has no idempotency key, so the last hour that was sent is kept in SSO_ALERT_STATE_DIR
    (the probe unit's StateDirectory); a failed send is not recorded and retries on the next run.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "") not in WEBHOOK_HOSTS:
        return "failed: SSO_ALERT_WEBHOOK must be an https://open.feishu.cn or open.larksuite.com bot URL"
    state_dir = os.environ.get("SSO_ALERT_STATE_DIR", "").strip()
    if not state_dir:
        return "failed: SSO_ALERT_STATE_DIR is not set, so the hourly limit cannot be kept"
    state = Path(state_dir) / "webhook-last-hour"
    try:
        if state.exists() and state.read_text(encoding="utf-8").strip() == hour:
            return "already sent this hour"
    except OSError as exc:
        return f"failed: state unreadable ({type(exc).__name__})"
    payload: dict[str, Any] = {"msg_type": "text", "content": {"text": text}}
    if secret:
        timestamp = str(int(time.time()))
        digest = hmac.new(f"{timestamp}\n{secret}".encode("utf-8"), digestmod=hashlib.sha256).digest()
        payload.update(timestamp=timestamp, sign=base64.b64encode(digest).decode())
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = json.loads(response.read() or b"{}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f"failed: {type(exc).__name__}"
    code = body.get("code", body.get("StatusCode"))
    if code != 0:
        return f"failed: feishu code {code}"
    try:
        state.write_text(hour, encoding="utf-8")
    except OSError as exc:
        return f"sent; state not saved ({type(exc).__name__})"
    return "sent"


def _serve(host: str, port: int) -> int:
    import uvicorn

    from .api import create_app

    settings = Settings.from_environment()
    providers = ProviderRegistry.load(settings.providers_path)
    callers = CallerRegistry.load(settings.callers_path, providers=set(providers.declared))
    if host not in LOOPBACK_HOSTS and not callers.tokens:
        _print({"ok": False, "error": "bind_insecure", "message": "binding outside loopback needs a caller token"})
        return EXIT_BLOCKED
    # proxy_headers off: the browser IP comes from nginx's X-Forwarded-For only for loopback peers (api._browser_ip).
    uvicorn.run(create_app(settings=settings), host=host, port=port, proxy_headers=False, server_header=False,
                access_log=False)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
