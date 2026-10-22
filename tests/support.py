"""In-memory store and OAuth fakes that follow the Store / OAuthClient contracts."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from fastapi.testclient import TestClient

from sso_service.callers import CallerRegistry
from sso_service.config import MysqlSettings, Settings
from sso_service.feishu import OAuthError
from sso_service.providers import ProviderRegistry
from sso_service.service import SsoService
from sso_service.store import LoginEvent, Member, NewSession, SessionRow, StateRow, StoreUnavailable

ROOT = Path(__file__).parents[1]
# Behaviour tests run on these generic catalogs; config/ holds the deployment's own (see test_catalogs).
FIXTURES = Path(__file__).parent / "fixtures"
PARTNER_TENANT = "tenant-partner"
APP_DEFAULT = "cli_default0001"
APP_PARTNER = "cli_partner0001"


def token(label: str) -> str:
    return f"{label}-".ljust(40, "x")


def provider_env() -> dict[str, str]:
    return {
        "SSO_FEISHU_DEFAULT_APP_ID": APP_DEFAULT,
        "SSO_FEISHU_DEFAULT_APP_SECRET": "secret-default",
        "SSO_FEISHU_PARTNER_APP_ID": APP_PARTNER,
        "SSO_FEISHU_PARTNER_APP_SECRET": "secret-partner",
        "SSO_FEISHU_PARTNER_TENANT_KEY": PARTNER_TENANT,
        "SSO_CALLER_INFO_TOKEN": token("info"),
        "SSO_CALLER_TASK_TOKEN": token("task"),
    }


def make_settings(tmp: Path, *, web_url: str = "https://example.com/sso", cookie_domain: str = "example.com"):
    return Settings(
        web_url=web_url,
        cookie_domain=cookie_domain,
        mysql=MysqlSettings(),
        access_log_path=tmp / "access.jsonl",
    )


def registries(env: Mapping[str, str] | None = None, callers_payload: dict | None = None, tmp: Path | None = None):
    values = provider_env() if env is None else env
    providers = ProviderRegistry.load(FIXTURES / "providers.v1.json", env=values)
    path = FIXTURES / "callers.v1.json"
    if callers_payload is not None:
        assert tmp is not None
        path = tmp / "callers.v1.json"
        path.write_text(json.dumps(callers_payload), encoding="utf-8")
    callers = CallerRegistry.load(path, providers=set(providers.declared), env=values)
    return providers, callers


class FakeStore:
    """Clock-driven store; ``now`` advances explicitly so recheck and expiry rules are testable."""

    def __init__(self) -> None:
        self.now = datetime(2026, 10, 22, 9, 0, 0)
        self.states: dict[str, tuple[StateRow, datetime]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.events: list[LoginEvent] = []
        self.members: dict[str, Member] = {}
        self.down = False
        self.renewals = 0

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)

    def _check(self) -> None:
        if self.down:
            raise StoreUnavailable("down")

    def issue_state(self, state_hash: str, state: StateRow, ttl_seconds: int) -> None:
        self._check()
        self.states[state_hash] = (state, self.now + timedelta(seconds=ttl_seconds))

    def consume_state(self, state_hash: str) -> StateRow | None:
        self._check()
        item = self.states.pop(state_hash, None)
        if item is None or item[1] <= self.now:
            return None
        return item[0]

    def create_session(self, session: NewSession, ttl_seconds: int, event: LoginEvent) -> None:
        self._check()
        self.sessions[session.token_hash] = {
            "session": session,
            "checked_at": self.now,
            "expires_at": self.now + timedelta(seconds=ttl_seconds),
        }
        self.events.append(event)

    def get_session(self, token_hash: str) -> SessionRow | None:
        self._check()
        item = self.sessions.get(token_hash)
        if item is None or item["expires_at"] <= self.now:
            return None
        s: NewSession = item["session"]
        return SessionRow(
            s.token_hash,
            s.subject_id,
            s.open_id,
            s.provider_id,
            s.provider_digest,
            s.caller_id,
            s.name,
            s.avatar,
            s.dept,
            item["expires_at"],
            int((self.now - item["checked_at"]).total_seconds()),
        )

    def renew_session(self, token_hash: str, name: str, avatar: str, dept: str, ttl_seconds: int) -> bool:
        self._check()
        self.before_renew()
        item = self.sessions.get(token_hash)
        if item is None or item["expires_at"] <= self.now:
            return False
        self.renewals += 1
        item["session"] = replace(item["session"], name=name, avatar=avatar, dept=dept)
        item["checked_at"] = self.now
        item["expires_at"] = self.now + timedelta(seconds=ttl_seconds)
        return True

    def before_renew(self) -> None:
        """Hook for interleaving tests (e.g. a logout landing between read and renewal)."""

    def delete_session(self, token_hash: str, event: LoginEvent | None) -> SessionRow | None:
        self._check()
        row = self.get_session(token_hash) if token_hash in self.sessions else None
        item = self.sessions.pop(token_hash, None)
        if item is None:
            return None
        if event is not None:
            s: NewSession = item["session"]
            self.events.append(replace(event, subject_id=s.subject_id, name=s.name, provider_id=s.provider_id))
        return row

    def append_event(self, event: LoginEvent) -> None:
        self._check()
        self.events.append(event)

    def active_member(self, open_id: str) -> Member | None:
        self._check()
        return self.members.get(open_id)

    def list_events(self, since, subject_id, limit):
        return []

    def health(self) -> dict[str, Any]:
        self._check()
        return {"tables_ok": True, "missing_tables": [], "schema_version": 1, "schema_ok": True}


class FakeOAuth:
    def __init__(self) -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.fail: OAuthError | None = None
        self.exchanged: list[tuple[str, str, str]] = []

    def authorize_url(self, provider, redirect_uri: str, state: str) -> str:
        return f"https://open.feishu.cn/open-apis/authen/v1/authorize?app_id={provider.app_id}&state={state}"

    def exchange_code(self, provider, code: str, redirect_uri: str) -> str:
        if self.fail:
            raise self.fail
        self.exchanged.append((provider.id, code, redirect_uri))
        return f"access:{code}"

    def user_info(self, access_token: str):
        return self.users[access_token.removeprefix("access:")]


def make_service(tmp: Path, *, store: FakeStore | None = None, oauth: FakeOAuth | None = None, settings=None):
    providers, callers = registries()
    counter = iter(range(1, 10_000))
    return SsoService(
        settings=settings or make_settings(tmp),
        providers=providers,
        callers=callers,
        store=store or FakeStore(),
        oauth=oauth or FakeOAuth(),
        new_token=lambda n: f"tok{next(counter):04d}".ljust(n, "z"),
    )


def peer_client(app, host: str = "127.0.0.1", **kwargs) -> TestClient:
    return TestClient(app, client=(host, 50000), follow_redirects=False, **kwargs)
