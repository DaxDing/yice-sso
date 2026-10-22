"""Declared callers (the web apps): allowed origins and providers, internal API token, source networks."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,47}$")
TOKEN_ENV_RE = re.compile(r"^SSO_CALLER_[A-Z0-9_]+_TOKEN$")
MIN_TOKEN_CHARS = 32
MAX_NEXT_URL = 1024


class CallerError(ValueError):
    pass


@dataclass(frozen=True)
class Caller:
    id: str
    label: str
    origins: tuple[str, ...]
    providers: tuple[str, ...]
    token_env: str
    sources: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    enabled: bool = True

    def allows_source(self, host: str) -> bool:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(address in network for network in self.sources)

    def safe_next(self, value: str | None) -> str:
        """Absolute URL on one of this caller's origins; anything else falls back to its first origin."""
        fallback = self.origins[0] + "/"
        if not value or len(value) > MAX_NEXT_URL or any(ord(ch) < 0x21 for ch in value):
            return fallback
        if value.startswith("/") and not value.startswith("//") and "\\" not in value:
            value = self.origins[0] + value
        parts = urllib.parse.urlsplit(value)
        if parts.username is not None or parts.password is not None or parts.fragment:
            return fallback
        origin = f"{parts.scheme}://{parts.netloc}".lower()
        if origin not in self.origins:
            return fallback
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc.lower(), parts.path or "/", parts.query, ""))

    def public(self) -> dict[str, Any]:
        return {"caller": self.id, "label": self.label, "origins": list(self.origins), "providers": list(self.providers)}


@dataclass(frozen=True)
class CallerRegistry:
    callers: dict[str, Caller]
    tokens: tuple[tuple[str, Caller], ...]

    @classmethod
    def load(
        cls, path: Path, *, providers: set[str], env: Mapping[str, str] | None = None
    ) -> "CallerRegistry":
        values = os.environ if env is None else env
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CallerError(f"cannot load caller catalog: {path}") from exc
        if not isinstance(payload, dict) or payload.get("catalog_version") != 1 or set(payload) - {
            "catalog_version",
            "callers",
        }:
            raise CallerError("caller catalog must be {catalog_version: 1, callers: {...}}")
        source = payload.get("callers")
        if not isinstance(source, dict) or not source:
            raise CallerError("caller catalog must declare at least one caller")
        callers: dict[str, Caller] = {}
        tokens: list[tuple[str, Caller]] = []
        envs: set[str] = set()
        origins: set[str] = set()
        for caller_id, raw in source.items():
            caller = _caller(caller_id, raw, providers)
            if caller.token_env in envs:
                raise CallerError(f"caller {caller.id}: token_env is shared with another caller")
            envs.add(caller.token_env)
            if origins & set(caller.origins):
                raise CallerError(f"caller {caller.id}: origin is declared by another caller")
            origins.update(caller.origins)
            callers[caller.id] = caller
            token = str(values.get(caller.token_env, "")).strip()
            if not caller.enabled or not token:
                continue
            if len(token) < MIN_TOKEN_CHARS:
                raise CallerError(f"caller {caller.id}: token must be at least {MIN_TOKEN_CHARS} characters")
            if any(secrets.compare_digest(token.encode(), known.encode()) for known, _ in tokens):
                raise CallerError(f"caller {caller.id}: token is shared with another caller")
            tokens.append((token, caller))
        return cls(callers, tuple(tokens))

    def get(self, caller_id: str | None) -> Caller | None:
        caller = self.callers.get(caller_id or "")
        return caller if caller and caller.enabled else None

    def authenticate(self, provided: str) -> Caller | None:
        match = None
        candidate = provided.encode()
        # Compare against every token so timing does not reveal which caller matched.
        for token, caller in self.tokens:
            if secrets.compare_digest(candidate, token.encode()):
                match = caller
        return match

    def check_cookie_domain(self, cookie_domain: str) -> None:
        """Every origin must receive the parent-domain cookie, or its users could never sign in."""
        for caller in self.callers.values():
            for origin in caller.origins:
                host = (urllib.parse.urlsplit(origin).hostname or "").lower()
                if cookie_domain and host != cookie_domain and not host.endswith("." + cookie_domain):
                    raise CallerError(f"caller {caller.id}: {origin} is outside cookie domain {cookie_domain}")

    def status(self) -> dict[str, dict[str, Any]]:
        configured = {caller.id for _, caller in self.tokens}
        return {
            cid: {"enabled": c.enabled, "token_configured": cid in configured, "sources": [str(n) for n in c.sources]}
            for cid, c in self.callers.items()
        }


def _caller(caller_id: Any, raw: Any, providers: set[str]) -> Caller:
    if not isinstance(caller_id, str) or not ID_RE.fullmatch(caller_id):
        raise CallerError("caller id must be a lowercase identifier")
    if not isinstance(raw, dict) or set(raw) - {"label", "origins", "providers", "token_env", "sources", "enabled"}:
        raise CallerError(f"caller {caller_id}: unknown fields")
    label = raw.get("label")
    if not isinstance(label, str) or not label.strip() or len(label) > 64:
        raise CallerError(f"caller {caller_id}: label must be 1-64 characters")
    enabled = raw.get("enabled", True)
    if type(enabled) is not bool:
        raise CallerError(f"caller {caller_id}: enabled must be boolean")
    origins = raw.get("origins")
    if not isinstance(origins, list) or not origins or len(origins) != len(set(origins)):
        raise CallerError(f"caller {caller_id}: origins must be a non-empty unique list")
    for origin in origins:
        parts = urllib.parse.urlsplit(origin) if isinstance(origin, str) else None
        if (
            parts is None
            or parts.scheme not in ("http", "https")
            or not parts.hostname
            or origin != f"{parts.scheme}://{parts.netloc}".lower()
        ):
            raise CallerError(f"caller {caller_id}: origin must be a lowercase scheme://host[:port]")
    allowed = raw.get("providers")
    if not isinstance(allowed, list) or not allowed or len(allowed) != len(set(allowed)):
        raise CallerError(f"caller {caller_id}: providers must be a non-empty unique list")
    unknown = [p for p in allowed if p not in providers]
    if unknown:
        raise CallerError(f"caller {caller_id}: undeclared providers {unknown}")
    token_env = raw.get("token_env")
    if not isinstance(token_env, str) or not TOKEN_ENV_RE.fullmatch(token_env):
        raise CallerError(f"caller {caller_id}: token_env must be SSO_CALLER_*_TOKEN")
    sources = raw.get("sources")
    if not isinstance(sources, list) or not sources or len(sources) != len(set(sources)):
        raise CallerError(f"caller {caller_id}: sources must be a non-empty unique list of CIDRs")
    try:
        networks = tuple(ipaddress.ip_network(value, strict=True) for value in sources)
    except (TypeError, ValueError) as exc:
        raise CallerError(f"caller {caller_id}: invalid source CIDR") from exc
    return Caller(caller_id, label.strip(), tuple(origins), tuple(allowed), token_env, networks, enabled)
