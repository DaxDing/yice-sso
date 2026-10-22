"""Runtime settings from the environment; declarations live in config/*.v1.json."""

from __future__ import annotations

import os
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SESSION_COOKIE = "yice_sso"
# Prefix only: each login flow gets its own cookie (prefix + "_" + 16 hex of the state hash), so two
# tabs signing in at once never overwrite each other's state.
STATE_COOKIE = "yice_sso_state"
SESSION_TTL_SECONDS = 30 * 86400
# The cookie outlives any session (browser cap ~400 days); the server-side sliding expiry is the only clock.
COOKIE_MAX_AGE_SECONDS = 400 * 86400
RECHECK_AFTER_SECONDS = 3600
STATE_TTL_SECONDS = 600
SCHEMA_RE = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _load_dotenv(path: Path) -> None:
    from dotenv import load_dotenv

    load_dotenv(path, override=False, interpolate=False)


def load_environment(path: Path | None = None) -> None:
    _load_dotenv(path or Path(os.environ.get("SSO_ENV_FILE", ROOT / ".env")))


@dataclass(frozen=True)
class MysqlSettings:
    host: str = ""
    port: int = 3306
    user: str = ""
    password: str = field(default="", repr=False)
    database: str = "yice_sso"
    directory_database: str = "yice_information"
    timeout_seconds: float = 5

    def __post_init__(self) -> None:
        # Both names are interpolated as schema qualifiers, so only plain identifiers are accepted.
        for value in (self.database, self.directory_database):
            if not SCHEMA_RE.fullmatch(value):
                raise ValueError("SSO_MYSQL_DB and SSO_DIRECTORY_DB must be plain lowercase identifiers")

    @property
    def configured(self) -> bool:
        return bool(self.host and self.user and self.database)


@dataclass(frozen=True)
class Settings:
    """``web_url`` is the browser entry (``https://example.com/sso``); its scheme decides Secure cookies."""

    web_url: str
    cookie_domain: str
    mysql: MysqlSettings
    providers_path: Path = ROOT / "config/providers.v1.json"
    callers_path: Path = ROOT / "config/callers.v1.json"
    access_log_path: Path = ROOT / "output/log/sso-access.jsonl"
    timeout_seconds: float = 15

    def __post_init__(self) -> None:
        parts = urllib.parse.urlsplit(self.web_url)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.path.rstrip("/") != "/sso"
        ):
            raise ValueError("SSO_WEB_URL must be an http(s) origin followed by /sso")
        if self.cookie_domain:
            if not HOST_RE.fullmatch(self.cookie_domain) or "." not in self.cookie_domain:
                raise ValueError("SSO_COOKIE_DOMAIN must be a registrable domain such as example.com")
            host = parts.hostname.lower()
            if host != self.cookie_domain and not host.endswith("." + self.cookie_domain):
                raise ValueError("SSO_WEB_URL host must be inside SSO_COOKIE_DOMAIN")
        elif self.secure:
            raise ValueError("SSO_COOKIE_DOMAIN is required when SSO_WEB_URL is https")
        if not 1 <= self.timeout_seconds <= 60:
            raise ValueError("SSO_TIMEOUT_SECONDS must be between 1 and 60")

    @property
    def secure(self) -> bool:
        return self.web_url.startswith("https://")

    @property
    def base(self) -> str:
        return self.web_url.rstrip("/")

    @property
    def redirect_uri(self) -> str:
        return f"{self.base}/callback"

    @property
    def web_host(self) -> str:
        return (urllib.parse.urlsplit(self.web_url).hostname or "").lower()

    @classmethod
    def from_environment(cls, *, env: dict[str, str] | None = None) -> "Settings":
        values = os.environ if env is None else env
        try:
            port = int(values.get("SSO_MYSQL_PORT", "3306"))
            timeout = float(values.get("SSO_TIMEOUT_SECONDS", "15"))
        except ValueError as exc:
            raise ValueError("SSO_MYSQL_PORT and SSO_TIMEOUT_SECONDS must be numeric") from exc
        if not 1 <= port <= 65535:
            raise ValueError("SSO_MYSQL_PORT must be between 1 and 65535")
        return cls(
            web_url=str(values.get("SSO_WEB_URL", "http://127.0.0.1:8773/sso")).strip(),
            cookie_domain=str(values.get("SSO_COOKIE_DOMAIN", "")).strip().lower(),
            mysql=MysqlSettings(
                host=str(values.get("SSO_MYSQL_HOST", "")).strip(),
                port=port,
                user=str(values.get("SSO_MYSQL_USER", "")).strip(),
                password=str(values.get("SSO_MYSQL_PASSWORD", "")),
                database=str(values.get("SSO_MYSQL_DB", "yice_sso")).strip(),
                directory_database=str(values.get("SSO_DIRECTORY_DB", "yice_information")).strip(),
            ),
            providers_path=_path(values, "SSO_PROVIDERS_PATH", "config/providers.v1.json"),
            callers_path=_path(values, "SSO_CALLERS_PATH", "config/callers.v1.json"),
            access_log_path=_path(values, "SSO_ACCESS_LOG_PATH", "output/log/sso-access.jsonl"),
            timeout_seconds=timeout,
        )


def _path(values, key: str, default: str) -> Path:
    path = Path(values.get(key, default))
    return path if path.is_absolute() else ROOT / path
