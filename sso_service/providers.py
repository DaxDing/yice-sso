"""Declared Feishu login providers (one enterprise app each); values come from env names only."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,47}$")
ENV_RE = re.compile(r"^SSO_FEISHU_[A-Z0-9_]+$")
APP_ID_RE = re.compile(r"^cli_[A-Za-z0-9]+$")


class ProviderError(ValueError):
    pass


@dataclass(frozen=True)
class Provider:
    """``directory`` providers admit active ``member`` rows only; others admit their declared tenant."""

    id: str
    label: str
    directory: bool
    app_id: str
    app_secret: str = field(repr=False)
    tenant_key: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.app_id and self.app_secret and (self.directory or self.tenant_key))

    @property
    def digest(self) -> str:
        """Changes whenever the identity-relevant configuration changes; never includes the secret."""
        return hashlib.sha256(
            json.dumps([self.id, self.app_id, self.tenant_key, self.directory], separators=(",", ":")).encode()
        ).hexdigest()

    def subject_id(self, open_id: str) -> str:
        if self.directory:
            return open_id
        return identity_id(self.app_id, self.tenant_key, open_id)

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label}


def identity_id(app_id: str, tenant_key: str, open_id: str) -> str:
    """Opaque app + tenant + user key, byte-identical to Info ``auth_providers.identity_id``."""
    digest = hashlib.sha256(json.dumps([app_id, tenant_key, open_id], separators=(",", ":")).encode()).hexdigest()
    return "fs:" + digest[:60]


@dataclass(frozen=True)
class ProviderRegistry:
    providers: dict[str, Provider]
    declared: frozenset[str] = frozenset()

    @classmethod
    def load(cls, path: Path, *, env: Mapping[str, str] | None = None) -> "ProviderRegistry":
        values = os.environ if env is None else env
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ProviderError(f"cannot load provider catalog: {path}") from exc
        if not isinstance(payload, dict) or payload.get("catalog_version") != 1 or set(payload) - {
            "catalog_version",
            "providers",
        }:
            raise ProviderError("provider catalog must be {catalog_version: 1, providers: {...}}")
        source = payload.get("providers")
        if not isinstance(source, dict) or not source:
            raise ProviderError("provider catalog must declare at least one provider")
        providers: dict[str, Provider] = {}
        envs: set[str] = set()
        for provider_id, raw in source.items():
            provider = _provider(provider_id, raw, values, envs)
            if provider is not None:
                providers[provider.id] = provider
        apps = [p.app_id for p in providers.values() if p.app_id]
        if len(apps) != len(set(apps)):
            raise ProviderError("two providers share one Feishu app")
        return cls(providers, frozenset(source))

    def get(self, provider_id: str) -> Provider | None:
        return self.providers.get(provider_id)

    def status(self) -> dict[str, dict[str, bool]]:
        return {pid: {"configured": p.configured, "directory": p.directory} for pid, p in self.providers.items()}


def _provider(provider_id: Any, raw: Any, values: Mapping[str, str], envs: set[str]) -> Provider | None:
    if not isinstance(provider_id, str) or not ID_RE.fullmatch(provider_id):
        raise ProviderError("provider id must be a lowercase identifier")
    if not isinstance(raw, dict) or set(raw) - {
        "label",
        "directory",
        "app_id_env",
        "app_secret_env",
        "tenant_key_env",
        "enabled",
    }:
        raise ProviderError(f"provider {provider_id}: unknown fields")
    label = raw.get("label")
    if not isinstance(label, str) or not label.strip() or len(label) > 64:
        raise ProviderError(f"provider {provider_id}: label must be 1-64 characters")
    directory = raw.get("directory")
    enabled = raw.get("enabled", True)
    if type(directory) is not bool or type(enabled) is not bool:
        raise ProviderError(f"provider {provider_id}: directory and enabled must be boolean")
    names = ["app_id_env", "app_secret_env"] + ([] if directory else ["tenant_key_env"])
    if directory and "tenant_key_env" in raw:
        raise ProviderError(f"provider {provider_id}: a directory provider has no tenant_key_env")
    for key in names:
        name = raw.get(key)
        if not isinstance(name, str) or not ENV_RE.fullmatch(name):
            raise ProviderError(f"provider {provider_id}: {key} must be an SSO_FEISHU_* variable name")
        if name in envs:
            raise ProviderError(f"provider {provider_id}: {key} is shared with another provider")
        envs.add(name)
    if not enabled:
        return None
    app_id = str(values.get(raw["app_id_env"], "")).strip()
    if app_id and not APP_ID_RE.fullmatch(app_id):
        raise ProviderError(f"provider {provider_id}: {raw['app_id_env']} is not a Feishu app id")
    tenant_key = "" if directory else str(values.get(raw["tenant_key_env"], "")).strip()
    if len(tenant_key) > 128:
        raise ProviderError(f"provider {provider_id}: tenant key too long")
    return Provider(
        id=provider_id,
        label=label.strip(),
        directory=directory,
        app_id=app_id,
        app_secret=str(values.get(raw["app_secret_env"], "")).strip(),
        tenant_key=tenant_key,
    )
