"""Feishu web-app OAuth adapter: the only module that talks to open.feishu.cn."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping, Protocol

from .providers import Provider

FEISHU_OPEN_API = "https://open.feishu.cn/open-apis"
MAX_RESPONSE_BYTES = 1024 * 1024


class OAuthError(RuntimeError):
    """Upstream failure with a stable, credential-free code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class OAuthClient(Protocol):
    def authorize_url(self, provider: Provider, redirect_uri: str, state: str) -> str: ...

    def exchange_code(self, provider: Provider, code: str, redirect_uri: str) -> str: ...

    def user_info(self, access_token: str) -> Mapping[str, Any]: ...


class FeishuOAuthClient:
    def __init__(self, timeout_seconds: float = 15) -> None:
        self.timeout_seconds = timeout_seconds

    def authorize_url(self, provider: Provider, redirect_uri: str, state: str) -> str:
        query = urllib.parse.urlencode({"app_id": provider.app_id, "redirect_uri": redirect_uri, "state": state})
        return f"{FEISHU_OPEN_API}/authen/v1/authorize?{query}"

    def exchange_code(self, provider: Provider, code: str, redirect_uri: str) -> str:
        payload = {
            "grant_type": "authorization_code",
            "client_id": provider.app_id,
            "client_secret": provider.app_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }
        request = urllib.request.Request(
            f"{FEISHU_OPEN_API}/authen/v2/oauth/token",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        response = self._json(request, "oauth_token_exchange_failed", "飞书授权码换取失败，请重新登录")
        token = response.get("access_token")
        if not isinstance(token, str) or not token:
            raise OAuthError("oauth_token_exchange_failed", "飞书授权码换取失败，请重新登录")
        return token

    def user_info(self, access_token: str) -> Mapping[str, Any]:
        request = urllib.request.Request(
            f"{FEISHU_OPEN_API}/authen/v1/user_info", headers={"Authorization": f"Bearer {access_token}"}
        )
        response = self._json(request, "oauth_user_info_failed", "无法读取飞书身份，请重新登录")
        data = response.get("data")
        if response.get("code") != 0 or not isinstance(data, dict):
            raise OAuthError("oauth_user_info_failed", "无法读取飞书身份（检查应用是否开通获取用户基本信息权限）")
        return data

    def _json(self, request: urllib.request.Request, code: str, message: str) -> dict[str, Any]:
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            # Feishu reports OAuth errors with 4xx bodies; the body may echo request details, so it is dropped.
            raise OAuthError(code, message) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise OAuthError("oauth_upstream_unavailable", "飞书暂时无法访问，请稍后重试") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise OAuthError(code, message)
        try:
            value = json.loads(raw)
        except ValueError as exc:
            raise OAuthError(code, message) from exc
        if not isinstance(value, dict):
            raise OAuthError(code, message)
        return value
