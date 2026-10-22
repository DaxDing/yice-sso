"""Unit tests never read developer credentials or perform external HTTP IO."""

import os
import urllib.request

import pytest

from sso_service import config


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for key in list(os.environ):
        if key.startswith(("FEISHU_", "SSO_")):
            monkeypatch.delenv(key)
    monkeypatch.setattr(config, "_load_dotenv", lambda path: None)

    def forbidden(*args, **kwargs):
        raise AssertionError("external HTTP is forbidden in unit tests")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
