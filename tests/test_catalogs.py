import ast
import hashlib
import json
from pathlib import Path

import pytest

from sso_service.callers import CallerError
from sso_service.config import MysqlSettings, Settings
from sso_service.providers import ProviderError, ProviderRegistry, identity_id
from sso_service.callers import CallerRegistry
from tests.support import FIXTURES, ROOT, provider_env, registries, token

# identity_id moved from auth_providers.py to auth_identities.py with the SSO cutover; check whichever exists.
INFO_IDENTITY_SOURCES = [ROOT.parent / "yice-information/server" / name for name in ("auth_identities.py", "auth_providers.py")]


def _info_identity_id():
    """Compile only Info's pure identity_id function, without importing its database modules."""
    for path in INFO_IDENTITY_SOURCES:
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        node = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "identity_id"), None)
        if node is not None:
            namespace = {"hashlib": hashlib, "json": json}
            exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
            return namespace["identity_id"]
    return None


def test_declared_catalogs_load_and_stay_inside_the_cookie_domain():
    providers, callers = registries()
    assert set(providers.providers) == {"default", "partner"}
    assert callers.get("task").providers == ("default",)
    assert callers.get("info").providers == ("default", "partner")
    callers.check_cookie_domain("example.com")
    with pytest.raises(CallerError):
        callers.check_cookie_domain("other.org")


def test_shipped_catalogs_load_with_their_declared_env_names():
    """config/ is what deploy.sh ships; it must load once every env name it declares has a value."""
    providers_path, callers_path = ROOT / "config/providers.v1.json", ROOT / "config/callers.v1.json"
    declared = json.loads(providers_path.read_text(encoding="utf-8"))["providers"]
    env = {}
    for provider_id, spec in declared.items():
        for key in ("app_id_env", "app_secret_env", "tenant_key_env"):
            if key in spec:
                env[spec[key]] = f"cli_{provider_id}" if key == "app_id_env" else f"value-{provider_id}"
    for caller_id, spec in json.loads(callers_path.read_text(encoding="utf-8"))["callers"].items():
        env[spec["token_env"]] = token(caller_id)
    providers = ProviderRegistry.load(providers_path, env=env)
    callers = CallerRegistry.load(callers_path, providers=set(providers.declared), env=env)
    assert all(providers.status()[p]["configured"] for p in declared)
    assert callers.authenticate(token(next(iter(json.loads(callers_path.read_text(encoding="utf-8"))["callers"])))) is not None


def test_identity_key_matches_info_byte_for_byte():
    assert identity_id("cli_a", "t", "ou_x") == "fs:" + hashlib.sha256(b'["cli_a","t","ou_x"]').hexdigest()[:60]
    info_identity_id = _info_identity_id()
    if info_identity_id is None:
        pytest.skip("Info identity_id source not present")
    for args in (("cli_a", "t", "ou_x"), ("cli_9f", "tenant-合作企业", "ou_汉字")):
        assert identity_id(*args) == info_identity_id(*args)


def test_missing_provider_values_leave_it_unconfigured_not_broken():
    env = provider_env()
    del env["SSO_FEISHU_PARTNER_TENANT_KEY"]
    providers, _ = registries(env)
    assert providers.status()["partner"] == {"configured": False, "directory": False}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p["providers"]["default"].update(app_secret_env="FEISHU_APP_SECRET"),
        lambda p: p["providers"]["default"].update(tenant_key_env="SSO_FEISHU_X_TENANT_KEY"),
        lambda p: p["providers"]["partner"].update(app_secret_env="SSO_FEISHU_DEFAULT_APP_SECRET"),
        lambda p: p["providers"]["partner"].pop("tenant_key_env"),
        lambda p: p["providers"]["partner"].update(extra=1),
        lambda p: p.update(catalog_version=2),
    ],
)
def test_invalid_provider_catalogs_are_rejected(tmp_path, mutate):
    payload = json.loads((FIXTURES / "providers.v1.json").read_text(encoding="utf-8"))
    mutate(payload)
    path = tmp_path / "providers.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ProviderError):
        ProviderRegistry.load(path, env=provider_env())


def test_provider_app_ids_must_be_feishu_ids_and_distinct(tmp_path):
    env = provider_env()
    env["SSO_FEISHU_PARTNER_APP_ID"] = env["SSO_FEISHU_DEFAULT_APP_ID"]
    with pytest.raises(ProviderError):
        ProviderRegistry.load(FIXTURES / "providers.v1.json", env=env)
    env["SSO_FEISHU_PARTNER_APP_ID"] = "not-an-app"
    with pytest.raises(ProviderError):
        ProviderRegistry.load(FIXTURES / "providers.v1.json", env=env)


def _callers_payload():
    return json.loads((FIXTURES / "callers.v1.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p["callers"]["task"].update(providers=["nobody"]),
        lambda p: p["callers"]["task"].update(origins=["https://Task.example.com"]),
        lambda p: p["callers"]["task"].update(origins=["https://task.example.com/path"]),
        lambda p: p["callers"]["task"].update(origins=["https://example.com"]),
        lambda p: p["callers"]["task"].update(token_env="SSO_CALLER_INFO_TOKEN"),
        lambda p: p["callers"]["task"].update(token_env="TASK_TOKEN"),
        lambda p: p["callers"]["task"].update(sources=["10.0.0.50/24"]),
        lambda p: p["callers"]["task"].update(sources=[]),
    ],
)
def test_invalid_caller_catalogs_are_rejected(tmp_path, mutate):
    payload = _callers_payload()
    mutate(payload)
    with pytest.raises(CallerError):
        registries(callers_payload=payload, tmp=tmp_path)


def test_caller_tokens_must_be_long_and_distinct(tmp_path):
    env = provider_env()
    env["SSO_CALLER_TASK_TOKEN"] = "short"
    with pytest.raises(CallerError):
        registries(env)
    env["SSO_CALLER_TASK_TOKEN"] = env["SSO_CALLER_INFO_TOKEN"]
    with pytest.raises(CallerError):
        registries(env)


def test_authenticate_and_sources(tmp_path):
    _, callers = registries()
    assert callers.authenticate(token("task")).id == "task"
    assert callers.authenticate(token("nope")) is None
    task = callers.get("task")
    assert task.allows_source("10.0.0.50") and not task.allows_source("10.0.0.51")
    assert not task.allows_source("testclient")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/warehouse?tab=daily", "https://task.example.com/warehouse?tab=daily"),
        ("https://task.example.com/a/b", "https://task.example.com/a/b"),
        ("https://TASK.example.com/a", "https://task.example.com/a"),
        ("https://task.example.com", "https://task.example.com/"),
        ("https://task.example.com/a#frag", "https://task.example.com/"),
        ("http://task.example.com/a", "https://task.example.com/"),
        ("https://task.example.com.evil.com/", "https://task.example.com/"),
        ("/\\evil.com", "https://task.example.com/"),
        ("//evil.com", "https://task.example.com/"),
        ("/a b", "https://task.example.com/"),
        ("javascript:alert(1)", "https://task.example.com/"),
        ("", "https://task.example.com/"),
    ],
)
def test_safe_next(value, expected):
    _, callers = registries()
    assert callers.get("task").safe_next(value) == expected


@pytest.mark.parametrize(
    ("web_url", "cookie_domain"),
    [
        ("https://example.com/sso", ""),
        ("https://example.com/login", "example.com"),
        ("https://other.com/sso", "example.com"),
        ("https://example.com/sso?x=1", "example.com"),
        ("ftp://example.com/sso", "example.com"),
        ("https://example.com/sso", "com"),
    ],
)
def test_invalid_web_urls(web_url, cookie_domain):
    with pytest.raises(ValueError):
        Settings(web_url=web_url, cookie_domain=cookie_domain, mysql=MysqlSettings())


def test_settings_from_environment_and_schema_names():
    settings = Settings.from_environment(
        env={"SSO_WEB_URL": "https://example.com/sso", "SSO_COOKIE_DOMAIN": "Example.com"}
    )
    assert settings.redirect_uri == "https://example.com/sso/callback" and settings.secure
    assert settings.cookie_domain == "example.com"
    with pytest.raises(ValueError):
        MysqlSettings(database="yice_sso`; DROP")
    assert Path(settings.callers_path).name == "callers.v1.json"
