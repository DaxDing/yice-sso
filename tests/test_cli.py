import io
import json
import urllib.error
import urllib.request

from sso_service import cli
from tests.support import FIXTURES, provider_env


def _run(capsys, argv):
    code = cli.main(argv)
    return code, json.loads(capsys.readouterr().out)


def test_self_check_reports_config_and_fails_without_mysql(monkeypatch, capsys):
    for key, value in provider_env().items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SSO_WEB_URL", "https://example.com/sso")
    monkeypatch.setenv("SSO_COOKIE_DOMAIN", "example.com")
    monkeypatch.setenv("SSO_PROVIDERS_PATH", str(FIXTURES / "providers.v1.json"))
    monkeypatch.setenv("SSO_CALLERS_PATH", str(FIXTURES / "callers.v1.json"))
    code, result = _run(capsys, ["--self-check"])
    assert code == cli.EXIT_FAILED and result["verdict"] == "FAIL"
    checks = result["checks"]
    assert checks["provider:default"]["ok"] and checks["caller:task"]["token_configured"]
    assert checks["mysql"]["ok"] is False
    assert provider_env()["SSO_FEISHU_DEFAULT_APP_SECRET"] not in json.dumps(result)


def test_self_check_flags_missing_secrets(monkeypatch, capsys):
    monkeypatch.setenv("SSO_HOST", "0.0.0.0")
    code, result = _run(capsys, ["--self-check"])
    assert code == cli.EXIT_FAILED
    assert result["checks"]["provider:default"]["ok"] is False
    assert result["checks"]["caller:info"]["ok"] is False
    assert result["checks"]["bind"]["ok"] is False


class _Response(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(json.dumps(body).encode())
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_probe_is_silent_when_healthy(monkeypatch, capsys):
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Response(200, {"ok": True}))
    assert cli.main(["probe"]) == cli.EXIT_OK
    assert capsys.readouterr().out == ""


def test_probe_alerts_once_per_hour_key(monkeypatch, capsys):
    sent = []

    def fake(request, timeout=0):
        if isinstance(request, str):
            raise urllib.error.URLError("refused")
        sent.append(json.loads(request.data))
        return _Response(200, {"status": "sent"})

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    monkeypatch.setenv("NOTIFICATION_API_URL", "http://127.0.0.1:8772")
    monkeypatch.setenv("NOTIFICATION_API_TOKEN", "t" * 40)
    monkeypatch.setenv("SSO_ALERT_TARGET", "ops-oncall")
    code, result = _run(capsys, ["probe"])
    assert code == cli.EXIT_FAILED and result["alerts"] == {"notification": "sent"}
    [payload] = sent
    assert payload["template"] == "ops.text.v1" and payload["target"] == {"ref": "ops-oncall"}
    assert payload["idempotency_key"].startswith("yice-sso-health-") and len(payload["idempotency_key"]) == 26


def test_probe_without_alert_config_is_blocked(monkeypatch, capsys):
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("refused"))
    )
    code, result = _run(capsys, ["probe"])
    assert code == cli.EXIT_BLOCKED and result["verdict"] == "BLOCKED" and result["alerts"] == "not configured"


def test_api_commands_need_a_base_url(capsys):
    code, result = _run(capsys, ["health"])
    assert code == cli.EXIT_BLOCKED and result["ok"] is False


def test_self_check_skips_the_directory_when_no_provider_uses_it(monkeypatch, capsys, tmp_path):
    providers = {"catalog_version": 1, "providers": {"partner": {
        "label": "合作企业", "directory": False, "app_id_env": "SSO_FEISHU_PARTNER_APP_ID",
        "app_secret_env": "SSO_FEISHU_PARTNER_APP_SECRET", "tenant_key_env": "SSO_FEISHU_PARTNER_TENANT_KEY"}}}
    callers = {"catalog_version": 1, "callers": {"task": {
        "label": "ops", "origins": ["https://task.example.com"], "providers": ["partner"],
        "token_env": "SSO_CALLER_TASK_TOKEN", "sources": ["10.0.0.50/32"]}}}
    (tmp_path / "p.json").write_text(json.dumps(providers), encoding="utf-8")
    (tmp_path / "c.json").write_text(json.dumps(callers), encoding="utf-8")
    for key, value in provider_env().items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SSO_WEB_URL", "https://example.com/sso")
    monkeypatch.setenv("SSO_COOKIE_DOMAIN", "example.com")
    monkeypatch.setenv("SSO_PROVIDERS_PATH", str(tmp_path / "p.json"))
    monkeypatch.setenv("SSO_CALLERS_PATH", str(tmp_path / "c.json"))

    class Store:
        def __init__(self, _settings):
            pass

        def health(self):
            return {"tables_ok": True, "schema_ok": True, "schema_version": 1}

        def active_member(self, _open_id):
            raise AssertionError("the directory must not be read without a directory provider")

    monkeypatch.setattr(cli, "MysqlStore", Store)
    code, result = _run(capsys, ["--self-check"])
    assert code == cli.EXIT_OK and result["verdict"] == "PASS"
    assert result["checks"]["member_directory"] == {"ok": True, "skipped": "no provider declares a directory"}


WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/0f0e-test-hook"


def _webhook_down(monkeypatch, sent, reply=None):
    def fake(request, timeout=0):
        if isinstance(request, str):
            raise urllib.error.URLError("refused")
        sent.append((request.full_url, json.loads(request.data)))
        return _Response(200, reply if reply is not None else {"code": 0, "msg": "success"})

    monkeypatch.setattr(urllib.request, "urlopen", fake)


def test_probe_alerts_a_feishu_group_webhook_signed_and_once_per_hour(monkeypatch, capsys, tmp_path):
    import base64
    import hashlib
    import hmac

    sent = []
    _webhook_down(monkeypatch, sent)
    monkeypatch.setenv("SSO_ALERT_WEBHOOK", WEBHOOK)
    monkeypatch.setenv("SSO_ALERT_WEBHOOK_SECRET", "s3cret")
    monkeypatch.setenv("SSO_ALERT_STATE_DIR", str(tmp_path))
    code, first = _run(capsys, ["probe"])
    assert code == cli.EXIT_FAILED and first["alerts"] == {"webhook": "sent"}
    [(url, payload)] = sent
    assert url == WEBHOOK and payload["msg_type"] == "text" and "健康检查失败" in payload["content"]["text"]
    expected = hmac.new(f"{payload['timestamp']}\ns3cret".encode(), digestmod=hashlib.sha256).digest()
    assert payload["sign"] == base64.b64encode(expected).decode()
    code, second = _run(capsys, ["probe"])
    assert second["alerts"] == {"webhook": "already sent this hour"} and len(sent) == 1
    assert WEBHOOK not in json.dumps([first, second]) and "s3cret" not in json.dumps([first, second])


def test_webhook_failures_are_reported_and_retried(monkeypatch, capsys, tmp_path):
    sent = []
    _webhook_down(monkeypatch, sent, reply={"code": 19021, "msg": "sign match fail"})
    monkeypatch.setenv("SSO_ALERT_WEBHOOK", WEBHOOK)
    monkeypatch.setenv("SSO_ALERT_STATE_DIR", str(tmp_path))
    for _ in range(2):
        code, result = _run(capsys, ["probe"])
        assert code == cli.EXIT_FAILED and result["alerts"] == {"webhook": "failed: feishu code 19021"}
    assert len(sent) == 2 and not (tmp_path / "webhook-last-hour").exists()


def test_webhook_outside_feishu_or_without_state_is_refused(monkeypatch, capsys, tmp_path):
    sent = []
    _webhook_down(monkeypatch, sent)
    monkeypatch.setenv("SSO_ALERT_WEBHOOK", "https://hooks.example.com/x")
    monkeypatch.setenv("SSO_ALERT_STATE_DIR", str(tmp_path))
    _, result = _run(capsys, ["probe"])
    assert result["alerts"]["webhook"].startswith("failed: SSO_ALERT_WEBHOOK must be")
    monkeypatch.setenv("SSO_ALERT_WEBHOOK", WEBHOOK)
    monkeypatch.delenv("SSO_ALERT_STATE_DIR")
    _, result = _run(capsys, ["probe"])
    assert result["alerts"]["webhook"].startswith("failed: SSO_ALERT_STATE_DIR")
    assert sent == []


def test_probe_unit_keeps_webhook_state():
    from tests.support import ROOT

    unit = (ROOT / "deploy/yice-sso-probe.service").read_text(encoding="utf-8")
    assert "StateDirectory=yice-sso-probe\n" in unit
    assert "Environment=SSO_ALERT_STATE_DIR=/var/lib/yice-sso-probe\n" in unit
