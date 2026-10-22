"""Drift checks between the catalogs, the deploy files and the copied token generator."""

import json
import re
import subprocess
import sys

from tests.support import ROOT

DEPLOY = ROOT / "deploy"
NOTIFICATION_TOKENS = ROOT.parent / "yice-notification/deploy/ensure_tokens.py"


def test_token_generator_matches_notification_apart_from_its_docstring_line():
    ours = (DEPLOY / "ensure_tokens.py").read_text(encoding="utf-8").splitlines()
    if not NOTIFICATION_TOKENS.exists():
        return
    theirs = NOTIFICATION_TOKENS.read_text(encoding="utf-8").splitlines()
    assert ours[2:] == theirs[2:]


def test_token_generator_plans_every_enabled_caller():
    result = subprocess.run(
        [sys.executable, str(DEPLOY / "ensure_tokens.py"), "--callers", str(ROOT / "config/callers.v1.json"),
         "--env-keys", "-"],
        input="SSO_CALLER_INFO_TOKEN\n",
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout)["missing"] == [{"caller": "task", "token_env": "SSO_CALLER_TASK_TOKEN"}]


def test_port_and_unit_names_agree():
    unit = (DEPLOY / "yice-sso.service").read_text(encoding="utf-8")
    script = (DEPLOY / "deploy.sh").read_text(encoding="utf-8")
    assert "--port 8773" in unit and "PORT=8773" in script
    for name in ("yice-sso.service", "yice-sso-probe.service"):
        text = (DEPLOY / name).read_text(encoding="utf-8")
        assert "WorkingDirectory=/opt/yice/yice-sso/current\n" in text
        assert "ExecStart=/opt/yice/yice-sso/current/.venv/bin/python -m sso_service.cli" in text
        assert "EnvironmentFile=/opt/yice/yice-sso/.env\n" in text
    assert "Environment=SSO_ACCESS_LOG_PATH=/var/log/yice-sso/access.jsonl" in unit
    for name in ("yice-sso-probe.service", "yice-sso-probe.timer"):
        assert (DEPLOY / name).exists() and name in script


def test_deploy_switches_releases_and_rolls_back():
    script = (DEPLOY / "deploy.sh").read_text(encoding="utf-8")
    switch = script.index('switch_to "$release"')
    assert script.index("--self-check") < switch < script.index("systemctl restart yice-sso")
    assert 'switch_to "$previous"' in script and "rolled back to" in script
    assert "mv -Tf" in script
    # A 0700 base dir (root umask 077) once made the DynamicUser fail with 203/EXEC.
    assert 'install -d -m 755 -o root -g root "$base" "$base/releases"' in script
    assert "--no-owner --no-group" in script
    # Pruning with a single release must not turn a healthy first deploy into FAIL (pipefail + grep exit 1).
    assert '{ grep -vx "$release" || true; }' in script


def test_prune_pipeline_survives_a_single_release(tmp_path):
    (tmp_path / "releases" / "only").mkdir(parents=True)
    script = (
        'set -euo pipefail; base="$1"; release=only; keep=3\n'
        'ls -1t "$base/releases" | { grep -vx "$release" || true; } | tail -n +"$keep" | while read -r old; do\n'
        '  rm -rf "$base/releases/$old"\ndone\necho survived'
    )
    result = subprocess.run(["bash", "-c", script, "prune", str(tmp_path)], capture_output=True, text=True)
    assert result.returncode == 0 and result.stdout.strip() == "survived"
    assert (tmp_path / "releases" / "only").exists()


def test_nginx_snippet_proxies_only_sso_and_hides_callback_queries():
    text = (DEPLOY / "nginx-sso.locations.conf").read_text(encoding="utf-8")
    locations = re.findall(r"^location\s+(.+?)\s*\{", text, re.M)
    assert locations == ["= /sso/callback", "= /sso/authorize", "^~ /sso/"]
    assert set(re.findall(r"proxy_pass\s+(\S+);", text)) == {"http://127.0.0.1:8773"}
    callback = text.split("location = /sso/callback", 1)[1].split("}", 1)[0]
    assert "access_log off;" in callback
    assert "/v1" not in "".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_production_env_template_names_every_declared_secret():
    template = (DEPLOY / "production.env.example").read_text(encoding="utf-8")
    providers = json.loads((ROOT / "config/providers.v1.json").read_text(encoding="utf-8"))["providers"]
    for provider in providers.values():
        for key in ("app_id_env", "app_secret_env", "tenant_key_env"):
            if key in provider:
                assert f"{provider[key]}=" in template
    for key in ("SSO_WEB_URL", "SSO_COOKIE_DOMAIN", "SSO_MYSQL_HOST", "SSO_MYSQL_PASSWORD"):
        assert f"{key}=" in template
    assert "SSO_ACCESS_LOG_PATH=" not in template and "SSO_HOST=" not in template


def test_grant_manifest_matches_grants_sql():
    manifest_path = ROOT.parent / "aliyun-subaccount/grants/yice_sso_app.json"
    if not manifest_path.exists():
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sql = "".join((ROOT / name).read_text(encoding="utf-8") for name in ("schema/grants.sql", "schema/grants.directory.sql"))
    granted = {}
    for privileges, table in re.findall(r"^GRANT (.+?) ON (\S+) TO 'yice_sso_app'@'%';$", sql, re.M):
        columns = re.match(r"SELECT \((.+)\)$", privileges)
        if columns:
            granted[table] = {"SELECT": [c.strip() for c in columns.group(1).split(",")]}
        else:
            granted[table] = {p.strip(): "*" for p in privileges.split(",")}
    assert granted == manifest["privileges"]


def test_info_nginx_carries_the_sso_locations():
    """The snippet is the review copy; the installed truth is Info's host-managed nginx.conf."""
    info = ROOT.parent / "yice-information/deploy/nginx-yice-information.conf"
    if not info.exists():
        return
    text = info.read_text(encoding="utf-8")
    assert "limit_req_zone $binary_remote_addr zone=yice_sso_authorize:10m rate=10r/m;" in text
    for header in ("location = /sso/callback {", "location = /sso/authorize {", "location ^~ /sso/ {"):
        block = text.split(header, 1)[1].split("}", 1)[0]
        assert "proxy_pass http://127.0.0.1:8773;" in block
        assert "proxy_set_header X-Forwarded-For $remote_addr;" in block
    callback = text.split("location = /sso/callback {", 1)[1].split("}", 1)[0]
    assert "access_log off;" in callback
    assert text.count("proxy_pass http://127.0.0.1:8773;") == 3


def test_directory_grants_are_separate_and_match_the_example_tables():
    """grants.sql works without a directory; the directory grants cover exactly what the example DDL creates."""
    core = (ROOT / "schema/grants.sql").read_text(encoding="utf-8")
    directory = (ROOT / "schema/grants.directory.sql").read_text(encoding="utf-8")
    example = (ROOT / "schema/directory.example.sql").read_text(encoding="utf-8")
    assert re.findall(r"^GRANT .+ ON (\S+) ", core, re.M) and all(
        table.startswith("yice_sso.") for table in re.findall(r"^GRANT .+ ON (\S+) ", core, re.M)
    )
    for columns, table in re.findall(r"^GRANT SELECT \((.+)\) ON (\S+) ", directory, re.M):
        block = example.split(f"CREATE TABLE IF NOT EXISTS {table} (", 1)[1].split(") ENGINE", 1)[0]
        declared = {line.split()[0] for line in block.splitlines() if line.strip() and not line.strip().startswith("KEY")}
        assert {c.strip() for c in columns.split(",")} <= declared
