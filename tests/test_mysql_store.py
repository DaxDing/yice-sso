"""MysqlStore against a private disposable mysqld, connected as yice_sso_app with schema/grants*.sql applied."""

from __future__ import annotations

import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sso_service.config import MysqlSettings
from sso_service.store import LoginEvent, MysqlStore, NewSession, StateRow, StoreUnavailable
from tests.support import ROOT

pytestmark = pytest.mark.mysql
MYSQLD = shutil.which("mysqld")
DIRECTORY_SQL = """
CREATE DATABASE yice_information DEFAULT CHARACTER SET utf8mb4;
CREATE TABLE yice_information.dept (dept_id VARCHAR(64) PRIMARY KEY, name VARCHAR(128) NOT NULL);
CREATE TABLE yice_information.member (
  open_id VARCHAR(64) PRIMARY KEY, name VARCHAR(64) NOT NULL, en_name VARCHAR(64), avatar VARCHAR(512),
  email VARCHAR(128), dept_id VARCHAR(64), enabled TINYINT(1) NOT NULL DEFAULT 1);
INSERT INTO yice_information.dept VALUES ('d1', '投放部');
INSERT INTO yice_information.member VALUES
  ('ou_active', '张三', NULL, 'https://a', 'a@x.com', 'd1', 1),
  ('ou_left', '李四', NULL, NULL, 'b@x.com', 'd1', 0);
"""


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Sandbox:
    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="yice-sso-mysql-"))
        self.socket = Path("/tmp") / f"yice-sso-{secrets.token_hex(6)}.sock"
        self.port = _free_port()
        self.password = secrets.token_urlsafe(18)
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        data = self.dir / "data"
        subprocess.run(
            [MYSQLD, "--no-defaults", "--initialize-insecure", f"--datadir={data}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        self.process = subprocess.Popen(
            [
                MYSQLD,
                "--no-defaults",
                f"--datadir={data}",
                "--bind-address=127.0.0.1",
                f"--port={self.port}",
                f"--socket={self.socket}",
                f"--pid-file={self.dir / 'mysqld.pid'}",
                "--skip-name-resolve",
                "--mysqlx=0",
            ],
            stdout=(self.dir / "mysqld.log").open("wb"),
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.socket.exists() and self.root_sql("SELECT 1", check=False).returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(f"mysqld not ready; see {self.dir / 'mysqld.log'}")
        self.root_sql((ROOT / "schema/yice_sso.sql").read_text(encoding="utf-8"))
        self.root_sql(DIRECTORY_SQL)
        self.root_sql(f"CREATE USER 'yice_sso_app'@'%' IDENTIFIED BY '{self.password}';")
        self.root_sql((ROOT / "schema/grants.sql").read_text(encoding="utf-8"))
        self.root_sql((ROOT / "schema/grants.directory.sql").read_text(encoding="utf-8"))

    def root_sql(self, sql: str, *, check: bool = True) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [shutil.which("mysql"), "--no-defaults", "--protocol=SOCKET", f"--socket={self.socket}", "-uroot"],
            input=sql.encode(),
            capture_output=True,
            check=False,
        )
        if check and result.returncode != 0:
            raise RuntimeError(result.stderr.decode())
        return result

    def stop(self) -> None:
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=30)
        shutil.rmtree(self.dir, ignore_errors=True)
        self.socket.unlink(missing_ok=True)


@pytest.fixture(scope="module")
def sandbox():
    if not MYSQLD or not shutil.which("mysql"):
        pytest.skip("mysqld not installed")
    box = Sandbox()
    try:
        box.start()
        yield box
    finally:
        box.stop()


@pytest.fixture
def store(sandbox):
    return MysqlStore(MysqlSettings(host="127.0.0.1", port=sandbox.port, user="yice_sso_app", password=sandbox.password))


def _event(kind="login", **fields):
    return LoginEvent(request_id=secrets.token_hex(16), event_type=kind, outcome="accepted", **fields)


def test_health_sees_all_tables_and_schema_version(store):
    assert store.health() == {"tables_ok": True, "missing_tables": [], "schema_version": 1, "schema_ok": True}


def test_state_is_consumed_exactly_once_under_concurrency(store):
    digest = secrets.token_hex(32)
    store.issue_state(digest, StateRow("default", "task", "https://task.example.com/", "d" * 64), 600)
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda _: store.consume_state(digest), range(8)))
    assert sum(r is not None for r in results) == 1
    assert next(r for r in results if r).caller_id == "task"


def test_expired_state_is_not_returned(store):
    digest = secrets.token_hex(32)
    store.issue_state(digest, StateRow("default", "task", "https://task.example.com/", "d" * 64), 0)
    assert store.consume_state(digest) is None


def test_session_lifecycle_and_events(store, sandbox):
    digest = secrets.token_hex(32)
    store.create_session(
        NewSession(digest, "ou_active", "ou_active", "default", "d" * 64, "task", "张三", "", "投放部"), 3600,
        _event(subject_id="ou_active"),
    )
    row = store.get_session(digest)
    assert (row.subject_id, row.caller_id, row.avatar, row.checked_age_seconds) == ("ou_active", "task", "", 0)
    assert store.renew_session(digest, "张三丰", "https://b", "数据部", 7200) is True
    # Same values again within the same statement batch still count as matched (FOUND_ROWS).
    assert store.renew_session(digest, "张三丰", "https://b", "数据部", 7200) is True
    assert store.get_session(digest).name == "张三丰"
    removed = store.delete_session(digest, _event("logout", caller_id="info"))
    assert removed.subject_id == "ou_active" and store.get_session(digest) is None
    assert store.renew_session(digest, "张三丰", "", "", 7200) is False
    assert store.delete_session(digest, _event("logout")) is None
    [logout] = [e for e in store.list_events(removed.expires_at.replace(year=2000), "ou_active", 10)
                if e["event_type"] == "logout"]
    assert (logout["caller_id"], logout["name"], logout["provider_id"]) == ("info", "张三丰", "default")


def test_session_and_login_event_commit_together(store):
    digest = secrets.token_hex(32)
    duplicate = _event(subject_id="ou_active")
    store.append_event(duplicate)
    # A second row with the same request id violates the unique key, so the session is rolled back too.
    with pytest.raises(StoreUnavailable):
        store.create_session(
            NewSession(digest, "ou_active", "ou_active", "default", "d" * 64, "task", "张三", "", ""), 3600, duplicate
        )
    assert store.get_session(digest) is None


def test_member_directory_reads_only_granted_columns(store, sandbox):
    member = store.active_member("ou_active")
    assert (member.name, member.avatar, member.dept) == ("张三", "https://a", "投放部")
    assert store.active_member("ou_left") is None
    import pymysql

    connection = pymysql.connect(host="127.0.0.1", port=sandbox.port, user="yice_sso_app", password=sandbox.password)
    try:
        with connection.cursor() as cursor, pytest.raises(pymysql.err.OperationalError) as denied:
            cursor.execute("SELECT email FROM yice_information.member")
        assert denied.value.args[0] == 1143
        with connection.cursor() as cursor, pytest.raises(pymysql.err.OperationalError) as no_update:
            cursor.execute("UPDATE yice_sso.login_event SET outcome='error'")
        assert no_update.value.args[0] == 1142
    finally:
        connection.close()


def test_login_event_is_append_only_even_for_root(store, sandbox):
    store.append_event(_event())
    for sql in ("UPDATE yice_sso.login_event SET outcome='error';", "DELETE FROM yice_sso.login_event;"):
        result = sandbox.root_sql(sql, check=False)
        assert result.returncode != 0 and b"append-only" in result.stderr


def test_unreachable_mysql_is_unavailable_not_empty():
    store = MysqlStore(MysqlSettings(host="127.0.0.1", port=_free_port(), user="x", password="y", timeout_seconds=1))
    with pytest.raises(StoreUnavailable):
        store.get_session("0" * 64)
