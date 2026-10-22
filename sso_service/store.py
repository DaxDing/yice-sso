"""MySQL adapter for yice_sso plus the read-only Info member directory.

All times come from MySQL ``NOW(3)`` so app hosts never compare clocks. Every failure surfaces as
``StoreUnavailable``; callers map it to 503 and never treat it as "no session".
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Iterator, Protocol

from .config import MysqlSettings


class StoreUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class Member:
    open_id: str
    name: str
    avatar: str
    dept: str


@dataclass(frozen=True)
class SessionRow:
    token_hash: str
    subject_id: str
    open_id: str
    provider_id: str
    provider_digest: str
    caller_id: str
    name: str
    avatar: str
    dept: str
    expires_at: datetime
    checked_age_seconds: int


@dataclass(frozen=True)
class StateRow:
    provider_id: str
    caller_id: str
    next_url: str
    provider_digest: str


@dataclass(frozen=True)
class LoginEvent:
    request_id: str
    event_type: str
    outcome: str
    error_code: str | None = None
    subject_id: str | None = None
    name: str | None = None
    provider_id: str | None = None
    caller_id: str | None = None
    client_ip: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True)
class NewSession:
    token_hash: str
    subject_id: str
    open_id: str
    provider_id: str
    provider_digest: str
    caller_id: str
    name: str
    avatar: str
    dept: str


class Store(Protocol):
    def issue_state(self, state_hash: str, state: StateRow, ttl_seconds: int) -> None: ...

    def consume_state(self, state_hash: str) -> StateRow | None: ...

    def create_session(self, session: NewSession, ttl_seconds: int, event: LoginEvent) -> None: ...

    def get_session(self, token_hash: str) -> SessionRow | None: ...

    def renew_session(self, token_hash: str, name: str, avatar: str, dept: str, ttl_seconds: int) -> bool: ...

    def delete_session(self, token_hash: str, event: LoginEvent | None) -> SessionRow | None: ...

    def append_event(self, event: LoginEvent) -> None: ...

    def active_member(self, open_id: str) -> Member | None: ...

    def list_events(self, since: datetime, subject_id: str | None, limit: int) -> list[dict[str, Any]]: ...

    def health(self) -> dict[str, Any]: ...


EVENT_COLUMNS = (
    "request_id",
    "event_type",
    "outcome",
    "error_code",
    "subject_id",
    "name",
    "provider_id",
    "caller_id",
    "client_ip",
    "user_agent",
)
EXPECTED_TABLES = frozenset({"schema_migration", "session", "oauth_state", "login_event"})
SCHEMA_VERSION = 1


class MysqlStore:
    def __init__(self, settings: MysqlSettings) -> None:
        self.settings = settings
        self.sso = settings.database
        self.directory = settings.directory_database

    @contextlib.contextmanager
    def _cursor(self, *, transaction: bool = False) -> Iterator[Any]:
        if not self.settings.configured:
            raise StoreUnavailable("SSO MySQL is not configured")
        import pymysql
        from pymysql.constants import CLIENT

        try:
            connection = pymysql.connect(
                host=self.settings.host,
                port=self.settings.port,
                user=self.settings.user,
                password=self.settings.password,
                database=self.sso,
                charset="utf8mb4",
                connect_timeout=self.settings.timeout_seconds,
                read_timeout=self.settings.timeout_seconds,
                write_timeout=self.settings.timeout_seconds,
                autocommit=not transaction,
                cursorclass=pymysql.cursors.DictCursor,
                # Affected rows = matched rows, so an unchanged renewal is not mistaken for a vanished session.
                client_flag=CLIENT.FOUND_ROWS,
            )
        except pymysql.MySQLError as exc:
            raise StoreUnavailable("SSO MySQL unavailable") from exc
        try:
            with connection.cursor() as cursor:
                yield cursor
            if transaction:
                connection.commit()
        except pymysql.MySQLError as exc:
            if transaction:
                with contextlib.suppress(pymysql.MySQLError):
                    connection.rollback()
            raise StoreUnavailable("SSO MySQL query failed") from exc
        except BaseException:
            if transaction:
                with contextlib.suppress(pymysql.MySQLError):
                    connection.rollback()
            raise
        finally:
            connection.close()

    def issue_state(self, state_hash: str, state: StateRow, ttl_seconds: int) -> None:
        with self._cursor() as cursor:
            cursor.execute("DELETE FROM oauth_state WHERE expires_at <= NOW(3)")
            cursor.execute(
                "INSERT INTO oauth_state (state_hash, provider_id, caller_id, next_url, provider_digest, expires_at) "
                "VALUES (%s,%s,%s,%s,%s,DATE_ADD(NOW(3), INTERVAL %s SECOND))",
                (state_hash, state.provider_id, state.caller_id, state.next_url, state.provider_digest, ttl_seconds),
            )

    def consume_state(self, state_hash: str) -> StateRow | None:
        # Row lock + delete in one transaction: concurrent callbacks with one state get it at most once.
        with self._cursor(transaction=True) as cursor:
            cursor.execute(
                "SELECT provider_id, caller_id, next_url, provider_digest, expires_at > NOW(3) AS live "
                "FROM oauth_state WHERE state_hash=%s FOR UPDATE",
                (state_hash,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            cursor.execute("DELETE FROM oauth_state WHERE state_hash=%s", (state_hash,))
        if not row["live"]:
            return None
        return StateRow(row["provider_id"], row["caller_id"], row["next_url"], row["provider_digest"])

    def create_session(self, session: NewSession, ttl_seconds: int, event: LoginEvent) -> None:
        # The session and its login event commit together: no unaudited session, no phantom login.
        with self._cursor(transaction=True) as cursor:
            cursor.execute("DELETE FROM session WHERE expires_at <= NOW(3)")
            cursor.execute(
                "INSERT INTO session (token_hash, subject_id, open_id, provider_id, provider_digest, caller_id, name, "
                "avatar, dept, checked_at, expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(3),DATE_ADD(NOW(3), INTERVAL %s SECOND))",
                (
                    session.token_hash,
                    session.subject_id,
                    session.open_id,
                    session.provider_id,
                    session.provider_digest,
                    session.caller_id,
                    session.name,
                    session.avatar or None,
                    session.dept or None,
                    ttl_seconds,
                ),
            )
            self._insert_event(cursor, event)

    def get_session(self, token_hash: str) -> SessionRow | None:
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT token_hash, subject_id, open_id, provider_id, provider_digest, caller_id, name, avatar, dept, "
                "expires_at, TIMESTAMPDIFF(SECOND, checked_at, NOW(3)) AS checked_age "
                "FROM session WHERE token_hash=%s AND expires_at > NOW(3)",
                (token_hash,),
            )
            row = cursor.fetchone()
        if not row:
            return None
        return SessionRow(
            token_hash=row["token_hash"],
            subject_id=row["subject_id"],
            open_id=row["open_id"],
            provider_id=row["provider_id"],
            provider_digest=row["provider_digest"],
            caller_id=row["caller_id"],
            name=row["name"] or "",
            avatar=row["avatar"] or "",
            dept=row["dept"] or "",
            expires_at=row["expires_at"],
            checked_age_seconds=max(0, int(row["checked_age"] or 0)),
        )

    def renew_session(self, token_hash: str, name: str, avatar: str, dept: str, ttl_seconds: int) -> bool:
        """False when the session was revoked or expired since it was read (FOUND_ROWS: matched, not changed)."""
        with self._cursor() as cursor:
            matched = cursor.execute(
                "UPDATE session SET name=%s, avatar=%s, dept=%s, checked_at=NOW(3), "
                "expires_at=DATE_ADD(NOW(3), INTERVAL %s SECOND) WHERE token_hash=%s AND expires_at > NOW(3)",
                (name, avatar or None, dept or None, ttl_seconds, token_hash),
            )
        return matched > 0

    def delete_session(self, token_hash: str, event: LoginEvent | None) -> SessionRow | None:
        with self._cursor(transaction=True) as cursor:
            cursor.execute(
                "SELECT token_hash, subject_id, open_id, provider_id, provider_digest, caller_id, name, avatar, dept, "
                "expires_at FROM session WHERE token_hash=%s FOR UPDATE",
                (token_hash,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            cursor.execute("DELETE FROM session WHERE token_hash=%s", (token_hash,))
            if event is not None:
                self._insert_event(
                    cursor,
                    replace(event, subject_id=row["subject_id"], name=row["name"], provider_id=row["provider_id"]),
                )
        return SessionRow(
            row["token_hash"],
            row["subject_id"],
            row["open_id"],
            row["provider_id"],
            row["provider_digest"],
            row["caller_id"],
            row["name"] or "",
            row["avatar"] or "",
            row["dept"] or "",
            row["expires_at"],
            0,
        )

    def append_event(self, event: LoginEvent) -> None:
        with self._cursor() as cursor:
            self._insert_event(cursor, event)

    def active_member(self, open_id: str) -> Member | None:
        with self._cursor() as cursor:
            cursor.execute(
                f"SELECT m.open_id, m.name, m.avatar, d.name AS dept FROM `{self.directory}`.member m "
                f"LEFT JOIN `{self.directory}`.dept d ON d.dept_id = m.dept_id "
                "WHERE m.open_id=%s AND m.enabled=1 LIMIT 1",
                (open_id,),
            )
            row = cursor.fetchone()
        if not row:
            return None
        return Member(row["open_id"], row["name"] or "", row["avatar"] or "", row["dept"] or "")

    def list_events(self, since: datetime, subject_id: str | None, limit: int) -> list[dict[str, Any]]:
        sql = (
            "SELECT id, occurred_at, event_type, outcome, error_code, subject_id, name, provider_id, caller_id, "
            "client_ip FROM login_event WHERE occurred_at >= %s"
        )
        args: list[Any] = [since]
        if subject_id:
            sql += " AND subject_id=%s"
            args.append(subject_id)
        sql += " ORDER BY occurred_at DESC, id DESC LIMIT %s"
        args.append(limit)
        with self._cursor() as cursor:
            cursor.execute(sql, args)
            return list(cursor.fetchall())

    def health(self) -> dict[str, Any]:
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT table_name AS name FROM information_schema.tables WHERE table_schema=%s", (self.sso,)
            )
            tables = {row["name"] for row in cursor.fetchall()}
            version = None
            if "schema_migration" in tables:
                cursor.execute("SELECT MAX(version) AS version FROM schema_migration")
                version = (cursor.fetchone() or {}).get("version")
        return {
            "tables_ok": EXPECTED_TABLES <= tables,
            "missing_tables": sorted(EXPECTED_TABLES - tables),
            "schema_version": version,
            "schema_ok": version == SCHEMA_VERSION,
        }

    @staticmethod
    def _insert_event(cursor: Any, event: LoginEvent) -> None:
        values = [getattr(event, column) for column in EVENT_COLUMNS]
        values[EVENT_COLUMNS.index("user_agent")] = (event.user_agent or "")[:255] or None
        values[EVENT_COLUMNS.index("name")] = (event.name or "")[:128] or None
        cursor.execute(
            f"INSERT INTO login_event ({', '.join(EVENT_COLUMNS)}) VALUES ({', '.join(['%s'] * len(EVENT_COLUMNS))})",
            values,
        )
