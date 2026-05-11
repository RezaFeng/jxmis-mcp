"""SQLite storage for users, connector state, login sessions, and audit logs."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .base import ConnectorStatus
from .context import AuthenticatedUser
from .crypto import CredentialCipher


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return "jxm_" + secrets.token_urlsafe(32)


class ServerStore:
    def __init__(self, path: Path, cipher: CredentialCipher) -> None:
        self.path = path
        self.cipher = cipher
        ensure_dir(path.parent)
        self._init_db()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS api_tokens (
                    token_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    token_prefix TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    revoked_at TEXT NOT NULL DEFAULT '',
                    last_used_at TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS connector_state (
                    user_id TEXT NOT NULL,
                    connector_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    credentials_ciphertext TEXT NOT NULL DEFAULT '',
                    qr_url TEXT NOT NULL DEFAULT '',
                    final_url TEXT NOT NULL DEFAULT '',
                    error_message TEXT NOT NULL DEFAULT '',
                    connected_at TEXT NOT NULL DEFAULT '',
                    last_verified_at TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (user_id, connector_id)
                );

                CREATE TABLE IF NOT EXISTS connector_login_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    connector_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    qr_url TEXT NOT NULL DEFAULT '',
                    error_message TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    token_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    args_json TEXT NOT NULL,
                    ok INTEGER NOT NULL,
                    error_message TEXT NOT NULL DEFAULT '',
                    result_summary_json TEXT NOT NULL DEFAULT '{}',
                    affected_count INTEGER,
                    jxmis_user_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_login_user_status
                    ON connector_login_sessions (user_id, connector_id, status, updated_at);
                CREATE INDEX IF NOT EXISTS idx_audit_user_created
                    ON audit_log (user_id, created_at);
                """
            )

    def create_token(self, name: str) -> tuple[AuthenticatedUser, str]:
        token = new_token()
        token_id = secrets.token_hex(8)
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO api_tokens (
                    token_id, name, token_hash, token_prefix, status, created_at
                ) VALUES (?, ?, ?, ?, 'active', ?)
                """,
                (token_id, name, token_hash(token), token[:12], now),
            )
        return AuthenticatedUser(user_id=token_id, token_id=token_id, token_name=name), token

    def revoke_token(self, token_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE api_tokens
                SET status = 'revoked', revoked_at = ?
                WHERE token_id = ? AND status != 'revoked'
                """,
                (utc_now(), token_id),
            )
        return cur.rowcount > 0

    def list_tokens(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT token_id, name, token_prefix, status, created_at, revoked_at, last_used_at
                FROM api_tokens
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def authenticate_token(self, token: str) -> AuthenticatedUser | None:
        hashed = token_hash(token)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT token_id, name, status
                FROM api_tokens
                WHERE token_hash = ?
                """,
                (hashed,),
            ).fetchone()
            if not row or row["status"] != "active":
                return None
            conn.execute(
                "UPDATE api_tokens SET last_used_at = ? WHERE token_id = ?",
                (utc_now(), row["token_id"]),
            )
        token_id = str(row["token_id"])
        return AuthenticatedUser(user_id=token_id, token_id=token_id, token_name=str(row["name"]))

    def user_store(self, user_id: str) -> "UserConnectorStore":
        return UserConnectorStore(self, user_id)

    def mark_stale_pending_logins_failed(self) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE connector_login_sessions
                SET status = 'failed',
                    error_message = 'server restarted before login completed',
                    updated_at = ?
                WHERE status IN ('starting', 'qr_pending', 'scanned')
                """,
                (utc_now(),),
            )
            conn.execute(
                """
                UPDATE connector_state
                SET status = 'failed',
                    error_message = 'server restarted before login completed',
                    updated_at = ?
                WHERE status IN ('starting', 'qr_pending', 'scanned')
                """,
                (utc_now(),),
            )
        return cur.rowcount

    def append_audit(
        self,
        *,
        user: AuthenticatedUser,
        tool_name: str,
        args: dict[str, Any],
        ok: bool,
        error_message: str = "",
        result_summary: dict[str, Any] | None = None,
        affected_count: int | None = None,
        jxmis_user: dict[str, Any] | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (
                    user_id, token_id, tool_name, args_json, ok, error_message,
                    result_summary_json, affected_count, jxmis_user_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user.user_id,
                    user.token_id,
                    tool_name,
                    json.dumps(redact(args), ensure_ascii=False, sort_keys=True),
                    1 if ok else 0,
                    error_message[:1000],
                    json.dumps(result_summary or {}, ensure_ascii=False, sort_keys=True),
                    affected_count,
                    json.dumps(jxmis_user or {}, ensure_ascii=False, sort_keys=True),
                    utc_now(),
                ),
            )


class UserConnectorStore:
    def __init__(self, server_store: ServerStore, user_id: str) -> None:
        self.server_store = server_store
        self.user_id = user_id

    def get_state(self, connector_id: str) -> dict[str, Any] | None:
        with self.server_store._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM connector_state
                WHERE user_id = ? AND connector_id = ?
                """,
                (self.user_id, connector_id),
            ).fetchone()
        return dict(row) if row else None

    def upsert_state(
        self,
        connector_id: str,
        *,
        status: ConnectorStatus,
        credentials: dict[str, Any] | None = None,
        qr_url: str | None = None,
        final_url: str | None = None,
        error_message: str | None = None,
        connected_at: str | None = None,
        last_verified_at: str | None = None,
    ) -> dict[str, Any]:
        existing = self.get_state(connector_id) or {}
        now = utc_now()
        if credentials is not None:
            credentials_ciphertext = self.server_store.cipher.encrypt(
                json.dumps(credentials, ensure_ascii=False)
            )
        else:
            credentials_ciphertext = str(existing.get("credentials_ciphertext") or "")
        payload = {
            "user_id": self.user_id,
            "connector_id": connector_id,
            "status": status,
            "credentials_ciphertext": credentials_ciphertext,
            "qr_url": qr_url if qr_url is not None else str(existing.get("qr_url", "")),
            "final_url": final_url if final_url is not None else str(existing.get("final_url", "")),
            "error_message": (
                error_message if error_message is not None else str(existing.get("error_message", ""))
            ),
            "connected_at": connected_at if connected_at is not None else str(existing.get("connected_at", "")),
            "last_verified_at": (
                last_verified_at if last_verified_at is not None else str(existing.get("last_verified_at", ""))
            ),
            "updated_at": now,
        }
        with self.server_store._connect() as conn:
            conn.execute(
                """
                INSERT INTO connector_state (
                    user_id, connector_id, status, credentials_ciphertext, qr_url,
                    final_url, error_message, connected_at, last_verified_at, updated_at
                ) VALUES (
                    :user_id, :connector_id, :status, :credentials_ciphertext, :qr_url,
                    :final_url, :error_message, :connected_at, :last_verified_at, :updated_at
                )
                ON CONFLICT(user_id, connector_id) DO UPDATE SET
                    status = excluded.status,
                    credentials_ciphertext = excluded.credentials_ciphertext,
                    qr_url = excluded.qr_url,
                    final_url = excluded.final_url,
                    error_message = excluded.error_message,
                    connected_at = excluded.connected_at,
                    last_verified_at = excluded.last_verified_at,
                    updated_at = excluded.updated_at
                """,
                payload,
            )
        return self.get_state(connector_id) or payload

    def decode_credentials(self, row: dict[str, Any] | None) -> dict[str, Any]:
        if not row:
            return {}
        ciphertext = str(row.get("credentials_ciphertext") or "")
        if not ciphertext:
            return {}
        try:
            data = json.loads(self.server_store.cipher.decrypt(ciphertext))
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def clear_state(self, connector_id: str) -> None:
        self.upsert_state(
            connector_id,
            status="disconnected",
            credentials={},
            qr_url="",
            final_url="",
            error_message="",
            connected_at="",
            last_verified_at="",
        )

    def create_login_session(self, session_id: str, connector_id: str) -> dict[str, Any]:
        now = utc_now()
        with self.server_store._connect() as conn:
            conn.execute(
                """
                INSERT INTO connector_login_sessions (
                    session_id, user_id, connector_id, status, created_at, updated_at
                ) VALUES (?, ?, ?, 'starting', ?, ?)
                """,
                (session_id, self.user_id, connector_id, now, now),
            )
        return self.get_login_session(session_id) or {}

    def update_login_session(
        self,
        session_id: str,
        *,
        status: ConnectorStatus,
        qr_url: str | None = None,
        error_message: str | None = None,
    ) -> dict[str, Any]:
        existing = self.get_login_session(session_id) or {}
        with self.server_store._connect() as conn:
            conn.execute(
                """
                UPDATE connector_login_sessions
                SET status = ?, qr_url = ?, error_message = ?, updated_at = ?
                WHERE session_id = ? AND user_id = ?
                """,
                (
                    status,
                    qr_url if qr_url is not None else str(existing.get("qr_url", "")),
                    error_message if error_message is not None else str(existing.get("error_message", "")),
                    utc_now(),
                    session_id,
                    self.user_id,
                ),
            )
        return self.get_login_session(session_id) or {}

    def get_login_session(self, session_id: str) -> dict[str, Any] | None:
        with self.server_store._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM connector_login_sessions
                WHERE session_id = ? AND user_id = ?
                """,
                (session_id, self.user_id),
            ).fetchone()
        return dict(row) if row else None

    def get_latest_login_session(
        self,
        connector_id: str,
        *,
        statuses: set[ConnectorStatus] | None = None,
    ) -> dict[str, Any] | None:
        query = """
            SELECT * FROM connector_login_sessions
            WHERE user_id = ? AND connector_id = ?
        """
        params: list[Any] = [self.user_id, connector_id]
        if statuses:
            placeholders = ", ".join("?" for _ in statuses)
            query += f" AND status IN ({placeholders})"
            params.extend(sorted(statuses))
        query += " ORDER BY updated_at DESC LIMIT 1"
        with self.server_store._connect() as conn:
            row = conn.execute(query, params).fetchone()
        return dict(row) if row else None


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in ("authorization", "cookie", "token", "secret", "password")):
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = redact(item)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value[:100]]
    return value
