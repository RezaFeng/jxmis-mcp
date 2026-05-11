from __future__ import annotations

import sqlite3

from jxmis_mcp_server.crypto import CredentialCipher
from jxmis_mcp_server.storage import ServerStore


def test_tokens_authenticate_and_revoke(tmp_path):
    store = ServerStore(tmp_path / "server.sqlite3", CredentialCipher(CredentialCipher.generate_key()))
    user, token = store.create_token("alice")

    assert store.authenticate_token(token).token_id == user.token_id
    assert store.revoke_token(user.token_id) is True
    assert store.authenticate_token(token) is None


def test_credentials_are_encrypted_at_rest(tmp_path):
    db_path = tmp_path / "server.sqlite3"
    store = ServerStore(db_path, CredentialCipher(CredentialCipher.generate_key()))
    user, _ = store.create_token("alice")
    user_store = store.user_store(user.user_id)

    user_store.upsert_state("jxmis", status="active", credentials={"authorization": "secret-token"})
    row = user_store.get_state("jxmis")

    assert user_store.decode_credentials(row) == {"authorization": "secret-token"}
    with sqlite3.connect(db_path) as conn:
        ciphertext = conn.execute("SELECT credentials_ciphertext FROM connector_state").fetchone()[0]
    assert "secret-token" not in ciphertext


def test_pending_logins_are_failed_on_startup(tmp_path):
    store = ServerStore(tmp_path / "server.sqlite3", CredentialCipher(CredentialCipher.generate_key()))
    user, _ = store.create_token("alice")
    user_store = store.user_store(user.user_id)
    user_store.create_login_session("login-1", "jxmis")
    user_store.update_login_session("login-1", status="qr_pending", qr_url="https://scan")

    assert store.mark_stale_pending_logins_failed() == 1
    assert user_store.get_login_session("login-1")["status"] == "failed"
