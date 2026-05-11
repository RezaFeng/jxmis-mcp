"""Environment-backed runtime settings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .jxmis import JxmisConfig


def _env_int(name: str, default: int, *, minimum: int | None = None) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, value) if minimum is not None else value


def _env_str(name: str, default: str = "") -> str:
    return os.environ.get(name, "").strip() or default


@dataclass(frozen=True, slots=True)
class Settings:
    host: str
    port: int
    database_path: Path
    credential_key: str
    refresh_interval_seconds: int
    public_base_url: str
    jxmis: JxmisConfig

    @classmethod
    def from_env(cls) -> "Settings":
        defaults = JxmisConfig()
        data_dir = Path(_env_str("JXMIS_MCP_DATA_DIR", "/var/lib/jxmis-mcp")).expanduser()
        db_path = Path(_env_str("JXMIS_MCP_DB_PATH", str(data_dir / "server.sqlite3"))).expanduser()
        credential_key = _env_str("JXMIS_CREDENTIAL_KEY")
        if not credential_key:
            raise RuntimeError(
                "JXMIS_CREDENTIAL_KEY is required. Generate one with: "
                "jxmis-mcp admin generate-key"
            )
        return cls(
            host=_env_str("JXMIS_MCP_HOST", "127.0.0.1"),
            port=_env_int("JXMIS_MCP_PORT", 8787, minimum=1),
            database_path=db_path,
            credential_key=credential_key,
            refresh_interval_seconds=_env_int("JXMIS_REFRESH_INTERVAL_SECONDS", 1800, minimum=30),
            public_base_url=_env_str("JXMIS_MCP_PUBLIC_BASE_URL", "https://jxmis-mcp.rezafeng.top:8443"),
            jxmis=JxmisConfig(
                entry_url=_env_str("JXMIS_ENTRY_URL", defaults.entry_url),
                api_base_url=_env_str("JXMIS_API_BASE_URL", defaults.api_base_url),
                baseuaa_auth_base=_env_str("JXMIS_BASEUAA_AUTH_BASE", defaults.baseuaa_auth_base),
                baseuaa_dingtalk_auth_code_url=_env_str(
                    "JXMIS_BASEUAA_DINGTALK_AUTH_CODE_URL",
                    defaults.baseuaa_dingtalk_auth_code_url,
                ),
                ding_client_id=_env_str("JXMIS_DING_CLIENT_ID", defaults.ding_client_id),
                client_id=_env_str("JXMIS_CLIENT_ID", defaults.client_id),
                redirect_uri=_env_str("JXMIS_REDIRECT_URI", defaults.redirect_uri),
                keepalive_primary_url=_env_str(
                    "JXMIS_KEEPALIVE_PRIMARY_URL",
                    defaults.keepalive_primary_url,
                ),
                keepalive_fallback_url=_env_str(
                    "JXMIS_KEEPALIVE_FALLBACK_URL",
                    defaults.keepalive_fallback_url,
                ),
                login_wait_timeout_seconds=_env_int("JXMIS_LOGIN_TIMEOUT_SECONDS", 180, minimum=30),
                request_retries=_env_int("JXMIS_REQUEST_RETRIES", 3, minimum=1),
            ),
        )
