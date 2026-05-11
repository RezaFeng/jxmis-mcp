"""Command line interface."""

from __future__ import annotations

import json

import typer
import uvicorn

from .crypto import CredentialCipher
from .server import create_app
from .settings import Settings
from .storage import ServerStore

app = typer.Typer(help="JXMIS remote MCP server")
admin_app = typer.Typer(help="Admin token and key commands")
app.add_typer(admin_app, name="admin")


def _store_from_env() -> ServerStore:
    settings = Settings.from_env()
    return ServerStore(settings.database_path, CredentialCipher(settings.credential_key))


@app.command()
def serve() -> None:
    """Run the Streamable HTTP MCP server."""
    settings = Settings.from_env()
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )


@admin_app.command("generate-key")
def generate_key() -> None:
    """Generate a JXMIS_CREDENTIAL_KEY value."""
    typer.echo(CredentialCipher.generate_key())


@admin_app.command("create-token")
def create_token(name: str = typer.Option(..., "--name", "-n", help="Human-readable token name")) -> None:
    """Create an MCP Bearer token and print it once."""
    settings = Settings.from_env()
    store = ServerStore(settings.database_path, CredentialCipher(settings.credential_key))
    user, token = store.create_token(name)
    typer.echo(
        json.dumps(
            {
                "token_id": user.token_id,
                "name": user.token_name,
                "token": token,
                "mcp_config": {
                    "mcpServers": {
                        "jxmis": {
                            "url": settings.public_base_url.rstrip("/") + "/mcp/",
                            "headers": {"Authorization": f"Bearer {token}"},
                        }
                    }
                },
            },
            ensure_ascii=False,
            indent=2,
        )
    )


@admin_app.command("list-tokens")
def list_tokens() -> None:
    """List tokens without exposing token secrets."""
    store = _store_from_env()
    typer.echo(json.dumps(store.list_tokens(), ensure_ascii=False, indent=2))


@admin_app.command("revoke-token")
def revoke_token(token_id: str) -> None:
    """Revoke a token by token_id."""
    store = _store_from_env()
    if store.revoke_token(token_id):
        typer.echo(f"revoked {token_id}")
    else:
        raise typer.Exit(1)
