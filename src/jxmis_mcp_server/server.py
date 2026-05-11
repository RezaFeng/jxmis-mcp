"""Remote Streamable HTTP MCP application."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator

from mcp.server import NotificationOptions, Server
from mcp.server.fastmcp.server import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.models import InitializationOptions
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from .auth import BearerAuthMiddleware
from .crypto import CredentialCipher
from .handlers import JxmisToolHandlers
from .manager import ClientManager
from .registry import get_tools
from .settings import Settings
from .storage import ServerStore
from .toolsets import parse_toolsets

SERVER_NAME = "jxmis-project-management"
SERVER_VERSION = "0.1.0"


def create_mcp_server(handlers: JxmisToolHandlers) -> Server:
    server = Server(SERVER_NAME, version=SERVER_VERSION)
    selected_toolsets = parse_toolsets()

    @server.list_tools()
    async def list_tools():
        return get_tools(selected_toolsets)

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        return await handlers.handle(name, arguments or {})

    return server


def create_app(settings: Settings | None = None) -> Starlette:
    settings = settings or Settings.from_env()
    store = ServerStore(settings.database_path, CredentialCipher(settings.credential_key))
    manager = ClientManager(settings, store)
    handlers = JxmisToolHandlers(manager=manager, store=store)
    mcp_server = create_mcp_server(handlers)
    session_manager = StreamableHTTPSessionManager(app=mcp_server, json_response=False, stateless=False)
    streamable_http_app = StreamableHTTPASGIApp(session_manager)

    async def healthz(_request):
        return JSONResponse({"ok": True, "service": SERVER_NAME})

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        store.mark_stale_pending_logins_failed()
        async with session_manager.run():
            try:
                yield
            finally:
                await manager.close()

    app = Starlette(
        routes=[
            Route("/healthz", healthz),
            Route("/readyz", healthz),
            Route("/mcp", streamable_http_app),
            Route("/mcp/", streamable_http_app),
        ],
        middleware=[Middleware(BearerAuthMiddleware, store=store)],
        lifespan=lifespan,
    )
    app.state.store = store
    app.state.settings = settings
    return app


def initialization_options(server: Server) -> InitializationOptions:
    return InitializationOptions(
        server_name=SERVER_NAME,
        server_version=SERVER_VERSION,
        capabilities=server.get_capabilities(
            NotificationOptions(),
            experimental_capabilities={},
        ),
    )
