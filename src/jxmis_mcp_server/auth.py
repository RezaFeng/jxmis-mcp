"""HTTP Bearer authentication for the MCP endpoint."""

from __future__ import annotations

from http import HTTPStatus

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .context import reset_current_user, set_current_user
from .storage import ServerStore


class BearerAuthMiddleware:
    def __init__(self, app: ASGIApp, store: ServerStore) -> None:
        self.app = app
        self.store = store

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path") or "")
        if path in {"/healthz", "/readyz"}:
            await self.app(scope, receive, send)
            return

        token_value = _bearer_token(scope)
        user = self.store.authenticate_token(token_value) if token_value else None
        if user is None:
            response = JSONResponse(
                {"error": "missing or invalid bearer token"},
                status_code=HTTPStatus.UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        ctx_token = set_current_user(user)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_current_user(ctx_token)


def _bearer_token(scope: Scope) -> str:
    headers = {
        key.decode("latin1").lower(): value.decode("latin1")
        for key, value in scope.get("headers", [])
    }
    authorization = headers.get("authorization", "")
    prefix = "bearer "
    if authorization.lower().startswith(prefix):
        return authorization[len(prefix) :].strip()
    return ""
