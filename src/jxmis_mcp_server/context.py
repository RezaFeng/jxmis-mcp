"""Per-request authentication context."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    user_id: str
    token_id: str
    token_name: str


_current_user: ContextVar[AuthenticatedUser | None] = ContextVar("jxmis_current_user", default=None)


def set_current_user(user: AuthenticatedUser | None):
    return _current_user.set(user)


def reset_current_user(token) -> None:
    _current_user.reset(token)


def current_user() -> AuthenticatedUser:
    user = _current_user.get()
    if user is None:
        raise RuntimeError("MCP request is not authenticated")
    return user
