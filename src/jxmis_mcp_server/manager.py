"""Per-user JXMIS client lifecycle."""

from __future__ import annotations

from .client import JxmisMcpClient
from .context import AuthenticatedUser
from .settings import Settings
from .storage import ServerStore


class ClientManager:
    def __init__(self, settings: Settings, store: ServerStore) -> None:
        self.settings = settings
        self.store = store
        self._clients: dict[str, JxmisMcpClient] = {}

    def get_client(self, user: AuthenticatedUser) -> JxmisMcpClient:
        client = self._clients.get(user.user_id)
        if client is None:
            client = JxmisMcpClient(
                store=self.store.user_store(user.user_id),
                jxmis_config=self.settings.jxmis,
                refresh_interval_seconds=self.settings.refresh_interval_seconds,
            )
            client.start_refresh_loop()
            self._clients[user.user_id] = client
        return client

    async def close(self) -> None:
        clients = list(self._clients.values())
        self._clients.clear()
        for client in clients:
            await client.close()
