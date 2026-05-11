"""Tool dispatch for the JXMIS MCP server."""

from __future__ import annotations

from typing import Any

from .client import JxmisMcpClient
from .context import current_user
from .manager import ClientManager
from .storage import ServerStore


class JxmisToolHandlers:
    def __init__(
        self,
        client: JxmisMcpClient | None = None,
        *,
        manager: ClientManager | None = None,
        store: ServerStore | None = None,
    ) -> None:
        self.manager = manager
        self.client = client if client is not None else (None if manager is not None else JxmisMcpClient())
        self.store = store

    async def close(self) -> None:
        if self.manager is not None:
            await self.manager.close()
        elif self.client is not None:
            await self.client.close()

    def start_refresh_loop(self) -> None:
        if self.manager is None:
            assert self.client is not None
            self.client.start_refresh_loop()

    async def handle(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        method_names = {
            "jxmis_connect": "connect",
            "jxmis_get_login_status": "get_login_status",
            "jxmis_disconnect": "disconnect",
            "jxmis_get_current_user": "get_current_user",
            "jxmis_get_todo_list": "get_todo_list",
            "jxmis_get_project_statistics": "get_project_statistics",
            "jxmis_get_project_progress": "get_project_progress",
            "jxmis_get_period_report": "get_period_report",
            "jxmis_get_milestone_report": "get_milestone_report",
            "jxmis_search_projects": "search_projects",
            "jxmis_get_project_detail": "get_project_detail",
            "jxmis_list_project_plans": "list_project_plans",
            "jxmis_list_project_plan_details": "list_project_plan_details",
            "jxmis_list_project_contracts": "list_project_contracts",
            "jxmis_list_project_attachments": "list_project_attachments",
            "jxmis_list_project_risks": "list_project_risks",
            "jxmis_list_project_dynamics": "list_project_dynamics",
            "jxmis_get_project_overview": "get_project_overview",
            "jxmis_list_weekly_reports": "list_weekly_reports",
            "jxmis_get_weekly_report_detail": "get_weekly_report_detail",
            "jxmis_get_task_workload_summary": "get_task_workload_summary",
            "jxmis_get_personal_task_calendar": "get_personal_task_calendar",
            "jxmis_preview_pending_daily_approvals": "preview_pending_daily_approvals",
            "jxmis_batch_approve_daily_reports": "batch_approve_daily_reports",
            "jxmis_preview_pending_weekly_approvals": "preview_pending_weekly_approvals",
            "jxmis_batch_approve_weekly_reports": "batch_approve_weekly_reports",
        }
        method_name = method_names.get(name)
        if method_name is None:
            return {"ok": False, "error": f"Unknown JXMIS tool: {name}", "error_code": "UNKNOWN_TOOL"}
        user = current_user()
        client = self.manager.get_client(user) if self.manager is not None else self.client
        assert client is not None
        handler = getattr(client, method_name)
        jxmis_user: dict[str, Any] = {}
        try:
            result = await handler(args)
            if isinstance(result, dict) and result.get("ok") is False:
                ok = False
                error_message = str(result.get("error") or result.get("error_message") or "")
            else:
                ok = True
                error_message = ""
            if name.startswith("jxmis_batch_") or name in {"jxmis_get_login_status", "jxmis_connect"}:
                jxmis_user = await client._safe_current_user_summary()
            self._audit(user, name, args, result, ok=ok, error_message=error_message, jxmis_user=jxmis_user)
            return result
        except RuntimeError as exc:
            message = str(exc)
            error_code = "AUTH_REQUIRED" if "not connected" in message.lower() or "expired" in message.lower() else "RUNTIME_ERROR"
            result = {"ok": False, "error": message, "error_code": error_code}
            self._audit(user, name, args, result, ok=False, error_message=message, jxmis_user=jxmis_user)
            return result
        except Exception as exc:
            message = repr(exc)
            result = {"ok": False, "error": message, "error_code": "TOOL_ERROR"}
            self._audit(user, name, args, result, ok=False, error_message=message, jxmis_user=jxmis_user)
            return result

    def _audit(
        self,
        user,
        name: str,
        args: dict[str, Any],
        result: dict[str, Any],
        *,
        ok: bool,
        error_message: str,
        jxmis_user: dict[str, Any],
    ) -> None:
        if self.store is None:
            return
        data = result.get("data") if isinstance(result, dict) else None
        summary = _result_summary(data)
        self.store.append_audit(
            user=user,
            tool_name=name,
            args=args,
            ok=ok,
            error_message=error_message,
            result_summary=summary,
            affected_count=_affected_count(data),
            jxmis_user=jxmis_user,
        )


def _result_summary(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    keys = (
        "status",
        "connected",
        "returned",
        "matched",
        "source_total",
        "submitted",
        "success_count",
        "failed_count",
        "dry_run",
    )
    return {key: data[key] for key in keys if key in data}


def _affected_count(data: Any) -> int | None:
    if not isinstance(data, dict):
        return None
    for key in ("success_count", "submitted", "approved_count", "affected_count", "returned"):
        value = data.get(key)
        if isinstance(value, int):
            return value
    items = data.get("items")
    if isinstance(items, list):
        return len(items)
    return None
