"""Toolset definitions for the JXMIS MCP server."""

from __future__ import annotations

import os

DEFAULT_TOOLSETS: tuple[str, ...] = (
    "auth",
    "base",
    "dashboard",
    "project",
    "weekly-report",
    "task",
    "approval",
)

TOOLSET_TOOLS: dict[str, tuple[str, ...]] = {
    "auth": (
        "jxmis_connect",
        "jxmis_get_login_status",
        "jxmis_disconnect",
    ),
    "base": (
        "jxmis_get_current_user",
        "jxmis_get_todo_list",
    ),
    "dashboard": (
        "jxmis_get_project_statistics",
        "jxmis_get_project_progress",
        "jxmis_get_period_report",
        "jxmis_get_milestone_report",
    ),
    "project": (
        "jxmis_search_projects",
        "jxmis_get_project_detail",
        "jxmis_list_project_plans",
        "jxmis_list_project_plan_details",
        "jxmis_list_project_contracts",
        "jxmis_list_project_attachments",
        "jxmis_list_project_risks",
        "jxmis_list_project_dynamics",
        "jxmis_get_project_overview",
    ),
    "weekly-report": (
        "jxmis_list_weekly_reports",
        "jxmis_get_weekly_report_detail",
    ),
    "task": (
        "jxmis_get_task_workload_summary",
        "jxmis_get_personal_task_calendar",
    ),
    "approval": (
        "jxmis_preview_pending_daily_approvals",
        "jxmis_batch_approve_daily_reports",
        "jxmis_preview_pending_weekly_approvals",
        "jxmis_batch_approve_weekly_reports",
    ),
}


def parse_toolsets(value: str | None = None) -> tuple[str, ...]:
    raw = value if value is not None else os.environ.get("JXMIS_TOOLSETS", "")
    if not raw.strip():
        return DEFAULT_TOOLSETS

    selected: list[str] = []
    for item in raw.split(","):
        name = item.strip()
        if not name:
            continue
        if name not in TOOLSET_TOOLS:
            raise ValueError(f"Unknown JXMIS toolset: {name}")
        selected.append(name)
    return tuple(dict.fromkeys(selected))


def enabled_tool_names(toolsets: tuple[str, ...]) -> set[str]:
    names: set[str] = set()
    for toolset in toolsets:
        names.update(TOOLSET_TOOLS[toolset])
    return names
