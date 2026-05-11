"""Tool registry for the JXMIS MCP server."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcp import types

from .schemas import PAGE_PROPS, obj
from .toolsets import enabled_tool_names


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    read_only: bool = True

    def to_mcp_tool(self) -> types.Tool:
        return types.Tool(
            name=self.name,
            description=self.description,
            inputSchema=self.input_schema,
            annotations=types.ToolAnnotations(readOnlyHint=self.read_only),
        )


def _year_schema() -> dict[str, Any]:
    return obj({
        "year": {"type": "integer", "description": "年份。未提供时默认当前年。"},
        "include_raw": {"type": "boolean", "default": False},
    })


def _year_month_schema() -> dict[str, Any]:
    return obj({
        "year": {"type": "integer", "description": "年份。未提供时默认当前年。"},
        "month": {"type": "integer", "minimum": 1, "maximum": 12, "description": "月份。未提供时默认当前月。"},
        "include_raw": {"type": "boolean", "default": False},
    })


ALL_TOOLS: dict[str, ToolSpec] = {
    "jxmis_connect": ToolSpec(
        "jxmis_connect",
        "[JXMIS Auth] 发起项目管理平台钉钉扫码登录。已有有效登录态且 force=false 时直接返回 active。",
        obj({
            "force": {"type": "boolean", "default": False},
            "include_qr_image": {"type": "boolean", "default": True},
            "include_qr_terminal": {"type": "boolean", "default": True},
            "timeout_seconds": {
                "type": "integer",
                "minimum": 30,
                "maximum": 600,
                "description": "本次扫码登录等待超时秒数。未提供时使用 JXMIS_LOGIN_TIMEOUT_SECONDS 或连接器配置。",
            },
        }),
        read_only=False,
    ),
    "jxmis_get_login_status": ToolSpec(
        "jxmis_get_login_status",
        "[JXMIS Auth] 查询扫码登录会话状态；不传 login_session_id 时返回当前连接器状态。",
        obj({
            "login_session_id": {"type": "string"},
            "include_qr_image": {"type": "boolean", "default": True},
            "include_qr_terminal": {"type": "boolean", "default": True},
        }),
    ),
    "jxmis_disconnect": ToolSpec(
        "jxmis_disconnect",
        "[JXMIS Auth] 清除本地项目管理平台登录态。必须 confirm=true 才执行。",
        obj({"confirm": {"type": "boolean", "default": False}}),
        read_only=False,
    ),
    "jxmis_get_current_user": ToolSpec(
        "jxmis_get_current_user",
        "[JXMIS Base] 获取当前连接的项目管理平台用户信息。",
        obj({"include_raw": {"type": "boolean", "default": False}}),
    ),
    "jxmis_get_todo_list": ToolSpec(
        "jxmis_get_todo_list",
        "[JXMIS Base] 读取当前用户项目管理平台待办列表。",
        obj({
            "limit": {"type": "integer", "minimum": 1, "maximum": 20, "default": 10},
            "keyword": {"type": "string", "description": "待办标题、发起人、部门、摘要关键字。"},
            "include_raw": {"type": "boolean", "default": False},
        }),
    ),
    "jxmis_get_project_statistics": ToolSpec(
        "jxmis_get_project_statistics",
        "[JXMIS Dashboard] 获取年度项目统计。",
        _year_schema(),
    ),
    "jxmis_get_project_progress": ToolSpec(
        "jxmis_get_project_progress",
        "[JXMIS Dashboard] 获取年度项目进度统计。",
        _year_schema(),
    ),
    "jxmis_get_period_report": ToolSpec(
        "jxmis_get_period_report",
        "[JXMIS Dashboard] 获取日/周/月报统计。",
        _year_month_schema(),
    ),
    "jxmis_get_milestone_report": ToolSpec(
        "jxmis_get_milestone_report",
        "[JXMIS Dashboard] 获取里程碑报表。",
        _year_month_schema(),
    ),
    "jxmis_search_projects": ToolSpec(
        "jxmis_search_projects",
        "[JXMIS Project] 搜索项目列表。keyword 会映射到 JXMIS likeAll。",
        obj({
            "keyword": {"type": "string", "description": "项目名、编号、负责人等模糊关键字。"},
            **PAGE_PROPS,
        }),
    ),
    "jxmis_get_project_detail": ToolSpec(
        "jxmis_get_project_detail",
        "[JXMIS Project] 获取项目详情。支持 project_id 或 keyword；keyword 多候选时返回候选列表。",
        obj({
            "project_id": {"type": "string"},
            "keyword": {"type": "string"},
            "include_raw": {"type": "boolean", "default": False},
        }),
    ),
    "jxmis_list_project_plans": ToolSpec(
        "jxmis_list_project_plans",
        "[JXMIS Project] 查询项目计划列表。",
        obj({"project_id": {"type": "string"}, "include_raw": {"type": "boolean", "default": False}}, ["project_id"]),
    ),
    "jxmis_list_project_plan_details": ToolSpec(
        "jxmis_list_project_plan_details",
        "[JXMIS Project] 查询项目计划明细。project_id 或 plan_id 至少提供一个。",
        obj({
            "project_id": {"type": "string"},
            "plan_id": {"type": "string"},
            **PAGE_PROPS,
        }),
    ),
    "jxmis_list_project_contracts": ToolSpec(
        "jxmis_list_project_contracts",
        "[JXMIS Project] 查询项目合同。",
        obj({
            "project_id": {"type": "string"},
            "contract_num": {"type": "string"},
            **PAGE_PROPS,
        }),
    ),
    "jxmis_list_project_attachments": ToolSpec(
        "jxmis_list_project_attachments",
        "[JXMIS Project] 查询项目相关附件元信息。",
        obj({"project_id": {"type": "string"}, **PAGE_PROPS}, ["project_id"]),
    ),
    "jxmis_list_project_risks": ToolSpec(
        "jxmis_list_project_risks",
        "[JXMIS Project] 查询项目风险列表。",
        obj({"project_id": {"type": "string"}, **PAGE_PROPS}, ["project_id"]),
    ),
    "jxmis_list_project_dynamics": ToolSpec(
        "jxmis_list_project_dynamics",
        "[JXMIS Project] 查询项目动态。",
        obj({"project_id": {"type": "string"}, **PAGE_PROPS}, ["project_id"]),
    ),
    "jxmis_get_project_overview": ToolSpec(
        "jxmis_get_project_overview",
        "[JXMIS Project] 获取项目概览组合数据，默认包含 detail/plans/risks/dynamics。",
        obj({
            "project_id": {"type": "string"},
            "keyword": {"type": "string"},
            "include": {
                "type": "array",
                "items": {"type": "string", "enum": ["detail", "plans", "risks", "dynamics", "contracts", "attachments", "weekly_reports"]},
                "default": ["detail", "plans", "risks", "dynamics"],
            },
            "limit_per_section": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            "include_raw": {"type": "boolean", "default": False},
        }),
    ),
    "jxmis_list_weekly_reports": ToolSpec(
        "jxmis_list_weekly_reports",
        "[JXMIS Weekly Report] 查询项目周报列表，可按项目和 keyword 模糊筛选。",
        obj({
            "project_id": {"type": "string"},
            "keyword": {"type": "string"},
            **PAGE_PROPS,
        }),
    ),
    "jxmis_get_weekly_report_detail": ToolSpec(
        "jxmis_get_weekly_report_detail",
        "[JXMIS Weekly Report] 获取周报详情。支持 weekly_report_id、project_id、keyword 模糊解析。",
        obj({
            "weekly_report_id": {"type": "string"},
            "project_id": {"type": "string"},
            "keyword": {"type": "string"},
            "include_raw": {"type": "boolean", "default": False},
        }),
    ),
    "jxmis_get_task_workload_summary": ToolSpec(
        "jxmis_get_task_workload_summary",
        "[JXMIS Task] 查询任务工时统计。未提供日期时默认本月 1 日到今天。",
        obj({
            "start_date": {"type": "string", "description": "YYYY-MM-DD"},
            "end_date": {"type": "string", "description": "YYYY-MM-DD"},
            "include_raw": {"type": "boolean", "default": False},
        }),
    ),
    "jxmis_get_personal_task_calendar": ToolSpec(
        "jxmis_get_personal_task_calendar",
        "[JXMIS Task] 查询个人任务日历。user_id 未提供时使用当前用户 ID。",
        obj({
            "year": {"type": "integer"},
            "month": {"type": "integer", "minimum": 1, "maximum": 12},
            "user_id": {"type": "string"},
            "include_raw": {"type": "boolean", "default": False},
        }),
    ),
    "jxmis_preview_pending_daily_approvals": ToolSpec(
        "jxmis_preview_pending_daily_approvals",
        "[JXMIS Approval] 预览当前用户待审批日报，不提交审批。",
        obj({
            "keyword": {"type": "string", "description": "按任务、人员、项目名称本地筛选。"},
            "page_size": {"type": "integer", "minimum": 1, "maximum": 100, "default": 50},
            "max_items": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
            "include_raw": {"type": "boolean", "default": False},
        }),
    ),
    "jxmis_batch_approve_daily_reports": ToolSpec(
        "jxmis_batch_approve_daily_reports",
        "[JXMIS Approval] 批量同意当前用户待审批日报。默认只预览；必须 dry_run=false 且 confirm=true 才提交。",
        obj({
            "dry_run": {"type": "boolean", "default": True},
            "confirm": {"type": "boolean", "default": False},
            "keyword": {"type": "string", "description": "按任务、人员、项目名称本地筛选。"},
            "page_size": {"type": "integer", "minimum": 1, "maximum": 100, "default": 50},
            "max_items": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
            "state": {"type": "string", "enum": ["1"], "default": "1"},
            "approval_timely": {"type": "string", "default": "1"},
            "achievement_complete": {"type": "string", "default": "1"},
            "achievement_quality": {"type": "string", "default": "1"},
            "approval_comment": {"type": "string", "default": ""},
            "base_delay_ms": {"type": "integer", "minimum": 0, "default": 1000},
            "random_delay_max_ms": {"type": "integer", "minimum": 0, "default": 3000},
            "include_raw": {"type": "boolean", "default": False},
        }),
        read_only=False,
    ),
    "jxmis_preview_pending_weekly_approvals": ToolSpec(
        "jxmis_preview_pending_weekly_approvals",
        "[JXMIS Approval] 预览当前用户作为生产负责人的待审核周报，不提交批复。",
        obj({
            "year": {"type": "integer", "description": "年份。未提供时默认当前年。"},
            "month": {"type": "integer", "minimum": 1, "maximum": 12, "description": "月份。未提供时默认当前月。"},
            "month_end": {"type": "integer", "minimum": 1, "maximum": 12, "description": "结束月份。未提供时等于 month。"},
            "keyword": {"type": "string", "description": "按项目、周报名称、编号本地筛选。"},
            "page_size": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
            "max_items": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
            "include_raw": {"type": "boolean", "default": False},
        }),
    ),
    "jxmis_batch_approve_weekly_reports": ToolSpec(
        "jxmis_batch_approve_weekly_reports",
        "[JXMIS Approval] 批量批复当前用户作为生产负责人的待审核周报。默认只预览；必须 dry_run=false 且 confirm=true 才提交。",
        obj({
            "dry_run": {"type": "boolean", "default": True},
            "confirm": {"type": "boolean", "default": False},
            "year": {"type": "integer", "description": "年份。未提供时默认当前年。"},
            "month": {"type": "integer", "minimum": 1, "maximum": 12, "description": "月份。未提供时默认当前月。"},
            "month_end": {"type": "integer", "minimum": 1, "maximum": 12, "description": "结束月份。未提供时等于 month。"},
            "reply": {"type": "string", "default": "已核实"},
            "keyword": {"type": "string", "description": "按项目、周报名称、编号本地筛选。"},
            "page_size": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
            "max_items": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
            "base_delay_ms": {"type": "integer", "minimum": 0, "default": 1000},
            "random_delay_max_ms": {"type": "integer", "minimum": 0, "default": 3000},
            "include_raw": {"type": "boolean", "default": False},
        }),
        read_only=False,
    ),
}


def get_tools(toolsets: tuple[str, ...]) -> list[types.Tool]:
    names = enabled_tool_names(toolsets)
    return [spec.to_mcp_tool() for name, spec in ALL_TOOLS.items() if name in names]
