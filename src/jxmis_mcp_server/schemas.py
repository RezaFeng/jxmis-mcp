"""JSON schemas and small argument helpers for JXMIS MCP tools."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

MAX_PAGE_SIZE = 100


def obj(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


PAGE_PROPS: dict[str, Any] = {
    "page": {"type": "integer", "minimum": 1, "default": 1},
    "page_size": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE_SIZE, "default": 20},
    "include_raw": {"type": "boolean", "default": False},
}


def page_args(args: dict[str, Any]) -> tuple[int, int]:
    page = max(1, int(args.get("page") or 1))
    page_size = max(1, min(int(args.get("page_size") or 20), MAX_PAGE_SIZE))
    return page, page_size


def include_raw(args: dict[str, Any]) -> bool:
    return bool(args.get("include_raw", False))


def current_year_month() -> tuple[int, int]:
    today = date.today()
    return today.year, today.month


def month_range() -> tuple[str, str]:
    today = date.today()
    return f"{today.year}-{today.month:02d}-01", today.isoformat()


def current_year(args: dict[str, Any]) -> int:
    return int(args.get("year") or date.today().year)


def current_month(args: dict[str, Any]) -> tuple[int, int]:
    year, month = current_year_month()
    return int(args.get("year") or year), int(args.get("month") or month)


def date_range(args: dict[str, Any]) -> tuple[str, str]:
    default_start, default_end = month_range()
    start = str(args.get("start_date") or default_start)
    end = str(args.get("end_date") or default_end)
    return start, end


def first_present(args: dict[str, Any], *names: str) -> str:
    for name in names:
        value = str(args.get(name) or "").strip()
        if value:
            return value
    return ""


def now_millis() -> str:
    return str(int(datetime.now().timestamp() * 1000))
