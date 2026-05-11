"""Authenticated JXMIS API client used by the MCP server."""

from __future__ import annotations

import asyncio
import base64
import io
import os
import random
import uuid
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from . import schemas
from .crypto import CredentialCipher
from .jxmis import (
    JxmisAuthRequiredError,
    JxmisConfig,
    JxmisConnector,
    JxmisRequestResult,
)
from .storage import ServerStore, UserConnectorStore, utc_now

CONNECTOR_ID = "jxmis"
DEFAULT_PAGE_SIZE = 20
DEFAULT_APPROVAL_LIMIT = 50
MAX_APPROVAL_LIMIT = 500
DEFAULT_REFRESH_INTERVAL_SECONDS = 1800
PENDING_LOGIN_STATES = {"starting", "qr_pending", "scanned"}


def _env_int(name: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, "").strip() or default


def _jxmis_config_from(raw: Any) -> JxmisConfig:
    if isinstance(raw, JxmisConfig):
        cfg = raw
    elif hasattr(raw, "model_dump"):
        cfg = JxmisConfig(**raw.model_dump())
    elif isinstance(raw, dict):
        cfg = JxmisConfig(**raw)
    else:
        cfg = JxmisConfig()

    return JxmisConfig(
        **{
            **asdict(cfg),
            "entry_url": _env_str("JXMIS_ENTRY_URL", cfg.entry_url),
            "api_base_url": _env_str("JXMIS_API_BASE_URL", cfg.api_base_url),
            "baseuaa_auth_base": _env_str("JXMIS_BASEUAA_AUTH_BASE", cfg.baseuaa_auth_base),
            "baseuaa_dingtalk_auth_code_url": _env_str(
                "JXMIS_BASEUAA_DINGTALK_AUTH_CODE_URL",
                cfg.baseuaa_dingtalk_auth_code_url,
            ),
            "ding_client_id": _env_str("JXMIS_DING_CLIENT_ID", cfg.ding_client_id),
            "client_id": _env_str("JXMIS_CLIENT_ID", cfg.client_id),
            "redirect_uri": _env_str("JXMIS_REDIRECT_URI", cfg.redirect_uri),
            "keepalive_primary_url": _env_str(
                "JXMIS_KEEPALIVE_PRIMARY_URL",
                cfg.keepalive_primary_url,
            ),
            "keepalive_fallback_url": _env_str(
                "JXMIS_KEEPALIVE_FALLBACK_URL",
                cfg.keepalive_fallback_url,
            ),
            "login_wait_timeout_seconds": _env_int(
                "JXMIS_LOGIN_TIMEOUT_SECONDS",
                cfg.login_wait_timeout_seconds,
                minimum=30,
                maximum=600,
            ),
            "request_retries": _env_int(
                "JXMIS_REQUEST_RETRIES",
                cfg.request_retries,
                minimum=1,
                maximum=10,
            ),
        }
    )


class JxmisMcpClient:
    """Authenticated JXMIS MCP business client for one remote MCP user."""

    def __init__(
        self,
        *,
        config_path: Path | None = None,
        workspace: Path | None = None,
        connector: JxmisConnector | None = None,
        store: UserConnectorStore | None = None,
        jxmis_config: JxmisConfig | dict[str, Any] | None = None,
        refresh_interval_seconds: int | None = None,
    ) -> None:
        # config_path is kept for compatibility with earlier tests; standalone
        # deployments are configured through environment variables.
        _ = config_path
        env_workspace = os.environ.get("JXMIS_MCP_DATA_DIR", "").strip()
        self.workspace = workspace or (Path(env_workspace).expanduser() if env_workspace else Path("."))
        self.jxmis_config = _jxmis_config_from(jxmis_config)
        self.connector = connector or JxmisConnector(self.jxmis_config)
        env_store = os.environ.get("JXMIS_STORE_PATH", "").strip()
        if store is None:
            key = os.environ.get("JXMIS_CREDENTIAL_KEY", "").strip()
            if not key:
                raise RuntimeError("JXMIS_CREDENTIAL_KEY is required when store is not injected")
            server_store = ServerStore(
                Path(env_store).expanduser() if env_store else self.workspace / "server.sqlite3",
                CredentialCipher(key),
            )
            store = server_store.user_store(os.environ.get("JXMIS_MCP_DEFAULT_USER", "default"))
        self.store = store
        self.refresh_interval_seconds = refresh_interval_seconds or _env_int(
            "JXMIS_REFRESH_INTERVAL_SECONDS",
            DEFAULT_REFRESH_INTERVAL_SECONDS,
            minimum=30,
        )
        self.login_tasks: dict[str, asyncio.Task[Any]] = {}
        self.refresh_task: asyncio.Task[Any] | None = None
        self._uses_injected_connector = connector is not None

    async def close(self) -> None:
        if self.refresh_task:
            self.refresh_task.cancel()
            try:
                await self.refresh_task
            except asyncio.CancelledError:
                pass
            self.refresh_task = None
        await self._cancel_login_tasks()
        await self.connector.client.aclose()

    def start_refresh_loop(self) -> None:
        if self.refresh_task is None:
            self.refresh_task = asyncio.create_task(
                self._refresh_loop(),
                name="jxmis-mcp-refresh",
            )

    async def connect(self, args: dict[str, Any]) -> dict[str, Any]:
        force = bool(args.get("force", False))
        include_qr_image = bool(args.get("include_qr_image", True))
        include_qr_terminal = bool(args.get("include_qr_terminal", False))
        timeout_seconds = self._login_timeout(args)

        row = self.store.get_state(CONNECTOR_ID)
        if row and row.get("status") == "active" and not force:
            return await self._connector_state_response(row=row)

        pending = self.store.get_latest_login_session(
            CONNECTOR_ID,
            statuses=PENDING_LOGIN_STATES,
        )
        if pending and not force:
            return self._login_session_response(
                pending,
                include_qr_image=include_qr_image,
                include_qr_terminal=include_qr_terminal,
            )

        if force:
            self._supersede_pending_login()
            await self._cancel_login_tasks()
            self.store.clear_state(CONNECTOR_ID)

        session_id = uuid.uuid4().hex
        self.store.create_login_session(session_id, CONNECTOR_ID)
        self.store.upsert_state(CONNECTOR_ID, status="starting", error_message="")
        task = asyncio.create_task(
            self._run_login(session_id, timeout_seconds),
            name=f"jxmis-mcp-login-{session_id}",
        )
        self.login_tasks[session_id] = task
        task.add_done_callback(lambda _task, sid=session_id: self.login_tasks.pop(sid, None))

        session = await self._wait_for_login_qr(session_id, timeout=min(30, timeout_seconds))
        return self._login_session_response(
            session,
            include_qr_image=include_qr_image,
            include_qr_terminal=include_qr_terminal,
        )

    async def get_login_status(self, args: dict[str, Any]) -> dict[str, Any]:
        include_qr_image = bool(args.get("include_qr_image", True))
        include_qr_terminal = bool(args.get("include_qr_terminal", False))
        session_id = str(args.get("login_session_id") or "").strip()
        if session_id:
            session = self.store.get_login_session(session_id)
            if not session or session.get("connector_id") != CONNECTOR_ID:
                return self._failure("login_session_id not found", error_code="NOT_FOUND")
            return self._login_session_response(
                session,
                include_qr_image=include_qr_image,
                include_qr_terminal=include_qr_terminal,
            )
        return await self._connector_state_response(row=self.store.get_state(CONNECTOR_ID))

    async def disconnect(self, args: dict[str, Any]) -> dict[str, Any]:
        if not bool(args.get("confirm", False)):
            return {
                "ok": True,
                "data": {
                    "status": str((self.store.get_state(CONNECTOR_ID) or {}).get("status") or "disconnected"),
                    "requires_confirmation": True,
                    "submit_hint": {"confirm": True},
                },
            }
        await self._cancel_login_tasks()
        row = self.store.get_state(CONNECTOR_ID)
        credentials = self.store.decode_credentials(row)
        await self.connector.disconnect(credentials)
        self._supersede_pending_login(error_message="disconnected")
        self.store.clear_state(CONNECTOR_ID)
        return {"ok": True, "data": {"status": "disconnected", "connected": False}}

    async def _cancel_login_tasks(self) -> None:
        tasks = list(self.login_tasks.values())
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.login_tasks.clear()

    def _login_timeout(self, args: dict[str, Any]) -> int:
        raw = args.get("timeout_seconds")
        if raw in ("", None):
            return self.jxmis_config.login_wait_timeout_seconds
        return max(30, min(int(raw), 600))

    def _new_login_connector(self, timeout_seconds: int) -> tuple[JxmisConnector, bool]:
        if self._uses_injected_connector:
            return self.connector, False
        cfg = replace(self.jxmis_config, login_wait_timeout_seconds=timeout_seconds)
        return JxmisConnector(cfg), True

    async def _run_login(self, session_id: str, timeout_seconds: int) -> None:
        connector, should_close = self._new_login_connector(timeout_seconds)

        async def on_qr(qr_url: str) -> None:
            self.store.update_login_session(session_id, status="qr_pending", qr_url=qr_url)
            self.store.upsert_state(CONNECTOR_ID, status="qr_pending", qr_url=qr_url)

        async def on_status(status: str, payload: dict[str, Any]) -> None:
            qr_url = str(payload.get("qr_url") or "")
            self.store.update_login_session(session_id, status=status, qr_url=qr_url or None)
            self.store.upsert_state(
                CONNECTOR_ID,
                status=status,
                qr_url=qr_url or None,
                error_message=str(payload.get("error", "")),
            )

        try:
            result = await connector.connect(on_qr=on_qr, on_status=on_status)
            if result.ok:
                now = utc_now()
                self.store.update_login_session(session_id, status="active", qr_url=result.qr_url)
                self.store.upsert_state(
                    CONNECTOR_ID,
                    status="active",
                    credentials=result.credentials,
                    qr_url=result.qr_url,
                    final_url=result.final_url,
                    error_message="",
                    connected_at=now,
                    last_verified_at=now,
                )
                return
            error = result.error_message or "login failed"
            self.store.update_login_session(
                session_id,
                status="failed",
                qr_url=result.qr_url,
                error_message=error,
            )
            self.store.upsert_state(
                CONNECTOR_ID,
                status="failed",
                credentials={},
                qr_url=result.qr_url,
                error_message=error,
            )
        except asyncio.CancelledError:
            self.store.update_login_session(
                session_id,
                status="failed",
                error_message="MCP server stopped before login completed",
            )
            self.store.upsert_state(
                CONNECTOR_ID,
                status="failed",
                error_message="MCP server stopped before login completed",
            )
            raise
        finally:
            if should_close:
                await connector.client.aclose()

    async def _wait_for_login_qr(self, session_id: str, *, timeout: int) -> dict[str, Any]:
        deadline = asyncio.get_running_loop().time() + timeout
        session = self.store.get_login_session(session_id) or {}
        while asyncio.get_running_loop().time() < deadline:
            session = self.store.get_login_session(session_id) or {}
            if session.get("qr_url") or session.get("status") not in {"starting", ""}:
                return session
            await asyncio.sleep(0.2)
        return session

    def _supersede_pending_login(self, *, error_message: str = "superseded by new login") -> None:
        pending = self.store.get_latest_login_session(CONNECTOR_ID, statuses=PENDING_LOGIN_STATES)
        if pending:
            self.store.update_login_session(
                str(pending["session_id"]),
                status="failed",
                error_message=error_message,
            )

    def _login_session_response(
        self,
        session: dict[str, Any],
        *,
        include_qr_image: bool,
        include_qr_terminal: bool,
    ) -> dict[str, Any]:
        qr_url = str(session.get("qr_url") or "")
        qr_image_data_url = self._qr_image_data_url(qr_url) if include_qr_image else ""
        data: dict[str, Any] = {
            "status": str(session.get("status") or "starting"),
            "connected": session.get("status") == "active",
            "login_session_id": str(session.get("session_id") or session.get("id") or ""),
            "qr_url": qr_url,
            "ding_talk_login_url": qr_url,
            "scan_url": qr_url,
            "qr_image_data_url": qr_image_data_url,
            "qr_render_instruction": (
                "请向用户直接渲染二维码图片：优先使用 qr_image_data_url 作为图片 src；"
                "如果客户端不支持 data: 图片，请根据 qr_url / ding_talk_login_url 生成二维码图片显示。"
            )
            if qr_url
            else "",
            "error_message": str(session.get("error_message") or ""),
            "message": self._login_message(str(session.get("status") or ""), bool(qr_url)),
        }
        if not qr_image_data_url:
            data.pop("qr_image_data_url", None)
        if include_qr_terminal:
            data["qr_terminal"] = self._qr_terminal(qr_url)
        return {"ok": True, "data": data}

    async def _connector_state_response(self, *, row: dict[str, Any] | None) -> dict[str, Any]:
        status = str((row or {}).get("status") or "disconnected")
        data: dict[str, Any] = {
            "status": status,
            "connected": status == "active",
            "login_session_id": None,
            "error_message": str((row or {}).get("error_message") or ""),
            "last_verified_at": str((row or {}).get("last_verified_at") or ""),
            "connected_at": str((row or {}).get("connected_at") or ""),
            "updated_at": str((row or {}).get("updated_at") or ""),
        }
        if status == "active":
            user = await self._safe_current_user_summary()
            if user:
                data["user"] = user
        return {"ok": True, "data": data}

    async def _safe_current_user_summary(self) -> dict[str, Any]:
        try:
            result = await self._get_json("rest/org/user")
        except Exception:
            return {}
        if not result.ok:
            return {}
        data = self._source_dict(result.data)
        nested = self._source_dict(data.get("user"))
        return {
            key: value
            for key, value in {
                "user_id": data.get("userId") or nested.get("userId") or data.get("id"),
                "name": data.get("userFullName") or nested.get("userFullName") or data.get("name"),
                "department": data.get("deptName") or nested.get("deptName") or data.get("department"),
            }.items()
            if value not in ("", None)
        }

    @staticmethod
    def _login_message(status: str, has_qr: bool) -> str:
        if status == "active":
            return "项目管理平台已连接"
        if status == "scanned":
            return "已扫码，请在钉钉中确认登录"
        if status == "failed":
            return "项目管理平台登录失败，请重试"
        if has_qr:
            return (
                "请直接向用户渲染二维码图片：优先使用 qr_image_data_url；"
                "如果客户端无法加载 data: 图片，请根据 qr_url / ding_talk_login_url 生成二维码图片显示，"
                "不要显示乱排的终端字符二维码。"
            )
        return "正在生成项目管理平台登录二维码"

    @staticmethod
    def _qr_image_data_url(qr_url: str) -> str:
        if not qr_url:
            return ""
        try:
            import qrcode
        except ModuleNotFoundError:
            return ""
        image = qrcode.make(qr_url)
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        encoded = base64.b64encode(buf.getvalue()).decode("ascii")
        return f"data:image/png;base64,{encoded}"

    @staticmethod
    def _qr_terminal(qr_url: str) -> str:
        if not qr_url:
            return ""
        try:
            import qrcode
        except ModuleNotFoundError:
            return qr_url
        qr = qrcode.QRCode(border=1)
        qr.add_data(qr_url)
        qr.make(fit=True)
        out = io.StringIO()
        qr.print_ascii(out=out, invert=True)
        return out.getvalue()

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(self.refresh_interval_seconds)
            try:
                await self.refresh_active_login_state()
            except asyncio.CancelledError:
                raise
            except Exception:
                continue

    async def refresh_active_login_state(self) -> dict[str, Any]:
        row = self.store.get_state(CONNECTOR_ID)
        if not row or row.get("status") != "active":
            return {"ok": True, "data": {"status": str((row or {}).get("status") or "disconnected"), "skipped": True}}
        credentials = self.store.decode_credentials(row)
        ok, message = await self.connector.verify(credentials)
        if ok:
            self.store.upsert_state(CONNECTOR_ID, status="active", last_verified_at=utc_now(), error_message="")
            return {"ok": True, "data": {"status": "active", "refreshed": False}}
        refreshed = await self.connector.refresh(credentials)
        if refreshed.ok:
            self.store.upsert_state(
                CONNECTOR_ID,
                status="active",
                credentials=refreshed.credentials,
                final_url=refreshed.final_url,
                last_verified_at=utc_now(),
                error_message="",
            )
            return {"ok": True, "data": {"status": "active", "refreshed": True}}
        error = refreshed.error_message or message or "JXMIS credentials expired"
        self.store.upsert_state(CONNECTOR_ID, status="expired", error_message=error)
        return {"ok": False, "error": error, "error_code": "AUTH_EXPIRED", "data": {"status": "expired"}}

    async def get_current_user(self, args: dict[str, Any]) -> dict[str, Any]:
        result = await self._get_json("rest/org/user")
        return self._response(result, data=self._entity(result.data, schemas.include_raw(args)))

    async def get_todo_list(self, args: dict[str, Any]) -> dict[str, Any]:
        credentials = await self._ensure_credentials()
        limit = max(1, min(int(args.get("limit") or 10), 20))
        keyword = str(args.get("keyword") or "")
        try:
            result = await self.connector.get_todo_list(credentials, limit=limit, keyword=keyword)
        except JxmisAuthRequiredError:
            credentials = await self._refresh_credentials(credentials)
            result = await self.connector.get_todo_list(credentials, limit=limit, keyword=keyword)
        if not result.ok:
            return self._failure(result.error, diagnostics=result.diagnostics)
        data = dict(result.data or {})
        if not schemas.include_raw(args):
            for item in data.get("items", []):
                if isinstance(item, dict):
                    item.pop("raw", None)
        return self._response(result, data=data)

    async def get_project_statistics(self, args: dict[str, Any]) -> dict[str, Any]:
        year = schemas.current_year(args)
        result = await self._get_json(
            "rest/project/JxSystemHomeService/getProjectStatistics",
            params={"year": year},
        )
        return self._response(result, data=self._entity(result.data, schemas.include_raw(args)))

    async def get_project_progress(self, args: dict[str, Any]) -> dict[str, Any]:
        year = schemas.current_year(args)
        result = await self._get_json(
            "rest/project/JxSystemHomeService/getProjectProgress",
            params={"year": year},
        )
        return self._response(result, data=self._entity(result.data, schemas.include_raw(args)))

    async def get_period_report(self, args: dict[str, Any]) -> dict[str, Any]:
        year, month = schemas.current_month(args)
        result = await self._get_json(
            "rest/project/JxSystemHomeService/getdayAweekAmonthReport",
            params={"year": year, "month": month},
        )
        return self._response(result, data=self._entity(result.data, schemas.include_raw(args)))

    async def get_milestone_report(self, args: dict[str, Any]) -> dict[str, Any]:
        year, month = schemas.current_month(args)
        result = await self._get_json(
            "rest/project/JxSystemHomeService/getlichengbeiReport",
            params={"year": year, "month": month},
        )
        return self._response(result, data=self._entity(result.data, schemas.include_raw(args)))

    async def search_projects(self, args: dict[str, Any]) -> dict[str, Any]:
        page, page_size = schemas.page_args(args)
        params = self._page_params(page, page_size, query_name="queryList")
        keyword = str(args.get("keyword") or "").strip()
        if keyword:
            params["likeAll"] = keyword
        result = await self._get_json("rest/project/ProjectInfoService/query", params=params)
        return self._paged_response(result, include_raw=schemas.include_raw(args), kind="project")

    async def get_project_detail(self, args: dict[str, Any]) -> dict[str, Any]:
        project_id = await self._resolve_project_id(args)
        if not project_id:
            return self._failure("project_id or keyword is required", error_code="VALIDATION_ERROR")
        if isinstance(project_id, dict):
            return project_id
        result = await self._get_json(
            f"project/ProjectInfoService/id/{project_id}",
            params={"refCols": "default"},
        )
        return self._response(result, data=self._entity(result.data, schemas.include_raw(args)))

    async def list_project_plans(self, args: dict[str, Any]) -> dict[str, Any]:
        result = await self._get_json(
            "rest/project/ProjectPlanService/query",
            params={
                "queryName": "queryList",
                "filterQuery": "true",
                "queryType": "all",
                "refCols": "default",
                "projectId": str(args.get("project_id") or ""),
            },
        )
        return self._list_response(result, include_raw=schemas.include_raw(args), kind="plan")

    async def list_project_plan_details(self, args: dict[str, Any]) -> dict[str, Any]:
        project_id = str(args.get("project_id") or "").strip()
        plan_id = str(args.get("plan_id") or "").strip()
        if not project_id and not plan_id:
            return self._failure("project_id or plan_id is required", error_code="VALIDATION_ERROR")
        page, page_size = schemas.page_args(args)
        params = self._page_params(page, page_size, query_name="queryVer")
        params["queryType"] = "page"
        params["filterQuery"] = "true"
        if project_id:
            params.update({"projectId": project_id, "max1": project_id, "planId1": project_id})
        if plan_id:
            params.update({"planId": plan_id, "queryFilter": "true", "refCols": "default"})
        result = await self._get_json("rest/project/ProjectPlanDetailService/query", params=params)
        return self._paged_response(result, include_raw=schemas.include_raw(args), kind="plan_detail")

    async def list_project_contracts(self, args: dict[str, Any]) -> dict[str, Any]:
        contract_num = str(args.get("contract_num") or "").strip()
        if contract_num:
            result = await self._get_json(
                "rest/project/ProjectInfoService/queryAllContract",
                params={"contractNum": contract_num},
            )
            return self._list_response(result, include_raw=schemas.include_raw(args), kind="contract")

        project_id = str(args.get("project_id") or "").strip()
        if not project_id:
            return self._failure("project_id or contract_num is required", error_code="VALIDATION_ERROR")
        page, page_size = schemas.page_args(args)
        params = self._page_params(page, page_size, query_name="queryContractRevenueAmount")
        params.update({"queryType": "page", "projectId": project_id})
        result = await self._get_json("rest/project/queryProjectcontractsService/query", params=params)
        return self._paged_response(result, include_raw=schemas.include_raw(args), kind="contract")

    async def list_project_attachments(self, args: dict[str, Any]) -> dict[str, Any]:
        page, page_size = schemas.page_args(args)
        params = self._page_params(page, page_size, query_name="queryAttachmentCount")
        params.update({"delflag": "0", "projectid": str(args.get("project_id") or "")})
        result = await self._get_json("rest/file/queryAttachmentService/query", params=params)
        return self._paged_response(result, include_raw=schemas.include_raw(args), kind="attachment")

    async def list_project_risks(self, args: dict[str, Any]) -> dict[str, Any]:
        page, page_size = schemas.page_args(args)
        params = self._page_params(page, page_size, query_name="queryWhereList")
        params.update({"queryType": "page", "wrprojectId": str(args.get("project_id") or "")})
        result = await self._get_json("rest/project/ProjectRiskService/query", params=params)
        return self._paged_response(result, include_raw=schemas.include_raw(args), kind="risk")

    async def list_project_dynamics(self, args: dict[str, Any]) -> dict[str, Any]:
        page, page_size = schemas.page_args(args)
        params = self._page_params(page, page_size, query_name="queryList")
        params.update({"queryType": "page", "projectId": str(args.get("project_id") or ""), "_": schemas.now_millis()})
        result = await self._get_json(
            "rest/project/queryProjcetDynamicInfoService/query",
            params=params,
        )
        return self._paged_response(result, include_raw=schemas.include_raw(args), kind="dynamic")

    async def get_project_overview(self, args: dict[str, Any]) -> dict[str, Any]:
        project_id = await self._resolve_project_id(args)
        if not project_id:
            return self._failure("project_id or keyword is required", error_code="VALIDATION_ERROR")
        if isinstance(project_id, dict):
            return project_id

        include = args.get("include") or ["detail", "plans", "risks", "dynamics"]
        if not isinstance(include, list):
            include = ["detail", "plans", "risks", "dynamics"]
        limit = max(1, min(int(args.get("limit_per_section") or 10), 50))
        include_raw = schemas.include_raw(args)

        sections: dict[str, Any] = {}
        if "detail" in include:
            sections["detail"] = await self.get_project_detail({"project_id": project_id, "include_raw": include_raw})
        if "plans" in include:
            sections["plans"] = await self.list_project_plans({"project_id": project_id, "include_raw": include_raw})
        if "risks" in include:
            sections["risks"] = await self.list_project_risks({"project_id": project_id, "page_size": limit, "include_raw": include_raw})
        if "dynamics" in include:
            sections["dynamics"] = await self.list_project_dynamics({"project_id": project_id, "page_size": limit, "include_raw": include_raw})
        if "contracts" in include:
            sections["contracts"] = await self.list_project_contracts({"project_id": project_id, "page_size": limit, "include_raw": include_raw})
        if "attachments" in include:
            sections["attachments"] = await self.list_project_attachments({"project_id": project_id, "page_size": limit, "include_raw": include_raw})
        if "weekly_reports" in include:
            sections["weekly_reports"] = await self.list_weekly_reports({"project_id": project_id, "page_size": limit, "include_raw": include_raw})
        return {"ok": True, "data": {"project_id": project_id, "sections": sections}, "meta": {"include": include}}

    async def list_weekly_reports(self, args: dict[str, Any]) -> dict[str, Any]:
        page, page_size = schemas.page_args(args)
        project_id = str(args.get("project_id") or "").strip()
        keyword = str(args.get("keyword") or "").strip()
        params = self._page_params(page, page_size, query_name="queryByProjectId" if project_id else "queryList")
        if project_id:
            params["projectId"] = project_id
        if keyword:
            params["likeAll"] = keyword
        result = await self._get_json("rest/project/WkReportService/query", params=params)
        return self._paged_response(result, include_raw=schemas.include_raw(args), kind="weekly_report")

    async def get_weekly_report_detail(self, args: dict[str, Any]) -> dict[str, Any]:
        report_id = await self._resolve_weekly_report_id(args)
        if not report_id:
            return self._failure(
                "weekly_report_id, project_id, or keyword is required",
                error_code="VALIDATION_ERROR",
            )
        if isinstance(report_id, dict):
            return report_id

        include_raw = schemas.include_raw(args)
        detail = await self._get_json(f"project/WkReportService/id/{report_id}", params={"refCols": "default"})
        detail_data = self._entity(detail.data, include_raw)
        project_id = (
            str(args.get("project_id") or "")
            or str(self._source_dict(detail.data).get("projectId") or "")
        )
        related: dict[str, Any] = {}
        related["landmarks"] = await self._weekly_related(
            "rest/project/WkLandmarkService/query",
            {"wkId": report_id, "queryName": "queryList", "refCols": "default"},
            include_raw,
            "landmark",
        )
        related["executions"] = await self._weekly_related(
            "rest/project/WkExecutionService/query",
            {"reportId": report_id, "queryName": "queryReportExtList", "type": "1"},
            include_raw,
            "execution",
        )
        if project_id:
            related["relations"] = await self._weekly_related(
                "rest/project/queryRelationService/query",
                {"projectId": project_id, "queryName": "queryRelationId"},
                include_raw,
                "relation",
            )
            related["qa_checks"] = await self._weekly_related(
                "rest/project/queryQaCheckService/query",
                {"projectId": project_id, "queryName": "queryCheckList"},
                include_raw,
                "qa_check",
            )
            related["contract_risks"] = await self._weekly_related(
                "rest/project/queryContractRiskService/query",
                {"projectId": project_id, "queryName": "queryList", "refCols": "default"},
                include_raw,
                "contract_risk",
            )
        return self._response(
            detail,
            data={
                "weekly_report_id": report_id,
                "project_id": project_id,
                "detail": detail_data,
                "related": related,
            },
        )

    async def get_task_workload_summary(self, args: dict[str, Any]) -> dict[str, Any]:
        start_date, end_date = schemas.date_range(args)
        result = await self._get_json(
            "rest/task/queryTaskService/query",
            params={
                "queryType": "all",
                "queryName": "queryTotalDay",
                "startTime": start_date,
                "endTime": end_date,
            },
        )
        return self._response(
            result,
            data={"start_date": start_date, "end_date": end_date, "items": self._items(result.data, schemas.include_raw(args), "workload")},
        )

    async def get_personal_task_calendar(self, args: dict[str, Any]) -> dict[str, Any]:
        year, month = schemas.current_month(args)
        user_id = str(args.get("user_id") or "").strip()
        if not user_id:
            user = await self.get_current_user({"include_raw": True})
            user_id = str((user.get("data") or {}).get("id") or "")
        if not user_id:
            return self._failure("user_id is required and current user id was not found", error_code="VALIDATION_ERROR")
        result = await self._get_json(
            "rest/reports/ProjectTaskReportService/queryPersonnalTask",
            params={"format": "json", "year": year, "month": month, "userId": user_id},
        )
        data = self._source_dict(result.data)
        tasks = self._items(data.get("realTaskList", []), schemas.include_raw(args), "task")
        return self._response(
            result,
            data={
                "year": year,
                "month": month,
                "user_id": user_id,
                "count_real_time": data.get("countRealTime"),
                "items": tasks,
            },
        )

    async def preview_pending_daily_approvals(self, args: dict[str, Any]) -> dict[str, Any]:
        candidates = await self._daily_approval_candidates(args)
        if not candidates["ok"]:
            return candidates
        return self._approval_preview_response("daily", candidates, args)

    async def batch_approve_daily_reports(self, args: dict[str, Any]) -> dict[str, Any]:
        candidates = await self._daily_approval_candidates(args)
        if not candidates["ok"]:
            return candidates
        if self._approval_is_preview_only(args):
            return self._approval_preview_response("daily", candidates, args, requires_confirmation=True)

        summary = {"success": 0, "skipped": 0, "failed": 0, "unknown": 0}
        results: list[dict[str, Any]] = []
        rows = list(candidates["data"]["items"])
        for index, row in enumerate(rows):
            try:
                payload = self._daily_approval_payload(row, args)
                result = await self._post_json(
                    "rest/project/ProjectRapportService/batchDailyApproval",
                    [payload],
                )
                if not result.ok:
                    item = self._approval_item_result(row, "failed", result.error)
                elif self._approval_text(result.data) == "success":
                    item = self._approval_item_result(row, "success", "success")
                else:
                    item = self._approval_item_result(
                        row,
                        "unknown",
                        f"unexpected response: {result.data!r}",
                    )
                summary[item["status"]] += 1
                results.append(item)
            except Exception as exc:
                summary["failed"] += 1
                results.append(self._approval_item_result(row, "failed", str(exc)))
            await self._approval_delay(args, index, len(rows))

        return {
            "ok": True,
            "data": {
                "mode": "submitted",
                "kind": "daily",
                "summary": summary,
                "items": results,
            },
            "meta": candidates["meta"],
        }

    async def preview_pending_weekly_approvals(self, args: dict[str, Any]) -> dict[str, Any]:
        candidates = await self._weekly_approval_candidates(args)
        if not candidates["ok"]:
            return candidates
        return self._approval_preview_response("weekly", candidates, args)

    async def batch_approve_weekly_reports(self, args: dict[str, Any]) -> dict[str, Any]:
        candidates = await self._weekly_approval_candidates(args)
        if not candidates["ok"]:
            return candidates
        if self._approval_is_preview_only(args):
            return self._approval_preview_response("weekly", candidates, args, requires_confirmation=True)

        current_user = candidates["meta"]["current_user"]
        reply = str(args.get("reply") or "已核实")
        summary = {"success": 0, "skipped": 0, "failed": 0, "unknown": 0}
        results: list[dict[str, Any]] = []
        rows = list(candidates["data"]["items"])
        for index, row in enumerate(rows):
            try:
                wk_id = str(row.get("weekly_report_id") or row.get("wkId") or "")
                if not wk_id:
                    item = self._approval_item_result(row, "failed", "wkId missing")
                    summary[item["status"]] += 1
                    results.append(item)
                    await self._approval_delay(args, index, len(rows))
                    continue

                latest = await self._weekly_report_by_id(wk_id)
                if (
                    not latest
                    or str(latest.get("prodPerson") or "") != current_user["user_id"]
                    or str(latest.get("status") or "") != "20"
                ):
                    item = self._approval_item_result(
                        row,
                        "skipped",
                        "生产负责人或状态已变化",
                        latest_status=latest.get("status") if latest else None,
                    )
                    summary[item["status"]] += 1
                    results.append(item)
                    await self._approval_delay(args, index, len(rows))
                    continue

                result = await self._get_json_or_text(
                    "rest/project/WkReportService/addReply",
                    params={"format": "json", "wkId": wk_id, "reply": reply},
                )
                if not result.ok:
                    item = self._approval_item_result(row, "failed", result.error)
                    summary[item["status"]] += 1
                    results.append(item)
                    await self._approval_delay(args, index, len(rows))
                    continue
                if self._approval_text(result.data) != "批复完成":
                    item = self._approval_item_result(
                        row,
                        "failed",
                        f"unexpected response: {result.data!r}",
                    )
                    summary[item["status"]] += 1
                    results.append(item)
                    await self._approval_delay(args, index, len(rows))
                    continue

                verified = await self._weekly_report_by_id(wk_id)
                if (
                    verified
                    and str(verified.get("status") or "") == "30"
                    and str(verified.get("prodPerson") or "") == current_user["user_id"]
                ):
                    item = self._approval_item_result(
                        row,
                        "success",
                        "批复完成",
                        approval_time=verified.get("approvalTime"),
                    )
                else:
                    item = self._approval_item_result(
                        row,
                        "unknown",
                        "批复接口成功但复查状态未确认",
                        latest_status=verified.get("status") if verified else None,
                    )
                summary[item["status"]] += 1
                results.append(item)
            except Exception as exc:
                summary["failed"] += 1
                results.append(self._approval_item_result(row, "failed", str(exc)))
            await self._approval_delay(args, index, len(rows))

        return {
            "ok": True,
            "data": {
                "mode": "submitted",
                "kind": "weekly",
                "summary": summary,
                "items": results,
            },
            "meta": candidates["meta"],
        }

    async def _daily_approval_candidates(self, args: dict[str, Any]) -> dict[str, Any]:
        current_user, failure = await self._current_user_identity(require_name=False)
        if failure:
            return failure
        assert current_user is not None
        page_size = self._approval_page_size(args, default=50)
        max_items = self._approval_max_items(args)
        keyword = str(args.get("keyword") or "").strip().lower()
        rows: list[dict[str, Any]] = []
        page = 1
        truncated = False
        while True:
            result = await self._get_json(
                "rest/project/queryDailyApprovalService/query",
                params={
                    "queryName": "queryList",
                    "queryType": "page",
                    "approval_state": "0",
                    "projectManager": current_user["user_id"],
                    "draw": page,
                    "page": page,
                    "start": (page - 1) * page_size,
                    "length": page_size,
                    "rows": page_size,
                },
            )
            if not result.ok:
                return self._failure(result.error, diagnostics=result.diagnostics)
            payload = self._source_dict(result.data)
            page_rows = payload.get("rows", [])
            if not isinstance(page_rows, list):
                page_rows = []
            for raw in page_rows:
                if not isinstance(raw, dict):
                    continue
                item = self._normalize_daily_approval(raw, schemas.include_raw(args))
                if keyword and keyword not in self._approval_haystack(item):
                    continue
                rows.append(item)
                if len(rows) >= max_items:
                    truncated = True
                    break
            if truncated or page >= self._page_count(payload, page_rows, page_size):
                break
            page += 1

        return {
            "ok": True,
            "data": {"items": rows, "returned": len(rows)},
            "meta": {
                "current_user": current_user,
                "page_size": page_size,
                "max_items": max_items,
                "truncated": truncated,
                "keyword": str(args.get("keyword") or ""),
            },
        }

    async def _weekly_approval_candidates(self, args: dict[str, Any]) -> dict[str, Any]:
        current_user, failure = await self._current_user_identity(require_name=True)
        if failure:
            return failure
        assert current_user is not None
        year, month = schemas.current_month(args)
        month_end = int(args.get("month_end") or args.get("monthEnd") or month)
        page_size = self._approval_page_size(args, default=25)
        max_items = self._approval_max_items(args)
        keyword = str(args.get("keyword") or "").strip().lower()
        rows: list[dict[str, Any]] = []
        page = 1
        truncated = False
        while True:
            result = await self._get_json(
                "rest/project/WkReportService/query",
                params={
                    "queryName": "queryList",
                    "filterQuery": "true",
                    "queryType": "page",
                    "year": year,
                    "month": month,
                    "monthEnd": month_end,
                    "likeAll": current_user["user_full_name"],
                    "draw": page,
                    "page": page,
                    "start": (page - 1) * page_size,
                    "length": page_size,
                    "rows": page_size,
                },
            )
            if not result.ok:
                return self._failure(result.error, diagnostics=result.diagnostics)
            payload = self._source_dict(result.data)
            page_rows = payload.get("rows", [])
            if not isinstance(page_rows, list):
                page_rows = []
            for raw in page_rows:
                if not isinstance(raw, dict):
                    continue
                if str(raw.get("prodPerson") or "") != current_user["user_id"]:
                    continue
                if str(raw.get("status") or "") != "20":
                    continue
                item = self._normalize_weekly_approval(raw, schemas.include_raw(args))
                if keyword and keyword not in self._approval_haystack(item):
                    continue
                rows.append(item)
                if len(rows) >= max_items:
                    truncated = True
                    break
            if truncated or page >= self._page_count(payload, page_rows, page_size):
                break
            page += 1

        return {
            "ok": True,
            "data": {"items": rows, "returned": len(rows)},
            "meta": {
                "current_user": current_user,
                "year": year,
                "month": month,
                "month_end": month_end,
                "page_size": page_size,
                "max_items": max_items,
                "truncated": truncated,
                "keyword": str(args.get("keyword") or ""),
            },
        }

    async def _current_user_identity(
        self,
        *,
        require_name: bool,
    ) -> tuple[dict[str, str] | None, dict[str, Any] | None]:
        result = await self._get_json("rest/org/user")
        if not result.ok:
            return None, self._failure(result.error, diagnostics=result.diagnostics)
        data = self._source_dict(result.data)
        nested = self._source_dict(data.get("user"))
        user_id = str(data.get("userId") or nested.get("userId") or "").strip()
        user_full_name = str(
            data.get("userFullName") or nested.get("userFullName") or data.get("name") or ""
        ).strip()
        if not user_id:
            return None, self._failure("current userId not found", error_code="VALIDATION_ERROR")
        if require_name and not user_full_name:
            return None, self._failure("current userFullName not found", error_code="VALIDATION_ERROR")
        return {"user_id": user_id, "user_full_name": user_full_name}, None

    def _approval_page_size(self, args: dict[str, Any], *, default: int) -> int:
        return max(1, min(int(args.get("page_size") or default), schemas.MAX_PAGE_SIZE))

    def _approval_max_items(self, args: dict[str, Any]) -> int:
        return max(1, min(int(args.get("max_items") or DEFAULT_APPROVAL_LIMIT), MAX_APPROVAL_LIMIT))

    def _page_count(self, payload: dict[str, Any], rows: list[Any], page_size: int) -> int:
        explicit = int(payload.get("pageCount") or 0)
        if explicit > 0:
            return explicit
        total = int(payload.get("recordsFiltered") or payload.get("total") or payload.get("recordsTotal") or 0)
        if total > 0:
            return max(1, (total + page_size - 1) // page_size)
        return 1 if len(rows) < page_size else 2

    def _approval_is_preview_only(self, args: dict[str, Any]) -> bool:
        return bool(args.get("dry_run", True)) or not bool(args.get("confirm", False))

    def _approval_preview_response(
        self,
        kind: str,
        candidates: dict[str, Any],
        args: dict[str, Any],
        *,
        requires_confirmation: bool = False,
    ) -> dict[str, Any]:
        data = dict(candidates["data"])
        data.update({
            "mode": "dry_run",
            "kind": kind,
            "requires_confirmation": requires_confirmation,
            "submit_hint": {"dry_run": False, "confirm": True},
        })
        return {"ok": True, "data": data, "meta": candidates["meta"]}

    def _normalize_daily_approval(self, row: dict[str, Any], include_raw: bool) -> dict[str, Any]:
        item = {
            "kind": "daily_approval",
            "id": str(row.get("id") or ""),
            "type": str(row.get("type") or "task"),
            "task_name": str(row.get("taskName") or ""),
            "people_name": str(row.get("peopleName") or row.get("userName") or ""),
            "create_time": str(row.get("createTime") or row.get("time") or ""),
            "ext_id": str(row.get("extId") or ""),
            "real_finish_rate": row.get("realFinishRate"),
            "plan_time": row.get("planTime", 0),
            "project_name": str(row.get("projectName") or ""),
        }
        if include_raw:
            item["raw"] = row
        return {k: v for k, v in item.items() if v not in ("", None)}

    def _normalize_weekly_approval(self, row: dict[str, Any], include_raw: bool) -> dict[str, Any]:
        item = {
            "kind": "weekly_approval",
            "id": str(row.get("wkId") or ""),
            "weekly_report_id": str(row.get("wkId") or ""),
            "name": str(row.get("wkName") or row.get("projectName") or ""),
            "project_name": str(row.get("projectName") or row.get("projName") or ""),
            "project_manager_name": str(row.get("projectManagerName") or row.get("pmName") or ""),
            "prod_person": str(row.get("prodPerson") or ""),
            "prod_person_name": str(row.get("prodPersonName") or ""),
            "status": str(row.get("status") or ""),
            "wk_num": str(row.get("wkNum") or ""),
            "week_date": str(row.get("weekDate") or ""),
        }
        if include_raw:
            item["raw"] = row
        return {k: v for k, v in item.items() if v not in ("", None)}

    def _daily_approval_payload(self, row: dict[str, Any], args: dict[str, Any]) -> dict[str, str]:
        state = str(args.get("state") or "1")
        if state != "1":
            raise ValueError("daily batch approval only supports state='1'")
        real_finish_rate = row.get("real_finish_rate")
        if real_finish_rate in ("", None):
            raise ValueError("realFinishRate missing")
        payload = {
            "id": str(row.get("id") or ""),
            "type": str(row.get("type") or "task"),
            "state": state,
            "createTime": str(row.get("create_time") or ""),
            "realFinishRate": str(real_finish_rate),
            "planTime": str(row.get("plan_time", 0)),
            "extId": str(row.get("ext_id") or ""),
            "approvalTimely": str(args.get("approval_timely") or "1"),
            "achievementComplete": str(args.get("achievement_complete") or "1"),
            "achievementQuality": str(args.get("achievement_quality") or "1"),
            "approvalComment": str(args.get("approval_comment") or ""),
        }
        missing = [key for key in ("id", "type", "createTime", "extId") if not payload[key]]
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")
        return payload

    async def _weekly_report_by_id(self, wk_id: str) -> dict[str, Any]:
        result = await self._get_json(
            "rest/project/queryByProjectInfosService/query",
            params={"queryType": "all", "queryName": "queryByProjectInfo", "wkId": wk_id},
        )
        if not result.ok:
            return {}
        data = result.data
        if isinstance(data, list):
            return data[0] if data and isinstance(data[0], dict) else {}
        source = self._source_dict(data)
        for key in ("rows", "data"):
            value = source.get(key)
            if isinstance(value, list):
                return value[0] if value and isinstance(value[0], dict) else {}
            if isinstance(value, dict):
                return value
        result_value = source.get("result")
        if isinstance(result_value, dict):
            return result_value
        return source

    def _approval_item_result(
        self,
        row: dict[str, Any],
        status: str,
        message: str,
        **extra: Any,
    ) -> dict[str, Any]:
        item = {
            "id": row.get("id") or row.get("weekly_report_id"),
            "name": row.get("name") or row.get("task_name") or row.get("project_name"),
            "status": status,
            "message": message,
        }
        item.update({k: v for k, v in extra.items() if v not in ("", None)})
        return item

    def _approval_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value.strip().strip('"')
        return str(value).strip().strip('"')

    def _approval_haystack(self, item: dict[str, Any]) -> str:
        return " ".join(str(value) for value in item.values() if not isinstance(value, dict)).lower()

    async def _approval_delay(self, args: dict[str, Any], index: int, total: int) -> None:
        if index >= total - 1:
            return
        base = max(0, int(args.get("base_delay_ms") if args.get("base_delay_ms") is not None else 1000))
        jitter = max(
            0,
            int(
                args.get("random_delay_max_ms")
                if args.get("random_delay_max_ms") is not None
                else 3000
            ),
        )
        delay_ms = base + (random.randint(0, jitter) if jitter else 0)
        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000)

    async def _weekly_related(
        self,
        path: str,
        params: dict[str, Any],
        include_raw: bool,
        kind: str,
    ) -> dict[str, Any]:
        full_params = self._page_params(1, 100, query_name=str(params.pop("queryName", "queryList")))
        full_params.update({"queryType": "page", "filterQuery": "true", **params})
        result = await self._get_json(path, params=full_params)
        return self._paged_response(result, include_raw=include_raw, kind=kind)

    async def _resolve_project_id(self, args: dict[str, Any]) -> str | dict[str, Any]:
        project_id = str(args.get("project_id") or "").strip()
        if project_id:
            return project_id
        keyword = str(args.get("keyword") or "").strip()
        if not keyword:
            return ""
        candidates = await self.search_projects({"keyword": keyword, "page_size": 5})
        items = ((candidates.get("data") or {}).get("items") or [])
        if len(items) == 1:
            return str(items[0].get("id") or items[0].get("project_id") or "")
        if not items:
            return self._failure(f"No project matched keyword: {keyword}", error_code="NOT_FOUND")
        return self._failure(
            "Multiple projects matched keyword; choose one project_id",
            error_code="AMBIGUOUS",
            data={"candidates": items},
        )

    async def _resolve_weekly_report_id(self, args: dict[str, Any]) -> str | dict[str, Any]:
        report_id = str(args.get("weekly_report_id") or "").strip()
        if report_id:
            return report_id
        keyword = str(args.get("keyword") or "").strip()
        project_id = str(args.get("project_id") or "").strip()
        candidates = await self.list_weekly_reports(
            {"keyword": keyword, "project_id": project_id, "page_size": 5}
        )
        items = ((candidates.get("data") or {}).get("items") or [])
        if len(items) == 1:
            return str(items[0].get("id") or items[0].get("weekly_report_id") or "")
        if not items:
            return self._failure("No weekly report matched", error_code="NOT_FOUND")
        if keyword:
            return self._failure(
                "Multiple weekly reports matched keyword; choose one weekly_report_id",
                error_code="AMBIGUOUS",
                data={"candidates": items},
            )
        return str(items[0].get("id") or items[0].get("weekly_report_id") or "")

    async def _ensure_credentials(self) -> dict[str, Any]:
        row = self.store.get_state(CONNECTOR_ID)
        if not row or row.get("status") != "active":
            raise RuntimeError(
                "JXMIS is not connected. Call jxmis_connect and scan the DingTalk QR code first."
            )
        credentials = self.store.decode_credentials(row)
        ok, message = await self.connector.verify(credentials)
        if ok:
            self.store.upsert_state(
                CONNECTOR_ID,
                status="active",
                last_verified_at=utc_now(),
                error_message="",
            )
            return credentials
        return await self._refresh_credentials(credentials, message)

    async def _refresh_credentials(
        self,
        credentials: dict[str, Any],
        message: str = "",
    ) -> dict[str, Any]:
        refreshed = await self.connector.refresh(credentials)
        if refreshed.ok:
            self.store.upsert_state(
                CONNECTOR_ID,
                status="active",
                credentials=refreshed.credentials,
                final_url=refreshed.final_url,
                last_verified_at=utc_now(),
                error_message="",
            )
            return refreshed.credentials
        error = refreshed.error_message or message or "JXMIS credentials expired"
        self.store.upsert_state(CONNECTOR_ID, status="expired", error_message=error)
        raise RuntimeError(f"JXMIS connector login expired: {error}")

    async def _get_json(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> JxmisRequestResult:
        credentials = await self._ensure_credentials()
        try:
            return await self.connector._get_json(path, credentials, params=params)
        except JxmisAuthRequiredError:
            credentials = await self._refresh_credentials(credentials)
            return await self.connector._get_json(path, credentials, params=params)

    async def _get_json_or_text(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> JxmisRequestResult:
        credentials = await self._ensure_credentials()
        try:
            return await self.connector._get_json_or_text(path, credentials, params=params)
        except JxmisAuthRequiredError:
            credentials = await self._refresh_credentials(credentials)
            return await self.connector._get_json_or_text(path, credentials, params=params)

    async def _post_json(
        self,
        path: str,
        json_data: Any,
        *,
        params: dict[str, Any] | None = None,
    ) -> JxmisRequestResult:
        credentials = await self._ensure_credentials()
        try:
            return await self.connector._post_json(path, credentials, json_data=json_data, params=params)
        except JxmisAuthRequiredError:
            credentials = await self._refresh_credentials(credentials)
            return await self.connector._post_json(path, credentials, json_data=json_data, params=params)

    def _page_params(self, page: int, page_size: int, *, query_name: str) -> dict[str, Any]:
        return {
            "queryName": query_name,
            "filterQuery": "true",
            "queryType": "page",
            "rows": page_size,
            "draw": 1,
            "page": page,
            "start": (page - 1) * page_size,
            "length": page_size,
        }

    def _response(
        self,
        result: JxmisRequestResult,
        *,
        data: Any,
        meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not result.ok:
            return self._failure(result.error, diagnostics=result.diagnostics)
        return {
            "ok": True,
            "data": data,
            "meta": meta or {},
            "diagnostics": self._safe_diagnostics(result.diagnostics),
        }

    def _paged_response(
        self,
        result: JxmisRequestResult,
        *,
        include_raw: bool,
        kind: str,
    ) -> dict[str, Any]:
        if not result.ok:
            return self._failure(result.error, diagnostics=result.diagnostics)
        payload = self._source_dict(result.data)
        rows = payload.get("rows", [])
        items = self._items(rows, include_raw, kind)
        return self._response(
            result,
            data={
                "items": items,
                "returned": len(items),
                "total": payload.get("total", len(items)),
                "page_no": payload.get("pageNo"),
                "page_size": payload.get("pageSize"),
            },
        )

    def _list_response(
        self,
        result: JxmisRequestResult,
        *,
        include_raw: bool,
        kind: str,
    ) -> dict[str, Any]:
        if not result.ok:
            return self._failure(result.error, diagnostics=result.diagnostics)
        return self._response(result, data={"items": self._items(result.data, include_raw, kind)})

    def _entity(self, data: Any, include_raw: bool) -> dict[str, Any]:
        row = self._source_dict(data)
        entity = self._normalize_row(row, "entity")
        if include_raw:
            entity["raw"] = data
        return entity

    def _items(self, data: Any, include_raw: bool, kind: str) -> list[dict[str, Any]]:
        if isinstance(data, dict) and isinstance(data.get("rows"), list):
            rows = data["rows"]
        elif isinstance(data, list):
            rows = data
        else:
            rows = [data] if isinstance(data, dict) else []
        return [
            self._normalize_row(row, kind, include_raw=include_raw)
            for row in rows
            if isinstance(row, dict)
        ]

    def _normalize_row(
        self,
        row: dict[str, Any],
        kind: str,
        *,
        include_raw: bool = False,
    ) -> dict[str, Any]:
        item = {
            "kind": kind,
            "id": self._first_value(row, "id", "userId", "projectId", "wkId", "taskId", "planId", "contractId"),
            "project_id": self._first_value(row, "projectId", "projectID", "wrprojectId"),
            "weekly_report_id": self._first_value(row, "wkId", "reportId"),
            "task_id": self._first_value(row, "taskId"),
            "name": self._first_value(row, "projectName", "wkName", "taskName", "name", "contractName"),
            "project_name": self._first_value(row, "projectName"),
            "status": self._first_value(row, "status", "statusDesc", "approvalState"),
            "owner_name": self._first_value(row, "projectManagerName", "prodPersonName", "taskOwnerName", "userName"),
            "dept_name": self._first_value(row, "projectDeptName", "deptName", "implementDeptName", "exeSecondaryDeptName"),
            "created_at": self._first_value(row, "createTime", "createdTime"),
            "updated_at": self._first_value(row, "modifyTime", "submissionTime"),
        }
        for key in (
            "projectNo",
            "wkName",
            "wkNum",
            "weekDate",
            "currWkResult",
            "nextWkPlan",
            "currExecuteStatusDesc",
            "contractNum",
            "contractName",
            "realEndTime",
            "complateTime",
            "realFinishRate",
        ):
            if key in row:
                item[key] = row[key]
        compact = {k: v for k, v in item.items() if v not in ("", None)}
        if include_raw:
            compact["raw"] = row
        return compact

    def _source_dict(self, data: Any) -> dict[str, Any]:
        if isinstance(data, dict):
            return data
        return {}

    def _first_value(self, row: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            value = row.get(key)
            if value not in ("", None):
                return value
        return ""

    def _safe_diagnostics(self, diagnostics: dict[str, Any]) -> dict[str, Any]:
        clean = dict(diagnostics or {})
        clean.pop("headers", None)
        return clean

    def _failure(
        self,
        error: str,
        *,
        error_code: str = "JXMIS_ERROR",
        data: Any = None,
        diagnostics: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "ok": False,
            "error": error,
            "error_code": error_code,
            "data": data,
            "diagnostics": self._safe_diagnostics(diagnostics or {}),
        }
