"""JXMIS project management platform connector."""

from __future__ import annotations

import asyncio
import json
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlencode, urljoin, urlparse, urlsplit

import httpx

from .base import (
    Connector,
    ConnectorLoginResult,
    QrCallback,
    StatusCallback,
)

DINGTALK_LOGIN_BASE_URL = "https://login.dingtalk.com"
DINGTALK_UMID_URL = "https://ynuf.aliapp.org/service/um.json?_bx-v=2.5.36"
BX_VERSION = "2.5.36"
QR_PENDING_ERROR_CODE = "11021"
QR_SCANNED_ERROR_CODE = "11041"
QR_INVALID_ERROR_CODE = "11019"
RETRYABLE_ERROR_CODES = frozenset({
    QR_PENDING_ERROR_CODE,
    QR_SCANNED_ERROR_CODE,
    QR_INVALID_ERROR_CODE,
    "283960126",
})


@dataclass(slots=True)
class JxmisConfig:
    enabled: bool = True
    entry_url: str = "https://jxmis.cyberwing.cn/jxpmo/login"
    api_base_url: str = "https://jxmis.cyberwing.cn/jxpmo/"
    baseuaa_auth_base: str = "https://baseuaa.cyberwing.cn/oauth2/authorize"
    baseuaa_dingtalk_auth_code_url: str = (
        "https://baseuaa.cyberwing.cn/api/base/uaa/ding/talk/auth/code"
    )
    ding_client_id: str = "dingrlcxvzggoyn7xvu1"
    client_id: str = "jxpmo"
    redirect_uri: str = "http://jxmis.cyberwing.cn/jxpmo/login"
    keepalive_primary_url: str = "https://jxmis.cyberwing.cn/jxpmo/rest/org/user"
    keepalive_fallback_url: str = (
        "https://jxmis.cyberwing.cn/jxpmo/rest/project/Service/pageQueryTodoList"
    )
    keepalive_interval_seconds: int = 600
    login_wait_timeout_seconds: int = 180
    request_retries: int = 3

    @property
    def referer_url(self) -> str:
        parsed = urlsplit(self.entry_url)
        base_path = parsed.path.rsplit("/", 1)[0] + "/"
        return f"{parsed.scheme}://{parsed.netloc}{base_path}"


@dataclass(slots=True)
class CurlResult:
    stdout: str
    stderr: str
    returncode: int


@dataclass(slots=True)
class JxmisRequestResult:
    ok: bool
    data: Any = None
    error: str = ""
    status_code: int = 0
    diagnostics: dict[str, Any] = field(default_factory=dict)


class JxmisAuthRequiredError(RuntimeError):
    pass


@dataclass(slots=True)
class BrowserFingerprint:
    sec_browser: str = "chrome"
    sec_browser_ver: str = "124.0.0.0"
    sec_refer: str = ""
    platform: str = "Windows"
    nw_shell: bool = False
    umid_token: str = "FAKE_UMID"
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )

    @property
    def pdm_title(self) -> str:
        return self.platform if self.nw_shell else f"{self.platform} Web"

    @property
    def pdm_model(self) -> str:
        return self.platform

    def build_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": DINGTALK_LOGIN_BASE_URL,
            "Referer": self.sec_refer or f"{DINGTALK_LOGIN_BASE_URL}/oauth2/challenge.htm",
            "User-Agent": self.user_agent,
            "sec_browser": self.sec_browser,
            "sec_browserVer": self.sec_browser_ver,
            "sec_umidToken": self.umid_token,
        }
        if self.sec_refer:
            headers["sec_refer"] = self.sec_refer
        if extra:
            headers.update(extra)
        return headers


@dataclass(slots=True, frozen=True)
class ChallengeContext:
    challenge_url: str
    redirect_uri: str
    client_id: str
    response_type: str = "code"
    scope: str = "openid"
    prompt: str = "consent"
    extra_query: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_url(cls, challenge_url: str) -> "ChallengeContext":
        parsed = urlparse(challenge_url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        redirect_uri = query.pop("redirect_uri", "")
        client_id = query.pop("client_id", "")
        response_type = query.pop("response_type", "code")
        scope = query.pop("scope", "openid")
        prompt = query.pop("prompt", "consent")
        return cls(
            challenge_url=challenge_url,
            redirect_uri=redirect_uri,
            client_id=client_id,
            response_type=response_type,
            scope=scope,
            prompt=prompt,
            extra_query=query,
        )

    @classmethod
    def from_authorize_url(cls, authorize_url: str, ding_client_id: str) -> "ChallengeContext":
        query = {
            "redirect_uri": authorize_url,
            "response_type": "code",
            "client_id": ding_client_id,
            "scope": "openid",
            "prompt": "consent",
        }
        challenge_url = f"{DINGTALK_LOGIN_BASE_URL}/oauth2/challenge.htm?{urlencode(query)}"
        return cls(challenge_url=challenge_url, redirect_uri=authorize_url, client_id=ding_client_id)

    def page_query(self) -> dict[str, str]:
        payload = {
            "redirect_uri": self.redirect_uri,
            "response_type": self.response_type,
            "client_id": self.client_id,
            "scope": self.scope,
            "prompt": self.prompt,
        }
        payload.update(self.extra_query)
        return payload


def _normalize_form(data: dict[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in data.items():
        if value is None:
            continue
        if isinstance(value, bool):
            normalized[key] = "true" if value else "false"
        else:
            normalized[key] = str(value)
    return normalized


def _prepare_ding_form(
    path: str,
    challenge: ChallengeContext,
    browser: BrowserFingerprint,
    payload: dict[str, Any],
) -> tuple[str, dict[str, str], dict[str, str]]:
    body = challenge.page_query()
    body.update(payload)
    body["pdmTitle"] = browser.pdm_title
    body["pdmModel"] = browser.pdm_model
    body["pdmToken"] = browser.umid_token
    url = f"{urljoin(DINGTALK_LOGIN_BASE_URL, path)}?_bx-v={BX_VERSION}"
    return url, browser.build_headers(), _normalize_form(body)


def parse_qr_confirm_code(qr_url: str) -> str:
    return dict(parse_qsl(urlparse(qr_url).query)).get("code", "")


def classify_qr_poll_error(error_code: str) -> str:
    if error_code == QR_PENDING_ERROR_CODE:
        return "pending"
    if error_code == QR_SCANNED_ERROR_CODE:
        return "scanned"
    if error_code == QR_INVALID_ERROR_CODE:
        return "invalid"
    if error_code in RETRYABLE_ERROR_CODES:
        return "retryable"
    return "fatal"


class DingTalkOAuthClient:
    def __init__(self, client: httpx.AsyncClient, browser: BrowserFingerprint) -> None:
        self.browser = browser
        self.client = client
        self.client.headers.setdefault("User-Agent", self.browser.user_agent)

    async def fetch_umid_token(self) -> str:
        try:
            response = await self.client.post(DINGTALK_UMID_URL)
            response.raise_for_status()
            token = response.json().get("tn") or self.browser.umid_token
        except Exception:
            token = self.browser.umid_token
        self.browser.umid_token = token
        return token

    async def open_challenge(self, challenge: ChallengeContext) -> ChallengeContext:
        response = await self.client.get(
            challenge.challenge_url,
            headers={"Referer": challenge.redirect_uri or DINGTALK_LOGIN_BASE_URL},
        )
        response.raise_for_status()
        return ChallengeContext.from_url(str(response.request.url))

    async def generate_qrcode(self, challenge: ChallengeContext) -> dict[str, Any]:
        url, headers, data = _prepare_ding_form(
            "/oauth2/generate_qrcode",
            challenge,
            self.browser,
            {},
        )
        response = await self.client.post(url, data=data, headers=headers)
        response.raise_for_status()
        return response.json()

    async def login_with_qr(
        self,
        challenge: ChallengeContext,
        *,
        code: str,
        stay_login: bool = False,
    ) -> dict[str, Any]:
        url, headers, data = _prepare_ding_form(
            "/oauth2/login_with_qr",
            challenge,
            self.browser,
            {"code": code, "exclusiveCorpId": "", "stayLogin": stay_login},
        )
        response = await self.client.post(url, data=data, headers=headers)
        response.raise_for_status()
        return response.json()

    async def confirm_auth(self, challenge: ChallengeContext) -> dict[str, Any]:
        url, headers, data = _prepare_ding_form(
            "/oauth2/confirm_auth",
            challenge,
            self.browser,
            {"corpId": "", "secondaryValidationResult": "", "redirect_uri": challenge.redirect_uri},
        )
        response = await self.client.post(url, data=data, headers=headers)
        response.raise_for_status()
        return response.json()


def parse_header_block(raw: str) -> tuple[dict[str, str], str, int]:
    normalized = raw.replace("\r\n", "\n")
    blocks = normalized.split("\n\n")
    header_blocks: list[str] = []
    body_parts: list[str] = []
    saw_body = False
    for block in blocks:
        stripped = block.lstrip()
        if not saw_body and stripped.startswith("HTTP/"):
            header_blocks.append(block)
            continue
        saw_body = True
        body_parts.append(block)
    head = header_blocks[-1] if header_blocks else (blocks[0] if blocks else "")
    body = "\n\n".join(body_parts)
    lines = [line for line in head.splitlines() if line.strip()]
    status = 0
    headers: dict[str, str] = {}
    if lines:
        first = lines[0].strip().split()
        if len(first) >= 2 and first[1].isdigit():
            status = int(first[1])
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers, body, status


def read_cookie_value(raw: str, name: str) -> str:
    marker = f"{name}="
    if marker not in raw:
        return ""
    return raw.split(marker, 1)[1].split(";", 1)[0]


def derive_jxmis_cookie_scope(entry_url: str) -> tuple[str, str]:
    parsed = urlsplit(entry_url)
    domain = f".{parsed.hostname}" if parsed.hostname else ".jxmis.cyberwing.cn"
    raw_path = parsed.path or "/"
    cookie_path = raw_path.rsplit("/", 1)[0] or "/"
    return domain, cookie_path


def curl_capture_result(
    url: str,
    headers: list[str] | None = None,
    body: bool = True,
    timeout: int = 30,
    cookie_jar: str | None = None,
) -> CurlResult:
    cmd = [
        "curl",
        "-k",
        "-m",
        str(timeout),
        "--connect-timeout",
        "15",
        "--retry",
        "3",
        "--retry-all-errors",
        "--retry-delay",
        "1",
        "-sS",
        "-D",
        "-",
    ]
    for header in headers or []:
        cmd += ["-H", header]
    if cookie_jar:
        cmd += ["-b", cookie_jar, "-c", cookie_jar]
    if not body:
        cmd += ["-o", "/dev/null"]
    cmd.append(url)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5, check=False)
    return CurlResult(stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode)


def parse_json_prefix(text: str) -> Any:
    decoder = json.JSONDecoder()
    return decoder.raw_decode(text.lstrip("\ufeff\r\n\t "))[0]


def complete_final_hop_sync(
    config: JxmisConfig,
    authorize_with_authcode_url: str,
    bootstrap_jsessionid: str,
) -> dict[str, Any]:
    parsed = urlparse(authorize_with_authcode_url)
    query = parse_qs(parsed.query)
    auth_code = query.get("authCode", [""])[0]
    state_value = query.get("state", [""])[0]
    client_id = query.get("client_id", [config.client_id])[0]
    redirect_uri = query.get("redirect_uri", [config.redirect_uri])[0]
    result: dict[str, Any] = {"auth_code": auth_code, "state": state_value}
    if not auth_code:
        return result
    token_resp = curl_capture_result(
        f"{config.baseuaa_dingtalk_auth_code_url}?authCode={auth_code}",
        timeout=30,
    )
    _, token_text, token_status = parse_header_block(token_resp.stdout)
    result["auth_code_status"] = token_status
    token_json = parse_json_prefix(token_text)
    token = str((token_json.get("data") or {}).get("token", ""))
    result["authorization"] = token
    if not token:
        return result
    authorize_query = urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state_value,
    })
    fresh_authorize = f"{config.baseuaa_auth_base}?{authorize_query}"
    authorize_resp = curl_capture_result(
        fresh_authorize,
        headers=[f"Cookie: Authorization={token}"],
        body=False,
        timeout=30,
    )
    authorize_headers, _, authorize_status = parse_header_block(authorize_resp.stdout)
    callback_url = authorize_headers.get("Location") or authorize_headers.get("location") or ""
    result["authorize_status"] = authorize_status
    result["callback_url"] = callback_url
    if not callback_url:
        return result
    cookie_domain, cookie_path = derive_jxmis_cookie_scope(config.entry_url)
    with tempfile.NamedTemporaryFile(prefix="jxmis_cookie_", suffix=".txt", delete=False) as fp:
        cookie_jar = fp.name
    try:
        Path(cookie_jar).write_text(
            "# Netscape HTTP Cookie File\n"
            f"{cookie_domain}\tTRUE\t{cookie_path}\tFALSE\t0\tJSESSIONID\t"
            f"{bootstrap_jsessionid}\n",
            encoding="utf-8",
        )
        current_url = callback_url
        current_jsessionid = bootstrap_jsessionid
        for _ in range(6):
            callback_resp = curl_capture_result(current_url, cookie_jar=cookie_jar, timeout=30)
            callback_headers, _, callback_status = parse_header_block(callback_resp.stdout)
            next_jsessionid = read_cookie_value(
                str(callback_headers.get("Set-Cookie") or callback_headers.get("set-cookie") or ""),
                "JSESSIONID",
            )
            if next_jsessionid:
                current_jsessionid = next_jsessionid
            next_location = callback_headers.get("Location") or callback_headers.get("location") or ""
            if callback_status not in {301, 302, 303, 307, 308} or not next_location:
                break
            current_url = urljoin(current_url, next_location)
        verify_resp = curl_capture_result(config.keepalive_primary_url, cookie_jar=cookie_jar, timeout=30)
        _, verify_body, verify_status = parse_header_block(verify_resp.stdout)
        result["jsessionid"] = current_jsessionid
        result["verify_status"] = verify_status
        result["verify_body"] = verify_body
        result["final_url"] = config.keepalive_primary_url if verify_status == 200 else current_url
    finally:
        Path(cookie_jar).unlink(missing_ok=True)
    return result


def silent_renew_jsessionid_sync(config: JxmisConfig, authorization: str) -> dict[str, Any]:
    result: dict[str, Any] = {"authorization_present": bool(authorization), "jsessionid": ""}
    if not authorization:
        result["error"] = "missing authorization"
        return result
    bootstrap_resp = curl_capture_result(config.entry_url, body=False, timeout=30)
    bootstrap_headers, _, _ = parse_header_block(bootstrap_resp.stdout)
    authorize_url = bootstrap_headers.get("Location") or bootstrap_headers.get("location") or ""
    bootstrap_jsessionid = read_cookie_value(
        str(bootstrap_headers.get("Set-Cookie") or bootstrap_headers.get("set-cookie") or ""),
        "JSESSIONID",
    )
    if not authorize_url or not bootstrap_jsessionid:
        result["error"] = "bootstrap missing authorize_url or jsessionid"
        return result
    authorize_resp = curl_capture_result(
        authorize_url,
        headers=[f"Cookie: Authorization={authorization}"],
        body=False,
        timeout=30,
    )
    authorize_headers, _, _ = parse_header_block(authorize_resp.stdout)
    callback_url = authorize_headers.get("Location") or authorize_headers.get("location") or ""
    if not callback_url:
        result["error"] = "authorize missing callback url"
        return result
    cookie_domain, cookie_path = derive_jxmis_cookie_scope(config.entry_url)
    with tempfile.NamedTemporaryFile(prefix="jxmis_renew_", suffix=".txt", delete=False) as fp:
        cookie_jar = fp.name
    try:
        Path(cookie_jar).write_text(
            "# Netscape HTTP Cookie File\n"
            f"{cookie_domain}\tTRUE\t{cookie_path}\tFALSE\t0\tJSESSIONID\t"
            f"{bootstrap_jsessionid}\n",
            encoding="utf-8",
        )
        current_url = callback_url
        current_jsessionid = bootstrap_jsessionid
        for _ in range(6):
            callback_resp = curl_capture_result(current_url, cookie_jar=cookie_jar, timeout=30)
            callback_headers, _, callback_status = parse_header_block(callback_resp.stdout)
            next_jsessionid = read_cookie_value(
                str(callback_headers.get("Set-Cookie") or callback_headers.get("set-cookie") or ""),
                "JSESSIONID",
            )
            if next_jsessionid:
                current_jsessionid = next_jsessionid
            next_location = callback_headers.get("Location") or callback_headers.get("location") or ""
            if callback_status not in {301, 302, 303, 307, 308} or not next_location:
                break
            current_url = urljoin(current_url, next_location)
        result["jsessionid"] = current_jsessionid
        result["final_url"] = current_url
    finally:
        Path(cookie_jar).unlink(missing_ok=True)
    return result


def _looks_like_login_page(body: str) -> bool:
    content = body.lower()
    return "统一登录" in body or "oauth2/authorize" in content or "<html" in content


class JxmisConnector(Connector):
    name = "jxmis"
    display_name = "项目管理平台"

    def __init__(self, config: Any) -> None:
        if isinstance(config, JxmisConfig):
            parsed = config
        elif hasattr(config, "model_dump"):
            parsed = JxmisConfig(**config.model_dump())
        elif isinstance(config, dict):
            parsed = JxmisConfig(**config)
        else:
            parsed = JxmisConfig()
        super().__init__(parsed)
        self.config: JxmisConfig = parsed
        self.client = httpx.AsyncClient(timeout=30, verify=False, follow_redirects=False)

    @classmethod
    def default_config(cls) -> dict[str, Any]:
        return asdict(JxmisConfig())

    def tool_specs(self) -> list:
        return []

    async def connect(
        self,
        *,
        on_qr: QrCallback | None = None,
        on_status: StatusCallback | None = None,
    ) -> ConnectorLoginResult:
        state: dict[str, str] = {"qr_url": "", "jsessionid": "", "authorization": ""}
        scanned = False
        try:
            async with httpx.AsyncClient(timeout=30, verify=False, follow_redirects=False) as http:
                authorize_url, bootstrap_jsessionid = await self._fetch_jxmis_entry_bootstrap(http)
                state["jsessionid"] = bootstrap_jsessionid
                challenge = ChallengeContext.from_authorize_url(
                    authorize_url,
                    self.config.ding_client_id,
                )
                browser = BrowserFingerprint(sec_refer=authorize_url or self.config.entry_url)
                ding = DingTalkOAuthClient(http, browser)
                challenge = await self._with_retries("open_challenge", ding.open_challenge, challenge)
                ding.browser.sec_refer = challenge.challenge_url
                await self._with_retries("fetch_umid_token", ding.fetch_umid_token)
                qr_response = await self._with_retries("generate_qrcode", ding.generate_qrcode, challenge)
                qr_url = str(qr_response.get("result", ""))
                if not qr_url:
                    raise RuntimeError(f"generate_qrcode failed: {qr_response!r}")
                state["qr_url"] = qr_url
                if on_qr:
                    await on_qr(qr_url)
                if on_status:
                    await on_status("qr_pending", {"qr_url": qr_url})
                qr_code = parse_qr_confirm_code(qr_url)
                if not qr_code:
                    raise RuntimeError("qrcode url missing code")
                deadline = time.time() + self.config.login_wait_timeout_seconds
                while time.time() < deadline:
                    poll = await self._with_retries(
                        "login_with_qr",
                        ding.login_with_qr,
                        challenge,
                        code=qr_code,
                        stay_login=False,
                    )
                    if poll.get("success"):
                        confirm = await self._with_retries("confirm_auth", ding.confirm_auth, challenge)
                        auth_url = str((confirm.get("result") or {}).get("url", ""))
                        if not auth_url:
                            raise RuntimeError(f"confirm_auth missing url: {confirm!r}")
                        final_result = await asyncio.to_thread(
                            complete_final_hop_sync,
                            self.config,
                            auth_url,
                            bootstrap_jsessionid,
                        )
                        authorization = str(final_result.get("authorization", ""))
                        jsessionid = str(final_result.get("jsessionid", bootstrap_jsessionid))
                        final_url = str(final_result.get("final_url", ""))
                        ok = int(final_result.get("verify_status", 0) or 0) == 200 and bool(jsessionid)
                        if ok:
                            credentials = self._build_credentials(jsessionid, authorization)
                            if on_status:
                                await on_status("active", {"final_url": final_url})
                            return ConnectorLoginResult(
                                ok=True,
                                credentials=credentials,
                                qr_url=qr_url,
                                final_url=final_url,
                            )
                        raise RuntimeError(f"final hop verify failed: {final_result!r}")

                    error_code = str(poll.get("errorCode", ""))
                    error_state = classify_qr_poll_error(error_code)
                    if error_state == "scanned" and not scanned:
                        scanned = True
                        if on_status:
                            await on_status("scanned", {"status": "scanned"})
                    elif error_state == "invalid":
                        raise RuntimeError(f"qr invalid: {poll!r}")
                    elif error_state == "fatal":
                        raise RuntimeError(f"qr poll failed: {poll!r}")
                    await asyncio.sleep(3)
                raise TimeoutError("Timeout waiting for QR login confirmation")
        except Exception as exc:
            if on_status:
                await on_status("failed", {"error": repr(exc)})
            return ConnectorLoginResult(
                ok=False,
                qr_url=state["qr_url"],
                error_message=repr(exc),
            )

    async def verify(self, credentials: dict[str, Any]) -> tuple[bool, str]:
        headers = self._headers_from_credentials(credentials)
        try:
            fallback = await self.client.get(
                self.config.keepalive_fallback_url,
                headers=headers,
                follow_redirects=False,
            )
        except Exception as exc:
            return False, f"verify failed: {exc!r}"
        if fallback.status_code == 200:
            return True, "business ok"
        if fallback.status_code in {301, 302, 303, 307, 308}:
            return False, "business redirected to login"
        return False, f"unexpected keepalive status {fallback.status_code}"

    async def refresh(self, credentials: dict[str, Any]) -> ConnectorLoginResult:
        authorization = str(credentials.get("authorization", ""))
        result = await asyncio.to_thread(silent_renew_jsessionid_sync, self.config, authorization)
        jsessionid = str(result.get("jsessionid", ""))
        if not jsessionid:
            return ConnectorLoginResult(ok=False, error_message=str(result.get("error", "renew failed")))
        refreshed = self._build_credentials(jsessionid, authorization)
        return ConnectorLoginResult(
            ok=True,
            credentials=refreshed,
            final_url=str(result.get("final_url", "")),
        )

    async def disconnect(self, credentials: dict[str, Any]) -> None:
        return None

    async def call_tool(
        self,
        tool_name: str,
        credentials: dict[str, Any],
        params: dict[str, Any],
    ) -> Any:
        raise KeyError(tool_name)

    async def get_todo_list(
        self,
        credentials: dict[str, Any],
        *,
        limit: int = 10,
        keyword: str = "",
    ) -> JxmisRequestResult:
        result = await self._get_json("rest/project/Service/pageQueryTodoList", credentials)
        if not result.ok:
            return result
        payload = result.data if isinstance(result.data, dict) else {}
        rows = payload.get("rows", [])
        if not isinstance(rows, list):
            rows = []
        normalized = [self._normalize_todo_row(row) for row in rows if isinstance(row, dict)]
        filtered = self._filter_todos(normalized, keyword=keyword)
        capped_limit = max(1, min(limit, 20))
        return JxmisRequestResult(
            ok=True,
            data={
                "items": filtered[:capped_limit],
                "returned": min(len(filtered), capped_limit),
                "matched": len(filtered),
                "source_total": payload.get("total", len(normalized)),
                "page_no": payload.get("pageNo", 1),
                "page_size": payload.get("pageSize", len(normalized)),
                "keyword": keyword,
            },
            status_code=result.status_code,
            diagnostics=result.diagnostics,
        )

    async def _get_json(
        self,
        path: str,
        credentials: dict[str, Any],
        *,
        params: dict[str, Any] | None = None,
    ) -> JxmisRequestResult:
        url = urljoin(self.config.api_base_url.rstrip("/") + "/", path)
        headers = self._headers_from_credentials(credentials)
        try:
            response = await self.client.get(url, headers=headers, params=params)
        except Exception as exc:
            return JxmisRequestResult(
                ok=False,
                error=f"请求失败：{exc!r}",
                diagnostics={"url": url, "params": params or {}},
            )
        diagnostics = {
            "url": str(response.request.url),
            "content_type": response.headers.get("content-type", ""),
            "params": params or {},
        }
        if response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("location", "")
            raise JxmisAuthRequiredError(f"请求被重定向到登录：{location or 'unknown'}")
        if response.status_code in {401, 403}:
            raise JxmisAuthRequiredError(f"认证失败，状态码 {response.status_code}")
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            body = response.text[:400]
            if _looks_like_login_page(body):
                raise JxmisAuthRequiredError("业务接口返回统一登录页")
            return JxmisRequestResult(
                ok=False,
                error="业务接口未返回 JSON",
                status_code=response.status_code,
                diagnostics={**diagnostics, "body_preview": body},
            )
        try:
            data = response.json()
        except Exception as exc:
            return JxmisRequestResult(
                ok=False,
                error=f"JSON 解析失败：{exc!r}",
                status_code=response.status_code,
                diagnostics={**diagnostics, "body_preview": response.text[:400]},
            )
        return JxmisRequestResult(
            ok=True,
            data=data,
            status_code=response.status_code,
            diagnostics=diagnostics,
        )

    async def _get_json_or_text(
        self,
        path: str,
        credentials: dict[str, Any],
        *,
        params: dict[str, Any] | None = None,
    ) -> JxmisRequestResult:
        url = urljoin(self.config.api_base_url.rstrip("/") + "/", path)
        headers = self._headers_from_credentials(credentials)
        try:
            response = await self.client.get(url, headers=headers, params=params)
        except Exception as exc:
            return JxmisRequestResult(
                ok=False,
                error=f"请求失败：{exc!r}",
                diagnostics={"url": url, "params": params or {}},
            )
        return self._parse_json_or_text_response(response, params=params or {})

    async def _post_json(
        self,
        path: str,
        credentials: dict[str, Any],
        *,
        json_data: Any,
        params: dict[str, Any] | None = None,
    ) -> JxmisRequestResult:
        url = urljoin(self.config.api_base_url.rstrip("/") + "/", path)
        headers = {
            **self._headers_from_credentials(credentials),
            "Content-Type": "application/json",
        }
        try:
            response = await self.client.post(url, headers=headers, params=params, json=json_data)
        except Exception as exc:
            return JxmisRequestResult(
                ok=False,
                error=f"请求失败：{exc!r}",
                diagnostics={"url": url, "params": params or {}},
            )
        return self._parse_json_or_text_response(response, params=params or {})

    def _parse_json_or_text_response(
        self,
        response: httpx.Response,
        *,
        params: dict[str, Any],
    ) -> JxmisRequestResult:
        diagnostics = {
            "url": str(response.request.url),
            "content_type": response.headers.get("content-type", ""),
            "params": params,
        }
        if response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("location", "")
            raise JxmisAuthRequiredError(f"请求被重定向到登录：{location or 'unknown'}")
        if response.status_code in {401, 403}:
            raise JxmisAuthRequiredError(f"认证失败，状态码 {response.status_code}")
        if not 200 <= response.status_code < 300:
            return JxmisRequestResult(
                ok=False,
                error=f"业务接口返回状态码 {response.status_code}",
                status_code=response.status_code,
                diagnostics={**diagnostics, "body_preview": response.text[:400]},
            )
        body = response.text.strip()
        if _looks_like_login_page(body):
            raise JxmisAuthRequiredError("业务接口返回统一登录页")
        content_type = response.headers.get("content-type", "")
        data: Any = body
        if "application/json" in content_type or body[:1] in {"{", "[", '"'}:
            try:
                data = response.json()
            except Exception:
                data = body
        return JxmisRequestResult(
            ok=True,
            data=data,
            status_code=response.status_code,
            diagnostics=diagnostics,
        )

    def _build_credentials(self, jsessionid: str, authorization: str) -> dict[str, Any]:
        authorization_header = f"Bearer {authorization}" if authorization else ""
        return {
            "authorization": authorization,
            "authorization_header": authorization_header,
            "cookie_header": f"JSESSIONID={jsessionid}" if jsessionid else "",
            "cookies": {"JSESSIONID": jsessionid} if jsessionid else {},
            "headers": {
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": self.config.referer_url,
                **({"Cookie": f"JSESSIONID={jsessionid}"} if jsessionid else {}),
                **({"Authorization": authorization_header} if authorization_header else {}),
            },
        }

    def _headers_from_credentials(self, credentials: dict[str, Any]) -> dict[str, str]:
        jsessionid = str((credentials.get("cookies") or {}).get("JSESSIONID", "")).strip()
        authorization = str(credentials.get("authorization_header", "")).strip()
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": self.config.referer_url,
        }
        if jsessionid:
            headers["Cookie"] = f"JSESSIONID={jsessionid}"
        if authorization:
            headers["Authorization"] = authorization
        return headers

    def _normalize_todo_row(self, row: dict[str, Any]) -> dict[str, Any]:
        form_url = str(row.get("formUrl", "") or "").strip()
        full_form_url = urljoin(self.config.api_base_url.rstrip("/") + "/", form_url.lstrip("/")) if form_url else ""
        return {
            "name": str(row.get("name", "") or ""),
            "task_name": str(row.get("taskName", "") or ""),
            "business_key": str(row.get("businessKey", "") or ""),
            "create_time": str(row.get("createTime", "") or ""),
            "assignee": str(row.get("assignee", "") or ""),
            "user_name": str(row.get("userName", "") or ""),
            "dept_name": str(row.get("deptName", "") or ""),
            "summary": str(row.get("computeValue", "") or ""),
            "form_url": form_url,
            "full_form_url": full_form_url,
            "raw": row,
        }

    def _filter_todos(self, rows: list[dict[str, Any]], *, keyword: str) -> list[dict[str, Any]]:
        needle = keyword.strip().lower()
        if not needle:
            return rows
        filtered: list[dict[str, Any]] = []
        for row in rows:
            haystack = " ".join(
                [
                    row.get("name", ""),
                    row.get("task_name", ""),
                    row.get("user_name", ""),
                    row.get("dept_name", ""),
                    row.get("summary", ""),
                ]
            ).lower()
            if needle in haystack:
                filtered.append(row)
        return filtered

    async def _fetch_jxmis_entry_bootstrap(
        self,
        http: httpx.AsyncClient,
    ) -> tuple[str, str]:
        last_location = ""
        last_set_cookie = ""
        for _ in range(self.config.request_retries):
            response = await http.get(self.config.entry_url, follow_redirects=False)
            last_location = response.headers.get("Location", "")
            last_set_cookie = response.headers.get("Set-Cookie", "")
            if last_location and last_set_cookie:
                break
        jsessionid = read_cookie_value(last_set_cookie, "JSESSIONID")
        if not last_location:
            raise RuntimeError("jxmis entry bootstrap missing redirect location")
        if not jsessionid:
            raise RuntimeError("jxmis entry bootstrap missing JSESSIONID")
        return last_location, jsessionid

    async def _with_retries(self, name: str, func, *args, **kwargs):
        last_exc: Exception | None = None
        for attempt in range(1, self.config.request_retries + 1):
            try:
                return await func(*args, **kwargs)
            except Exception as exc:
                last_exc = exc
                if attempt >= self.config.request_retries:
                    break
                await asyncio.sleep(min(2 * attempt, 5))
        assert last_exc is not None
        raise RuntimeError(f"{name} failed: {last_exc!r}") from last_exc
