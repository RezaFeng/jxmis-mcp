from __future__ import annotations

from jxmis_mcp_server.client import JxmisMcpClient


def test_login_response_returns_scan_url_and_data_image_by_default():
    client = JxmisMcpClient.__new__(JxmisMcpClient)

    result = client._login_session_response(
        {
            "session_id": "login-1",
            "status": "qr_pending",
            "qr_url": "https://login.dingtalk.com/example",
            "error_message": "",
        },
        include_qr_image=True,
        include_qr_terminal=False,
    )

    data = result["data"]
    assert data["qr_url"] == "https://login.dingtalk.com/example"
    assert data["ding_talk_login_url"] == "https://login.dingtalk.com/example"
    assert data["scan_url"] == "https://login.dingtalk.com/example"
    assert data["qr_image_data_url"].startswith("data:image/png;base64,")
    assert "渲染二维码图片" in data["message"]
    assert "qr_image_data_url" in data["qr_render_instruction"]
    assert "qr_terminal" not in data


def test_login_response_can_omit_data_image():
    client = JxmisMcpClient.__new__(JxmisMcpClient)

    result = client._login_session_response(
        {
            "session_id": "login-1",
            "status": "qr_pending",
            "qr_url": "https://login.dingtalk.com/example",
            "error_message": "",
        },
        include_qr_image=False,
        include_qr_terminal=False,
    )

    assert "qr_image_data_url" not in result["data"]


def test_login_response_can_include_terminal_qr_when_requested():
    client = JxmisMcpClient.__new__(JxmisMcpClient)

    result = client._login_session_response(
        {
            "session_id": "login-1",
            "status": "qr_pending",
            "qr_url": "https://login.dingtalk.com/example",
            "error_message": "",
        },
        include_qr_image=False,
        include_qr_terminal=True,
    )

    assert result["data"]["qr_terminal"]
