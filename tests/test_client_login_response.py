from __future__ import annotations

from jxmis_mcp_server.client import JxmisMcpClient


def test_login_response_returns_scan_url_without_image_or_terminal_by_default():
    client = JxmisMcpClient.__new__(JxmisMcpClient)

    result = client._login_session_response(
        {
            "session_id": "login-1",
            "status": "qr_pending",
            "qr_url": "https://login.dingtalk.com/example",
            "error_message": "",
        },
        include_qr_terminal=False,
    )

    data = result["data"]
    assert data["qr_url"] == "https://login.dingtalk.com/example"
    assert data["ding_talk_login_url"] == "https://login.dingtalk.com/example"
    assert data["scan_url"] == "https://login.dingtalk.com/example"
    assert "qr_image_data_url" not in data
    assert "qr_terminal" not in data


def test_login_response_can_include_terminal_qr_when_requested():
    client = JxmisMcpClient.__new__(JxmisMcpClient)

    result = client._login_session_response(
        {
            "session_id": "login-1",
            "status": "qr_pending",
            "qr_url": "https://login.dingtalk.com/example",
            "error_message": "",
        },
        include_qr_terminal=True,
    )

    assert result["data"]["qr_terminal"]
