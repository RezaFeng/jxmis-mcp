from __future__ import annotations

from mcp import types

from jxmis_mcp_server.server import _format_tool_result


def test_qr_data_url_is_returned_as_mcp_image_content():
    result = {
        "ok": True,
        "data": {
            "status": "qr_pending",
            "qr_url": "https://example.test/scan",
            "qr_image_data_url": "data:image/png;base64,abc123",
        },
    }

    content, structured = _format_tool_result(result)

    assert structured is result
    assert isinstance(content[0], types.TextContent)
    assert isinstance(content[1], types.ImageContent)
    assert content[1].mimeType == "image/png"
    assert content[1].data == "abc123"
    assert "attached as MCP image content" in content[0].text
