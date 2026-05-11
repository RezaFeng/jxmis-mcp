# JXMIS MCP Server

Standalone remote MCP server for the JXMIS project management platform.

Users add one remote MCP JSON entry and scan DingTalk through `jxmis_connect`.
Each Bearer token owns an isolated JXMIS login state. JXMIS credentials are
encrypted before they are written to SQLite.

## MCP Client Config

```json
{
  "mcpServers": {
    "jxmis": {
      "url": "https://jxmis-mcp.rezafeng.top:8443/mcp/",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

## Local Admin Setup

```bash
cp .env.example .env
jxmis-mcp admin generate-key
```

Put the generated value in `.env` as `JXMIS_CREDENTIAL_KEY`, then create a
token:

```bash
jxmis-mcp admin create-token --name alice
jxmis-mcp admin list-tokens
jxmis-mcp admin revoke-token <token_id>
```

## Docker Deployment

```bash
docker compose up -d --build
docker compose exec jxmis-mcp jxmis-mcp admin create-token --name alice
```

Add this to your existing Caddy config:

```caddyfile
jxmis-mcp.rezafeng.top:8443 {
  reverse_proxy 127.0.0.1:8787
}
```

## Login Flow

1. Add the MCP config to the client.
2. Call `jxmis_connect`.
3. Render the returned `qr_image_data_url` as an image. If the client cannot
   render `data:` images, generate a QR image from `qr_url` /
   `ding_talk_login_url` and show that to the user.
4. Poll `jxmis_get_login_status`.
5. Use the business tools after status becomes `active`.

If the service restarts while a QR login is pending, that pending login is
marked failed. Existing active credentials remain encrypted in SQLite.

## Tool Safety

Approval write tools are available in the first release. They still require
`dry_run=false` and `confirm=true` before submitting changes:

- `jxmis_batch_approve_daily_reports`
- `jxmis_batch_approve_weekly_reports`

Every tool call is written to `audit_log` with token id, tool name, redacted
arguments, result summary, affected count, and JXMIS user summary when
available. Cookie and Authorization values are never logged.
