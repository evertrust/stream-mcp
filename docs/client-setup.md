# Client Setup

The Stream MCP server runs over **stdio**. Configure your MCP client to launch
it with the `STREAM_*` environment variables from
[authentication.md](authentication.md). All examples below use a local build
(`node /abs/path/to/stream-mcp/dist/index.js`); to use the published package
instead, replace `command`/`args` with `bunx`/`npx -y @evertrust/stream-mcp`.

## Claude Desktop

`claude_desktop_config.json` (macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "stream": {
      "command": "node",
      "args": ["/abs/path/to/stream-mcp/dist/index.js"],
      "env": {
        "STREAM_URL": "https://stream.example.com",
        "STREAM_API_ID": "my-account",
        "STREAM_API_KEY": "********",
        "STREAM_API_IDPROV": "local"
      }
    }
  }
}
```

## Claude Code

```bash
claude mcp add stream \
  --env STREAM_URL=https://stream.example.com \
  --env STREAM_API_ID=my-account \
  --env STREAM_API_KEY='********' \
  --env STREAM_API_IDPROV=local \
  -- node /abs/path/to/stream-mcp/dist/index.js
```

Or add it to `.mcp.json` in your project:

```json
{
  "mcpServers": {
    "stream": {
      "command": "node",
      "args": ["/abs/path/to/stream-mcp/dist/index.js"],
      "env": { "STREAM_URL": "https://stream.example.com", "STREAM_API_ID": "my-account", "STREAM_API_KEY": "********" }
    }
  }
}
```

## Cursor

`~/.cursor/mcp.json` (or the workspace `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "stream": {
      "command": "node",
      "args": ["/abs/path/to/stream-mcp/dist/index.js"],
      "env": { "STREAM_URL": "https://stream.example.com", "STREAM_API_ID": "my-account", "STREAM_API_KEY": "********" }
    }
  }
}
```

## Codex / OpenCode

TOML-style MCP config:

```toml
[mcp_servers.stream]
command = "node"
args = ["/abs/path/to/stream-mcp/dist/index.js"]
env = { STREAM_URL = "https://stream.example.com", STREAM_API_ID = "my-account", STREAM_API_KEY = "********" }
```

## MCP Inspector

For interactive exploration of the tool surface:

```bash
STREAM_URL=https://stream.example.com \
STREAM_API_ID=my-account STREAM_API_KEY='********' \
npx @modelcontextprotocol/inspector node /abs/path/to/stream-mcp/dist/index.js
```

## mTLS variant

For X.509 / mTLS, swap the local-account env vars for the client-certificate
ones (see [authentication.md](authentication.md)):

```json
"env": {
  "STREAM_URL": "https://stream.example.com",
  "STREAM_CLIENT_PFX": "/abs/path/to/client.p12",
  "STREAM_CLIENT_PFX_PASSWORD": "********"
}
```

## Tips

- The binary name is **`stream-mcp`** — keep the server id consistent across
  clients.
- Never commit credentials. Prefer your client's secret handling, or a
  git-ignored `.env.local` consumed by a wrapper.
- Start with the `whoami`, `search_docs`, and `list_*` tools to confirm
  connectivity and explore the instance read-only.
