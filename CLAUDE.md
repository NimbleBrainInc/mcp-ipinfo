# IPInfo MCP Server

MCP server providing IP intelligence via IPInfo API.

## Architecture

```
src/mcp_ipinfo/
├── server.py      # MCP tools (FastMCP) + stdio entrypoint
├── api_client.py  # Async HTTP client
└── api_models.py  # Pydantic models
```

## Critical

- Package name: `@nimblebraininc/ipinfo` (npm-style, matches GitHub org)
- Manifest uses module execution: `python -m mcp_ipinfo.server`
- Server needs both entrypoints:
  ```python
  app = mcp.http_app()  # HTTP deployment
  if __name__ == "__main__":
      mcp.run()  # Stdio for Claude Desktop / mpak
  ```

## user_config

API token configured via manifest `user_config`, not hardcoded:
```json
{
  "user_config": {
    "api_key": {
      "type": "string",
      "sensitive": true,
      "required": false
    }
  },
  "server": {
    "mcp_config": {
      "env": { "IPINFO_API_TOKEN": "${user_config.api_key}" }
    }
  }
}
```

## Key APIs

| API | Endpoint | Used By |
|-----|----------|---------|
| Plus (primary) | `api.ipinfo.io/lookup/{ip}` | `get_plus_ip_info()` |
| Core | `ipinfo.io/{ip}` | `get_ip_info()`, `batch_lookup()` |
| Residential proxy | `/resproxy/{ip}` | `get_residential_proxy_info()` |
| Domains | `/domains/{ip}` | `get_hosted_domains()` |
| Ranges | `/ranges/{domain}` | `get_ip_ranges()` |
| Abuse | `/{ip}/abuse` | `get_abuse_contact()` |
| WHOIS | `/whois/net/{ip}` | `whois_lookup_by_*()` |

Privacy detection (VPN/proxy/Tor) is ONLY available via Plus API.

## Testing

```bash
uv run pytest tests/ -v           # Unit tests
uv run ruff check src/ tests/     # Lint
uv run mypy src/                  # Type check
```

## Releasing

Uses mcpb-pack v2 workflow. Releases trigger on `release: published`.

```bash
# New release
git tag v0.1.2 && git push origin v0.1.2
gh release create v0.1.2 --title "v0.1.2" --notes "- changelog"

# Re-release (to fix issues)
gh release delete v0.1.1 --yes
git push origin --delete v0.1.1
git tag -d v0.1.1
git tag v0.1.1
git push origin v0.1.1
gh release create v0.1.1 --title "v0.1.1" --notes "- changelog"
```

## Local Testing with mpak

```bash
mpak config set @nimblebraininc/ipinfo IPINFO_API_TOKEN=xxx
mpak bundle run @nimblebraininc/ipinfo
```

Claude Code config (`~/.claude/settings.json`):
```json
{
  "mcpServers": {
    "ipinfo": {
      "command": "mpak",
      "args": ["bundle", "run", "@nimblebraininc/ipinfo"]
    }
  }
}
```

## Adding New Endpoints

1. Add response model to `api_models.py`
2. Add client method to `api_client.py`
3. Add MCP tool to `server.py`
4. Add unit test to `tests/`
5. Add integration test to `tests-integration/`
