# IPInfo MCP Server

MCP server that provides IP intelligence tools via the IPInfo API.

## Architecture

```
src/mcp_ipinfo/
├── server.py      # MCP tool definitions (FastMCP)
├── api_client.py  # Async HTTP client for IPInfo APIs
└── api_models.py  # Pydantic response models
```

## Key APIs

### Plus API (Primary)
- Endpoint: `api.ipinfo.io/lookup/{ip}`
- Returns comprehensive data in one call: geo, ASN, privacy detection
- Used by `get_plus_ip_info()` tool
- Privacy detection (VPN/proxy/Tor) is ONLY available via Plus API

### Core API
- Endpoint: `ipinfo.io/{ip}`
- Basic IP lookup, batch, single fields
- Used by `get_ip_info()`, `batch_lookup()`, field tools

### Specialty APIs
- Residential proxy: `/resproxy/{ip}`
- Domains: `/domains/{ip}`
- Ranges: `/ranges/{domain}`
- Abuse: `/{ip}/abuse`
- WHOIS: `/whois/net/{ip}`

## MCP Tools (20 total)

| Tool | Purpose |
|------|---------|
| `get_ip_info` | Basic IP lookup |
| `get_plus_ip_info` | Comprehensive lookup with privacy detection |
| `batch_lookup` | Multiple IPs at once |
| `get_residential_proxy_info` | Detect residential proxies |
| `get_company_info` | Company details |
| `get_carrier_info` | Mobile carrier info |
| `get_hosted_domains` | Domains on an IP |
| `get_ip_ranges` | IP ranges for a domain |
| `get_abuse_contact` | Abuse contact info |
| `whois_lookup_by_*` | WHOIS lookups |
| `get_ip_*` | Single field lookups (city, country, etc.) |

## Testing

```bash
# Unit tests (no API needed)
make test

# Integration tests (requires IPINFO_API_TOKEN)
export IPINFO_API_TOKEN=your_token
make test-integration

# All CI checks
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy src/
uv run pytest tests/ -v
```

## Use Cases Tested

1. **Suspicious Login Detection** - VPN/proxy/Tor detection via Plus API
2. **DevOps Error Diagnosis** - Batch lookup, ASN grouping
3. **Geo Compliance** - Country verification, VPN blocking
4. **IP Intelligence Report** - Comprehensive IP analysis

## Environment

```bash
IPINFO_API_TOKEN=xxx  # Required for API access
```

## Common Tasks

### Add a new API endpoint
1. Add response model to `api_models.py`
2. Add client method to `api_client.py`
3. Add MCP tool to `server.py`
4. Add integration test to `tests-integration/`
5. Add unit test to `tests/`

### Run the server
```bash
uv run mcp-ipinfo
```

## Releasing

This server uses MCPB bundles. Releases are manual via git tags.

### Create a Release

```bash
# 1. Ensure you're on main with latest
git checkout main && git pull

# 2. Tag the release
git tag v1.0.0
git push origin v1.0.0

# 3. GitHub Actions builds bundles automatically
# Check: https://github.com/NimbleBrainInc/mcp-ipinfo/actions

# 4. Get SHA256 hashes from release page
# Update mcp-registry/servers/ipinfo/server.json with new version and hashes
```

### Manual Workflow Dispatch (alternative)

```bash
gh workflow run build-bundle.yml -f version=1.0.0
```

### Local Bundle Testing

```bash
# Build deps using runtime image
docker run --rm -v "$(pwd):/app" -w /app --entrypoint bash \
  nimbletools/mcpb-python:3.14 -c \
  "pip install uv && ~/.local/bin/uv pip install --target ./deps ."

# Pack and test
mcpb pack . mcp-ipinfo-v1.0.0.mcpb
python3 -m http.server 9999 &
docker run --rm -p 8000:8000 \
  --add-host host.docker.internal:host-gateway \
  -e BUNDLE_URL=http://host.docker.internal:9999/mcp-ipinfo-v1.0.0.mcpb \
  nimbletools/mcpb-python:3.14

# Verify
curl http://localhost:8000/health

# Cleanup
rm -rf deps/ *.mcpb
```
