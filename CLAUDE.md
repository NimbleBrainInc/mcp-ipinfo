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
