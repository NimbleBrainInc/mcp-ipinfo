# MCP Server IPInfo

![GitHub License](https://img.shields.io/github/license/nimblebraininc/mcp-ipinfo)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/nimblebraininc/mcp-ipinfo/ci.yaml)

This is a version of the MCP Server for IPInfo that implements the complete IPInfo OpenAPI specification with strongly-typed models and comprehensive tool coverage.

## Features

- **Full OpenAPI Spec Implementation**: Complete implementation of IPInfo's OpenAPI specification
- **Strongly Typed**: All API responses use Pydantic models for type safety
- **HTTP Transport**: Supports streamable-http transport with health endpoint
- **Comprehensive Tools**: 25+ MCP tools covering all IPInfo API endpoints
- **Backward Compatible**: Maintains the original `get_ip_details` tool for compatibility

## Installation

```bash
# Using uv (recommended)
uv pip install -e .

# Or with pip
pip install -e .
```

## Configuration

Set your IPInfo API token as an environment variable:

```bash
export IPINFO_API_TOKEN=your_token_here
```

## Running the Server

### As a standalone MCP server

```bash
# Using uv
uv run mcp-ipinfo

# Or with Python
python -m mcp_ipinfo.server
```

### In Claude Code

Add this configuration to your Claude Code settings:

```json
{
  "mcpServers": {
    "ipinfo": {
      "command": "/path/to/.local/bin/uv",
      "args": [
        "--directory",
        "/path/to/mcp-server-ipinfo",
        "run",
        "mcp-ipinfo"
      ],
      "env": {
        "IPINFO_API_TOKEN": "your_ipinfo_api_token_here"
      }
    }
  }
}
```

## Available MCP Tools

### Core IP Information

- `get_ip_info(ip?)` - Get comprehensive IP information
- `get_plus_ip_info(ip)` - Get full IP intelligence via Plus API (includes privacy detection)
- `get_account_info()` - Get API account limits and features
- `batch_lookup(ips[])` - Batch lookup multiple IPs
- `summarize_ips(ips[])` - Get summary statistics for IP list
- `map_ips(ips[])` - Create visual map of IP locations

### Company & Carrier

- `get_company_info(ip)` - Get company details for an IP
- `get_carrier_info(ip)` - Get mobile carrier information

### Privacy & Security

- `get_plus_ip_info(ip)` - Detect VPN, proxy, Tor, relay (via Plus API)
- `get_residential_proxy_info(ip)` - Detect residential proxy services
- `get_abuse_contact(ip)` - Get abuse contact information

### Network Information

- `get_hosted_domains(ip, page?, limit?)` - Get domains on an IP
- `get_ip_ranges(domain)` - Get IP ranges for a domain

### WHOIS Lookups

- `whois_lookup_by_ip(ip, page?, source?)` - WHOIS by IP
- `whois_lookup_by_domain(domain, page?, source?)` - WHOIS by domain
- `whois_lookup_by_asn(asn, page?, source?)` - WHOIS by ASN

### Single Field Tools

- `get_ip_city(ip?)` - Get just the city
- `get_ip_country(ip?)` - Get just the country code
- `get_ip_region(ip?)` - Get just the region/state
- `get_ip_location(ip?)` - Get just the coordinates
- `get_ip_postal(ip?)` - Get just the postal code
- `get_ip_timezone(ip?)` - Get just the timezone
- `get_ip_hostname(ip?)` - Get just the hostname
- `get_ip_org(ip?)` - Get just the organization/ASN

## Testing

Run the test client to verify the implementation:

```bash
python test_client.py
```

## API Client Usage

You can also use the API client directly in your Python code:

```python
import asyncio
from mcp_ipinfo.api_client import IPInfoClient

async def main():
    async with IPInfoClient() as client:
        # Get current IP info
        info = await client.get_current_info()
        print(f"Current IP: {info.ip}")
        print(f"Location: {info.city}, {info.country}")

        # Get specific IP info
        google = await client.get_info_by_ip("8.8.8.8")
        print(f"Google DNS: {google.org}")

        # Privacy detection via Plus API
        plus_info = await client.get_plus_info("1.1.1.1")
        print(f"VPN detected: {plus_info.anonymous.is_vpn}")
        print(f"ASN: {plus_info.as_info.asn}")

asyncio.run(main())
```

## Type Safety

All models are strongly typed using Pydantic:

```python
from mcp_ipinfo.api_models import (
    FullResponse,      # Basic IP information
    PlusResponse,      # Comprehensive IP intelligence (geo, ASN, privacy)
    CompanyResponse,   # Company information
    RangesResponse,    # IP ranges for a domain
    # ... and many more
)
```

## Requirements

- Python 3.13+
- aiohttp
- fastmcp
- pydantic
- mcp

## About

Part of the [NimbleTools](https://www.nimbletools.ai) ecosystem.
From the makers of [NimbleBrain](https://www.nimblebrain.ai). 

## License

MIT