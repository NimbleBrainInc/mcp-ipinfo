import asyncio
import os
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from mcp.server.fastmcp import Context, FastMCP

from mcp_ipinfo.api_client import IPInfoAPIError, IPInfoClient
from mcp_ipinfo.api_models import (
    AbuseResponse,
    AsnResponse,
    CarrierResponse,
    CompanyResponse,
    DomainsResponse,
    FullResponse,
    MeResponse,
    PrivacyResponse,
    RangesResponse,
    WhoisSource,
)

# Create an MCP server with HTTP transport support
mcp = FastMCP("IPInfo")

# Global client instance for new API
_client: IPInfoClient | None = None


def get_client(ctx: Context[Any, Any, Any]) -> IPInfoClient:
    """Get or create the API client instance."""
    global _client
    if _client is None:
        api_token = os.environ.get("IPINFO_API_TOKEN")
        if not api_token:
            ctx.warning("IPINFO_API_TOKEN is not set - some features may be limited")
        _client = IPInfoClient(api_token=api_token)
    return _client


# Health endpoint for HTTP transport
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint for monitoring."""
    return JSONResponse({"status": "healthy"})


# Main IP information tool


@mcp.tool()
async def get_ip_info(ip: str | None, ctx: Context[Any, Any, Any]) -> FullResponse:
    """Get comprehensive information about an IP address.

    Args:
        ip: IP address to lookup. If None, returns info about current IP.
        ctx: MCP context

    Returns:
        Complete IP information including location, ASN, company, privacy, etc.
    """
    client = get_client(ctx)
    try:
        if ip:
            return await client.get_info_by_ip(ip)
        else:
            return await client.get_current_info()
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def get_account_info(ctx: Context[Any, Any, Any]) -> MeResponse:
    """Get IPInfo account information and API limits.

    Returns:
        Account information including API limits and available features.
    """
    client = get_client(ctx)
    try:
        return await client.get_me()
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def batch_lookup(ips: list[str], ctx: Context[Any, Any, Any]) -> dict[str, Any]:
    """Batch lookup multiple IP addresses.

    Args:
        ips: List of IP addresses to lookup (can include field paths like "8.8.8.8/city")

    Returns:
        Dictionary with IP information for each address.
    """
    client = get_client(ctx)
    try:
        return await client.batch(ips)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def summarize_ips(ips: list[str], ctx: Context[Any, Any, Any]) -> dict[str, Any]:
    """Summarize a list of IP addresses with statistics and insights.

    Args:
        ips: List of IP addresses to summarize (up to 500,000)

    Returns:
        Summary report with statistics and map URL.
    """
    client = get_client(ctx)
    ips_text = "\n".join(ips)
    try:
        return await client.summarize_ips(ips_text)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def map_ips(ips: list[str], ctx: Context[Any, Any, Any]) -> dict[str, Any]:
    """Create a visual map of IP address locations.

    Args:
        ips: List of IP addresses to map (up to 500,000)

    Returns:
        Map report with visualization URL.
    """
    client = get_client(ctx)
    ips_text = "\n".join(ips)
    try:
        return await client.map_ips(ips_text)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


# ASN tools


@mcp.tool()
async def get_asn_info(asn: int, ctx: Context[Any, Any, Any]) -> AsnResponse:
    """Get information about an Autonomous System Number (ASN).

    Args:
        asn: The ASN number (without 'AS' prefix)

    Returns:
        ASN information including prefixes, peers, and network details.
    """
    client = get_client(ctx)
    try:
        return await client.get_asn(asn)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


# Company tools


@mcp.tool()
async def get_company_info(ip: str, ctx: Context[Any, Any, Any]) -> CompanyResponse:
    """Get company information for an IP address.

    Args:
        ip: IP address to lookup

    Returns:
        Company name, domain, and type.
    """
    client = get_client(ctx)
    try:
        return await client.get_company(ip)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


# Carrier tools


@mcp.tool()
async def get_carrier_info(ip: str, ctx: Context[Any, Any, Any]) -> CarrierResponse:
    """Get mobile carrier information for an IP address.

    Args:
        ip: IP address to lookup

    Returns:
        Mobile carrier details including MCC and MNC codes.
    """
    client = get_client(ctx)
    try:
        return await client.get_carrier(ip)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


# Privacy detection tools


@mcp.tool()
async def get_privacy_info(ip: str, ctx: Context[Any, Any, Any]) -> PrivacyResponse:
    """Detect privacy services (VPN, proxy, Tor, etc.) for an IP address.

    Args:
        ip: IP address to check

    Returns:
        Privacy detection results including VPN, proxy, Tor, relay, and hosting status.
    """
    client = get_client(ctx)
    try:
        return await client.get_privacy(ip)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


# Domains tools


@mcp.tool()
async def get_hosted_domains(
    ip: str, ctx: Context[Any, Any, Any], page: int | None = None, limit: int | None = None
) -> DomainsResponse:
    """Get domains hosted on an IP address.

    Args:
        ip: IP address to lookup
        page: Page number (starts at 0)
        limit: Number of results per page (max 1000, default 100)

    Returns:
        List of domains hosted on the IP address.
    """
    client = get_client(ctx)
    try:
        return await client.get_domains(ip, page, limit)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


# Ranges tools


@mcp.tool()
async def get_ip_ranges(domain: str, ctx: Context[Any, Any, Any]) -> RangesResponse:
    """Get IP ranges owned by a domain/organization.

    Args:
        domain: Domain name to lookup

    Returns:
        IP ranges information including IPv4 and IPv6 blocks.
    """
    client = get_client(ctx)
    try:
        return await client.get_ranges(domain)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


# Abuse tools


@mcp.tool()
async def get_abuse_contact(ip: str, ctx: Context[Any, Any, Any]) -> AbuseResponse:
    """Get abuse contact information for an IP address.

    Args:
        ip: IP address to lookup

    Returns:
        Abuse contact details including email, phone, and address.
    """
    client = get_client(ctx)
    try:
        return await client.get_abuse(ip)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


# WHOIS tools


@mcp.tool()
async def whois_lookup_by_ip(
    ip: str, ctx: Context[Any, Any, Any], page: int | None = None, source: str | None = None
) -> dict[str, Any]:
    """WHOIS lookup by IP address or IP range.

    Args:
        ip: IP address or range to lookup
        page: Page number for paginated results
        source: Filter by WHOIS source (arin, ripe, afrinic, apnic, lacnic)

    Returns:
        WHOIS records for the IP or range.
    """
    client = get_client(ctx)
    whois_source = WhoisSource(source) if source else None
    try:
        result = await client.get_whois_net_by_ip(ip, page, whois_source)
        return result.model_dump(exclude_none=True)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def whois_lookup_by_domain(
    domain: str, ctx: Context[Any, Any, Any], page: int | None = None, source: str | None = None
) -> dict[str, Any]:
    """WHOIS lookup by organization domain.

    Args:
        domain: Domain name to lookup
        page: Page number for paginated results
        source: Filter by WHOIS source (arin, ripe, afrinic, apnic, lacnic)

    Returns:
        WHOIS records for the domain.
    """
    client = get_client(ctx)
    whois_source = WhoisSource(source) if source else None
    try:
        result = await client.get_whois_net_by_domain(domain, page, whois_source)
        return result.model_dump(exclude_none=True)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def whois_lookup_by_asn(
    asn: int, ctx: Context[Any, Any, Any], page: int | None = None, source: str | None = None
) -> dict[str, Any]:
    """WHOIS lookup by ASN.

    Args:
        asn: ASN number to lookup
        page: Page number for paginated results
        source: Filter by WHOIS source (arin, ripe, afrinic, apnic, lacnic)

    Returns:
        WHOIS records for the ASN.
    """
    client = get_client(ctx)
    whois_source = WhoisSource(source) if source else None
    try:
        result = await client.get_whois_net_by_asn(asn, page, whois_source)
        return result.model_dump(exclude_none=True)
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


# Single field tools


@mcp.tool()
async def get_ip_city(ctx: Context[Any, Any, Any], ip: str | None = None) -> str:
    """Get just the city for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current city.

    Returns:
        City name.
    """
    client = get_client(ctx)
    try:
        if ip:
            return await client.get_city_by_ip(ip)
        else:
            return await client.get_current_city()
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def get_ip_country(ctx: Context[Any, Any, Any], ip: str | None = None) -> str:
    """Get just the country code for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current country.

    Returns:
        Two-letter country code (ISO-3166).
    """
    client = get_client(ctx)
    try:
        if ip:
            return await client.get_country_by_ip(ip)
        else:
            return await client.get_current_country()
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def get_ip_region(ctx: Context[Any, Any, Any], ip: str | None = None) -> str:
    """Get just the region/state for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current region.

    Returns:
        Region or state name.
    """
    client = get_client(ctx)
    try:
        if ip:
            return await client.get_region_by_ip(ip)
        else:
            return await client.get_current_region()
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def get_ip_location(ctx: Context[Any, Any, Any], ip: str | None = None) -> str:
    """Get just the coordinates for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current location.

    Returns:
        Latitude,longitude coordinates.
    """
    client = get_client(ctx)
    try:
        if ip:
            return await client.get_location_by_ip(ip)
        else:
            return await client.get_current_location()
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def get_ip_postal(ctx: Context[Any, Any, Any], ip: str | None = None) -> str:
    """Get just the postal code for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current postal code.

    Returns:
        Postal or ZIP code.
    """
    client = get_client(ctx)
    try:
        if ip:
            return await client.get_postal_by_ip(ip)
        else:
            return await client.get_current_postal()
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def get_ip_timezone(ctx: Context[Any, Any, Any], ip: str | None = None) -> str:
    """Get just the timezone for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current timezone.

    Returns:
        IANA timezone string.
    """
    client = get_client(ctx)
    try:
        if ip:
            return await client.get_timezone_by_ip(ip)
        else:
            return await client.get_current_timezone()
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def get_ip_hostname(ctx: Context[Any, Any, Any], ip: str | None = None) -> str:
    """Get just the hostname for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current hostname.

    Returns:
        Hostname.
    """
    client = get_client(ctx)
    try:
        if ip:
            return await client.get_hostname_by_ip(ip)
        else:
            return await client.get_current_hostname()
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise


@mcp.tool()
async def get_ip_org(ctx: Context[Any, Any, Any], ip: str | None = None) -> str:
    """Get just the organization/ASN for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current organization.

    Returns:
        ASN and organization name.
    """
    client = get_client(ctx)
    try:
        if ip:
            return await client.get_org_by_ip(ip)
        else:
            return await client.get_current_org()
    except IPInfoAPIError as e:
        ctx.error(f"API error: {e.message}")
        raise

# Create ASGI application for uvicorn
app = mcp.streamable_http_app()

