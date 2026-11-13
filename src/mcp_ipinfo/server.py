import logging
import os
import sys
from importlib.resources import files
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_ipinfo.api_client import IPInfoAPIError, IPInfoClient
from mcp_ipinfo.api_models import (
    AbuseResponse,
    CarrierResponse,
    CompanyResponse,
    DomainsResponse,
    FullResponse,
    MeResponse,
    PlusResponse,
    RangesResponse,
    ResidentialProxyResponse,
    WhoisSource,
)

# Diagnostics go to stderr (stdout carries JSON-RPC), never to the client: MCP's logging
# capability is deprecated as of the 2026-07-28 protocol (SEP-2577). A failure the caller
# must see is raised as a ToolError.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("mcp_ipinfo")

# Create an MCP server with HTTP transport support
mcp = FastMCP(
    "IPInfo",
    instructions=(
        "Before using IPInfo tools, read the skill://ipinfo/usage resource "
        "for tool selection guidance and context reuse patterns."
    ),
)


SKILL_CONTENT = files("mcp_ipinfo").joinpath("SKILL.md").read_text()


@mcp.resource("skill://ipinfo/usage")
def ipinfo_skill() -> str:
    """How to effectively use IPInfo tools: context reuse, tool selection, VPN detection."""
    return SKILL_CONTENT


# Global client instance for new API
_client: IPInfoClient | None = None


def get_client() -> IPInfoClient:
    """Get or create the API client instance."""
    global _client
    if _client is None:
        api_token = os.environ.get("IPINFO_API_TOKEN")
        if not api_token:
            logger.warning("IPINFO_API_TOKEN is not set - some features may be limited")
        _client = IPInfoClient(api_token=api_token)
    return _client


# Health endpoint for HTTP transport
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint for monitoring."""
    return JSONResponse({"status": "healthy"})


# Main IP information tool


@mcp.tool()
async def get_ip_info(ip: str | None) -> FullResponse:
    """Get comprehensive information about an IP address.

    Args:
        ip: IP address to lookup. If None, returns info about current IP.

    Returns:
        Complete IP information including location, ASN, company, privacy, etc.
    """
    client = get_client()
    try:
        if ip:
            return await client.get_info_by_ip(ip)
        else:
            return await client.get_current_info()
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def get_account_info() -> MeResponse:
    """Get IPInfo account information and API limits.

    Returns:
        Account information including API limits and available features.
    """
    client = get_client()
    try:
        return await client.get_me()
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def batch_lookup(ips: list[str]) -> dict[str, Any]:
    """Batch lookup multiple IP addresses.

    Args:
        ips: List of IP addresses to lookup (can include field paths like "8.8.8.8/city")

    Returns:
        Dictionary with IP information for each address.
    """
    client = get_client()
    try:
        return await client.batch(ips)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def summarize_ips(ips: list[str]) -> dict[str, Any]:
    """Summarize a list of IP addresses with statistics and insights.

    Args:
        ips: List of IP addresses to summarize (up to 500,000)

    Returns:
        Summary report with statistics and map URL.
    """
    client = get_client()
    ips_text = "\n".join(ips)
    try:
        return await client.summarize_ips(ips_text)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def map_ips(ips: list[str]) -> dict[str, Any]:
    """Create a visual map of IP address locations.

    Args:
        ips: List of IP addresses to map (up to 500,000)

    Returns:
        Map report with visualization URL.
    """
    client = get_client()
    ips_text = "\n".join(ips)
    try:
        return await client.map_ips(ips_text)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


# Company tools


@mcp.tool()
async def get_company_info(ip: str) -> CompanyResponse:
    """Get company information for an IP address.

    Args:
        ip: IP address to lookup

    Returns:
        Company name, domain, and type.
    """
    client = get_client()
    try:
        return await client.get_company(ip)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


# Carrier tools


@mcp.tool()
async def get_carrier_info(ip: str) -> CarrierResponse:
    """Get mobile carrier information for an IP address.

    Args:
        ip: IP address to lookup

    Returns:
        Mobile carrier details including MCC and MNC codes.
    """
    client = get_client()
    try:
        return await client.get_carrier(ip)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


# Residential proxy and Plus API tools


@mcp.tool()
async def get_residential_proxy_info(ip: str) -> ResidentialProxyResponse:
    """Detect if an IP is a residential proxy and get activity details.

    Identifies IPs associated with residential proxy services, including mobile/carrier
    and datacenter-based proxies. Useful for fraud detection and risk assessment.

    Args:
        ip: IP address to check

    Returns:
        Residential proxy data including service name, last seen date, and activity
        percentage. Returns empty fields if the IP is not a residential proxy.
    """
    client = get_client()
    try:
        return await client.get_residential_proxy(ip)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def get_plus_ip_info(ip: str) -> PlusResponse:
    """Get comprehensive IP intelligence using the Plus API.

    Returns detailed geolocation, ASN information, privacy/anonymity detection,
    and network characteristics in a single call. This is the recommended endpoint
    for complete IP analysis.

    Args:
        ip: IP address to lookup

    Returns:
        Comprehensive data including:
        - geo: City, region, country, coordinates, timezone
        - as_info: ASN, organization name, domain, type
        - anonymous: VPN, proxy, Tor, relay detection
        - Flags: is_anonymous, is_hosting, is_mobile, is_anycast, is_satellite
    """
    client = get_client()
    try:
        return await client.get_plus_info(ip)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


# Domains tools


@mcp.tool()
async def get_hosted_domains(
    ip: str, page: int | None = None, limit: int | None = None
) -> DomainsResponse:
    """Get domains hosted on an IP address.

    Args:
        ip: IP address to lookup
        page: Page number (starts at 0)
        limit: Number of results per page (max 1000, default 100)

    Returns:
        List of domains hosted on the IP address.
    """
    client = get_client()
    try:
        return await client.get_domains(ip, page, limit)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


# Ranges tools


@mcp.tool()
async def get_ip_ranges(domain: str) -> RangesResponse:
    """Get IP ranges owned by a domain/organization.

    Args:
        domain: Domain name to lookup

    Returns:
        IP ranges information including IPv4 and IPv6 blocks.
    """
    client = get_client()
    try:
        return await client.get_ranges(domain)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


# Abuse tools


@mcp.tool()
async def get_abuse_contact(ip: str) -> AbuseResponse:
    """Get abuse contact information for an IP address.

    Args:
        ip: IP address to lookup

    Returns:
        Abuse contact details including email, phone, and address.
    """
    client = get_client()
    try:
        return await client.get_abuse(ip)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


# WHOIS tools


@mcp.tool()
async def whois_lookup_by_ip(
    ip: str, page: int | None = None, source: str | None = None
) -> dict[str, Any]:
    """WHOIS lookup by IP address or IP range.

    Args:
        ip: IP address or range to lookup
        page: Page number for paginated results
        source: Filter by WHOIS source (arin, ripe, afrinic, apnic, lacnic)

    Returns:
        WHOIS records for the IP or range.
    """
    client = get_client()
    whois_source = WhoisSource(source) if source else None
    try:
        result = await client.get_whois_net_by_ip(ip, page, whois_source)
        return result.model_dump(exclude_none=True)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def whois_lookup_by_domain(
    domain: str, page: int | None = None, source: str | None = None
) -> dict[str, Any]:
    """WHOIS lookup by organization domain.

    Args:
        domain: Domain name to lookup
        page: Page number for paginated results
        source: Filter by WHOIS source (arin, ripe, afrinic, apnic, lacnic)

    Returns:
        WHOIS records for the domain.
    """
    client = get_client()
    whois_source = WhoisSource(source) if source else None
    try:
        result = await client.get_whois_net_by_domain(domain, page, whois_source)
        return result.model_dump(exclude_none=True)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def whois_lookup_by_asn(
    asn: int, page: int | None = None, source: str | None = None
) -> dict[str, Any]:
    """WHOIS lookup by ASN.

    Args:
        asn: ASN number to lookup
        page: Page number for paginated results
        source: Filter by WHOIS source (arin, ripe, afrinic, apnic, lacnic)

    Returns:
        WHOIS records for the ASN.
    """
    client = get_client()
    whois_source = WhoisSource(source) if source else None
    try:
        result = await client.get_whois_net_by_asn(asn, page, whois_source)
        return result.model_dump(exclude_none=True)
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


# Single field tools


@mcp.tool()
async def get_ip_city(ip: str | None = None) -> str:
    """Get just the city for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current city.

    Returns:
        City name.
    """
    client = get_client()
    try:
        if ip:
            return await client.get_city_by_ip(ip)
        else:
            return await client.get_current_city()
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def get_ip_country(ip: str | None = None) -> str:
    """Get just the country code for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current country.

    Returns:
        Two-letter country code (ISO-3166).
    """
    client = get_client()
    try:
        if ip:
            return await client.get_country_by_ip(ip)
        else:
            return await client.get_current_country()
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def get_ip_region(ip: str | None = None) -> str:
    """Get just the region/state for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current region.

    Returns:
        Region or state name.
    """
    client = get_client()
    try:
        if ip:
            return await client.get_region_by_ip(ip)
        else:
            return await client.get_current_region()
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def get_ip_location(ip: str | None = None) -> str:
    """Get just the coordinates for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current location.

    Returns:
        Latitude,longitude coordinates.
    """
    client = get_client()
    try:
        if ip:
            return await client.get_location_by_ip(ip)
        else:
            return await client.get_current_location()
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def get_ip_postal(ip: str | None = None) -> str:
    """Get just the postal code for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current postal code.

    Returns:
        Postal or ZIP code.
    """
    client = get_client()
    try:
        if ip:
            return await client.get_postal_by_ip(ip)
        else:
            return await client.get_current_postal()
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def get_ip_timezone(ip: str | None = None) -> str:
    """Get just the timezone for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current timezone.

    Returns:
        IANA timezone string.
    """
    client = get_client()
    try:
        if ip:
            return await client.get_timezone_by_ip(ip)
        else:
            return await client.get_current_timezone()
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def get_ip_hostname(ip: str | None = None) -> str:
    """Get just the hostname for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current hostname.

    Returns:
        Hostname.
    """
    client = get_client()
    try:
        if ip:
            return await client.get_hostname_by_ip(ip)
        else:
            return await client.get_current_hostname()
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


@mcp.tool()
async def get_ip_org(ip: str | None = None) -> str:
    """Get just the organization/ASN for an IP address.

    Args:
        ip: IP address to lookup. If None, returns current organization.

    Returns:
        ASN and organization name.
    """
    client = get_client()
    try:
        if ip:
            return await client.get_org_by_ip(ip)
        else:
            return await client.get_current_org()
    except IPInfoAPIError as e:
        logger.warning("IPinfo API error: %s", e.message)
        raise ToolError(f"API error: {e.message}") from e


# Create ASGI application for HTTP deployment
app = mcp.http_app()


# Stdio entrypoint for Claude Desktop / mpak
if __name__ == "__main__":
    mcp.run()
