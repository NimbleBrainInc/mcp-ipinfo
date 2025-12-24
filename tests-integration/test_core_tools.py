"""
Core tools integration tests.

Tests basic IPInfo API functionality with real API calls.
"""

import pytest
from conftest import TestIPs

from mcp_ipinfo.api_client import IPInfoAPIError, IPInfoClient


async def has_company_access(client: IPInfoClient) -> bool:
    """Check if we have access to company API."""
    try:
        await client.get_company(TestIPs.GOOGLE_DNS)
        return True
    except IPInfoAPIError as e:
        if e.status in (401, 403):
            return False
        raise


async def has_ranges_access(client: IPInfoClient) -> bool:
    """Check if we have access to ranges API."""
    try:
        await client.get_ranges("google.com")
        return True
    except IPInfoAPIError as e:
        if e.status in (401, 403):
            return False
        raise


class TestIPLookup:
    """Test basic IP lookup functionality."""

    @pytest.mark.asyncio
    async def test_get_current_ip(self, client: IPInfoClient):
        """Test getting current IP information."""
        result = await client.get_current_info()

        assert result.ip is not None
        assert result.country is not None
        print(f"Current IP: {result.ip}, Country: {result.country}")

    @pytest.mark.asyncio
    async def test_get_google_dns_info(self, client: IPInfoClient):
        """Test looking up Google DNS IP."""
        result = await client.get_info_by_ip(TestIPs.GOOGLE_DNS)

        assert result.ip == TestIPs.GOOGLE_DNS
        assert result.city is not None
        assert result.region is not None
        assert result.country is not None
        assert result.org is not None
        assert "Google" in result.org

        print(f"Google DNS: {result.city}, {result.region}, {result.country}")
        print(f"Organization: {result.org}")

    @pytest.mark.asyncio
    async def test_get_cloudflare_dns_info(self, client: IPInfoClient):
        """Test looking up Cloudflare DNS IP."""
        result = await client.get_info_by_ip(TestIPs.CLOUDFLARE_DNS)

        assert result.ip == TestIPs.CLOUDFLARE_DNS
        assert result.org is not None
        assert "Cloudflare" in result.org

        print(f"Cloudflare DNS: {result.org}")


class TestSingleFieldLookups:
    """Test single field extraction endpoints."""

    @pytest.mark.asyncio
    async def test_get_city(self, client: IPInfoClient):
        """Test getting just the city."""
        city = await client.get_city_by_ip(TestIPs.GOOGLE_DNS)

        assert city is not None
        assert isinstance(city, str)
        print(f"City: {city}")

    @pytest.mark.asyncio
    async def test_get_country(self, client: IPInfoClient):
        """Test getting just the country code."""
        country = await client.get_country_by_ip(TestIPs.GOOGLE_DNS)

        assert country is not None
        country = country.strip()  # API may return with newline
        assert len(country) == 2  # ISO country code
        print(f"Country: {country}")

    @pytest.mark.asyncio
    async def test_get_location(self, client: IPInfoClient):
        """Test getting coordinates."""
        location = await client.get_location_by_ip(TestIPs.GOOGLE_DNS)

        assert location is not None
        assert "," in location  # Format: "lat,lon"
        print(f"Location: {location}")

    @pytest.mark.asyncio
    async def test_get_timezone(self, client: IPInfoClient):
        """Test getting timezone."""
        timezone = await client.get_timezone_by_ip(TestIPs.GOOGLE_DNS)

        assert timezone is not None
        assert "/" in timezone  # Format: "America/Los_Angeles"
        print(f"Timezone: {timezone}")

    @pytest.mark.asyncio
    async def test_get_org(self, client: IPInfoClient):
        """Test getting organization/ASN."""
        org = await client.get_org_by_ip(TestIPs.GOOGLE_DNS)

        assert org is not None
        assert "AS" in org  # Contains ASN
        assert "Google" in org
        print(f"Organization: {org}")


class TestBatchLookup:
    """Test batch IP lookup functionality."""

    @pytest.mark.asyncio
    async def test_batch_lookup_multiple_ips(self, client: IPInfoClient):
        """Test batch lookup of multiple IPs."""
        ips = [TestIPs.GOOGLE_DNS, TestIPs.CLOUDFLARE_DNS, TestIPs.QUAD9_DNS]
        result = await client.batch(ips)

        assert isinstance(result, dict)
        assert len(result) == 3

        for ip in ips:
            assert ip in result
            assert "city" in result[ip] or "org" in result[ip]

        print(f"Batch lookup returned {len(result)} results")
        for ip, data in result.items():
            print(f"  {ip}: {data.get('org', 'N/A')}")

    @pytest.mark.asyncio
    async def test_batch_lookup_with_field_paths(self, client: IPInfoClient):
        """Test batch lookup with specific field paths."""
        # IPInfo supports field paths like "8.8.8.8/city"
        ips = [
            f"{TestIPs.GOOGLE_DNS}/city",
            f"{TestIPs.CLOUDFLARE_DNS}/org",
        ]
        result = await client.batch(ips)

        assert isinstance(result, dict)
        print(f"Field path batch: {result}")


class TestAccountInfo:
    """Test account information endpoint."""

    @pytest.mark.asyncio
    async def test_get_account_info(self, client: IPInfoClient):
        """Test getting account information and limits."""
        result = await client.get_me()

        assert result.token is not None
        assert result.requests is not None

        print(f"Account token: {result.token[:10]}...")
        print(f"Requests this month: {result.requests.get('month', 0)}")
        print(f"Monthly limit: {result.requests.get('limit', 0)}")


class TestCompanyLookup:
    """Test company information lookup."""

    @pytest.mark.asyncio
    async def test_get_company_info(self, client: IPInfoClient):
        """Test getting company information for an IP."""
        if not await has_company_access(client):
            pytest.skip("Company lookup requires Business tier")

        result = await client.get_company(TestIPs.GOOGLE_DNS)

        assert result.name is not None
        print(f"Company: {result.name}")
        print(f"Domain: {result.domain}")
        print(f"Type: {result.type}")


class TestDomainsAndRanges:
    """Test hosted domains and IP ranges functionality."""

    @pytest.mark.asyncio
    async def test_get_hosted_domains(self, client: IPInfoClient):
        """Test getting domains hosted on an IP."""
        # Use Cloudflare IP which hosts many domains
        result = await client.get_domains(TestIPs.CLOUDFLARE_DNS, limit=10)

        assert result.total is not None
        assert result.domains is not None
        assert isinstance(result.domains, list)

        print(f"Total domains on {TestIPs.CLOUDFLARE_DNS}: {result.total}")
        print(f"Sample domains: {result.domains[:5]}")

    @pytest.mark.asyncio
    async def test_get_ip_ranges(self, client: IPInfoClient):
        """Test getting IP ranges for a domain."""
        if not await has_ranges_access(client):
            pytest.skip("IP ranges requires Business tier")

        result = await client.get_ranges("google.com")

        assert result.domain == "google.com"
        assert result.ranges is not None
        assert isinstance(result.ranges, list)
        assert len(result.ranges) > 0

        print(f"Google IP ranges: {len(result.ranges)} total")
        print(f"Sample ranges: {result.ranges[:3]}")


class TestAbuseContact:
    """Test abuse contact information."""

    @pytest.mark.asyncio
    async def test_get_abuse_contact(self, client: IPInfoClient):
        """Test getting abuse contact for an IP."""
        result = await client.get_abuse(TestIPs.GOOGLE_DNS)

        assert result.email is not None or result.address is not None

        print(f"Abuse email: {result.email}")
        print(f"Abuse phone: {result.phone}")
        print(f"Abuse address: {result.address}")


class TestResidentialProxy:
    """Test residential proxy detection."""

    @pytest.mark.asyncio
    async def test_non_proxy_ip_returns_empty(self, client: IPInfoClient):
        """Test that non-proxy IPs return empty response."""
        result = await client.get_residential_proxy(TestIPs.GOOGLE_DNS)

        # Google DNS is not a residential proxy, should return empty/null fields
        assert result.service is None or result.service == ""
        print(f"Google DNS residential proxy check: service={result.service}")

    @pytest.mark.asyncio
    async def test_residential_proxy_response_structure(self, client: IPInfoClient):
        """Test that residential proxy API returns expected structure."""
        result = await client.get_residential_proxy(TestIPs.CLOUDFLARE_DNS)

        # Verify the response has the expected fields (even if null)
        assert hasattr(result, "ip")
        assert hasattr(result, "last_seen")
        assert hasattr(result, "percent_days_seen")
        assert hasattr(result, "service")

        print(f"Residential proxy response: {result}")


class TestPlusAPI:
    """Test Plus API (comprehensive IP intelligence)."""

    @pytest.mark.asyncio
    async def test_plus_api_returns_full_response(self, client: IPInfoClient):
        """Test that Plus API returns comprehensive data."""
        result = await client.get_plus_info(TestIPs.GOOGLE_DNS)

        assert result.ip == TestIPs.GOOGLE_DNS
        assert result.hostname is not None

        # Check geo data
        assert result.geo is not None
        assert result.geo.city is not None
        assert result.geo.country_code == "US"

        print(f"Plus API - City: {result.geo.city}, Country: {result.geo.country}")

    @pytest.mark.asyncio
    async def test_plus_api_returns_asn_info(self, client: IPInfoClient):
        """Test that Plus API returns ASN information."""
        result = await client.get_plus_info(TestIPs.GOOGLE_DNS)

        assert result.as_info is not None
        assert result.as_info.asn == "AS15169"
        assert result.as_info.name is not None
        assert "Google" in result.as_info.name

        print(f"Plus API - ASN: {result.as_info.asn}, Name: {result.as_info.name}")

    @pytest.mark.asyncio
    async def test_plus_api_returns_privacy_detection(self, client: IPInfoClient):
        """Test that Plus API returns privacy/anonymity detection."""
        result = await client.get_plus_info(TestIPs.GOOGLE_DNS)

        assert result.anonymous is not None
        # Google DNS should not be flagged as VPN/proxy/Tor
        assert result.anonymous.is_vpn is False
        assert result.anonymous.is_proxy is False
        assert result.anonymous.is_tor is False
        assert result.is_anonymous is False

        print(f"Plus API - Anonymous: {result.anonymous}")

    @pytest.mark.asyncio
    async def test_plus_api_returns_network_flags(self, client: IPInfoClient):
        """Test that Plus API returns network characteristic flags."""
        result = await client.get_plus_info(TestIPs.GOOGLE_DNS)

        # Verify boolean flags exist
        assert isinstance(result.is_hosting, bool)
        assert isinstance(result.is_mobile, bool)
        assert isinstance(result.is_anycast, bool)
        assert isinstance(result.is_satellite, bool)

        print(f"Plus API - Hosting: {result.is_hosting}, Anycast: {result.is_anycast}")
