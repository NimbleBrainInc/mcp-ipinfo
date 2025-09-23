"""Unit tests for the MCP server tools."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import Context

from mcp_ipinfo.server import (
    batch_lookup,
    get_abuse_contact,
    get_account_info,
    get_asn_info,
    get_carrier_info,
    get_company_info,
    get_hosted_domains,
    get_ip_city,
    get_ip_country,
    get_ip_hostname,
    get_ip_info,
    get_ip_location,
    get_ip_org,
    get_ip_postal,
    get_ip_ranges,
    get_ip_region,
    get_ip_timezone,
    get_privacy_info,
    map_ips,
    summarize_ips,
    whois_lookup_by_ip,
)


@pytest.fixture
def mock_context():
    """Create a mock MCP context."""
    ctx = MagicMock(spec=Context)
    ctx.warning = MagicMock()
    ctx.error = MagicMock()
    return ctx


class TestMCPTools:
    """Test the MCP server tools."""

    @pytest.mark.asyncio
    async def test_get_ip_info(self, mock_context):
        """Test get_ip_info tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_info_by_ip.return_value = MagicMock(
                ip="1.1.1.1",
                city="Los Angeles",
            )

            result = await get_ip_info("1.1.1.1", mock_context)

            assert result.ip == "1.1.1.1"
            mock_client.get_info_by_ip.assert_called_once_with("1.1.1.1")

    @pytest.mark.asyncio
    async def test_get_ip_info_current(self, mock_context):
        """Test get_ip_info for current IP."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_current_info.return_value = MagicMock(
                ip="192.168.1.1",
            )

            result = await get_ip_info(None, mock_context)

            assert result.ip == "192.168.1.1"
            mock_client.get_current_info.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_account_info(self, mock_context):
        """Test get_account_info tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_me.return_value = MagicMock(
                token="test_token",
                requests={"limit": 50000},
            )

            result = await get_account_info(mock_context)

            assert result.token == "test_token"
            mock_client.get_me.assert_called_once()

    @pytest.mark.asyncio
    async def test_batch_lookup(self, mock_context):
        """Test batch_lookup tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.batch.return_value = {
                "8.8.8.8": {"city": "Mountain View"},
                "1.1.1.1": {"city": "Los Angeles"},
            }

            result = await batch_lookup(["8.8.8.8", "1.1.1.1"], mock_context)

            assert "8.8.8.8" in result
            assert "1.1.1.1" in result
            mock_client.batch.assert_called_once_with(["8.8.8.8", "1.1.1.1"])

    @pytest.mark.asyncio
    async def test_summarize_ips(self, mock_context):
        """Test summarize_ips tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.summarize_ips.return_value = {
                "status": "Report Generated",
                "reportUrl": "https://example.com/report",
            }

            result = await summarize_ips(["8.8.8.8", "1.1.1.1"], mock_context)

            assert result["status"] == "Report Generated"
            mock_client.summarize_ips.assert_called_once_with("8.8.8.8\n1.1.1.1")

    @pytest.mark.asyncio
    async def test_map_ips(self, mock_context):
        """Test map_ips tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.map_ips.return_value = {
                "status": "Report Generated",
                "reportUrl": "https://example.com/map",
            }

            result = await map_ips(["8.8.8.8", "1.1.1.1"], mock_context)

            assert result["reportUrl"] == "https://example.com/map"
            mock_client.map_ips.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_asn_info(self, mock_context):
        """Test get_asn_info tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_asn.return_value = MagicMock(
                asn="AS15169",
                name="Google LLC",
            )

            result = await get_asn_info(15169, mock_context)

            assert result.asn == "AS15169"
            mock_client.get_asn.assert_called_once_with(15169)

    @pytest.mark.asyncio
    async def test_get_company_info(self, mock_context):
        """Test get_company_info tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            return_val = MagicMock()
            return_val.name = "Example Corp"
            return_val.domain = "example.com"
            mock_client.get_company.return_value = return_val

            result = await get_company_info("1.2.3.4", mock_context)

            assert result.name == "Example Corp"
            mock_client.get_company.assert_called_once_with("1.2.3.4")

    @pytest.mark.asyncio
    async def test_get_carrier_info(self, mock_context):
        """Test get_carrier_info tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            return_val = MagicMock()
            return_val.name = "Verizon"
            return_val.mcc = "310"
            return_val.mnc = "004"
            mock_client.get_carrier.return_value = return_val

            result = await get_carrier_info("1.2.3.4", mock_context)

            assert result.name == "Verizon"
            mock_client.get_carrier.assert_called_once_with("1.2.3.4")

    @pytest.mark.asyncio
    async def test_get_privacy_info(self, mock_context):
        """Test get_privacy_info tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_privacy.return_value = MagicMock(
                vpn=True,
                proxy=False,
                service="NordVPN",
            )

            result = await get_privacy_info("1.2.3.4", mock_context)

            assert result.vpn is True
            assert result.service == "NordVPN"
            mock_client.get_privacy.assert_called_once_with("1.2.3.4")

    @pytest.mark.asyncio
    async def test_get_hosted_domains(self, mock_context):
        """Test get_hosted_domains tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_domains.return_value = MagicMock(
                total=100,
                domains=["example.com", "test.com"],
            )

            result = await get_hosted_domains("1.1.1.1", mock_context, page=1, limit=50)

            assert result.total == 100
            mock_client.get_domains.assert_called_once_with("1.1.1.1", 1, 50)

    @pytest.mark.asyncio
    async def test_get_ip_ranges(self, mock_context):
        """Test get_ip_ranges tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_ranges.return_value = MagicMock(
                domain="google.com",
                ranges=["8.8.8.0/24"],
            )

            result = await get_ip_ranges("google.com", mock_context)

            assert result.domain == "google.com"
            mock_client.get_ranges.assert_called_once_with("google.com")

    @pytest.mark.asyncio
    async def test_get_abuse_contact(self, mock_context):
        """Test get_abuse_contact tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_abuse.return_value = MagicMock(
                email="abuse@example.com",
                phone="+1-234-567-8900",
            )

            result = await get_abuse_contact("1.2.3.4", mock_context)

            assert result.email == "abuse@example.com"
            mock_client.get_abuse.assert_called_once_with("1.2.3.4")

    @pytest.mark.asyncio
    async def test_whois_lookup_by_ip(self, mock_context):
        """Test whois_lookup_by_ip tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_result = MagicMock()
            mock_result.model_dump.return_value = {"net": "1.2.3.0/24", "total": 1}
            mock_client.get_whois_net_by_ip.return_value = mock_result

            result = await whois_lookup_by_ip("1.2.3.4", mock_context, page=0, source="arin")

            assert result["net"] == "1.2.3.0/24"

    @pytest.mark.asyncio
    async def test_single_field_tools(self, mock_context):
        """Test single field extraction tools."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client

            # Test get_ip_city
            mock_client.get_city_by_ip.return_value = "San Francisco"
            city = await get_ip_city(mock_context, ip="1.2.3.4")
            assert city == "San Francisco"

            # Test get_ip_country
            mock_client.get_current_country.return_value = "US"
            country = await get_ip_country(mock_context, ip=None)
            assert country == "US"

            # Test get_ip_region
            mock_client.get_region_by_ip.return_value = "California"
            region = await get_ip_region(mock_context, ip="1.2.3.4")
            assert region == "California"

            # Test get_ip_location
            mock_client.get_location_by_ip.return_value = "37.7749,-122.4194"
            location = await get_ip_location(mock_context, ip="1.2.3.4")
            assert location == "37.7749,-122.4194"

            # Test get_ip_postal
            mock_client.get_postal_by_ip.return_value = "94102"
            postal = await get_ip_postal(mock_context, ip="1.2.3.4")
            assert postal == "94102"

            # Test get_ip_timezone
            mock_client.get_timezone_by_ip.return_value = "America/Los_Angeles"
            timezone = await get_ip_timezone(mock_context, ip="1.2.3.4")
            assert timezone == "America/Los_Angeles"

            # Test get_ip_hostname
            mock_client.get_hostname_by_ip.return_value = "example.com"
            hostname = await get_ip_hostname(mock_context, ip="1.2.3.4")
            assert hostname == "example.com"

            # Test get_ip_org
            mock_client.get_org_by_ip.return_value = "AS12345 Example Org"
            org = await get_ip_org(mock_context, ip="1.2.3.4")
            assert org == "AS12345 Example Org"
