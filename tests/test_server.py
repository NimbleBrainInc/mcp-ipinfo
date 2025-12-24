"""Unit tests for the MCP server tools."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import Client

from mcp_ipinfo.api_models import (
    AbuseResponse,
    CarrierResponse,
    CompanyResponse,
    CompanyType,
    DomainsResponse,
    FullResponse,
    MeResponse,
    RangesResponse,
)
from mcp_ipinfo.server import mcp


@pytest.fixture
def mcp_server():
    """Return the MCP server instance."""
    return mcp


class TestMCPTools:
    """Test the MCP server tools."""

    @pytest.mark.asyncio
    async def test_get_ip_info(self, mcp_server):
        """Test get_ip_info tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_info_by_ip.return_value = FullResponse(
                ip="1.1.1.1",
                city="Los Angeles",
            )

            async with Client(mcp_server) as client:
                result = await client.call_tool("get_ip_info", {"ip": "1.1.1.1"})

            assert result is not None
            mock_client.get_info_by_ip.assert_called_once_with("1.1.1.1")

    @pytest.mark.asyncio
    async def test_get_ip_info_current(self, mcp_server):
        """Test get_ip_info for current IP."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_current_info.return_value = FullResponse(
                ip="192.168.1.1",
            )

            async with Client(mcp_server) as client:
                result = await client.call_tool("get_ip_info", {"ip": None})

            assert result is not None
            mock_client.get_current_info.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_account_info(self, mcp_server):
        """Test get_account_info tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_me.return_value = MeResponse(
                token="test_token",
                requests={"limit": 50000},
                features={},
            )

            async with Client(mcp_server) as client:
                result = await client.call_tool("get_account_info", {})

            assert result is not None
            mock_client.get_me.assert_called_once()

    @pytest.mark.asyncio
    async def test_batch_lookup(self, mcp_server):
        """Test batch_lookup tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.batch.return_value = {
                "8.8.8.8": {"city": "Mountain View"},
                "1.1.1.1": {"city": "Los Angeles"},
            }

            async with Client(mcp_server) as client:
                result = await client.call_tool("batch_lookup", {"ips": ["8.8.8.8", "1.1.1.1"]})

            assert result is not None
            mock_client.batch.assert_called_once_with(["8.8.8.8", "1.1.1.1"])

    @pytest.mark.asyncio
    async def test_summarize_ips(self, mcp_server):
        """Test summarize_ips tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.summarize_ips.return_value = {
                "status": "Report Generated",
                "reportUrl": "https://example.com/report",
            }

            async with Client(mcp_server) as client:
                result = await client.call_tool("summarize_ips", {"ips": ["8.8.8.8", "1.1.1.1"]})

            assert result is not None
            mock_client.summarize_ips.assert_called_once_with("8.8.8.8\n1.1.1.1")

    @pytest.mark.asyncio
    async def test_map_ips(self, mcp_server):
        """Test map_ips tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.map_ips.return_value = {
                "status": "Report Generated",
                "reportUrl": "https://example.com/map",
            }

            async with Client(mcp_server) as client:
                result = await client.call_tool("map_ips", {"ips": ["8.8.8.8", "1.1.1.1"]})

            assert result is not None
            mock_client.map_ips.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_company_info(self, mcp_server):
        """Test get_company_info tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_company.return_value = CompanyResponse(
                name="Example Corp",
                domain="example.com",
                type=CompanyType.BUSINESS,
            )

            async with Client(mcp_server) as client:
                result = await client.call_tool("get_company_info", {"ip": "1.2.3.4"})

            assert result is not None
            mock_client.get_company.assert_called_once_with("1.2.3.4")

    @pytest.mark.asyncio
    async def test_get_carrier_info(self, mcp_server):
        """Test get_carrier_info tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_carrier.return_value = CarrierResponse(
                name="Verizon",
                mcc="310",
                mnc="004",
            )

            async with Client(mcp_server) as client:
                result = await client.call_tool("get_carrier_info", {"ip": "1.2.3.4"})

            assert result is not None
            mock_client.get_carrier.assert_called_once_with("1.2.3.4")

    @pytest.mark.asyncio
    async def test_get_hosted_domains(self, mcp_server):
        """Test get_hosted_domains tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_domains.return_value = DomainsResponse(
                total=100,
                domains=["example.com", "test.com"],
            )

            async with Client(mcp_server) as client:
                result = await client.call_tool(
                    "get_hosted_domains", {"ip": "1.1.1.1", "page": 1, "limit": 50}
                )

            assert result is not None
            mock_client.get_domains.assert_called_once_with("1.1.1.1", 1, 50)

    @pytest.mark.asyncio
    async def test_get_ip_ranges(self, mcp_server):
        """Test get_ip_ranges tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_ranges.return_value = RangesResponse(
                domain="google.com",
                num_ranges=1,
                ranges=["8.8.8.0/24"],
            )

            async with Client(mcp_server) as client:
                result = await client.call_tool("get_ip_ranges", {"domain": "google.com"})

            assert result is not None
            mock_client.get_ranges.assert_called_once_with("google.com")

    @pytest.mark.asyncio
    async def test_get_abuse_contact(self, mcp_server):
        """Test get_abuse_contact tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.get_abuse.return_value = AbuseResponse(
                email="abuse@example.com",
                phone="+1-234-567-8900",
            )

            async with Client(mcp_server) as client:
                result = await client.call_tool("get_abuse_contact", {"ip": "1.2.3.4"})

            assert result is not None
            mock_client.get_abuse.assert_called_once_with("1.2.3.4")

    @pytest.mark.asyncio
    async def test_whois_lookup_by_ip(self, mcp_server):
        """Test whois_lookup_by_ip tool."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_result = MagicMock()
            mock_result.model_dump.return_value = {"net": "1.2.3.0/24", "total": 1}
            mock_client.get_whois_net_by_ip.return_value = mock_result

            async with Client(mcp_server) as client:
                result = await client.call_tool(
                    "whois_lookup_by_ip", {"ip": "1.2.3.4", "page": 0, "source": "arin"}
                )

            assert result is not None

    @pytest.mark.asyncio
    async def test_single_field_tools(self, mcp_server):
        """Test single field extraction tools."""
        with patch("mcp_ipinfo.server.get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client

            # Test get_ip_city
            mock_client.get_city_by_ip.return_value = "San Francisco"
            async with Client(mcp_server) as client:
                result = await client.call_tool("get_ip_city", {"ip": "1.2.3.4"})
            assert result is not None

            # Test get_ip_country (current IP)
            mock_client.get_current_country.return_value = "US"
            async with Client(mcp_server) as client:
                result = await client.call_tool("get_ip_country", {})
            assert result is not None

            # Test get_ip_region
            mock_client.get_region_by_ip.return_value = "California"
            async with Client(mcp_server) as client:
                result = await client.call_tool("get_ip_region", {"ip": "1.2.3.4"})
            assert result is not None

            # Test get_ip_location
            mock_client.get_location_by_ip.return_value = "37.7749,-122.4194"
            async with Client(mcp_server) as client:
                result = await client.call_tool("get_ip_location", {"ip": "1.2.3.4"})
            assert result is not None

            # Test get_ip_postal
            mock_client.get_postal_by_ip.return_value = "94102"
            async with Client(mcp_server) as client:
                result = await client.call_tool("get_ip_postal", {"ip": "1.2.3.4"})
            assert result is not None

            # Test get_ip_timezone
            mock_client.get_timezone_by_ip.return_value = "America/Los_Angeles"
            async with Client(mcp_server) as client:
                result = await client.call_tool("get_ip_timezone", {"ip": "1.2.3.4"})
            assert result is not None

            # Test get_ip_hostname
            mock_client.get_hostname_by_ip.return_value = "example.com"
            async with Client(mcp_server) as client:
                result = await client.call_tool("get_ip_hostname", {"ip": "1.2.3.4"})
            assert result is not None

            # Test get_ip_org
            mock_client.get_org_by_ip.return_value = "AS12345 Example Org"
            async with Client(mcp_server) as client:
                result = await client.call_tool("get_ip_org", {"ip": "1.2.3.4"})
            assert result is not None
