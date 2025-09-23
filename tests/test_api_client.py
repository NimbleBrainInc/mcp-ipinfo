"""Unit tests for the IPInfo API client."""

import os
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from aiohttp import ClientError

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
)


@pytest_asyncio.fixture
async def client():
    """Create an IPInfo client for testing."""
    client = IPInfoClient(api_token="test_token")
    yield client
    await client.close()


@pytest_asyncio.fixture
async def mock_client():
    """Create a mocked IPInfo client."""
    client = IPInfoClient(api_token="test_token")
    client._session = AsyncMock()
    yield client
    await client.close()


class TestIPInfoClient:
    """Test cases for IPInfoClient."""

    @pytest.mark.asyncio
    async def test_client_initialization(self):
        """Test client initialization with and without token."""
        # Test with explicit token
        client = IPInfoClient(api_token="explicit_token")
        assert client.api_token == "explicit_token"
        await client.close()

        # Test with environment variable
        os.environ["IPINFO_API_TOKEN"] = "env_token"
        client = IPInfoClient()
        assert client.api_token == "env_token"
        await client.close()
        del os.environ["IPINFO_API_TOKEN"]

        # Test without token
        client = IPInfoClient()
        assert client.api_token is None
        await client.close()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test using client as a context manager."""
        async with IPInfoClient(api_token="test") as client:
            assert client._session is not None
        assert client._session is None

    @pytest.mark.asyncio
    async def test_get_current_info(self, mock_client):
        """Test getting current IP information."""
        mock_response = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "org": "AS15169 Google LLC",
            "postal": "94043",
            "timezone": "America/Los_Angeles",
        }

        with patch.object(mock_client, "_request", return_value=mock_response):
            result = await mock_client.get_current_info()

        assert isinstance(result, FullResponse)
        assert result.ip == "8.8.8.8"
        assert result.city == "Mountain View"
        assert result.country == "US"

    @pytest.mark.asyncio
    async def test_get_info_by_ip(self, mock_client):
        """Test getting information for a specific IP."""
        mock_response = {
            "ip": "1.1.1.1",
            "hostname": "one.one.one.one",
            "city": "Los Angeles",
            "region": "California",
            "country": "US",
            "org": "AS13335 Cloudflare, Inc.",
        }

        with patch.object(mock_client, "_request", return_value=mock_response):
            result = await mock_client.get_info_by_ip("1.1.1.1")

        assert isinstance(result, FullResponse)
        assert result.ip == "1.1.1.1"
        assert result.hostname == "one.one.one.one"

    @pytest.mark.asyncio
    async def test_get_me(self, mock_client):
        """Test getting account information."""
        mock_response = {
            "token": "test_token",
            "requests": {"day": 100, "month": 1000, "limit": 50000},
            "features": {"core": {"daily": 50000, "monthly": 50000}},
        }

        with patch.object(mock_client, "_request", return_value=mock_response):
            result = await mock_client.get_me()

        assert isinstance(result, MeResponse)
        assert result.token == "test_token"
        assert result.requests["limit"] == 50000

    @pytest.mark.asyncio
    async def test_batch_lookup(self, mock_client):
        """Test batch IP lookup."""
        mock_response = {
            "8.8.8.8": {"ip": "8.8.8.8", "city": "Mountain View"},
            "1.1.1.1": {"ip": "1.1.1.1", "city": "Los Angeles"},
        }

        with patch.object(mock_client, "_request", return_value=mock_response):
            result = await mock_client.batch(["8.8.8.8", "1.1.1.1"])

        assert "8.8.8.8" in result
        assert "1.1.1.1" in result

    @pytest.mark.asyncio
    async def test_get_asn(self, mock_client):
        """Test getting ASN information."""
        mock_response = {
            "asn": "AS15169",
            "name": "Google LLC",
            "domain": "google.com",
            "type": "hosting",
        }

        with patch.object(mock_client, "_request", return_value=mock_response):
            result = await mock_client.get_asn(15169)

        assert isinstance(result, AsnResponse)
        assert result.asn == "AS15169"
        assert result.name == "Google LLC"

    @pytest.mark.asyncio
    async def test_get_company(self, mock_client):
        """Test getting company information."""
        mock_response = {
            "name": "Google LLC",
            "domain": "google.com",
            "type": "hosting",
        }

        with patch.object(mock_client, "_request", return_value=mock_response):
            result = await mock_client.get_company("8.8.8.8")

        assert isinstance(result, CompanyResponse)
        assert result.name == "Google LLC"
        assert result.domain == "google.com"

    @pytest.mark.asyncio
    async def test_get_carrier(self, mock_client):
        """Test getting carrier information."""
        mock_response = {
            "name": "Verizon",
            "mcc": "310",
            "mnc": "004",
        }

        with patch.object(mock_client, "_request", return_value=mock_response):
            result = await mock_client.get_carrier("1.2.3.4")

        assert isinstance(result, CarrierResponse)
        assert result.name == "Verizon"
        assert result.mcc == "310"

    @pytest.mark.asyncio
    async def test_get_privacy(self, mock_client):
        """Test getting privacy information."""
        mock_response = {
            "vpn": True,
            "proxy": False,
            "tor": False,
            "hosting": False,
            "relay": False,
            "service": "NordVPN",
        }

        with patch.object(mock_client, "_request", return_value=mock_response):
            result = await mock_client.get_privacy("1.2.3.4")

        assert isinstance(result, PrivacyResponse)
        assert result.vpn is True
        assert result.service == "NordVPN"

    @pytest.mark.asyncio
    async def test_get_domains(self, mock_client):
        """Test getting hosted domains."""
        mock_response = {
            "ip": "1.1.1.1",
            "total": 100,
            "domains": ["example.com", "test.com"],
        }

        with patch.object(mock_client, "_request", return_value=mock_response):
            result = await mock_client.get_domains("1.1.1.1", page=0, limit=10)

        assert isinstance(result, DomainsResponse)
        assert result.total == 100
        assert "example.com" in result.domains

    @pytest.mark.asyncio
    async def test_get_ranges(self, mock_client):
        """Test getting IP ranges for a domain."""
        mock_response = {
            "domain": "google.com",
            "num_ranges": "10",
            "redirects_to": "",
            "ranges": ["8.8.8.0/24", "8.8.4.0/24"],
        }

        with patch.object(mock_client, "_request", return_value=mock_response):
            result = await mock_client.get_ranges("google.com")

        assert isinstance(result, RangesResponse)
        assert result.domain == "google.com"
        assert "8.8.8.0/24" in result.ranges

    @pytest.mark.asyncio
    async def test_get_abuse(self, mock_client):
        """Test getting abuse contact information."""
        mock_response = {
            "email": "abuse@example.com",
            "phone": "+1-234-567-8900",
            "address": "123 Main St",
            "country": "US",
        }

        with patch.object(mock_client, "_request", return_value=mock_response):
            result = await mock_client.get_abuse("1.2.3.4")

        assert isinstance(result, AbuseResponse)
        assert result.email == "abuse@example.com"

    @pytest.mark.asyncio
    async def test_single_field_endpoints(self, mock_client):
        """Test single field endpoints like city, country, etc."""
        # Test get_current_city
        with patch.object(mock_client, "_request", return_value={"result": "Mountain View"}):
            city = await mock_client.get_current_city()
            assert city == "Mountain View"

        # Test get_country_by_ip
        with patch.object(mock_client, "_request", return_value={"result": "US"}):
            country = await mock_client.get_country_by_ip("8.8.8.8")
            assert country == "US"

        # Test get_location_by_ip
        with patch.object(mock_client, "_request", return_value={"result": "37.4056,-122.0775"}):
            location = await mock_client.get_location_by_ip("8.8.8.8")
            assert location == "37.4056,-122.0775"

    @pytest.mark.asyncio
    async def test_error_handling(self, mock_client):
        """Test error handling for API errors."""
        # Test 404 error
        with patch.object(
            mock_client,
            "_request",
            side_effect=IPInfoAPIError(404, "IP not found", {"error": "Not found"}),
        ):
            with pytest.raises(IPInfoAPIError) as exc_info:
                await mock_client.get_info_by_ip("999.999.999.999")
            assert exc_info.value.status == 404
            assert "not found" in exc_info.value.message.lower()

        # Test 403 error (unauthorized)
        with patch.object(
            mock_client,
            "_request",
            side_effect=IPInfoAPIError(403, "Invalid token", {"error": "Unauthorized"}),
        ):
            with pytest.raises(IPInfoAPIError) as exc_info:
                await mock_client.get_me()
            assert exc_info.value.status == 403

        # Test 429 error (rate limit)
        with patch.object(
            mock_client,
            "_request",
            side_effect=IPInfoAPIError(429, "Rate limit exceeded", None),
        ):
            with pytest.raises(IPInfoAPIError) as exc_info:
                await mock_client.get_current_info()
            assert exc_info.value.status == 429

    @pytest.mark.asyncio
    async def test_network_error_handling(self):
        """Test handling of network errors."""
        client = IPInfoClient(api_token="test_token")

        with patch.object(client, "_request", side_effect=ClientError("Connection failed")):
            with patch.object(
                client,
                "_request",
                side_effect=IPInfoAPIError(500, "Network error: Connection failed"),
            ):
                with pytest.raises(IPInfoAPIError) as exc_info:
                    await client.get_current_info()
                assert exc_info.value.status == 500
                assert "Network error" in exc_info.value.message

        await client.close()
