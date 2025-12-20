"""
Shared fixtures and configuration for integration tests.

These tests require a valid IPINFO_API_TOKEN environment variable.
They make real API calls to IPInfo and should not be run in CI without proper setup.

Uses the Plus API (api.ipinfo.io) for comprehensive IP intelligence.
"""

import os

import pytest
import pytest_asyncio

from mcp_ipinfo.api_client import IPInfoClient


def pytest_configure(config):
    """Check for required environment variables before running tests."""
    if not os.environ.get("IPINFO_API_TOKEN"):
        pytest.exit(
            "ERROR: IPINFO_API_TOKEN environment variable is required.\n"
            "Set it before running integration tests:\n"
            "  export IPINFO_API_TOKEN=your_token_here\n"
            "  make test-integration"
        )


@pytest.fixture
def api_token() -> str:
    """Get the IPInfo API token from environment."""
    token = os.environ.get("IPINFO_API_TOKEN")
    if not token:
        pytest.skip("IPINFO_API_TOKEN not set")
    return token


@pytest_asyncio.fixture
async def client(api_token: str) -> IPInfoClient:
    """Create an IPInfo client for testing."""
    client = IPInfoClient(api_token=api_token)
    yield client
    await client.close()


# Well-known test IPs
class TestIPs:
    """Well-known IPs for testing."""

    # Google DNS - reliable, always available
    GOOGLE_DNS = "8.8.8.8"
    GOOGLE_DNS_SECONDARY = "8.8.4.4"

    # Cloudflare DNS
    CLOUDFLARE_DNS = "1.1.1.1"

    # Quad9 DNS
    QUAD9_DNS = "9.9.9.9"

    # Known hosting providers
    AWS_IP = "52.94.76.1"  # AWS
    AZURE_IP = "20.60.0.1"  # Azure

    # Batch of IPs for testing
    BATCH_IPS = [GOOGLE_DNS, CLOUDFLARE_DNS, QUAD9_DNS]


@pytest.fixture
def test_ips() -> type[TestIPs]:
    """Provide test IP constants."""
    return TestIPs
