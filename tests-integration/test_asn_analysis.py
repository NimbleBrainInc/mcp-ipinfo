"""
ASN analysis integration tests.

Use Case: DevOps Error Diagnosis
Tests ASN lookup, batch analysis, and grouping capabilities.

Uses Plus API for comprehensive IP intelligence including ASN data.
"""

from collections import defaultdict

import pytest
from conftest import TestIPs

from mcp_ipinfo.api_client import IPInfoAPIError, IPInfoClient


async def has_ranges_access(client: IPInfoClient) -> bool:
    """Check if we have access to ranges API."""
    try:
        await client.get_ranges("google.com")
        return True
    except IPInfoAPIError as e:
        if e.status in (401, 403):
            return False
        raise


class TestASNLookup:
    """Test ASN information lookup."""

    @pytest.mark.asyncio
    async def test_asn_from_ip(self, client: IPInfoClient):
        """Test extracting ASN from IP lookup."""
        result = await client.get_info_by_ip(TestIPs.GOOGLE_DNS)

        assert result.org is not None
        assert "AS" in result.org

        # Parse ASN from org string (format: "AS15169 Google LLC")
        asn_str = result.org.split()[0] if result.org else None

        print("\n--- ASN from IP ---")
        print(f"IP: {TestIPs.GOOGLE_DNS}")
        print(f"Org: {result.org}")
        print(f"Extracted ASN: {asn_str}")

        assert asn_str is not None
        assert asn_str.startswith("AS")


class TestDevOpsDiagnosisScenario:
    """
    Simulates the DevOps Error Diagnosis use case.

    Scenario: Error spike detected, need to identify if errors
    are coming from a single source/ASN.
    """

    @pytest.mark.asyncio
    async def test_error_source_grouping(self, client: IPInfoClient):
        """
        Test grouping error source IPs by ASN.

        Simulates analyzing a batch of IPs from error logs
        to identify if they share a common source.
        """
        # Simulate IPs from error logs
        # Using 2 Google IPs and 1 Cloudflare to test grouping
        error_ips = [
            TestIPs.GOOGLE_DNS,
            TestIPs.GOOGLE_DNS_SECONDARY,
            TestIPs.CLOUDFLARE_DNS,
        ]

        # Batch lookup all IPs
        batch_results = await client.batch(error_ips)

        # Group by ASN/Organization
        asn_groups: dict[str, list[str]] = defaultdict(list)
        for ip in error_ips:
            if ip in batch_results:
                org = batch_results[ip].get("org", "Unknown")
                asn_groups[org].append(ip)

        print("\n--- Error Source Analysis ---")
        print(f"Total error IPs: {len(error_ips)}")
        print(f"Unique ASNs/Orgs: {len(asn_groups)}")
        print("\nGrouped by Organization:")
        for org, ips in sorted(asn_groups.items(), key=lambda x: -len(x[1])):
            pct = (len(ips) / len(error_ips)) * 100
            print(f"  {org}: {len(ips)} IPs ({pct:.1f}%)")

        # Verify grouping worked
        assert len(asn_groups) >= 1
        # Google IPs should be grouped together
        google_orgs = [org for org in asn_groups if "Google" in org]
        assert len(google_orgs) >= 1

    @pytest.mark.asyncio
    async def test_single_source_detection(self, client: IPInfoClient):
        """
        Test detecting when errors come from a single source.

        If 80%+ of errors are from one ASN, flag for investigation.
        """
        # Simulate all errors from same source
        error_ips = [
            TestIPs.GOOGLE_DNS,
            TestIPs.GOOGLE_DNS_SECONDARY,
            "8.34.208.1",  # Another Google IP
        ]

        batch_results = await client.batch(error_ips)

        # Group by ASN
        asn_groups: dict[str, list[str]] = defaultdict(list)
        for ip in error_ips:
            if ip in batch_results:
                org = batch_results[ip].get("org", "Unknown")
                # Extract just the ASN part
                asn = org.split()[0] if org else "Unknown"
                asn_groups[asn].append(ip)

        # Find dominant source
        total_ips = len(error_ips)
        dominant_source = None
        dominant_pct = 0

        for asn, ips in asn_groups.items():
            pct = (len(ips) / total_ips) * 100
            if pct > dominant_pct:
                dominant_pct = pct
                dominant_source = asn

        # Determine if single source
        is_single_source = dominant_pct >= 80

        print("\n--- Single Source Detection ---")
        print(f"Total IPs: {total_ips}")
        print(f"Dominant Source: {dominant_source} ({dominant_pct:.1f}%)")
        print(f"Single Source Attack: {is_single_source}")

        if is_single_source:
            print("\n[ACTION REQUIRED] Errors concentrated from single source!")
            print(f"Recommend investigating: {dominant_source}")

        assert dominant_source is not None

    @pytest.mark.asyncio
    async def test_github_issue_generation(self, client: IPInfoClient):
        """
        Test generating a GitHub issue from error analysis.

        This simulates what would be posted to GitHub.
        """
        # Analyze error sources
        error_ips = [TestIPs.GOOGLE_DNS, TestIPs.CLOUDFLARE_DNS]
        batch_results = await client.batch(error_ips)

        # Build issue content
        ip_details = []
        for ip in error_ips:
            if ip in batch_results:
                data = batch_results[ip]
                ip_details.append(
                    {
                        "ip": ip,
                        "org": data.get("org", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "country": data.get("country", "Unknown"),
                    }
                )

        # Generate issue body
        issue_title = f"Error Spike Analysis: {len(error_ips)} Source IPs Identified"
        issue_body = f"""## Error Source Analysis

**Total Unique IPs:** {len(error_ips)}

### Source Details

| IP | Organization | Location |
|----|--------------|----------|
"""
        for detail in ip_details:
            issue_body += (
                f"| {detail['ip']} | {detail['org']} | {detail['city']}, {detail['country']} |\n"
            )

        issue_body += """
### Recommended Actions

1. Review firewall rules for identified ASNs
2. Check if these IPs should be rate-limited
3. Investigate if this is a coordinated attack
"""

        print("\n--- Generated GitHub Issue ---")
        print(f"Title: {issue_title}")
        print(f"\nBody:\n{issue_body}")

        # Verify issue content
        assert len(ip_details) == len(error_ips)
        assert "Organization" in issue_body


class TestSummarizeAndMap:
    """Test IP summarization and mapping features."""

    @pytest.mark.asyncio
    async def test_summarize_ips(self, client: IPInfoClient):
        """Test IP summarization for large batches."""
        # Summarize a list of IPs
        ips = [TestIPs.GOOGLE_DNS, TestIPs.CLOUDFLARE_DNS, TestIPs.QUAD9_DNS]
        ips_text = "\n".join(ips)

        result = await client.summarize_ips(ips_text)

        print("\n--- IP Summary ---")
        print(f"Result: {result}")

        # API returns a report URL or summary data
        assert result is not None

    @pytest.mark.asyncio
    async def test_map_ips(self, client: IPInfoClient):
        """Test creating a visual map of IPs."""
        ips = [TestIPs.GOOGLE_DNS, TestIPs.CLOUDFLARE_DNS, TestIPs.QUAD9_DNS]
        ips_text = "\n".join(ips)

        result = await client.map_ips(ips_text)

        print("\n--- IP Map ---")
        print(f"Result: {result}")

        # API returns a map URL
        assert result is not None


class TestNetworkDiagnostics:
    """Test network diagnostic capabilities."""

    @pytest.mark.asyncio
    async def test_ip_ranges_for_organization(self, client: IPInfoClient):
        """Test getting all IP ranges for an organization."""
        if not await has_ranges_access(client):
            pytest.skip("IP ranges requires Business tier")

        result = await client.get_ranges("google.com")

        assert result.domain == "google.com"
        assert result.ranges is not None
        assert len(result.ranges) > 0

        print("\n--- Google IP Ranges ---")
        print(f"Domain: {result.domain}")
        print(f"Total Ranges: {len(result.ranges)}")
        print(f"Sample: {result.ranges[:5]}")

    @pytest.mark.asyncio
    async def test_identify_hosting_provider(self, client: IPInfoClient):
        """Test identifying if IPs belong to hosting providers using Plus API."""
        test_ips = [TestIPs.GOOGLE_DNS, TestIPs.CLOUDFLARE_DNS]

        results = []
        for ip in test_ips:
            # Use Plus API for hosting detection
            plus_info = await client.get_plus_info(ip)

            org = (
                f"{plus_info.as_info.asn} {plus_info.as_info.name}"
                if plus_info.as_info
                else "Unknown"
            )
            results.append(
                {
                    "ip": ip,
                    "org": org,
                    "is_hosting": plus_info.is_hosting,
                }
            )

        print("\n--- Hosting Provider Detection ---")
        for r in results:
            status = "HOSTING" if r["is_hosting"] else "NOT HOSTING"
            print(f"{r['ip']}: {r['org']} [{status}]")

        # Verify we got results for all IPs
        assert len(results) == len(test_ips)
