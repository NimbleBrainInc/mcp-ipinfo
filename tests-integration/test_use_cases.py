"""
Full use case scenario tests.

These tests simulate complete workflows that would be implemented
as NimbleBrain playbooks for the IPInfo partnership.

Uses the Plus API (api.ipinfo.io) for comprehensive IP intelligence.
"""

from collections import defaultdict
from dataclasses import dataclass
from typing import Literal

import pytest
from conftest import TestIPs

from mcp_ipinfo.api_client import IPInfoClient

# =============================================================================
# Use Case 1: Suspicious Login Detection (Threat Response)
# =============================================================================


@dataclass
class LoginEvent:
    """Simulated login event."""

    ip: str
    user_id: str
    timestamp: str


@dataclass
class LoginRiskAssessment:
    """Result of login risk assessment."""

    ip: str
    user_id: str
    risk_level: Literal["HIGH", "MEDIUM", "LOW", "NONE"]
    action: Literal["BLOCK", "MFA_REQUIRED", "FLAG_FOR_REVIEW", "ALLOW"]
    factors: list[str]
    location: str
    organization: str


class TestSuspiciousLoginDetection:
    """
    Use Case: Threat Response - Suspicious Login Detection

    When a user logs in, check if the IP is from a VPN, proxy, or Tor.
    Determine risk level and recommended action.

    Uses Plus API for privacy detection.
    """

    @pytest.mark.asyncio
    async def test_full_login_assessment_flow(self, client: IPInfoClient):
        """
        Test the complete login assessment workflow.

        This is what a NimbleBrain playbook would execute.
        """
        # Simulate login events
        login_events = [
            LoginEvent(ip=TestIPs.GOOGLE_DNS, user_id="user_001", timestamp="2024-01-15T10:30:00Z"),
            LoginEvent(
                ip=TestIPs.CLOUDFLARE_DNS, user_id="user_002", timestamp="2024-01-15T10:31:00Z"
            ),
        ]

        assessments = []

        for event in login_events:
            # Use Plus API for comprehensive data including privacy detection
            plus_info = await client.get_plus_info(event.ip)

            # Build risk factors from Plus API anonymous detection
            factors = []
            if plus_info.anonymous:
                if plus_info.anonymous.is_vpn:
                    factors.append("VPN_DETECTED")
                if plus_info.anonymous.is_proxy:
                    factors.append("PROXY_DETECTED")
                if plus_info.anonymous.is_tor:
                    factors.append("TOR_EXIT_NODE")
                if plus_info.anonymous.is_relay:
                    factors.append("RELAY_DETECTED")
            if plus_info.is_hosting:
                factors.append("HOSTING_PROVIDER")

            # Determine risk level and action
            anon = plus_info.anonymous
            if anon and anon.is_tor:
                risk_level = "HIGH"
                action = "BLOCK"
            elif anon and (anon.is_vpn or anon.is_proxy):
                risk_level = "MEDIUM"
                action = "MFA_REQUIRED"
            elif plus_info.is_hosting:
                risk_level = "LOW"
                action = "FLAG_FOR_REVIEW"
            else:
                risk_level = "NONE"
                action = "ALLOW"

            # Build location from geo data
            geo = plus_info.geo
            location = f"{geo.city}, {geo.region}, {geo.country}" if geo else "Unknown"
            org = (
                f"{plus_info.as_info.asn} {plus_info.as_info.name}"
                if plus_info.as_info
                else "Unknown"
            )

            assessment = LoginRiskAssessment(
                ip=event.ip,
                user_id=event.user_id,
                risk_level=risk_level,
                action=action,
                factors=factors,
                location=location,
                organization=org,
            )
            assessments.append(assessment)

        # Print results
        print("\n" + "=" * 60)
        print("LOGIN RISK ASSESSMENT REPORT")
        print("=" * 60)

        for a in assessments:
            print(f"\nUser: {a.user_id}")
            print(f"IP: {a.ip}")
            print(f"Location: {a.location}")
            print(f"Organization: {a.organization}")
            print(f"Risk Level: {a.risk_level}")
            print(f"Action: {a.action}")
            print(f"Factors: {a.factors if a.factors else 'None'}")

        # Verify all assessments completed
        assert len(assessments) == len(login_events)
        for a in assessments:
            assert a.risk_level in ["HIGH", "MEDIUM", "LOW", "NONE"]
            assert a.action in ["BLOCK", "MFA_REQUIRED", "FLAG_FOR_REVIEW", "ALLOW"]


# =============================================================================
# Use Case 2: DevOps Error Diagnosis
# =============================================================================


@dataclass
class ErrorEvent:
    """Simulated error event from logs."""

    source_ip: str
    error_code: int
    endpoint: str
    timestamp: str


@dataclass
class ErrorDiagnosis:
    """Result of error source diagnosis."""

    total_errors: int
    unique_ips: int
    unique_asns: int
    dominant_asn: str | None
    dominant_percentage: float
    is_single_source: bool
    ip_details: list[dict]


class TestDevOpsErrorDiagnosis:
    """
    Use Case: DevOps Automation - Error Source Diagnosis

    When error rates spike, analyze source IPs to determine
    if errors are from a single source (potential attack or misconfigured client).
    """

    @pytest.mark.asyncio
    async def test_full_error_diagnosis_flow(self, client: IPInfoClient):
        """
        Test the complete error diagnosis workflow.

        This is what a NimbleBrain playbook would execute.
        """
        # Simulate error events (in reality, these would come from logs)
        error_events = [
            ErrorEvent(
                source_ip=TestIPs.GOOGLE_DNS,
                error_code=500,
                endpoint="/api/users",
                timestamp="10:30:01",
            ),
            ErrorEvent(
                source_ip=TestIPs.GOOGLE_DNS_SECONDARY,
                error_code=500,
                endpoint="/api/users",
                timestamp="10:30:02",
            ),
            ErrorEvent(
                source_ip=TestIPs.CLOUDFLARE_DNS,
                error_code=500,
                endpoint="/api/data",
                timestamp="10:30:03",
            ),
        ]

        # Step 1: Extract unique IPs
        unique_ips = list({e.source_ip for e in error_events})

        # Step 2: Batch lookup all IPs
        batch_results = await client.batch(unique_ips)

        # Step 3: Group by ASN
        asn_groups: dict[str, list[str]] = defaultdict(list)
        ip_details = []

        for ip in unique_ips:
            if ip in batch_results:
                data = batch_results[ip]
                org = data.get("org", "Unknown")
                asn = org.split()[0] if org else "Unknown"

                asn_groups[asn].append(ip)
                ip_details.append(
                    {
                        "ip": ip,
                        "asn": asn,
                        "org": org,
                        "city": data.get("city", "Unknown"),
                        "country": data.get("country", "Unknown"),
                    }
                )

        # Step 4: Find dominant source
        dominant_asn = None
        dominant_count = 0
        for asn, ips in asn_groups.items():
            if len(ips) > dominant_count:
                dominant_count = len(ips)
                dominant_asn = asn

        dominant_percentage = (dominant_count / len(unique_ips)) * 100 if unique_ips else 0
        is_single_source = dominant_percentage >= 80

        diagnosis = ErrorDiagnosis(
            total_errors=len(error_events),
            unique_ips=len(unique_ips),
            unique_asns=len(asn_groups),
            dominant_asn=dominant_asn,
            dominant_percentage=dominant_percentage,
            is_single_source=is_single_source,
            ip_details=ip_details,
        )

        # Print diagnosis report
        print("\n" + "=" * 60)
        print("ERROR SOURCE DIAGNOSIS REPORT")
        print("=" * 60)
        print(f"\nTotal Errors: {diagnosis.total_errors}")
        print(f"Unique Source IPs: {diagnosis.unique_ips}")
        print(f"Unique ASNs: {diagnosis.unique_asns}")
        print(f"\nDominant Source: {diagnosis.dominant_asn} ({diagnosis.dominant_percentage:.1f}%)")
        print(f"Single Source Attack: {'YES' if diagnosis.is_single_source else 'NO'}")

        print("\nIP Details:")
        for detail in diagnosis.ip_details:
            print(f"  {detail['ip']}: {detail['org']} ({detail['city']}, {detail['country']})")

        if diagnosis.is_single_source:
            print(f"\n[ALERT] Errors concentrated from {diagnosis.dominant_asn}")
            print("Recommended: Investigate this source, consider rate limiting")

        # Verify diagnosis completed
        assert diagnosis.total_errors == len(error_events)
        assert diagnosis.unique_ips > 0


# =============================================================================
# Use Case 3: Geo Compliance Check
# =============================================================================


@dataclass
class AccessRequest:
    """Simulated access request to secure resource."""

    ip: str
    user_id: str
    resource: str


@dataclass
class ComplianceResult:
    """Result of compliance check."""

    ip: str
    user_id: str
    resource: str
    country: str
    is_approved_country: bool
    is_vpn: bool
    access_granted: bool
    denial_reason: str | None


class TestGeoComplianceCheck:
    """
    Use Case: On-Prem Security & Compliance

    Check if access requests come from approved countries
    and are not using anonymizers.

    Uses Plus API for geo and privacy detection.
    """

    @pytest.mark.asyncio
    async def test_full_compliance_check_flow(self, client: IPInfoClient):
        """
        Test the complete compliance check workflow.

        This is what a NimbleBrain playbook would execute.
        """
        # Compliance configuration
        approved_countries = ["US", "CA", "GB", "DE", "FR"]
        block_vpn = True

        # Simulate access requests
        access_requests = [
            AccessRequest(ip=TestIPs.GOOGLE_DNS, user_id="user_001", resource="/secure/data"),
            AccessRequest(ip=TestIPs.CLOUDFLARE_DNS, user_id="user_002", resource="/secure/admin"),
        ]

        results = []

        for request in access_requests:
            # Use Plus API for geo and privacy in one call
            plus_info = await client.get_plus_info(request.ip)

            # Check compliance using Plus API data
            country_code = plus_info.geo.country_code if plus_info.geo else None
            is_approved_country = country_code in approved_countries

            # Check for VPN/proxy using anonymous detection
            anon = plus_info.anonymous
            is_vpn = anon and (anon.is_vpn or anon.is_proxy or anon.is_tor)

            # Determine access
            if not is_approved_country:
                access_granted = False
                denial_reason = f"Country {country_code} not in approved list"
            elif block_vpn and is_vpn:
                access_granted = False
                denial_reason = "VPN/Proxy detected, not allowed for this resource"
            else:
                access_granted = True
                denial_reason = None

            result = ComplianceResult(
                ip=request.ip,
                user_id=request.user_id,
                resource=request.resource,
                country=country_code or "Unknown",
                is_approved_country=is_approved_country,
                is_vpn=is_vpn,
                access_granted=access_granted,
                denial_reason=denial_reason,
            )
            results.append(result)

        # Print compliance report
        print("\n" + "=" * 60)
        print("COMPLIANCE CHECK REPORT")
        print("=" * 60)
        print(f"\nApproved Countries: {', '.join(approved_countries)}")
        print(f"Block VPN/Proxy: {block_vpn}")

        for r in results:
            status = "GRANTED" if r.access_granted else "DENIED"
            print(f"\nUser: {r.user_id}")
            print(f"Resource: {r.resource}")
            print(f"IP: {r.ip}")
            print(
                f"Country: {r.country} ({'Approved' if r.is_approved_country else 'Not Approved'})"
            )
            print(f"VPN/Proxy: {'Yes' if r.is_vpn else 'No'}")
            print(f"Access: {status}")
            if r.denial_reason:
                print(f"Reason: {r.denial_reason}")

        # Verify all checks completed
        assert len(results) == len(access_requests)


# =============================================================================
# Use Case 4: IP Intelligence Report
# =============================================================================


class TestIPIntelligenceReport:
    """
    Use Case: Generate comprehensive IP intelligence report.

    Combines all available data for a single IP into
    a formatted report.

    Uses Plus API for comprehensive data in one call.
    """

    @pytest.mark.asyncio
    async def test_full_intelligence_report(self, client: IPInfoClient):
        """
        Test generating a complete IP intelligence report.

        This is what a NimbleBrain playbook would execute
        for an "IP Intelligence Report" use case.
        """
        target_ip = TestIPs.GOOGLE_DNS

        # Use Plus API for comprehensive data
        plus_info = await client.get_plus_info(target_ip)
        abuse = await client.get_abuse(target_ip)

        # Extract data from Plus API response
        geo = plus_info.geo
        as_info = plus_info.as_info
        anon = plus_info.anonymous

        # Build report
        report = f"""
{"=" * 60}
IP INTELLIGENCE REPORT
{"=" * 60}

TARGET: {target_ip}
GENERATED: [timestamp]

--- BASIC INFORMATION ---
Hostname: {plus_info.hostname or "N/A"}
City: {geo.city if geo else "N/A"}
Region: {geo.region if geo else "N/A"}
Country: {geo.country if geo else "N/A"} ({geo.country_code if geo else "N/A"})
Postal: {geo.postal_code if geo else "N/A"}
Timezone: {geo.timezone if geo else "N/A"}
Coordinates: {f"{geo.latitude}, {geo.longitude}" if geo else "N/A"}

--- NETWORK INFORMATION ---
ASN: {as_info.asn if as_info else "N/A"}
Organization: {as_info.name if as_info else "N/A"}
Domain: {as_info.domain if as_info else "N/A"}
Type: {as_info.type if as_info else "N/A"}

--- NETWORK FLAGS ---
Hosting: {"Yes" if plus_info.is_hosting else "No"}
Mobile: {"Yes" if plus_info.is_mobile else "No"}
Anycast: {"Yes" if plus_info.is_anycast else "No"}
Satellite: {"Yes" if plus_info.is_satellite else "No"}

--- PRIVACY/THREAT INDICATORS ---
Anonymous: {"Yes" if plus_info.is_anonymous else "No"}
VPN: {"Yes" if anon and anon.is_vpn else "No"}
Proxy: {"Yes" if anon and anon.is_proxy else "No"}
Tor: {"Yes" if anon and anon.is_tor else "No"}
Relay: {"Yes" if anon and anon.is_relay else "No"}
Service: {anon.name if anon and anon.name else "N/A"}

--- ABUSE CONTACT ---
Email: {abuse.email or "N/A"}
Phone: {abuse.phone or "N/A"}
Address: {abuse.address or "N/A"}
Country: {abuse.country or "N/A"}

--- RISK ASSESSMENT ---
"""
        # Calculate risk score
        risk_score = 0
        risk_factors = []

        if anon and anon.is_tor:
            risk_score += 50
            risk_factors.append("Tor exit node (+50)")
        if anon and anon.is_vpn:
            risk_score += 20
            risk_factors.append("VPN detected (+20)")
        if anon and anon.is_proxy:
            risk_score += 30
            risk_factors.append("Proxy detected (+30)")
        if plus_info.is_hosting:
            risk_score += 10
            risk_factors.append("Hosting provider (+10)")

        if risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 20:
            risk_level = "MEDIUM"
        elif risk_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        report += f"Risk Score: {risk_score}/100\n"
        report += f"Risk Level: {risk_level}\n"
        if risk_factors:
            report += f"Factors: {', '.join(risk_factors)}\n"
        else:
            report += "Factors: None detected\n"

        report += f"\n{'=' * 60}\n"

        print(report)

        # Verify report was generated
        assert target_ip in report
        assert geo.country if geo else True
