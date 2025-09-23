#!/usr/bin/env python3
"""Example usage of the mcp-ipinfo API client."""

import asyncio
import os

from mcp_ipinfo.api_client import IPInfoAPIError, IPInfoClient


async def main():
    """Example usage of the IPInfo API client."""

    # Set your API token (or use environment variable IPINFO_API_TOKEN)
    api_token = os.environ.get("IPINFO_API_TOKEN")

    async with IPInfoClient(api_token=api_token) as client:
        print("IPInfo API Client Example")
        print("=" * 50)

        try:
            # 1. Get current IP information
            print("\n1. Current IP Information:")
            current = await client.get_current_info()
            print(f"   IP: {current.ip}")
            print(f"   Location: {current.city}, {current.region}, {current.country}")
            print(f"   Organization: {current.org}")

            # 2. Look up a specific IP (Google DNS)
            print("\n2. Google DNS (8.8.8.8) Information:")
            google = await client.get_info_by_ip("8.8.8.8")
            print(f"   Hostname: {google.hostname}")
            print(f"   City: {google.city}")
            print(f"   Organization: {google.org}")
            print(f"   Timezone: {google.timezone}")

            # 3. Look up Cloudflare DNS
            print("\n3. Cloudflare DNS (1.1.1.1) Information:")
            cloudflare = await client.get_info_by_ip("1.1.1.1")
            print(f"   Hostname: {cloudflare.hostname}")
            print(f"   City: {cloudflare.city}")
            print(f"   Organization: {cloudflare.org}")

            # 4. Get just specific fields
            print("\n4. Single Field Lookups:")
            city = await client.get_city_by_ip("8.8.8.8")
            print(f"   8.8.8.8 city: {city}")

            country = await client.get_country_by_ip("1.1.1.1")
            print(f"   1.1.1.1 country: {country}")

            location = await client.get_location_by_ip("8.8.8.8")
            print(f"   8.8.8.8 coordinates: {location}")

            # 5. Batch lookup (multiple IPs at once)
            print("\n5. Batch Lookup:")
            batch = await client.batch(["8.8.8.8", "1.1.1.1", "9.9.9.9"])
            for ip, info in batch.items():
                if isinstance(info, dict) and "city" in info:
                    print(f"   {ip}: {info.get('city', 'Unknown')}, {info.get('org', 'Unknown')}")

            # 6. Account information (if token is provided)
            if api_token:
                print("\n6. Account Information:")
                try:
                    me = await client.get_me()
                    print(f"   Token: {me.token[:10]}...")
                    print(f"   Monthly limit: {me.requests.get('limit', 0):,}")
                    print(f"   Used this month: {me.requests.get('month', 0):,}")
                    remaining = me.requests.get("limit", 0) - me.requests.get("month", 0)
                    print(f"   Remaining: {remaining:,}")
                except IPInfoAPIError as e:
                    print(f"   Error: {e.message}")

            # 7. ASN lookup (may require paid plan)
            print("\n7. ASN Information (Google - AS15169):")
            try:
                asn = await client.get_asn(15169)
                print(f"   Name: {asn.name}")
                print(f"   Domain: {asn.domain}")
                print(f"   Type: {asn.type}")
                print(f"   Number of IPs: {asn.num_ips:,}" if asn.num_ips else "   Number of IPs: N/A")
            except IPInfoAPIError as e:
                print(f"   Error (may require paid plan): {e.message}")

            # 8. Privacy detection (may require paid plan)
            print("\n8. Privacy Detection:")
            try:
                # Test with a known VPN IP (this is an example, may not always be a VPN)
                privacy = await client.get_privacy("1.1.1.1")
                print(f"   1.1.1.1 VPN: {privacy.vpn}")
                print(f"   1.1.1.1 Proxy: {privacy.proxy}")
                print(f"   1.1.1.1 Tor: {privacy.tor}")
                print(f"   1.1.1.1 Hosting: {privacy.hosting}")
            except IPInfoAPIError as e:
                print(f"   Error (may require paid plan): {e.message}")

        except IPInfoAPIError as e:
            print(f"\nAPI Error: {e.message}")
            print(f"Status Code: {e.status}")
        except Exception as e:
            print(f"\nUnexpected Error: {e}")


if __name__ == "__main__":
    print("Starting IPInfo API Client Example...")
    print("Make sure IPINFO_API_TOKEN environment variable is set for full functionality.\n")
    asyncio.run(main())