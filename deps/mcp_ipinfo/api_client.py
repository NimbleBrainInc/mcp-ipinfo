import os
from typing import Any

import aiohttp
from aiohttp import ClientError

from .api_models import (
    AbuseResponse,
    CarrierResponse,
    CompanyResponse,
    DomainsResponse,
    FullResponse,
    MeResponse,
    PlusResponse,
    RangesResponse,
    ResidentialProxyResponse,
    WhoisAsnResponse,
    WhoisDomainResponse,
    WhoisIpResponse,
    WhoisNetIdResponse,
    WhoisOrgResponse,
    WhoisPocResponse,
    WhoisSource,
)


class IPInfoAPIError(Exception):
    def __init__(self, status: int, message: str, details: dict[str, Any] | None = None) -> None:
        self.status = status
        self.message = message
        self.details = details
        super().__init__(f"IPInfo API Error {status}: {message}")


class IPInfoClient:
    def __init__(
        self,
        api_token: str | None = None,
        base_url: str = "https://ipinfo.io",
        timeout: float = 30.0,
    ) -> None:
        self.api_token = api_token or os.environ.get("IPINFO_API_TOKEN")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "IPInfoClient":
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def _ensure_session(self) -> None:
        if not self._session:
            headers = {"User-Agent": "mcp-server-ipinfo/2.0", "Accept": "application/json"}
            if self.api_token:
                headers["Authorization"] = f"Bearer {self.api_token}"

            self._session = aiohttp.ClientSession(
                headers=headers, timeout=aiohttp.ClientTimeout(total=self.timeout)
            )

    async def close(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
        data: str | None = None,
        content_type: str | None = None,
    ) -> dict[str, Any]:
        await self._ensure_session()

        url = f"{self.base_url}{path}"

        # Add token to params if not using Bearer auth
        if self.api_token and params is None:
            params = {}
        if self.api_token and params is not None:
            params["token"] = self.api_token

        kwargs = {}
        if json_data is not None:
            kwargs["json"] = json_data
        elif data is not None:
            kwargs["data"] = data
            if content_type:
                kwargs["headers"] = {"Content-Type": content_type}

        try:
            if not self._session:
                raise RuntimeError("Session not initialized")
            async with self._session.request(method, url, params=params, **kwargs) as response:
                # Handle different content types
                content_type = response.headers.get("Content-Type", "")

                if "application/json" in content_type:
                    result = await response.json()
                elif "text/plain" in content_type:
                    text = await response.text()
                    return {"result": text}
                else:
                    text = await response.text()

                    # Try to parse as JSON if it looks like JSON
                    if text.startswith("{") or text.startswith("["):
                        import json

                        try:
                            result = json.loads(text)
                        except json.JSONDecodeError:
                            result = {"result": text}
                    else:
                        result = {"result": text}

                # Check for errors
                if response.status >= 400:
                    error_msg = "Unknown error"
                    if isinstance(result, dict):
                        if "error" in result:
                            if isinstance(result["error"], dict):
                                error_msg = result["error"].get("message", str(result["error"]))
                            else:
                                error_msg = str(result["error"])
                        elif "message" in result:
                            error_msg = result["message"]
                        elif "title" in result:
                            error_msg = result["title"]

                    raise IPInfoAPIError(response.status, error_msg, result)

                return result  # type: ignore[no-any-return]

        except ClientError as e:
            raise IPInfoAPIError(500, f"Network error: {str(e)}") from e

    # Main API endpoints

    async def get_current_info(self) -> FullResponse:
        """Get information about the current IP."""
        data = await self._request("GET", "/")
        return FullResponse(**data)

    async def get_info_by_ip(self, ip: str) -> FullResponse:
        """Get information about a specific IP address."""
        data = await self._request("GET", f"/{ip}")
        return FullResponse(**data)

    async def get_me(self) -> MeResponse:
        """Get API token information and limits."""
        data = await self._request("GET", "/me")
        return MeResponse(**data)

    async def batch(self, ips: list[str]) -> dict[str, Any]:
        """Batch lookup multiple IP addresses."""
        data = await self._request("POST", "/batch", json_data=ips)
        return data

    async def summarize_ips(self, ips: str) -> dict[str, Any]:
        """Summarize a list of IP addresses."""
        data = await self._request(
            "POST", "/tools/summarize-ips", params={"cli": "1"}, data=ips, content_type="text/plain"
        )
        return data

    async def map_ips(self, ips: str) -> dict[str, Any]:
        """Create a map of IP addresses."""
        data = await self._request(
            "POST", "/tools/map", params={"cli": "1"}, data=ips, content_type="text/plain"
        )
        return data

    # Company endpoints

    async def get_company(self, ip: str) -> CompanyResponse:
        """Get company information for an IP."""
        data = await self._request("GET", f"/{ip}/company")
        return CompanyResponse(**data)

    # Carrier endpoints

    async def get_carrier(self, ip: str) -> CarrierResponse:
        """Get carrier information for an IP."""
        data = await self._request("GET", f"/{ip}/carrier")
        return CarrierResponse(**data)

    # Ranges endpoints

    async def get_ranges(self, domain: str) -> RangesResponse:
        """Get IP ranges for a domain."""
        data = await self._request("GET", f"/ranges/{domain}")
        return RangesResponse(**data)

    # Domains endpoints

    async def get_domains(
        self, ip: str, page: int | None = None, limit: int | None = None
    ) -> DomainsResponse:
        """Get domains hosted on an IP."""
        params = {}
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit

        data = await self._request("GET", f"/domains/{ip}", params=params or None)
        return DomainsResponse(**data)

    # Abuse endpoints

    async def get_abuse(self, ip: str) -> AbuseResponse:
        """Get abuse contact information for an IP."""
        data = await self._request("GET", f"/{ip}/abuse")
        return AbuseResponse(**data)

    # Residential Proxy endpoints

    async def get_residential_proxy(self, ip: str) -> ResidentialProxyResponse:
        """Get residential proxy information for an IP.

        Returns activity data if the IP is associated with a residential proxy,
        including the proxy service name and activity patterns.
        Returns empty/null fields if not a residential proxy.
        """
        data = await self._request("GET", f"/resproxy/{ip}")
        # API returns empty {} for non-proxy IPs, handle gracefully
        if not data:
            return ResidentialProxyResponse(
                ip=None, last_seen=None, percent_days_seen=None, service=None
            )
        return ResidentialProxyResponse(**data)

    # Plus API endpoints (https://api.ipinfo.io)

    async def get_plus_info(self, ip: str) -> PlusResponse:
        """Get comprehensive IP information using the Plus API.

        The Plus API provides detailed geolocation, ASN, privacy detection,
        and network characteristics in a single call.

        Args:
            ip: IP address to lookup (or 'me' for current IP)

        Returns:
            Comprehensive IP data including geo, ASN, privacy flags, and more.
        """
        # Plus API uses different base URL
        await self._ensure_session()
        url = f"https://api.ipinfo.io/lookup/{ip}"
        params = {"token": self.api_token} if self.api_token else {}

        try:
            if not self._session:
                raise RuntimeError("Session not initialized")
            async with self._session.get(url, params=params) as response:
                result = await response.json()

                if response.status >= 400:
                    error_msg = result.get("error", {}).get("message", "Unknown error")
                    raise IPInfoAPIError(response.status, error_msg, result)

                return PlusResponse(**result)
        except ClientError as e:
            raise IPInfoAPIError(500, f"Network error: {str(e)}") from e

    async def get_plus_current_info(self) -> PlusResponse:
        """Get comprehensive information about the current IP using Plus API."""
        return await self.get_plus_info("me")

    # WHOIS endpoints

    async def get_whois_net_by_id(
        self, net_id: str, page: int | None = None, source: WhoisSource | None = None
    ) -> WhoisNetIdResponse:
        """Get WHOIS information by Net ID."""
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        if source:
            params["source"] = source.value

        data = await self._request("GET", f"/whois/net/{net_id}", params=params or None)
        return WhoisNetIdResponse(**data)

    async def get_whois_net_by_ip(
        self, ip: str, page: int | None = None, source: WhoisSource | None = None
    ) -> WhoisIpResponse:
        """Get WHOIS information by IP or IP range."""
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        if source:
            params["source"] = source.value

        data = await self._request("GET", f"/whois/net/{ip}", params=params or None)
        return WhoisIpResponse(**data)

    async def get_whois_net_by_domain(
        self, domain: str, page: int | None = None, source: WhoisSource | None = None
    ) -> WhoisDomainResponse:
        """Get WHOIS information by domain."""
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        if source:
            params["source"] = source.value

        data = await self._request("GET", f"/whois/net/{domain}", params=params or None)
        return WhoisDomainResponse(**data)

    async def get_whois_net_by_asn(
        self, asn: int, page: int | None = None, source: WhoisSource | None = None
    ) -> WhoisAsnResponse:
        """Get WHOIS information by ASN."""
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        if source:
            params["source"] = source.value

        data = await self._request("GET", f"/whois/net/AS{asn}", params=params or None)
        return WhoisAsnResponse(**data)

    async def get_whois_org(
        self, org_id: str, page: int | None = None, source: WhoisSource | None = None
    ) -> WhoisOrgResponse:
        """Get WHOIS organization information."""
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        if source:
            params["source"] = source.value

        data = await self._request("GET", f"/whois/org/{org_id}", params=params or None)
        return WhoisOrgResponse(**data)

    async def get_whois_poc(
        self, poc_id: str, page: int | None = None, source: WhoisSource | None = None
    ) -> WhoisPocResponse:
        """Get WHOIS POC information."""
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        if source:
            params["source"] = source.value

        data = await self._request("GET", f"/whois/poc/{poc_id}", params=params or None)
        return WhoisPocResponse(**data)

    # Single field endpoints

    async def get_current_ip(self) -> str:
        """Get current IP address."""
        data = await self._request("GET", "/ip")
        return str(data.get("result", ""))

    async def get_ip_by_ip(self, ip: str) -> str:
        """Get IP for the selected IP (validation)."""
        data = await self._request("GET", f"/{ip}/ip")
        return str(data.get("result", ""))

    async def get_current_hostname(self) -> str:
        """Get current hostname."""
        data = await self._request("GET", "/hostname")
        return str(data.get("result", ""))

    async def get_hostname_by_ip(self, ip: str) -> str:
        """Get hostname for an IP."""
        data = await self._request("GET", f"/{ip}/hostname")
        return str(data.get("result", ""))

    async def get_current_city(self) -> str:
        """Get current city."""
        data = await self._request("GET", "/city")
        return str(data.get("result", ""))

    async def get_city_by_ip(self, ip: str) -> str:
        """Get city for an IP."""
        data = await self._request("GET", f"/{ip}/city")
        return str(data.get("result", ""))

    async def get_current_region(self) -> str:
        """Get current region."""
        data = await self._request("GET", "/region")
        return str(data.get("result", ""))

    async def get_region_by_ip(self, ip: str) -> str:
        """Get region for an IP."""
        data = await self._request("GET", f"/{ip}/region")
        return str(data.get("result", ""))

    async def get_current_country(self) -> str:
        """Get current country."""
        data = await self._request("GET", "/country")
        return str(data.get("result", ""))

    async def get_country_by_ip(self, ip: str) -> str:
        """Get country for an IP."""
        data = await self._request("GET", f"/{ip}/country")
        return str(data.get("result", ""))

    async def get_current_location(self) -> str:
        """Get current location coordinates."""
        data = await self._request("GET", "/loc")
        return str(data.get("result", ""))

    async def get_location_by_ip(self, ip: str) -> str:
        """Get location coordinates for an IP."""
        data = await self._request("GET", f"/{ip}/loc")
        return str(data.get("result", ""))

    async def get_current_postal(self) -> str:
        """Get current postal code."""
        data = await self._request("GET", "/postal")
        return str(data.get("result", ""))

    async def get_postal_by_ip(self, ip: str) -> str:
        """Get postal code for an IP."""
        data = await self._request("GET", f"/{ip}/postal")
        return str(data.get("result", ""))

    async def get_current_timezone(self) -> str:
        """Get current timezone."""
        data = await self._request("GET", "/timezone")
        return str(data.get("result", ""))

    async def get_timezone_by_ip(self, ip: str) -> str:
        """Get timezone for an IP."""
        data = await self._request("GET", f"/{ip}/timezone")
        return str(data.get("result", ""))

    async def get_current_org(self) -> str:
        """Get current ASN organization."""
        data = await self._request("GET", "/org")
        return str(data.get("result", ""))

    async def get_org_by_ip(self, ip: str) -> str:
        """Get ASN organization for an IP."""
        data = await self._request("GET", f"/{ip}/org")
        return str(data.get("result", ""))
