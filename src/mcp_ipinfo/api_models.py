from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CompanyType(str, Enum):
    ISP = "isp"
    BUSINESS = "business"
    EDUCATION = "education"
    HOSTING = "hosting"
    INACTIVE = "inactive"


class WhoisSource(str, Enum):
    ARIN = "arin"
    RIPE = "ripe"
    AFRINIC = "afrinic"
    APNIC = "apnic"
    LACNIC = "lacnic"


class AsnResponse(BaseModel):
    asn: str = Field(..., description="ASN identifier")
    name: str = Field(..., description="Name of the ASN")
    country: str | None = Field(None, description="Country code")
    allocated: str | None = Field(None, description="Allocation date")
    registry: str | None = Field(None, description="Registry name")
    domain: str = Field(..., description="Domain")
    num_ips: int | None = Field(None, description="Number of IPs")
    route: str | None = Field(None, description="Route")
    type: CompanyType = Field(..., description="Type of organization")
    prefixes: list[dict[str, Any]] | None = Field(None)
    prefixes6: list[dict[str, Any]] | None = Field(None)
    peers: list[str] | None = Field(None)
    upstreams: list[str] | None = Field(None)
    downstreams: list[str] | None = Field(None)


class CompanyResponse(BaseModel):
    name: str = Field(..., description="Company name")
    domain: str = Field(..., description="Company domain")
    type: CompanyType = Field(..., description="Company type")


class CarrierResponse(BaseModel):
    name: str = Field(..., description="Carrier name")
    mcc: str = Field(..., description="Mobile Country Code")
    mnc: str = Field(..., description="Mobile Network Code")


class PrivacyResponse(BaseModel):
    vpn: bool = Field(..., description="VPN detected")
    proxy: bool = Field(..., description="Proxy detected")
    tor: bool = Field(..., description="Tor detected")
    hosting: bool = Field(..., description="Hosting provider detected")
    relay: bool = Field(..., description="Relay detected")
    service: str | None = Field(None, description="Service name if detected")


class DomainsResponse(BaseModel):
    ip: str | None = Field(None, description="IP address")
    page: int | None = Field(None, description="Page number")
    total: int = Field(..., description="Total domains")
    domains: list[str] | None = Field(None, description="List of domains")


class AbuseResponse(BaseModel):
    address: str | None = Field(None, description="Address")
    country: str | None = Field(None, description="Country")
    email: str | None = Field(None, description="Email")
    name: str | None = Field(None, description="Name")
    network: str | None = Field(None, description="Network")
    phone: str | None = Field(None, description="Phone")


class FullResponse(BaseModel):
    ip: str = Field(..., description="IP address")
    bogon: bool | None = Field(None, description="Bogon IP")
    hostname: str | None = Field(None, description="Hostname")
    city: str | None = Field(None, description="City")
    region: str | None = Field(None, description="Region/State")
    country: str | None = Field(None, description="Country code")
    loc: str | None = Field(None, description="Location coordinates")
    postal: str | None = Field(None, description="Postal code")
    timezone: str | None = Field(None, description="Timezone")
    org: str | None = Field(None, description="Organization")
    asn: AsnResponse | None = Field(None, description="ASN details")
    company: CompanyResponse | None = Field(None, description="Company details")
    carrier: CarrierResponse | None = Field(None, description="Carrier details")
    privacy: PrivacyResponse | None = Field(None, description="Privacy detection")
    domains: DomainsResponse | None = Field(None, description="Hosted domains")
    abuse: AbuseResponse | None = Field(None, description="Abuse contact")


class MeResponse(BaseModel):
    token: str = Field(..., description="API token")
    requests: dict[str, int] = Field(..., description="Request limits and usage")
    features: dict[str, Any] = Field(..., description="Available features")


class RangesResponse(BaseModel):
    domain: str = Field(..., description="Domain name")
    num_ranges: int = Field(..., description="Number of ranges")
    redirects_to: str | None = Field(None, description="Redirects to domain")
    ranges: list[str] = Field(..., description="List of IP ranges")


class ResidentialProxyResponse(BaseModel):
    ip: str | None = Field(None, description="The IP address")
    last_seen: str | None = Field(None, description="Last seen date (YYYY-MM-DD UTC)")
    percent_days_seen: int | None = Field(
        None, description="Percentage of days active in last 7 days"
    )
    service: str | None = Field(None, description="Residential proxy service name")


# Plus API models (https://api.ipinfo.io/lookup/{ip})


class PlusGeoResponse(BaseModel):
    """Geographic information from Plus API."""

    city: str | None = Field(None, description="City name")
    region: str | None = Field(None, description="Region/state name")
    region_code: str | None = Field(None, description="Region code")
    country: str | None = Field(None, description="Country name")
    country_code: str | None = Field(None, description="ISO country code")
    continent: str | None = Field(None, description="Continent name")
    continent_code: str | None = Field(None, description="Continent code")
    latitude: float | None = Field(None, description="Latitude")
    longitude: float | None = Field(None, description="Longitude")
    timezone: str | None = Field(None, description="Timezone")
    postal_code: str | None = Field(None, description="Postal code")
    dma_code: str | None = Field(None, description="DMA code")
    geoname_id: str | None = Field(None, description="GeoName ID")
    radius: int | None = Field(None, description="Accuracy radius in km")


class PlusAsResponse(BaseModel):
    """ASN information from Plus API."""

    asn: str | None = Field(None, description="ASN identifier (e.g. AS15169)")
    name: str | None = Field(None, description="Organization name")
    domain: str | None = Field(None, description="Organization domain")
    type: str | None = Field(
        None, description="Organization type (isp, hosting, business, education)"
    )
    last_changed: str | None = Field(None, description="Last changed date (ISO-8601)")


class PlusMobileResponse(BaseModel):
    """Mobile carrier information from Plus API."""

    mcc: str | None = Field(None, description="Mobile Country Code")
    mnc: str | None = Field(None, description="Mobile Network Code")
    name: str | None = Field(None, description="Carrier name")


class PlusAnonymousResponse(BaseModel):
    """Anonymous/privacy detection from Plus API."""

    is_proxy: bool = Field(False, description="Open web proxy detected")
    is_relay: bool = Field(False, description="Anonymous relay (e.g. iCloud Private Relay)")
    is_tor: bool = Field(False, description="Tor exit node detected")
    is_vpn: bool = Field(False, description="VPN exit node detected")
    name: str | None = Field(None, description="Privacy service provider name")


class PlusResponse(BaseModel):
    """Full response from Plus API (https://api.ipinfo.io/lookup/{ip})."""

    ip: str = Field(..., description="IP address")
    hostname: str | None = Field(None, description="Hostname")
    geo: PlusGeoResponse | None = Field(None, description="Geographic information")
    as_info: PlusAsResponse | None = Field(None, alias="as", description="ASN information")
    mobile: PlusMobileResponse | None = Field(None, description="Mobile carrier info")
    anonymous: PlusAnonymousResponse | None = Field(None, description="Privacy/anonymity detection")
    is_anonymous: bool = Field(False, description="Overall anonymity flag")
    is_anycast: bool = Field(False, description="Anycast IP")
    is_hosting: bool = Field(False, description="Hosting provider IP")
    is_mobile: bool = Field(False, description="Mobile network IP")
    is_satellite: bool = Field(False, description="Satellite provider IP")


class WhoisRecord(BaseModel):
    range: str | None = None
    id: str | None = None
    name: str | None = None
    country: str | None = None
    org: str | None = None
    admin: Any | None = None
    abuse: Any | None = None
    tech: Any | None = None
    maintainer: Any | None = None
    updated: str | None = None
    status: str | None = None
    source: str | None = None
    raw: str | None = None
    domain: str | None = None


class WhoisNetIdResponse(BaseModel):
    net: str | None = None
    total: int | None = None
    page: int | None = None
    records: list[WhoisRecord] | None = None


class WhoisIpResponse(BaseModel):
    net: str | None = None
    total: int | None = None
    page: int | None = None
    records: list[WhoisRecord] | None = None


class WhoisDomainResponse(BaseModel):
    net: str | None = None
    total: int | None = None
    page: int | None = None
    records: list[WhoisRecord] | None = None


class WhoisAsnResponse(BaseModel):
    net: str | None = None
    total: int | None = None
    page: int | None = None
    records: list[WhoisRecord] | None = None


class WhoisOrgRecord(BaseModel):
    id: str | None = None
    name: str | None = None
    address: str | None = None
    country: str | None = None
    admin: Any | None = None
    abuse: Any | None = None
    tech: Any | None = None
    maintainer: Any | None = None
    created: str | None = None
    updated: str | None = None
    source: str | None = None
    raw: str | None = None


class WhoisOrgResponse(BaseModel):
    org: str | None = None
    total: int | None = None
    page: int | None = None
    records: list[WhoisOrgRecord] | None = None


class WhoisPocRecord(BaseModel):
    id: str | None = None
    name: str | None = None
    email: str | None = None
    address: str | None = None
    country: str | None = None
    phone: str | None = None
    fax: str | None = None
    created: str | None = None
    updated: str | None = None
    source: str | None = None
    raw: str | None = None


class WhoisPocResponse(BaseModel):
    poc: str | None = None
    total: int | None = None
    page: int | None = None
    records: list[WhoisPocRecord] | None = None


class ErrorResponse(BaseModel):
    status: int | None = None
    error: dict[str, str] | None = None
    title: str | None = None
    message: str | None = None
