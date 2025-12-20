# IPInfo MCP Server Integration Tests

These tests validate the IPInfo MCP server against the real IPInfo API. They test complete workflows that map to NimbleBrain playbook use cases.

## Prerequisites

### 1. IPInfo API Token

Get a token from [ipinfo.io](https://ipinfo.io/):

- Free tier: 50,000 requests/month
- Plus tier: Comprehensive IP intelligence (geo, ASN, privacy detection in one call)
- Business tier: Additional features (IP ranges, ASN details endpoint, etc.)

### 2. Set Environment Variable

```bash
export IPINFO_API_TOKEN=your_token_here
```

## Running Tests

### Run all integration tests

```bash
make test-integration
```

### Run with verbose output (see print statements)

```bash
make test-integration-verbose
```

### Run only use case scenario tests

```bash
make test-use-cases
```

### Run all tests (unit + integration)

```bash
make test-all
```

### Run specific test file

```bash
uv run pytest tests-integration/test_core_tools.py -v -s
```

### Run specific test

```bash
uv run pytest tests-integration/test_use_cases.py::TestSuspiciousLoginDetection -v -s
```

## Test Structure

```
tests-integration/
├── conftest.py              # Shared fixtures, API token validation
├── test_core_tools.py       # Basic API functionality + Plus API
├── test_asn_analysis.py     # ASN grouping for DevOps (Use Case 2)
└── test_use_cases.py        # Full scenario tests (all 4 use cases)
```

## API Architecture

These tests use the **Plus API** (`api.ipinfo.io/lookup/{ip}`) for comprehensive IP intelligence. The Plus API returns geo, ASN, and privacy detection data in a single call, which is more efficient than making separate requests.

### Plus API Response Includes:
- **geo**: City, region, country, coordinates, timezone, postal code
- **as**: ASN, organization name, domain, type
- **anonymous**: VPN, proxy, Tor, relay detection
- **Flags**: is_anonymous, is_hosting, is_mobile, is_anycast, is_satellite

## Use Cases Tested

### 1. Suspicious Login Detection (Threat Response)

**File:** `test_use_cases.py::TestSuspiciousLoginDetection`

Tests the workflow for detecting suspicious logins:
- Check if IP is VPN/proxy/Tor using Plus API privacy detection
- Calculate risk level based on anonymity flags
- Determine action (BLOCK, MFA_REQUIRED, FLAG_FOR_REVIEW, ALLOW)

**IPInfo Tools Used:**
- `get_plus_ip_info(ip)` - Comprehensive IP intelligence including privacy detection

### 2. DevOps Error Diagnosis

**File:** `test_asn_analysis.py`, `test_use_cases.py::TestDevOpsErrorDiagnosis`

Tests the workflow for diagnosing error sources:
- Batch lookup IPs from error logs
- Group by ASN/organization
- Detect single-source attacks (80%+ from one ASN)
- Generate GitHub issue content

**IPInfo Tools Used:**
- `batch_lookup(ips)` - Batch IP lookup
- `get_plus_ip_info(ip)` - ASN and hosting detection
- `summarize_ips(ips)` - IP summary statistics

### 3. Geo Compliance Check

**File:** `test_use_cases.py::TestGeoComplianceCheck`

Tests the workflow for access compliance:
- Check if IP is from approved country
- Check if using VPN/proxy via Plus API anonymous detection
- Grant or deny access based on policy

**IPInfo Tools Used:**
- `get_plus_ip_info(ip)` - Country/location + VPN detection in one call

### 4. IP Intelligence Report

**File:** `test_use_cases.py::TestIPIntelligenceReport`

Tests generating comprehensive IP reports:
- Basic information (location, timezone)
- Network information (ASN, organization)
- Privacy/threat indicators (VPN, proxy, Tor, relay)
- Abuse contact information
- Risk assessment with scoring

**IPInfo Tools Used:**
- `get_plus_ip_info(ip)` - Full IP details with privacy flags
- `get_abuse_contact(ip)` - Abuse contact

## Test IPs

Tests use well-known IPs that are stable and reliable:

| IP | Description |
|----|-------------|
| 8.8.8.8 | Google DNS |
| 8.8.4.4 | Google DNS Secondary |
| 1.1.1.1 | Cloudflare DNS |
| 9.9.9.9 | Quad9 DNS |

## CI/CD Integration

These tests are **not** run automatically because they:
1. Require an API token
2. Make real HTTP requests
3. Count against API rate limits

To run in CI:

```yaml
integration-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.13'
    - name: Install uv
      run: pip install uv
    - name: Install dependencies
      run: uv pip install -e ".[dev]"
    - name: Run integration tests
      env:
        IPINFO_API_TOKEN: ${{ secrets.IPINFO_API_TOKEN }}
      run: make test-integration
```

## Troubleshooting

### "IPINFO_API_TOKEN not set"

Set the environment variable:
```bash
export IPINFO_API_TOKEN=your_token_here
```

### 401 Unauthorized

Your API token is invalid or expired. Check at [ipinfo.io/account](https://ipinfo.io/account).

### 403 Forbidden

The API feature requires a higher tier. Tests that require Business tier will skip automatically.

### 429 Rate Limited

You've exceeded your API quota. Wait or upgrade your plan.

### Tests timing out

Integration tests have 30-second timeouts. If the API is slow, increase timeout:
```bash
uv run pytest tests-integration/ -v --timeout=60
```

## Cost

Running all integration tests makes approximately 20-30 API calls. With the free tier (50,000 requests/month), you can run the full suite ~1,500 times per month.
