#!/usr/bin/env python3
"""Check whether EDR (endpoint sensor) is enabled for an endpoint in TrendAI Vision One.

Usage:
    export TMV1_TOKEN=<api key token>
    python3 edr_status.py <endpoint name> [--region api.xdr.trendmicro.com] [--json]

Exit codes:
    0  every matching endpoint has EDR enabled
    1  at least one matching endpoint has EDR disabled or unrecognized, or fails the version check
    2  no endpoint matched the name
    3  configuration, auth, or API error
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# Path of the endpoint list API (read-only inventory call).
ENDPOINTS_PATH = "/v3.0/endpointSecurity/endpoints"
DEFAULT_REGION = "api.xdr.trendmicro.com"  # US region; use your region's API host if different

# Exit codes returned by main(). edr_policy.py and edr.py import some of these.
EXIT_OK, EXIT_DISABLED, EXIT_NOT_FOUND, EXIT_ERROR = 0, 1, 2, 3

# Minimum versions. An endpoint below either one fails the version check.
# Change these here; every script reads them from this file.
MIN_AGENT_VERSION = "202507"
MIN_EPP_VERSION = "20.0.1-25770"


def parse_version(text):
    """Split a version string into a tuple of integers, e.g. '20.0.1-25770' -> (20, 0, 1, 25770).
    Returns None if the text is missing or has no numbers."""
    if not text:
        return None
    # Any run of digits is one part, so dots and dashes both act as separators.
    numbers = re.findall(r"\d+", str(text))
    return tuple(int(n) for n in numbers) or None


def is_below(version, minimum):
    """True if version sorts lower than minimum. Missing trailing parts count as zero."""
    width = max(len(version), len(minimum))
    padded_version = version + (0,) * (width - len(version))
    padded_minimum = minimum + (0,) * (width - len(minimum))
    return padded_version < padded_minimum


def check_versions(agent_version, epp_version):
    """Return a description of what fails the version check, or None if both versions pass.
    A missing or unreadable version counts as a failure, because the minimum can't be confirmed."""
    problems = []

    # Agent version: a date-style number such as 202609.
    agent = parse_version(agent_version)
    if agent is None:
        problems.append("agent version unknown")
    elif is_below(agent, parse_version(MIN_AGENT_VERSION)):
        problems.append(f"agent {agent_version} below minimum {MIN_AGENT_VERSION}")

    # EPP agent version: dotted, such as 20.0.3.28120.
    epp = parse_version(epp_version)
    if epp is None:
        problems.append("EPP agent version unknown")
    elif is_below(epp, parse_version(MIN_EPP_VERSION)):
        problems.append(f"EPP agent {epp_version} below minimum {MIN_EPP_VERSION}")

    return "; ".join(problems) or None


def find_endpoints(region, token, name):
    """Return the raw list response for endpoints whose name matches exactly."""
    # Ask for up to 100 records per page; a name filter should return only one or a few.
    query = urllib.parse.urlencode({"top": 100})
    url = f"https://{region}{ENDPOINTS_PATH}?{query}"
    # The filter uses OData-style quoting, where a literal apostrophe is written as two apostrophes.
    escaped_name = name.replace("'", "''")
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        # Server-side filter on endpoint name.
        "TMV1-Filter": f"endpointName eq '{escaped_name}'",
        "Accept": "application/json",
    })
    # Raises HTTPError or URLError on failure; callers handle those.
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def get_details(region, token, guid):
    """Return the detailed profile of one endpoint by agent GUID. Unlike the list call, this includes edrSettings."""
    url = f"https://{region}{ENDPOINTS_PATH}/{urllib.parse.quote(guid)}"
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def describe_overrides(details):
    """Return display lines for the overrides in effect and the EDR settings a disable would affect."""
    lines = [f"  Policy overridden: {details.get('securityPolicyOverriddenStatus') or 'unknown'}"]
    settings = (details.get("edrSensor") or {}).get("edrSettings")
    if settings:
        lines.append("  EDR settings:")
        for key, value in settings.items():
            lines.append(f"    {key}: {json.dumps(value)}")
    else:
        lines.append("  EDR settings: none reported")
    return lines


def summarize(item):
    """Pull the fields we care about out of one endpoint record."""
    # EDR details live under "edrSensor"; fall back to an empty dict if it's missing.
    edr = item.get("edrSensor") or {}
    status = edr.get("status")
    return {
        "endpointName": item.get("endpointName"),
        "agentGuid": item.get("agentGuid"),
        # Agent version is a top-level field on the endpoint record, not part of edrSensor.
        "agentVersion": item.get("agentVersion"),
        # EPP agent version is nested under "eppAgent".
        "eppAgentVersion": (item.get("eppAgent") or {}).get("version"),
        # None when both versions pass; otherwise a description of what failed.
        "versionProblem": check_versions(item.get("agentVersion"), (item.get("eppAgent") or {}).get("version")),
        "edrStatus": status,
        # Advanced risk telemetry uses the same status values as EDR, read from the same nested object.
        "advancedRiskStatus": edr.get("advancedRiskTelemetryStatus"),
        # True/False for a settled state; None for anything else (e.g. pending or unknown).
        "edrEnabled": status == "enabled" if status in ("enabled", "disabled") else None,
        "connectivity": edr.get("connectivity"),
        "lastConnectedDateTime": edr.get("lastConnectedDateTime"),
    }


# Labels for transitional states the API reports while a change is still applying.
PENDING_STATUSES = {"enabling": "enabling", "disabling": "disabling"}


def edr_label(result):
    """Turn a summarized endpoint into a short human-readable EDR label."""
    if result["edrEnabled"] is True:
        return "ON"
    if result["edrEnabled"] is False:
        return "OFF"
    # Not settled yet: show the pending state instead of "unknown".
    if result["edrStatus"] in PENDING_STATUSES:
        return PENDING_STATUSES[result["edrStatus"]]
    return f"UNKNOWN ({result['edrStatus']})"


def advanced_label(result):
    """Turn the advanced risk telemetry status into a short label: ON, OFF, a transitional state, or UNKNOWN."""
    value = result["advancedRiskStatus"]
    if value == "enabled":
        return "ON"
    if value == "disabled":
        return "OFF"
    # Same transitional states as EDR; show them as-is.
    if value in PENDING_STATUSES:
        return PENDING_STATUSES[value]
    # Missing values show plain UNKNOWN; unexpected values also show what the API returned.
    return "UNKNOWN" if value is None else f"UNKNOWN ({value})"


def print_table(results):
    """Print the results as an aligned text table."""
    headers = ["Endpoint", "Agent GUID", "Agent Version", "EPP Agent Version", "EDR", "Adv. Risk Telemetry", "Connectivity", "Last Connected", "Version Check"]
    # Build one list of cell values per endpoint, blanking out any missing fields.
    rows = [
        [
            r["endpointName"] or "",
            r["agentGuid"] or "",
            r["agentVersion"] or "",
            r["eppAgentVersion"] or "",
            edr_label(r),
            advanced_label(r),
            r["connectivity"] or "",
            r["lastConnectedDateTime"] or "",
            r["versionProblem"] or "OK",
        ]
        for r in results
    ]
    # Column width = longest value in each column, including the header.
    widths = [max(len(str(v)) for v in column) for column in zip(headers, *rows)]
    # Build a format string like "{:<20}  {:<36}  ..." that pads each column to its width.
    line = "  ".join("{:<" + str(w) + "}" for w in widths)
    print(line.format(*headers))
    for row in rows:
        print(line.format(*row))


def main():
    """Command-line entry point: look up one endpoint and report its EDR status."""
    parser = argparse.ArgumentParser(description="Check EDR status for a Vision One endpoint by name.")
    parser.add_argument("name", help="exact endpoint name, e.g. host-01.example.internal")
    parser.add_argument("--region", default=DEFAULT_REGION, help=f"Vision One API host (default: {DEFAULT_REGION})")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = parser.parse_args()

    # The API token comes from the environment so it is never stored in this file.
    token = os.environ.get("TMV1_TOKEN")
    if not token:
        print("error: set the TMV1_TOKEN environment variable first", file=sys.stderr)
        return EXIT_ERROR

    try:
        data = find_endpoints(args.region, token, args.name)
    except urllib.error.HTTPError as e:
        # Translate the most common auth and permission failures into plain hints.
        hints = {
            401: "token is invalid or expired",
            403: "API key needs the 'Endpoint Inventory: View' role",
        }
        hint = f" ({hints[e.code]})" if e.code in hints else ""
        print(f"error: API returned HTTP {e.code}{hint}", file=sys.stderr)
        return EXIT_ERROR
    except urllib.error.URLError as e:
        # Network problems: DNS failure, refused connection, timeout, and similar.
        print(f"error: could not reach {args.region}: {e.reason}", file=sys.stderr)
        return EXIT_ERROR

    # No items means no endpoint with that exact name.
    items = data.get("items", [])
    if not items:
        print(f"No endpoint found named '{args.name}'.", file=sys.stderr)
        return EXIT_NOT_FOUND

    # The API reports the total match count; warn if we didn't receive all of them.
    if data.get("totalCount", len(items)) > len(items):
        print(f"warning: {data['totalCount']} matches, showing first {len(items)}", file=sys.stderr)

    results = [summarize(item) for item in items]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_table(results)

    # Exit 0 only when every match is ON and passes the version check; otherwise exit 1.
    all_ok = all(r["edrEnabled"] is True and r["versionProblem"] is None for r in results)
    return EXIT_OK if all_ok else EXIT_DISABLED


if __name__ == "__main__":
    # Only run main() when executed directly, not when imported by edr_policy.py or edr.py.
    sys.exit(main())
