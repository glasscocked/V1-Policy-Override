#!/usr/bin/env python3
"""Turn EDR on or off for Vision One endpoints by overriding their sensor policy.

Usage:
    export TMV1_TOKEN=<api key token>
    python3 edr_policy.py <endpoint name> --edr on|off --advanced-risk on|off [--yes] [--dry-run]
    python3 edr_policy.py <endpoint name> --remove-override [--yes] [--dry-run]
    python3 edr_policy.py --csv <file.csv|file.xlsx> --edr on|off --advanced-risk on|off [--yes] [--dry-run]
    python3 edr_policy.py --csv <file.csv|file.xlsx> --remove-override [--yes] [--dry-run]

--edr applies an override (sensorDetectionAndResponse). --remove-override reverts the
endpoint to its assigned policy. Both change live state, so the script prompts first unless --yes.

--csv reads hostnames from the HOSTNAME column of a CSV or XLSX file and applies the same
change to each one. Hosts that are not found or match more than one endpoint are skipped.
Enabling is refused for endpoints below the minimum agent versions set in edr_status.py.

Exit codes:
    0  change accepted (or dry run)
    1  a change failed, or some hosts were skipped
    2  no endpoint matched the name (single-host mode)
    3  configuration, auth, validation, or API error, or the user declined
"""
import argparse
import csv
import json
import os
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

# Reuse the lookup and status helpers from the read-only script.
from edr_status import (
    DEFAULT_REGION, EXIT_ERROR, EXIT_NOT_FOUND, advanced_label, describe_overrides, edr_label,
    find_endpoints, get_details, summarize,
)

# Endpoint paths for the two change operations.
BASE_PATH = "/v3.0/endpointSecurity/endpoints"
APPLY_PATH = f"{BASE_PATH}/applySensorPolicy"  # creates an override
REMOVE_PATH = f"{BASE_PATH}/removeOverriddenSensorPolicy"  # reverts to the assigned policy

# Exit codes for this script. Lookup-related codes are shared with edr_status.py.
EXIT_OK, EXIT_FAILED = 0, 1

# Per-request status codes the change API returns in its 207 response.
ACCEPTED = 202
STATUS_TEXT = {
    202: "accepted",
    404: "endpoint not found",
    500: "server error",
}
# Map the on/off words used on the command line to the API's enabled/disabled values.
SETTING = {"on": "enabled", "off": "disabled"}

# XML namespace used inside .xlsx files.
XLSX_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"

# Errors that can come from reading a CSV or XLSX file. Callers catch these together.
READ_ERRORS = (OSError, ValueError, zipfile.BadZipFile, KeyError, ET.ParseError)


def post(region, token, path, body):
    """POST a JSON body and return the parsed per-request status list (HTTP 207)."""
    request = urllib.request.Request(
        f"https://{region}{path}",
        data=json.dumps(body).encode(),  # the API expects a JSON body
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    # Raises HTTPError or URLError on failure; callers handle those.
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def print_results(results):
    """Print each per-request status and return True only if all were accepted."""
    all_ok = True
    for item in results:
        status = item.get("status")
        # Keep False once any request fails; later successes don't undo it.
        all_ok = all_ok and status == ACCEPTED
        print(f"  HTTP {status}: {STATUS_TEXT.get(status, 'unexpected response')}")
    return all_ok


def build_request(guid, edr, advanced):
    """Return (path, body) for one endpoint. edr is 'on' or 'off' to apply an override, or None to remove it."""
    if edr is None:
        # Removing an override takes just the agent GUID per item.
        return REMOVE_PATH, [{"agentGuid": guid}]
    # Applying an override needs both the EDR setting and the advanced risk telemetry setting.
    return APPLY_PATH, {
        "agentGuids": [guid],
        "sensorDetectionAndResponse": SETTING[edr],
        "advancedRiskTelemetry": SETTING[advanced],
    }


def send_one(region, token, path, body):
    """Send one change request. Returns (ok, text) so batch runs can print one line per endpoint."""
    try:
        results = post(region, token, path, body)
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return False, f"could not reach {region}: {e.reason}"
    statuses = [item.get("status") for item in results]
    # Only a non-empty response where every item was accepted counts as success.
    ok = bool(statuses) and all(s == ACCEPTED for s in statuses)
    text = ", ".join(f"{s} {STATUS_TEXT.get(s, 'unexpected response')}" for s in statuses)
    return ok, text


def apply_batch(region, token, plan):
    """Send one request per endpoint so each result maps to its hostname. Prints a line per endpoint and returns the failure count."""
    failures = 0
    for name, path, body in plan:
        ok, text = send_one(region, token, path, body)
        if not ok:
            failures += 1
        print(f"  {name}: {'OK' if ok else 'FAILED'} ({text})")
    return failures


def column_index(letters):
    """Convert a spreadsheet column label such as 'A' or 'AB' to a zero-based index."""
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - ord("A") + 1)
    return n - 1


def read_xlsx_rows(path):
    """Read the first sheet of an .xlsx file with only the standard library. Returns a list of rows, each a list of strings."""
    with zipfile.ZipFile(path) as z:
        # Text cells in .xlsx files are stored once in a shared table and referenced by index.
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            shared = ["".join(t.text or "" for t in si.iter(XLSX_NS + "t")) for si in root.iter(XLSX_NS + "si")]
        # Assumes the data is on the first sheet, which is what Excel saves by default.
        sheet = ET.fromstring(z.read("xl/worksheets/sheet1.xml"))

    rows = []
    for row in sheet.iter(XLSX_NS + "row"):
        values = {}
        for cell in row.iter(XLSX_NS + "c"):
            # The cell reference (e.g. "B3") tells us which column the value belongs to.
            letters = re.match(r"[A-Z]+", cell.get("r")).group()
            kind = cell.get("t")
            v = cell.find(XLSX_NS + "v")
            if kind == "s" and v is not None:
                value = shared[int(v.text)]
            elif kind == "inlineStr":
                value = "".join(t.text or "" for t in cell.iter(XLSX_NS + "t"))
            else:
                value = v.text if v is not None else ""
            values[column_index(letters)] = value.strip()
        # Pad each row to the widest column so every row lines up by position.
        width = max(values) + 1 if values else 0
        rows.append([values.get(i, "") for i in range(width)])
    return rows


def load_hostnames(path):
    """Read endpoint names from the HOSTNAME column of a .csv or .xlsx file. Blanks and duplicates are dropped."""
    if path.lower().endswith(".xlsx"):
        rows = read_xlsx_rows(path)
    else:
        # utf-8-sig also handles a byte-order mark that Excel sometimes adds to CSV files.
        with open(path, newline="", encoding="utf-8-sig") as f:
            rows = list(csv.reader(f))

    if not rows:
        raise ValueError("the file is empty")
    # Match the header case-insensitively, so "hostname" and "Hostname" both work.
    header = [h.strip().upper() for h in rows[0]]
    if "HOSTNAME" not in header:
        raise ValueError(f"no HOSTNAME column found (headers: {', '.join(rows[0])})")
    col = header.index("HOSTNAME")

    names, seen = [], set()
    for row in rows[1:]:
        name = row[col].strip() if col < len(row) else ""
        # Hostnames are case-insensitive, so dedupe on the lowercase form but keep the original text.
        key = name.lower()
        if name and key not in seen:
            seen.add(key)
            names.append(name)
    if not names:
        raise ValueError("no hostnames found under the HOSTNAME column")
    return names


def lookup_hostnames(region, token, names):
    """Look up each name. Returns a list of dicts with name, current (summary or None), and problem (text or None).
    Network and auth errors are raised so the whole batch stops rather than failing one host at a time."""
    results = []
    for name in names:
        data = find_endpoints(region, token, name)
        items = data.get("items", [])
        if not items:
            results.append({"name": name, "current": None, "problem": "not found"})
        elif len(items) > 1:
            # Ambiguous names are skipped, the same as in single-host mode.
            results.append({"name": name, "current": None, "problem": f"{len(items)} matches"})
        else:
            results.append({"name": name, "current": summarize(items[0]), "problem": None})
    return results


def print_lookup_table(rows):
    """Print the batch lookup results as an aligned table."""
    headers = ["Hostname", "Agent GUID", "Agent Version", "EPP Agent Version", "Current EDR", "Note"]
    table = []
    for r in rows:
        current = r["current"]
        table.append([
            r["name"],
            current["agentGuid"] if current else "",
            (current["agentVersion"] or "") if current else "",
            (current["eppAgentVersion"] or "") if current else "",
            edr_label(current) if current else "",
            r["problem"] or (current["versionProblem"] if current else None) or "",
        ])
    widths = [max(len(str(v)) for v in column) for column in zip(headers, *table)]
    line = "  ".join("{:<" + str(w) + "}" for w in widths)
    print(line.format(*headers))
    for row in table:
        print(line.format(*row))


def show_overrides(region, token, guid):
    """Print the overrides a disable would remove. Read-only. Lookup errors are printed, not raised."""
    try:
        details = get_details(region, token, guid)
    except urllib.error.HTTPError as e:
        print(f"  Could not read current overrides (HTTP {e.code}).")
        return
    except urllib.error.URLError as e:
        print(f"  Could not read current overrides: {e.reason}")
        return
    for line in describe_overrides(details):
        print(line)


def run_single(args, token):
    """Change or revert one endpoint looked up by name."""
    try:
        data = find_endpoints(args.region, token, args.name)
    except urllib.error.HTTPError as e:
        hints = {401: "token is invalid or expired", 403: "API key needs Endpoint Inventory: View"}
        hint = f" ({hints[e.code]})" if e.code in hints else ""
        print(f"error: lookup returned HTTP {e.code}{hint}", file=sys.stderr)
        return EXIT_ERROR
    except urllib.error.URLError as e:
        print(f"error: could not reach {args.region}: {e.reason}", file=sys.stderr)
        return EXIT_ERROR

    items = data.get("items", [])
    if not items:
        print(f"No endpoint found named '{args.name}'.", file=sys.stderr)
        return EXIT_NOT_FOUND
    # Never change more than one endpoint from a single name lookup.
    if len(items) > 1:
        print(f"error: {len(items)} endpoints match '{args.name}'. Refusing to change more than one.", file=sys.stderr)
        for item in items:
            print(f"  {item.get('endpointName')}  {item.get('agentGuid')}", file=sys.stderr)
        return EXIT_ERROR

    # Show what we found before anything is changed.
    current = summarize(items[0])
    guid = current["agentGuid"]
    print(f"Endpoint:    {current['endpointName']}")
    print(f"Agent GUID:  {guid}")
    print(f"Agent ver.:  {current['agentVersion'] or 'unknown'}")
    print(f"EPP ver.:    {current['eppAgentVersion'] or 'unknown'}")
    print(f"Current EDR: {edr_label(current)}")
    print(f"Adv. risk:   {advanced_label(current)}")

    # Enabling is refused outright when either version is below the minimum (or unknown).
    if args.edr == "on" and current["versionProblem"]:
        print(f"error: refusing to enable EDR: {current['versionProblem']}", file=sys.stderr)
        return EXIT_ERROR

    path, body = build_request(guid, args.edr, args.advanced_risk)
    if args.edr:
        print(f"Change:      apply override, EDR {args.edr.upper()}, advanced risk telemetry {args.advanced_risk}")
    else:
        print("Change:      remove override (revert to assigned policy)")
        # Disabling also removes console overrides and hypersensitive mode, so show what is in effect first.
        show_overrides(args.region, token, guid)

    # Dry run: print the request that would be sent and stop before anything is changed.
    if args.dry_run:
        print(f"\nDry run. Would POST {path}:")
        print(json.dumps(body, indent=2))
        return EXIT_OK

    # Ask before changing a live endpoint, unless --yes was given.
    if not args.yes:
        answer = input("\nApply this change to the live endpoint? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Cancelled. No change made.")
            return EXIT_ERROR

    try:
        results = post(args.region, token, path, body)
    except urllib.error.HTTPError as e:
        print(f"error: change request returned HTTP {e.code}", file=sys.stderr)
        return EXIT_ERROR
    except urllib.error.URLError as e:
        print(f"error: could not reach {args.region}: {e.reason}", file=sys.stderr)
        return EXIT_ERROR

    # The API accepts the request, then reports a status per item. Check each one.
    print("\nAPI response:")
    ok = print_results(results)
    if ok:
        print("\nAccepted. If the endpoint is offline, the change applies when it reconnects.")
        print("Run edr_status.py to confirm the new EDR state.")
    return EXIT_OK if ok else EXIT_FAILED


def run_csv(args, token):
    """Read hostnames from a file, look them all up, then apply one change to every match."""
    try:
        names = load_hostnames(args.csv)
    except READ_ERRORS as e:
        print(f"error: could not read {args.csv}: {e}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Read {len(names)} hostname(s) from {args.csv}")

    try:
        rows = lookup_hostnames(args.region, token, names)
    except urllib.error.HTTPError as e:
        hints = {401: "token is invalid or expired", 403: "API key needs Endpoint Inventory: View"}
        hint = f" ({hints[e.code]})" if e.code in hints else ""
        print(f"error: lookup returned HTTP {e.code}{hint}", file=sys.stderr)
        return EXIT_ERROR
    except urllib.error.URLError as e:
        print(f"error: could not reach {args.region}: {e.reason}", file=sys.stderr)
        return EXIT_ERROR

    print()
    print_lookup_table(rows)
    print()

    # Only hosts that matched exactly one endpoint get the change.
    # Enabling is refused for hosts that fail the version check. Disabling is not affected.
    eligible = [r for r in rows
                if r["current"] and not (args.edr == "on" and r["current"]["versionProblem"])]
    plan = [(r["name"], *build_request(r["current"]["agentGuid"], args.edr, args.advanced_risk))
            for r in eligible]
    skipped = len(rows) - len(plan)
    if not plan:
        print("Nothing to change: no hostnames were eligible for this change.")
        return EXIT_ERROR

    if args.edr:
        describe = f"apply override, EDR {args.edr.upper()}, advanced risk telemetry {args.advanced_risk}"
    else:
        describe = "remove override (revert to assigned policy)"
    print(f"Change to {len(plan)} endpoint(s): {describe}. Skipping {skipped} not found, ambiguous, or failing the version check.")

    if args.dry_run:
        print("\nDry run. Nothing sent. Requests that would be sent:")
        for name, path, body in plan:
            print(f"  {name}: POST {path}  {json.dumps(body)}")
        return EXIT_OK

    # One confirmation covers the whole batch.
    if not args.yes:
        answer = input(f"\nApply to {len(plan)} live endpoint(s)? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Cancelled. No change made.")
            return EXIT_ERROR

    print("\nResults:")
    failures = apply_batch(args.region, token, plan)
    print(f"\n{len(plan) - failures} accepted, {failures} failed, {skipped} skipped.")
    # Exit 0 only if every matched host was accepted and nothing was skipped.
    return EXIT_OK if failures == 0 and skipped == 0 else EXIT_FAILED


def main():
    """Command-line entry point: validate arguments, then run a single-host or CSV batch change."""
    parser = argparse.ArgumentParser(description="Override or revert EDR sensor policy for Vision One endpoints.")
    parser.add_argument("name", nargs="?", help="exact endpoint name (omit when using --csv)")
    parser.add_argument("--csv", metavar="FILE", help="CSV or XLSX file with a HOSTNAME column")
    parser.add_argument("--region", default=DEFAULT_REGION, help=f"Vision One API host (default: {DEFAULT_REGION})")

    # Exactly one of --edr or --remove-override must be given.
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--edr", choices=["on", "off"], help="apply an override that turns EDR on or off")
    action.add_argument("--remove-override", action="store_true", help="remove the override and revert to policy")

    parser.add_argument("--advanced-risk", choices=["on", "off"],
                        help="advanced risk telemetry setting; the API requires it with --edr")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    parser.add_argument("--dry-run", action="store_true", help="show the change without sending it")
    args = parser.parse_args()

    # Need exactly one way to pick endpoints: a name or a CSV file.
    if args.name and args.csv:
        parser.error("give either an endpoint name or --csv, not both")
    if not args.name and not args.csv:
        parser.error("give an endpoint name or --csv FILE")

    # The apply call needs advanced risk telemetry, and the remove call must not include it.
    if args.edr and not args.advanced_risk:
        parser.error("--advanced-risk on|off is required with --edr (the API requires it)")
    if args.remove_override and args.advanced_risk:
        parser.error("--advanced-risk only applies with --edr")

    # The API token comes from the environment so it is never stored in this file.
    token = os.environ.get("TMV1_TOKEN")
    if not token:
        print("error: set the TMV1_TOKEN environment variable first", file=sys.stderr)
        return EXIT_ERROR

    if args.csv:
        return run_csv(args, token)
    return run_single(args, token)


if __name__ == "__main__":
    # Only run main() when executed directly, not when imported by edr.py.
    sys.exit(main())
