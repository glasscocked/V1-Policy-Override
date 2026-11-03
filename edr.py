#!/usr/bin/env python3
"""Interactive EDR control for TrendAI Vision One.

    python3 edr.py                  # interactive prompts (default)
    python3 edr.py <name> [flags]   # command-line mode, same flags as edr_policy.py

Interactive mode asks for a hostname, shows its EDR status, then offers to
enable EDR (applies an override) or disable it (removes the override).
At the hostname prompt, type c to import hostnames from a CSV or XLSX file instead.
"""
import os
import shlex
import sys
import urllib.error

# edr_policy holds the change logic and the CLI; this file adds the prompts on top of it.
import edr_policy
from edr_policy import (
    APPLY_PATH, EXIT_ERROR, EXIT_OK, READ_ERRORS, REMOVE_PATH, SETTING,
    apply_batch, build_request, load_hostnames, lookup_hostnames, print_lookup_table,
    show_overrides,
)
from edr_status import DEFAULT_REGION, advanced_label, edr_label, find_endpoints, summarize


def lookup(region, token, name):
    """Return the summarized endpoint for an exact name, or None (after printing why)."""
    try:
        data = find_endpoints(region, token, name)
    except urllib.error.HTTPError as e:
        print(f"  Lookup failed: HTTP {e.code}")
        return None
    except urllib.error.URLError as e:
        print(f"  Could not reach {region}: {e.reason}")
        return None

    items = data.get("items", [])
    if not items:
        print(f"  No endpoint named '{name}'.")
        return None
    # Refuse to act when the name is ambiguous, and list the matches so the user can see why.
    if len(items) > 1:
        print(f"  {len(items)} endpoints match '{name}'. Refusing to continue:")
        for item in items:
            print(f"    {item.get('endpointName')}  {item.get('agentGuid')}")
        return None
    return summarize(items[0])


def show_status(current):
    """Print the endpoint's details and EDR status as a small block."""
    print()
    print(f"  Endpoint:        {current['endpointName']}")
    print(f"  Agent GUID:      {current['agentGuid']}")
    print(f"  Agent version:   {current['agentVersion'] or 'unknown'}")
    print(f"  EPP agent ver.:  {current['eppAgentVersion'] or 'unknown'}")
    print(f"  Version check:   {current['versionProblem'] or 'OK'}")
    print(f"  EDR:             {edr_label(current)}")
    print(f"  Adv. risk tel.:  {advanced_label(current)}")
    print(f"  Connectivity:    {current['connectivity'] or 'unknown'}")
    print(f"  Last connected:  {current['lastConnectedDateTime'] or 'unknown'}")
    print()


def send_change(region, token, path, body, description):
    """Confirm, send the change, and report the result. Returns True if accepted."""
    # Confirm before anything is sent. Anything other than y or yes cancels.
    answer = input(f"  {description}? [y/N]: ").strip().lower()
    if answer not in ("y", "yes"):
        print("  Cancelled. No change made.")
        return False
    try:
        results = edr_policy.post(region, token, path, body)
    except urllib.error.HTTPError as e:
        print(f"  Change request returned HTTP {e.code}.")
        return False
    except urllib.error.URLError as e:
        print(f"  Could not reach {region}: {e.reason}")
        return False

    # The API returns a status per request. Print them and report whether all were accepted.
    print("  API response:")
    ok = edr_policy.print_results(results)
    if ok:
        print("  Accepted. If the endpoint is offline, the change applies when it reconnects.")
    return ok


def clean_path(raw):
    """Turn typed or dragged-in path text into a usable path: handles quotes, backslash-escaped spaces, and ~."""
    try:
        # shlex understands quotes and backslash escapes the way the shell does.
        parts = shlex.split(raw)
    except ValueError:
        # Unbalanced quotes: fall back to the raw text with any outer quotes removed.
        return raw.strip().strip('"').strip("'")
    # Rejoin in case the path had unescaped spaces, which shlex splits into separate pieces.
    return os.path.expanduser(" ".join(parts))


def csv_flow(region, token):
    """Import hostnames from a CSV or XLSX file and apply one EDR action to every match."""
    path = clean_path(input("  Path to CSV or XLSX (blank to cancel): "))
    if not path:
        return

    try:
        names = load_hostnames(path)
    except READ_ERRORS as e:
        print(f"  Could not read {path}: {e}")
        if not os.path.isfile(path):
            # The most common cause is a missing or wrong extension, such as .xlsx left off.
            print("  That file does not exist. Check the spelling and the extension (.csv or .xlsx).")
        return
    print(f"  Read {len(names)} hostname(s). Looking them up...")

    try:
        rows = lookup_hostnames(region, token, names)
    except urllib.error.HTTPError as e:
        print(f"  Lookup failed: HTTP {e.code}")
        return
    except urllib.error.URLError as e:
        print(f"  Could not reach {region}: {e.reason}")
        return

    print()
    print_lookup_table(rows)
    print()

    # Only hosts that matched exactly one endpoint can be changed.
    found = [r for r in rows if r["current"]]
    skipped = len(rows) - len(found)
    if not found:
        print("  No endpoints to change.")
        return

    choice = input(
        f"  [e] enable EDR on {len(found)}  [d] disable EDR on {len(found)} (removes overrides)  [q] cancel: "
    ).strip().lower()

    # Build one request per matched host for whichever action was chosen.
    refused = []
    if choice == "e":
        # Hosts that fail the version check are refused. The rest are eligible to enable.
        refused = [r for r in found if r["current"]["versionProblem"]]
        eligible = [r for r in found if not r["current"]["versionProblem"]]
        for r in refused:
            print(f"  Refused {r['name']}: {r['current']['versionProblem']}")
        if not eligible:
            print("  No hosts can be enabled: all fail the version check.")
            return
        telemetry = input("  Advanced risk telemetry? [on/off]: ").strip().lower()
        if telemetry not in SETTING:
            print("  Enter on or off. Cancelled.")
            return
        plan = [(r["name"], *build_request(r["current"]["agentGuid"], "on", telemetry)) for r in eligible]
        description = f"Enable EDR on {len(eligible)} endpoint(s) (advanced risk telemetry {telemetry})"
    elif choice == "d":
        plan = [(r["name"], *build_request(r["current"]["agentGuid"], None, None)) for r in found]
        description = f"Disable EDR on {len(found)} endpoint(s) by removing the policy override"
    else:
        print("  Cancelled. No change made.")
        return

    # One confirmation covers the whole batch.
    answer = input(f"  {description}? [y/N]: ").strip().lower()
    if answer not in ("y", "yes"):
        print("  Cancelled. No change made.")
        return

    print("  Results:")
    failures = apply_batch(region, token, plan)
    print(f"  {len(plan) - failures} accepted, {failures} failed, {skipped + len(refused)} skipped (not found, ambiguous, or failing the version check).")


def run_tui(region, token):
    """Interactive loop: pick a host, view its status, then enable, disable, refresh, or switch hosts."""
    print("TrendAI Vision One: EDR control. Press Enter on an empty hostname to quit.")
    # Outer loop: one iteration per hostname (or CSV import).
    while True:
        print()
        name = input("Input a Hostname (or c=import CSV or XLSX, blank = quit): ").strip()
        if not name:
            return EXIT_OK
        if name.lower() == "c":
            # Batch import from a file. Returns to this prompt when done.
            csv_flow(region, token)
            continue

        current = lookup(region, token, name)
        if current is None:
            continue

        # Inner loop: act on the current host until the user chooses a new one.
        while True:
            show_status(current)
            choice = input(
                "[e] enable EDR  [d] disable EDR (removes override)  [r] refresh  [n] new host  [q] quit: "
            ).strip().lower()

            # Refresh: look the host up again. Keep the old view if the lookup fails.
            if choice == "r":
                current = lookup(region, token, name) or current
                continue

            if choice == "e":
                # Enabling is refused outright when either version is below the minimum (or unknown).
                if current["versionProblem"]:
                    print(f"  Refused: {current['versionProblem']}. Enable is blocked until the agent meets the minimum.")
                    continue
                # Enabling needs the advanced risk telemetry setting too, since the API requires it.
                telemetry = input("  Advanced risk telemetry? [on/off]: ").strip().lower()
                if telemetry not in SETTING:
                    print("  Enter on or off.")
                    continue
                body = {
                    "agentGuids": [current["agentGuid"]],
                    "sensorDetectionAndResponse": SETTING["on"],
                    "advancedRiskTelemetry": SETTING[telemetry],
                }
                changed = send_change(
                    region, token, APPLY_PATH, body,
                    f"Enable EDR on {name} (advanced risk telemetry {telemetry})",
                )
            elif choice == "d":
                # Disabling means removing the override, which reverts the endpoint to its assigned policy.
                # It also removes console overrides and hypersensitive mode, so show what is in effect first.
                show_overrides(region, token, current["agentGuid"])
                body = [{"agentGuid": current["agentGuid"]}]
                changed = send_change(
                    region, token, REMOVE_PATH, body,
                    f"Disable EDR on {name} by removing the policy override",
                )
            elif choice == "n" or choice == "":
                # Leave the inner loop and ask for a new hostname.
                break
            elif choice == "q":
                # Exit the program from anywhere in the inner loop.
                return EXIT_OK
            else:
                print("  Choose e, d, r, n, or q.")
                continue

            # After an accepted change, refresh the status so the screen shows the new state.
            if changed:
                refreshed = lookup(region, token, name)
                if refreshed:
                    current = refreshed


def main():
    """Entry point: pass arguments to the CLI, or start the interactive prompts when there are none."""
    # Any command-line arguments go to the flag-based CLI in edr_policy.py.
    if len(sys.argv) > 1:
        return edr_policy.main()

    token = os.environ.get("TMV1_TOKEN")
    if not token:
        print("error: set the TMV1_TOKEN environment variable first", file=sys.stderr)
        return EXIT_ERROR

    try:
        return run_tui(DEFAULT_REGION, token)
    except (KeyboardInterrupt, EOFError):
        # Ctrl-C or Ctrl-D at any prompt exits cleanly without a traceback.
        print()
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
