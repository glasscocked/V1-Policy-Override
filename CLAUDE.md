# CLAUDE.md

Guidance for Claude Code when working in this folder.

## What this project is

Python tools that check and change the EDR (endpoint sensor) state of endpoints in
TrendAI Vision One, using the Endpoint Security Operations API. See [README.md](README.md)
for usage.

| File | Purpose | Changes live state? |
|---|---|---|
| `edr_status.py` | Read-only lookup of one endpoint's EDR status. Also holds the shared lookup helpers. | No |
| `edr_policy.py` | Command-line change tool: override EDR on/off, remove override, single host or `--csv` batch. | Yes |
| `edr.py` | Interactive TUI (default when run with no arguments). Passes any arguments through to `edr_policy.py`. | Yes |
| `CSV_EXAMPLE.xlsx` | Sample input with a `HOSTNAME` column. Real input is `.xlsx`, not `.csv`. | No |

Dependency direction: `edr.py` imports `edr_policy.py`, which imports `edr_status.py`.
Keep it that way; don't add a circular import.

## API facts (verified against the live US region)

- Base host: `api.xdr.trendmicro.com` (US). Other regions use a different host, passed with `--region`.
- Auth: `Authorization: Bearer <TMV1_TOKEN>`. The token is read from the environment and must never be written into code, docs, or chat output.
- Lookup: `GET /v3.0/endpointSecurity/endpoints` with header `TMV1-Filter: endpointName eq '<name>'`.
  The response includes `agentGuid` and an `edrSensor` object with `status` (`enabled` / `disabled`, plus the transitional `enabling` / `disabling`), `connectivity`, and `lastConnectedDateTime`.
  The `select` parameter does not trim the response, so read the nested fields.
- Apply override: `POST /v3.0/endpointSecurity/endpoints/applySensorPolicy`, body
  `{"agentGuids": [...], "sensorDetectionAndResponse": "enabled|disabled", "advancedRiskTelemetry": "enabled|disabled"}`. The spec's request body is a oneOf: EDR setting only, advanced telemetry only, or both.
  Both settings are required by the API.
- Remove override: `POST /v3.0/endpointSecurity/endpoints/removeOverriddenSensorPolicy`, body `[{"agentGuid": "..."}]`.
  Verified live.
- Change responses are HTTP 207 with one item per request. Item status `202` means accepted. `404` means not found, `500` means server error.
- Required API key roles: `Endpoint Inventory: View` for lookup. Changes also need the sensor-configuration and override permissions shown in the API docs.

## Rules for working in this folder

1. **Never send a live change without explicit approval in this conversation.** That covers
   `applySensorPolicy` and `removeOverriddenSensorPolicy`, including through the scripts without
   `--dry-run`. Use `--dry-run` for tests. Read-only lookups (`edr_status.py`, the TUI `r` option,
   `--dry-run`) are fine to run for testing.
2. **Never print, log, or store the token.** If a user pastes a token into chat, use it only for
   the request they asked for, don't repeat it, and suggest rotating it afterward.
3. **Enforce the minimum versions.** `MIN_AGENT_VERSION` and `MIN_EPP_VERSION` live in `edr_status.py`.
   A host below either minimum, or with an unknown version, must never be enabled. Only the enable
   action is blocked. Disabling is always allowed. Don't add an override for this check without asking.
   Refuse to change more than one endpoint from one name. Ambiguous names (several matches) are
   skipped in batch mode and rejected in single-host mode. Keep that behavior.
4. **Confirmation before every change.** Single host and batch both prompt unless `--yes` is given.
   Don't add an auto-confirm path.
5. **Standard library only.** No third-party packages. The `.xlsx` reader is built on `zipfile` and
   `xml.etree` for this reason.
6. **Comment all code.** Every function gets a docstring, and non-obvious steps get a short comment.
   Match the existing style.
7. **Keep the three scripts consistent.** Shared logic lives in `edr_status.py` and `edr_policy.py`.
   Don't duplicate lookup or request-building code in `edr.py`.
8. **Exit codes are part of the interface.** Documented in each script's docstring and in
   [README.md](README.md). Update both if they change.

## Known open points

- The `TMV1-Filter` quoting for names containing an apostrophe (doubled `''`) is unverified.
- Disabling EDR uses "remove override". Per the spec, that also clears console overrides and hypersensitive mode, and the tool shows the current overrides before a disable. It reverts to the assigned policy. If that policy has EDR on,
  the endpoint stays on. A hard-off option would need a different approach.
- `CSV_EXAMPLE.xlsx` is read from its first sheet only.
- Batch mode sends one request per host (deliberate, so each result maps to its hostname).
  The API allows up to 200 GUIDs per apply call; batching by 200 is a possible later optimization.

## Testing without changing anything

```bash
python3 -m py_compile edr.py edr_policy.py edr_status.py
python3 edr_policy.py --csv CSV_EXAMPLE.xlsx --edr on --advanced-risk off --dry-run
printf 'c\nCSV_EXAMPLE.xlsx\nq\n\n' | python3 edr.py
```

The last command needs `TMV1_TOKEN` set. It performs lookups only, then cancels at the action prompt.
