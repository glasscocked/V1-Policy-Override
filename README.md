# EDR Override Tools for TrendAI Vision One

Check and change the EDR (endpoint sensor) state of endpoints in TrendAI Vision One by name.
You can work through an interactive prompt, a command-line switch, or a CSV/XLSX batch list.

## Contents

- [Setup](#setup)
- [Running on Windows](#running-on-windows)
- [Interactive mode (default)](#interactive-mode-default)
- [Command-line mode](#command-line-mode)
- [Batch import (CSV or XLSX)](#batch-import-csv-or-xlsx)
- [Read-only status check](#read-only-status-check)
- [Exit codes](#exit-codes)
- [What "disable" does](#what-disable-does)
- [Troubleshooting](#troubleshooting)
- [Files](#files)

## Setup

**Requirements:** Python 3 (tested with the macOS system Python 3). No packages to install (standard library only).

**1. Get an API key.** In the Vision One console, create an API key with the
`Endpoint Inventory: View` role. Changing EDR also needs the endpoint security policy
permissions listed in the Vision One API documentation.

**2. Set the token.** Run this in each terminal before using the tools:

```bash
export TMV1_TOKEN=<your api key token>
```

The token is read from the environment. It isn't stored in any file.

**3. Go to the project folder:**

```bash
cd /path/to/EDR-API-REGENERON   # the folder that contains edr.py
```

**Region:** the default API host is `api.xdr.trendmicro.com` (US). For another region, add
`--region <your API host>` to any command-line call.

## Running on Windows

These steps use PowerShell. The tools are the same as on macOS. The only differences are the
Python command (`py` instead of `python3`), the way you set the token, and how you write file paths.

### 1. Install Python

1. Download the latest Python 3 installer from <https://www.python.org/downloads/windows/>.
2. Run the installer. **On the first screen, tick "Add python.exe to PATH"** before you click
   Install Now. Without this, the commands below won't be found.
3. Finish the installer.

Or install it from PowerShell with Windows' built-in package manager:

```powershell
winget install -e --id Python.Python.3.12
```

Open a **new** PowerShell window and check that Python runs:

```powershell
py --version
```

The `py` command is the Python launcher that the installer adds. It replaces `python3` in every
command in this README. If `py` isn't recognized, try `python --version`.

If `python` opens the Microsoft Store instead of running, turn off the Store alias: go to
**Settings > Apps > Advanced app settings > App execution aliases**, switch off `python.exe` and
`python3.exe`, then open a new PowerShell window.

### 2. Get the project folder

Copy the project folder to a location you can find, for example `C:\Users\<you>\EDR-API-REGENERON`.

### 3. Set the token

For the current PowerShell window only:

```powershell
$env:TMV1_TOKEN = "<your api key token>"
```

To keep it for future windows (open a new window after running this):

```powershell
setx TMV1_TOKEN "<your api key token>"
```

`setx` saves the token in your Windows user settings, where other programs you run can read it.
If you'd rather not store it, use the `$env:` form each time you open PowerShell.

### 4. Run the tools

```powershell
cd C:\Users\<you>\EDR-API-REGENERON
py edr.py
```

Command-line examples:

```powershell
py edr_status.py host-01.example.internal
py edr_policy.py host-01.example.internal --edr on --advanced-risk off --dry-run
```

### Batch files on Windows

**Always wrap file paths in double quotes.** Windows paths use backslashes, and without quotes they
are read as escape characters, so the path breaks.

```powershell
py edr_policy.py --csv "C:\Users\<you>\Documents\CSV_EXAMPLE.xlsx" --edr on --advanced-risk off --dry-run
```

In the interactive prompt, type `c`, then the path in quotes:

```
"C:\Users\<you>\Documents\CSV_EXAMPLE.xlsx"
```

Dragging a file into the PowerShell window also pastes its path in quotes, so that works too.

### Windows troubleshooting

| Message | Likely cause |
|---|---|
| `'py' is not recognized` | Python was installed without "Add python.exe to PATH". Re-run the installer and tick that option, or reinstall with winget. |
| `'python' is not recognized` or Store opens | Use `py` instead, or turn off the Store alias (see step 1). |
| `set the TMV1_TOKEN environment variable first` | The token isn't set in this window. Run step 3 again, or open a new window after `setx`. |
| `error: could not read ...: No such file` | The path is wrong or is missing its extension, or it isn't in quotes. |

## Interactive mode (default)

Run the tool with no arguments:

```bash
python3 edr.py
```

You'll see:

```
Input a Hostname (or c=import CSV or XLSX, blank = quit):
```

1. **Type a hostname**, for example `host-01.example.internal`. The tool shows
   its agent GUID, EDR status, connectivity, and last-connected time.
2. **Choose an action:**

   | Key | Action |
   |---|---|
   | `e` | Enable EDR. Creates an override. You'll be asked for advanced risk telemetry (`on` or `off`). |
   | `d` | Disable EDR. Removes the override, which reverts the endpoint to its assigned policy. |
   | `r` | Refresh the status. |
   | `n` | Look up a different host. |
   | `q` | Quit. |

3. **Confirm.** Every change asks `[y/N]` before it's sent. Anything other than `y` cancels.

After an accepted change, the status refreshes automatically. If the endpoint is offline, the
change applies when it reconnects.

**Batch from the prompt:** type `c` at the hostname prompt, then enter the path to your file.
See [Batch import](#batch-import-csv-or-xlsx).

**Paths:** you can drag a file from Finder into the terminal. Escaped spaces (`\ `) and quotes are
accepted. Include the extension (`.csv` or `.xlsx`).

**Quit:** press Enter on an empty line at the hostname prompt, or type `q` at the action prompt.

### Interactive mode on Windows

Set your token first (see [Running on Windows](#running-on-windows)), then start the prompts from
PowerShell:

```powershell
cd C:\Users\<you>\EDR-API-REGENERON
py edr.py
```

The prompts are the same as on macOS. A hostname shows its details, then you choose an action:

```
Input a Hostname (or c=import CSV or XLSX, blank = quit): host-01.example.internal

  Endpoint:        host-01.example.internal
  Agent GUID:      00000000-0000-0000-0000-000000000001
  Agent version:   202609
  EPP agent ver.:  20.0.3.28120
  Version check:   OK
  EDR:             ON
  Adv. risk tel.:  ON
  Connectivity:    connected
  Last connected:  2026-10-21T14:16:00

[e] enable EDR  [d] disable EDR (removes override)  [r] refresh  [n] new host  [q] quit:
```

**Batch import on Windows:** at the hostname prompt, type `c`, then the path to your file **in
double quotes**:

```
"C:\Users\<you>\Documents\CSV_EXAMPLE.xlsx"
```

Quotes are required here. Without them, the backslashes are read as escape characters and the path
breaks. Dragging a file from File Explorer into the PowerShell window also pastes the path in quotes.

**Quitting on Windows:** press Enter on an empty line at the hostname prompt, type `q` at the action
prompt, or press Ctrl+C at any prompt. Ctrl+C exits cleanly without an error message.

## Command-line mode

Any arguments switch to command-line mode, which is the same tool without the prompts:

```bash
# Turn EDR on for one host (advanced risk telemetry is required with --edr)
python3 edr_policy.py host-01.example.internal --edr on --advanced-risk off

# Turn EDR off by removing the override
python3 edr_policy.py host-01.example.internal --remove-override

# Preview a change without sending it
python3 edr_policy.py host-01.example.internal --edr on --advanced-risk off --dry-run

# Skip the confirmation prompt (for scripts)
python3 edr_policy.py host-01.example.internal --remove-override --yes
```

| Option | Meaning |
|---|---|
| `NAME` | Exact endpoint name. Omit when using `--csv`. |
| `--csv FILE` | Batch input from a `.csv` or `.xlsx` file. See [Batch import](#batch-import-csv-or-xlsx). |
| `--edr on\|off` | Apply an override that turns EDR on or off. |
| `--remove-override` | Remove the override and revert to the assigned policy. |
| `--advanced-risk on\|off` | Advanced risk telemetry setting. Required with `--edr`. |
| `--yes` | Skip the confirmation prompt. |
| `--dry-run` | Show the request that would be sent, without sending it. |
| `--region HOST` | API host. Default `api.xdr.trendmicro.com`. |

`--edr` and `--remove-override` can't be used together. `--advanced-risk` only applies with
`--edr`.

## Batch import (CSV or XLSX)

Use a file with a column named **`HOSTNAME`** (the header is not case-sensitive). Other columns are
ignored.

| HOSTNAME |
|---|
| host-01.example.internal |
| host-02.example.local |

- Both `.csv` and `.xlsx` files work. Only the first sheet of an `.xlsx` file is read.
- Blank rows and duplicate names are dropped.
- A sample file is included: `CSV_EXAMPLE.xlsx`.

**From the command line:**

```bash
python3 edr_policy.py --csv CSV_EXAMPLE.xlsx --edr on --advanced-risk off --dry-run
python3 edr_policy.py --csv hosts.csv --remove-override
```

**From the interactive prompt:** type `c`, then the file path. The tool looks up every host, shows a
table of current states, and asks which action to apply to all matches.

**What happens to each host:**

- **Found, one match:** the change is sent. Each host gets its own request, so every result line
  matches its hostname.
- **Not found:** skipped and marked in the table.
- **Matches more than one endpoint:** skipped, with the matches listed, so nothing changes by
  accident.

A single confirmation covers the whole batch. A summary at the end shows how many were accepted,
failed, and skipped.

## Read-only status check

`edr_status.py` only reads. It never changes anything.

```bash
python3 edr_status.py host-01.example.internal
python3 edr_status.py host-01.example.internal --json
```

Example output:

```
Endpoint                                     Agent GUID                            Agent Version  EPP Agent Version  EDR  Adv. Risk Telemetry  Connectivity  Last Connected      Version Check
host-01.example.internal  00000000-0000-0000-0000-000000000001  202609         20.0.3.28120       ON   ON                   connected     2026-10-21T14:16:00  OK
```

The EDR column shows `ON`, `OFF`, or `enabling` / `disabling` while a change is still
applying.

## Version check

Every lookup checks two versions against minimums set as constants at the top of
`edr_status.py`:

| Constant | Current minimum | Compared against |
|---|---|---|
| `MIN_AGENT_VERSION` | `202507` | `agentVersion` |
| `MIN_EPP_VERSION` | `20.0.1-25770` | `eppAgent.version` |

- **Below minimum:** the host fails the check. The status table, interactive details, and batch table
  show the reason in the Version Check or Note column.
- **Either version below minimum:** the host fails, even if the other version passes.
- **Version missing or unreadable:** shown as "unknown" and treated as a failure.
- **Enable is refused** for any host that fails the check, in single-host mode, the interactive prompt,
  and batch mode. Batch mode enables only the hosts that pass, and reports the rest as skipped.
- **Disable is not affected.** Removing an override is always allowed.
- A host that fails the check and is already ON stays ON. Nothing is disabled automatically.

To change the minimums, edit the two constants in `edr_status.py`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. For status checks, every match is ON. For changes, everything was accepted. |
| `1` | Status check: at least one match is OFF, unknown, or fails the version check. Change: a request failed, or hosts were skipped. |
| `2` | No endpoint matched the name (single-host mode). |
| `3` | Configuration, authentication, or API error, or the change was cancelled. |

## What "disable" does

Disabling EDR removes the override. The endpoint then goes back to its **assigned policy**.
The remove call also clears overrides made in the Vision One console and the hypersensitive detection mode setting. Before a disable, the tool shows whether the policy is overridden and any EDR settings it can read, so you can see what will change.
If that policy has EDR turned on, the endpoint stays on after the override is removed. Check the
status after disabling to confirm the result.

## Troubleshooting

| Message | Likely cause |
|---|---|
| `set the TMV1_TOKEN environment variable first` | The token isn't set in this terminal. Run the `export` command from Setup. |
| `HTTP 401 (token is invalid or expired)` | Wrong or expired token. Create a new one in the console. |
| `HTTP 403 (API key needs ... role)` | The API key is missing the required role. |
| `could not reach api.xdr.trendmicro.com` | Network issue, or the wrong region. Try `--region` with your API host. |
| `No endpoint found named '...'` | The name must match exactly. Check the spelling, or use the hostname as Vision One shows it. |
| `N endpoints match ...` | The name is ambiguous. The tool refuses to change any of them. |
| `That file does not exist` | Check the path and the extension (`.csv` or `.xlsx`). |
| `no HOSTNAME column found` | The header row must contain `HOSTNAME`. |
| `HTTP 404` or `500` on a change | Shown per host in batch mode. Retry that host individually. |

## Files

| File | Purpose |
|---|---|
| `edr.py` | Interactive prompts. Default entry point. |
| `edr_policy.py` | Change tool: single host or CSV batch. |
| `edr_status.py` | Read-only status check and shared lookup helpers. |
| `CSV_EXAMPLE.xlsx` | Sample batch input. |
| `CLAUDE.md` | Guidance for Claude Code working in this folder. |
