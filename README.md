# nautobot-fixups

Nautobot Jobs for fleet-wide "fix-ups". The first job is the **SSH Fixup Engine**: paste a
list of CLI commands, pick devices, and the job logs in to each one over SSH with
[netmiko](https://github.com/ktbyers/netmiko), runs the commands one at a time with an
optional pause, and records `sending:` / `response:` pairs for the whole session.

It was built for APC Network Management Cards (UPS NMC2/NMC3, Rack PDUs) but embeds no
vendor commands: the operator supplies them, so the same job works for any CLI netmiko can
drive. The side quest on *other* ways to talk to APC cards lives in
[docs/apc-api-options.md](docs/apc-api-options.md) (short version: there is no REST API,
SNMP cannot set these settings, and config.ini uploads are the only alternative write path).

```
.
├── __init__.py              # makes the repo importable as <slug>.jobs (Git data source)
├── jobs/
│   ├── __init__.py          # register_jobs(SSHFixupEngine)
│   ├── ssh_fixup_engine.py  # the Nautobot Job: form, pre-flight, fleet loop, summary
│   └── ssh_runner.py        # vendor-agnostic netmiko session runner (no Nautobot imports)
├── docs/apc-api-options.md  # side quest: programmatic interfaces for APC NMCs
├── requirements.txt         # netmiko, for the Nautobot environment
└── tests/
    ├── fake_apc_server.py   # paramiko-based fake APC NMC SSH server
    ├── test_runner.py       # runner tests against the fake server (no database needed)
    ├── test_job_e2e.py      # opt-in: the real Job inside Nautobot (Postgres + Redis in Docker)
    └── e2e/run_e2e.sh       # one-shot script for the above
```

## Requirements

| Component | Version | Notes |
|---|---|---|
| Nautobot | 2.x (developed and tested on 2.4.43) | Job API from `nautobot.apps.jobs` |
| netmiko | >= 4.7, < 5 | 4.7 added the `apc_aos` driver. |
| paramiko | installed by netmiko | **paramiko 5.0 removed the SHA-1 `ssh-rsa` signature algorithm and SHA-1 Diffie-Hellman** (RSA keys still work through `rsa-sha2-*`). NMC2 cards have been observed to sign only with `ssh-rsa` (one AOS 7.1.8 card, see the open questions in the APC doc) and old AOS 6.x offers only SHA-1 key exchange, so for NMC2 fleets install `netmiko[par4]` (paramiko 3.5-4.x) in the Nautobot environment. `pip install -r requirements.txt` alone pulls paramiko 5; verify on one card with `ssh -vv`. NMC3 negotiates ECDH and can use an ECDSA host key. |

netmiko is **not** installed by Nautobot. Install it in the environment of every Nautobot
web and worker process (`pip install -r requirements.txt` in the image or venv) or the job
will fail to import.

## Installation (Git Repository data source)

1. Install netmiko where Nautobot runs (see above) and **restart the web and worker processes**;
   a worker started before the install cannot import the job.
2. In Nautobot go to **Extensibility → Git Repositories → Add**, point it at this repository,
   tick **Jobs** under *Provides*, and sync. The repository *slug* becomes the Python package
   name (`<slug>.jobs.ssh_fixup_engine`); keep it a plain identifier such as `nautobot_fixups`
   that does not collide with an installed package.
3. Go to **Jobs → Jobs**, open **Fixups / SSH Fixup Engine**, click **Edit** and tick **Enabled**.
   Consider also ticking **Approval required** (dry runs are exempt automatically) and pinning
   the job to a **task queue** whose worker can reach the management network.

The repository root contains an `__init__.py` on purpose: Nautobot imports Git-sourced jobs
as `<repository-slug>.jobs`, and the loader only discovers directories that are real Python
packages. Alternative: copy `jobs/` into `JOBS_ROOT`; the job then registers as
`jobs.ssh_fixup_engine.SSHFixupEngine` (that is how the end-to-end tests run it).

Optional but recommended for APC: set `network_driver` on your APC Platform to `apc_aos` and
add this to `nautobot_config.py` (or the Admin → Configuration page) so the driver is chosen
from the Platform instead of the manufacturer-name heuristic. netutils has no `apc_aos` entry,
so without this setting the Platform value alone maps to nothing:

```python
NETWORK_DRIVERS = {"netmiko": {"apc_aos": "apc_aos"}}
```

## Credentials: Secrets Group

The job never accepts a password in the form. Create a **Secrets Group** with:

| Access type | Secret type | Required |
|---|---|---|
| Generic (or SSH) | username | yes |
| Generic (or SSH) | password | yes |
| Generic (or SSH) | secret | only if *Enter enable mode* is used |

Create the underlying **Secrets** first (Extensibility → Secrets) with a provider that resolves
**on the Celery worker**: an environment-variable Secret must be set in the worker's environment,
a text-file Secret must exist on the worker host. Then pick the group in the job form, or leave
the field blank and the job uses the **Secrets Group assigned to each Device**. The job refuses
to start if the chosen group lacks a username+password pair under one access type; a group that
exists but cannot be resolved at run time (unset variable, missing file) marks that device
**failed**, not skipped.

Host keys are **not verified by default** (netmiko's accept-anything policy, because management
cards regenerate keys on firmware upgrades and NMC2 only offers `ssh-rsa`): the password is sent
to whatever answers at the device's primary IP. Set *Known hosts file* to an OpenSSH
`known_hosts` file on the worker to refuse unknown or changed keys; the transcript records the
host key fingerprint either way.

Secrets that belong *inside* a command (an APC RADIUS shared secret, a new user password) go in
a Nautobot **Secret** and are referenced from the command text with the `secret()` helper:

```
radius -p1 10.0.0.11 -s1 {{ secret("radius-shared-secret") }}
```

The value is fetched at run time (only Secrets the running user may view), sent to the device,
and masked everywhere else (job log, transcript, results file, stored job inputs). Anything
typed literally into the command box is stored with the Job Result **and published in the
`nautobot.jobs.job.started/completed` events** to every configured event broker, so the job
warns when a line looks like it carries a credential.

## Running the job

The form, in order:

| Field | What it does |
|---|---|
| Devices / Tags / Dynamic groups | Targets, unioned. Dynamic groups are Nautobot's saved filters (membership as last cached). |
| Include non-Active devices | Off by default: devices whose Status is not *Active* are listed as skipped. |
| Maximum devices | Refuse to start if the selection resolves to more than this (default 50). To touch 300 cards you must type 300. |
| Canary devices | Run this many devices first (name order); if any fails, stop before the rest (default 1). |
| Abort after N failed devices | Circuit breaker, default 3 (0 = never). Wrong credentials or a bad command list stop early; one dead PDU does not. |
| Change reference | Free text recorded in the log header and results file. |
| Secrets Group | See above. |
| Commands | One per line, in order. Blank lines and `#`, `!`, `//` comments ignored. Windows line endings are converted; tabs, smart quotes, en/em dashes, invisible and non-ASCII characters are normalised and reported in the log. |
| Render with Jinja2 | Each line is a template with `device`, `obj`, `secret()` and the Nautobot/netutils filters. An undefined name fails the run before anything is sent. |
| Deny pattern | Refuse the run if any rendered command matches. Suggested for APC: `^(reboot\|resetToDef\|format\|user\|console)\b\|^tcpip\b.*\s-(i\|s\|g)\b` (session-ending / lock-out / re-addressing commands). Clear it deliberately when you mean it. |
| Mask pattern | Regex whose matches are shown as `****` in the log and files, for secrets typed literally. |
| Pause between commands | Seconds after each response (default 1; NMC2 cards write flash on every command). |
| Command timeout | Seconds to wait for the prompt after a command (default 30). |
| Connection timeout | TCP connect timeout (default 15); SSH banner and authentication get twice that, minimum 30 s. |
| Connection retries | Extra attempts with 5 s doubling backoff on timeouts, early disconnects or a missing prompt (default 1). Never on authentication or algorithm failures. |
| Known hosts file | Path on the worker to an OpenSSH `known_hosts` file; when set, unknown or changed host keys are refused. Blank accepts any key. |
| SSH port | Default 22. |
| Netmiko device type | *Auto*: the Platform's netmiko driver, else `apc_aos` when the manufacturer/platform name contains APC or Schneider, else `generic`. A selection that resolves to more than one driver is refused unless you pick one. |
| Send method | `prompt` (default): wait for the CLI prompt after each command. `timing`: wait for output to go quiet; needed for `reboot` + `YES`. |
| Error pattern | A response matching it is a failed command. APC: `^E1\d{2}:` (E100-E108). |
| Success pattern | A response **not** matching it is a failed command. APC: `^E00[012]:`. Catches a wrong platform or an empty response. |
| Warning pattern | Logged as a warning, still OK. APC: `^E002:` (reboot required). |
| Stop device on error | After an error or timeout, send nothing further to that device (default on). |
| Dropped connection after the last command is OK | For lists that end with a reboot or logout. |
| Verify re-login afterwards | Log in once more after the commands; a device whose login no longer works is marked failed (default on). This is the generic defence against RADIUS/user/console changes that answer `Success` and lock you out. Skipped on dry runs and when *Dropped connection after the last command is OK* is ticked (the log says so). |
| Enter enable mode first | netmiko `enable()` for Cisco-style platforms. No-op for APC. |
| Logout command | Written before disconnecting (default `exit`) so the card frees its session slot. |
| Attach transcript and results files | `ssh-fixup-transcript.txt` (verbatim sending/response transcript plus raw SSH session log per device) and `ssh-fixup-results.json` on the Job Result. |
| Dry run | **On by default.** Connects, detects the prompt, logs what would be sent, sends nothing. Untick to run live. |

### What a run looks like

1. **Pre-flight (no network):** the command list is normalised, the target set resolved and
   capped, and for *every* device the host, driver, Secrets Group and rendered commands are
   worked out and the deny pattern applied. Any problem (template typo, missing Secret, mixed
   drivers, denied command) refuses the whole run before a single login. The log shows a plan
   table, the netmiko/paramiko versions, which legacy SSH algorithms are available, and a
   worst-case duration estimate against the job's time limit.
2. **Fleet loop, one device at a time**, each device its own grouping in the log:

   ```
   connecting to pdu-a1 at 10.1.2.3:22 as apc (device_type=apc_aos)
   connected to pdu-a1; prompt detected: 'apc>'
   sending: tcpip -d example.local
   response: E000: Success
   sending: ntp -p 10.0.0.123 -s 10.0.1.123
   response: E002: Reboot required for change to take effect      <- warning pattern
   ...
   pdu-a1: re-login OK (prompt 'apc>')
   device pdu-a1 OK (7 command(s), 1 warning(s))
   ```

   Canary and failure-count breakers stop the loop early. If the job's soft time limit hits
   mid-run, the summary is still written and the device in progress is reported as
   *interrupted* (its transcript is lost; check the device).
3. **Summary:** a table (device, host, status, sent, failed, warnings, detail), a one-line
   total, the two attachments, and a structured result on the Job Result
   (`ok`, `failed`, `skipped`, `not_attempted`, `aborted`, per-device status, host key,
   duration). The Job Result is marked **failed** if any attempted device failed, the run was
   aborted, or every selected device was skipped; otherwise skipped devices (no primary IP,
   not Active, no Secrets Group at all) do not fail it.

### Example: pointing APC management cards at new DNS/NTP/RADIUS/mail settings

```
tcpip -d example.local
Email -f1 {{ device.name }}@example.local
Radius -p1 10.0.0.11 -p2 10.0.1.11
dns -p 10.0.0.53 -s 10.0.1.53 -d example.local
ntp -p 10.0.0.123 -s 10.0.1.123
Email -t1 noc-alerts@example.com
Email -s1 mailrelay.example.local
# read back what we changed so the transcript proves the end state
dns
ntp
radius
email
```

Suggested rollout: error pattern `^E1\d{2}:`, success pattern `^E00[012]:`, warning
pattern `^E002:`, the deny pattern above. (1) Dry run on the full selection and read the plan.
(2) Live run on one or two devices. (3) Live run on the fleet with canary 1 and the failure
breaker at 3. To reboot cards that answered `E002`, run a second job with send method
`timing`, the two lines `reboot` and `YES`, *Dropped connection after the last command is OK*
ticked, and the deny pattern cleared (the re-login check is skipped on that run). Keep
`tcpip -i/-s/-g` out of fleet runs: the card moves away from its Nautobot primary IP mid-session.

### Things worth knowing about the Nautobot log

* Nautobot sanitises every job log message with `SANITIZER_PATTERNS`. The first default pattern
  redacts anything that looks like `user@host`, **including e-mail addresses**, so
  `Email -t1 noc@example.com` shows up as `Email -t1 (redacted)@example.com` and the template
  `{{ device.name }}@example.local` as `{{ device.name (redacted)@example.local` in the UI. The
  second pattern redacts the word after `secret`, `secrets`, `password` or `username`, which is
  why the job's own wording avoids those phrases. The transcript attachment is verbatim. Adjust
  `SANITIZER_PATTERNS` in `nautobot_config.py` if that bothers you.
* Job inputs are stored with the Job Result (`has_sensitive_variables = False`), so a run can be
  re-run or scheduled from the UI; the Re-run button pre-fills every field, including tags and
  dynamic groups left over from a previous run. The device cap and dry-run default exist for that
  reason. Re-runs re-send non-idempotent commands; there is no idempotency guard by design.
* The raw SSH session log in the transcript has the login password masked by netmiko (every
  occurrence of that string, so a lab password of `apc` also turns the `apc>` prompt into
  `********>`), and the job additionally masks the enable secret, `secret()` values and the
  mask pattern.

## APC notes

* Device type: `apc_aos` (netmiko >= 4.7). The driver waits for the `>` prompt and has no
  enable/config mode.
* Result codes: `E000: Success` and `E001: Successfully Issued` are fine, `E002: Reboot required
  for change to take effect` means exactly that, and `E100`-`E108` are failures
  (`E101 Command not found`, `E102 Parameter Error`, ...). The job has no built-in knowledge of
  these; give it the three patterns above. Anchor on the line start: `E100` can appear inside a
  serial number.
* No SSH exec channel on NMC2: `ssh apc@card "dns -p ..."` does not work on NMC2 (Schneider
  support confirmed only NMC3 2.x+ supports it). netmiko uses an interactive shell, which works
  on both generations.
* Legacy crypto: NMC2 cards have been seen to sign only with `ssh-rsa` and, on old AOS 6.x
  firmware, offer only SHA-1 Diffie-Hellman. paramiko 3.x/4.x accept those out of the box;
  paramiko 5.0 cannot connect to such cards. A failure reads "SSH negotiation failed:
  Incompatible ssh peer ..." and the log names the missing algorithms; the environment line at
  the top of every run says up front whether the installed paramiko still has them. Nothing in
  netmiko's `disabled_algorithms` or an ssh config file can add algorithms back, which is why
  the job has no "legacy SSH" switch.
* First login: NMC2 6.8+ and NMC3 force the Super User to change the default password on the
  first connection, and the CLI prompt never appears until that happens. The job reports this
  as "logged in but no CLI prompt appeared". Pre-provision new cards before fleet runs.
* Sessions: with *Allow Concurrent Logins* off (`session -m disable`) a card accepts one CLI
  login at a time, and sessions linger until the idle timeout (`user -st`) unless the client
  logs out, which is why the logout command defaults to `exit`. Clear a stuck session on the card
  with `session` and `session -d <ID>`. The job runs devices one after another on purpose.
* The command set is in the NMC CLI guides (NMC2: 990-4879L, NMC3: 990-91149L).

## Reusing the engine for other vendors

Nothing in the job is APC-specific apart from the manufacturer-name heuristic that picks
`apc_aos`. For Cisco/Arista/Juniper/Linux boxes: set `network_driver` on the Platform (or pick
the netmiko device type in the form), choose the right Secrets Group, set the error/success
patterns for that CLI (Cisco: error `^%`), optionally tick *Enter enable mode*, and paste the
commands. `jobs/ssh_runner.py` has no Nautobot imports and can be used from scripts or Nornir
tasks directly:

```python
from jobs.ssh_runner import SessionSpec, run_session, PrintLogger

spec = SessionSpec(host="10.1.2.3", username="apc", password="...", device_type="apc_aos",
                   commands=["about", "dns"], pause_seconds=1,
                   error_pattern=r"^E1\d{2}:", success_pattern=r"^E00[012]:", warning_pattern=r"^E002:")
result = run_session(spec, PrintLogger())
print(result.ok, result.transcript)
```

## Development

```bash
uv venv .venv --python 3.12            # or: python3.12 -m venv .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt   # or: .venv/bin/pip install -r requirements-dev.txt
.venv/bin/ruff check jobs tests
.venv/bin/python -m pytest -q          # runner tests against the fake APC server, no database (the e2e tests show as skipped)
tests/e2e/run_e2e.sh                   # the real Job inside Nautobot (needs Docker; ~3 minutes first time)
```

`tests/fake_apc_server.py` can also be started on its own (`python tests/fake_apc_server.py`)
to poke at the runner interactively with `ssh -p <port> apc@127.0.0.1` (password `apc`).

The end-to-end harness runs Celery eagerly inside the test process with Nautobot's own
database result backend, so Job Result status and the structured result behave as they do on a
real worker.
