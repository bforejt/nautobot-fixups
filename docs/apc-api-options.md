# Side quest: how else can we talk to APC management cards programmatically?

Research notes for the question *"what options do we have to interact with the APC devices
using API calls?"*, gathered on 2026-10-07 from Schneider Electric / APC documentation, the
PowerNet MIB, the Schneider community forums and the state of community tooling. Scope: APC
Network Management Card 2 (AP9630/AP9631/AP9635, Rack PDU 2G AP8xxx), Network Management
Card 3 (AP9640/AP9641/AP9643 and NMC3-based Rack PDUs / NetShelter) and, where relevant,
NMC4 and the NetShelter Rack PDU Advanced line.

## TL;DR

| Interface | Can it set DNS / NTP / SMTP+recipients / RADIUS / domain? | Fleet-friendly? | Verdict |
|---|---|---|---|
| **SSH CLI** (what the SSH Fixup Engine does) | Yes, all of them (`dns`, `ntp`, `smtp`, `email`, `radius`, `tcpip`) with a result code per command | Yes, one session per card | **Best for ad-hoc fix-ups with feedback.** Interactive shell only: NMC2 has no SSH exec channel. |
| **config.ini / .csf file upload** over SCP or FTP | Yes (every setting the card exposes, except passwords, which go in `.csf`) | Yes, it is Schneider's official mass-configuration path (INI Utility, DCE, EcoStruxure IT all use it) | **Best for "make 500 cards identical".** No per-setting feedback, some settings apply only on reboot/log-off. Natural second mode for this job. |
| **SNMP (PowerNet MIB)** | **No.** The MIB has no DNS/NTP/SMTP/RADIUS/hostname objects at all | n/a | Monitoring, traps, outlet control, clock, restart. Not a configuration API for these settings. |
| **HTTP REST / JSON API on the card** | **Does not exist** on NMC2 or NMC3 | n/a | No official REST, no OpenAPI, no Redfish on NMC2/3/4. |
| **Redfish** (NetShelter Rack PDU *Advanced* only) | No (GET-heavy; POST only for accounts, outlets, event subscriptions) | partly | Monitoring + outlet control on APDU9xxx/10xxx/11xxx native firmware only. |
| **Web UI form scraping** | Technically, but undocumented, firmware-specific, session-limited | No | Don't. Cards get wedged by clients that forget to log out. |
| **Modbus TCP** | No, UPS/PDU telemetry and UPS-level settings only | n/a | BMS integration, not management. |
| **EcoStruxure IT Expert API / DCE API** | No (read-only inventory, alarms, sensors, measurements) | n/a | Pull-side integration (e.g. reconcile Nautobot inventory). Their *GUI* can push config.ini templates to NMC2/NMC3. |

Bottom line: there is no API that lets us set these fields with a JSON call. The two real
options are the CLI over SSH (per-command feedback, what we built) and config.ini uploads
(bulk, no feedback). Everything else is read-only or out of scope.

## 1. SSH CLI (current approach)

* Same command family on NMC2 and NMC3: `dns -p/-s/-d/-n/-h`, `ntp -p/-s/-e`, `smtp -f/-s/-p/...`,
  `email -t[n]/-g[n]/-f[n]/-s[n]/...` (recipients 1-4), `radius -a` plus `-p1/-p2/-o1/-o2/-s1/-s2/-t1/-t2`,
  `tcpip -i/-s/-g/-d/-h`, `session`, `reboot`. Commands are case-insensitive, options are
  case-sensitive. NMC2 CLI guide: 990-4879L, NMC3 CLI guide: 990-91149L.
* Every command answers with a result code designed for scripting: `E000: Success`,
  `E001: Successfully Issued`, `E002: Reboot required for change to take effect`,
  `E100: Command failed`, `E101: Command not found`, `E102: Parameter Error`,
  `E103: Command Line Error`, `E104: User Level Denial`, `E105: Command Prefill`,
  `E106: Data Not Available`, `E107: Serial communication with the UPS has been lost`,
  `E108: EAPoL disabled due to invalid/encrypted certificate` (NMC3). Key on the code, not the
  text, and anchor the regex to the start of a line (`^E1\d{2}:`): `E100` can appear inside
  a serial number (haught.apcos issue 5).
* **NMC2 does not support the SSH exec channel** (`ssh user@card "dns -p ..."`, paramiko
  `exec_command`); Schneider support confirmed only NMC3 2.x+ does. netmiko always uses an
  interactive shell, which works on both generations.
* Password-only logins (no SSH keys). `tcpip` IP changes, `console`/hostname changes and
  `reboot` (which asks for `YES`) drop the session; the job's *timing* send method plus
  "dropped connection after the last command is OK" handles the reboot case.
* Session hygiene: `session -m disable` ("Allow Concurrent Logins" off) means one CLI login at
  a time; `session` lists sessions, `session -d <ID>` kills a stuck one; CLI idle timeout is
  `user -st <minutes>`. Always log out (`exit`/`quit`, `bye` on NMC3).
* Crypto: NMC2 firmware signs with `ssh-rsa` and older AOS 6.x offers only SHA-1 DH key
  exchange. paramiko 3.5.x / 4.0.x still accept those by default; **paramiko 5.0 removed them**,
  so pin `paramiko<5` in the Nautobot environment for NMC2 fleets. NMC3 can switch to an ECDSA
  host key (`ssh key -ecdsa 256`) and already negotiates ECDH.
* First login on NMC2 6.8+ / NMC3 forces a Super User password change; the card never shows
  the prompt until that is done, so pre-provision cards before running fleet jobs.
* Netmiko ships an `apc_aos` driver since 4.7.0 (2026-05). Prior art: jtdub's
  `nautobot-app-pdu-manager` (Nornir + netmiko `apc_aos`, outlet control, Nautobot 3.x) and the
  `haught.apcos` Ansible collection (NMC3 >= 1.4.2.1 only, per-setting modules, unmaintained
  since 2023).

Sources: NMC2 CLI guide <https://download.schneider-electric.com/files?p_Doc_Ref=SPD_LFLG-ACVDQ9_EN>,
NMC3 CLI guide <https://download.schneider-electric.com/files?p_Doc_Ref=SPD_CCON-AYCELJ_EN>,
Schneider support on exec channel <https://community.se.com/t5/APC-UPS-Data-Center-Enterprise/Scripting-SSH-connections-to-NMC-s-take-2/td-p/449384>,
NMC2 ssh-rsa negotiation <https://community.se.com/t5/APC-UPS-Data-Center-Enterprise/SSH-from-Fedora-41-to-AP9631-fails-ssh-dispatch-run-fatal-error/td-p/498038>,
paramiko changelog <https://www.paramiko.org/changelog.html>, netmiko PR 3768 <https://github.com/ktbyers/netmiko/pull/3768>,
<https://github.com/jtdub/nautobot-app-pdu-manager>, <https://github.com/haught/ansible_apcos>.

## 2. config.ini and .csf files (the official bulk path)

* Every NMC1/NMC2/NMC3 (AOS 3.x+) exposes its configuration as `config.ini`: download it (FTP
  `get config.ini`, SCP, or the web UI *Configuration > General > User Config File*), edit, and
  upload it to any number of cards (FTP `put`, SCP, TFTP, the web UI, a DHCP option-67 boot file,
  or the serial-only `xferINI` command). The card parses the file, applies it and deletes it.
* **Partial files are officially supported** and are the recommended unit of change: any
  `<name>.ini` with at least one `[Section]` and one `keyword=value`. Section and keyword names
  are case-insensitive, string values are case-sensitive, `;` starts a comment, `""` sets an
  empty value. Unknown keywords/sections are ignored with per-line warnings in the event log.
  NMC3 3.2+ optionally verifies a file named `<name>_CRC32-<8 hex>.ini`.
* IP/mask/gateway/boot-mode lines are protected by the `[NetworkTCP/IP]` `Override` keyword
  (defaults to the card's MAC), so a shared file cannot accidentally re-address a card; a similar
  `UPSOverride` protects UPS output settings.
* **Nobody publishes the full key list.** Official docs name only a handful of sections
  (`[NetworkTCP/IP]`, `[SystemDate/Time]` `NTPEnable`, `[NetworkSNMP]`, `[EventActionConfig]`,
  `[CryptographicAlgorithms]`, `[SystemUserManager]`); the RADIUS, DNS, NTP-server and SMTP keys
  have to be read from a `config.ini` downloaded from one card of each generation (the file is
  self-documenting with `;` comments above each key). Schneider staff confirm no reference exists.
* `.csf` files are plain-text lists of CLI `user` commands, upload-only, for user/password
  management (NMC2 6.0.6+ and NMC3 no longer accept users via config.ini). Known bug: `.csf`
  uploaded over SCP is stored but not parsed on NMC2 AOS < 6.3.3.
* **Validation is after the fact.** The transfer always "succeeds"; the card then logs
  `Configuration file upload complete, with N valid values` plus
  `Configuration file warning: Invalid keyword/value/section on line N` for anything it skipped.
  Automation must read the event log (CLI `eventlog`, or `event.txt` over FTP/SCP) to know what
  was applied, then verify with `dns`, `ntp`, `email`, `radius`, `tcpip`.
* Reboots: the upload itself does not reboot the card. System/network changes raise a
  "needs to reboot" banner; logging off reboots (the auto-reboot waits for other sessions to
  close), or send `reboot` over the CLI. No per-key list of reboot-required settings exists.
* Transports: **FTP** (`ftplib` STOR/RETR in binary mode) is the only one with several working
  public examples, but it is disabled by default on NMC3, often banned by policy, and uses
  active-mode data connections that endpoint firewalls block. **SCP** is on by default on NMC3
  (and NMC2 6.8+ once the default password is changed) but the card has no SFTP: OpenSSH 9+
  needs `scp -O`, paramiko's SFTP client cannot be used, and the PyPI `scp` library (legacy scp
  protocol over `exec_command("scp -t ...")`) is plausible on NMC3 and unproven on NMC2, which
  lacks the exec channel for commands yet accepts OpenSSH `scp` for firmware. Lab-test before
  relying on it.
* Schneider's own tools: the free **INI Utility v3** (`iniutil.exe`, Windows, FTP-only, plaintext
  credentials in `download_list.txt`/`upload_list.txt`, still distributed with FA156117 but not
  developed), **Data Center Expert** ("APC SNMP Device Configuration": GUI editor, templates,
  FTP or SCP push), **EcoStruxure IT Gateway 2.0+** ("Device configuration", NMC2/NMC3 only,
  no NMC4), and the **Firmware Upgrade Utility** (firmware only, ~10 devices per batch, superseded
  for NMC3 3.x by the subscription-based Secure NMC System Tool). For factory-fresh cards the
  DHCP option-67 boot-file method applies an `.ini` with no credentials at all.
* No Ansible collection, Nornir plugin or PyPI package pushes config.ini today; the only
  community code is `DiData/pdumgr` (2016, Python 2 + ftplib) and the Perl `RackMan` role (2011).
* Schneider's stated preference for fleets is this mechanism ("the .ini file does not need to be
  complete, so you can push a file that only contains the settings you need to change"), while
  acknowledging that SSH scripting "could return accurate error messages and even command
  output", which is the trade-off this job makes.
* Natural follow-up for this repository: a second job (or mode) that renders a partial
  `config.ini` from Nautobot data, pushes it over SCP (FTP fallback), reads the event log for the
  "N valid values" / warning lines, reboots when needed and re-downloads `config.ini` to verify.

Sources: FA156117 mass configuration + INI Utility <https://www.se.com/us/en/faqs/FA156117/>,
FA176542 .csf files <https://www.se.com/us/en/faqs/FA176542/>,
NMC2 user guide (990-3402L) <https://media.distributordatasolutions.com/schneider2/2020q3/documents/266afb3ee792e25c599a84d8e8eb7f3e9acae0f4.pdf>,
NMC3 user guide (990-91148R) <https://download.se.com/files?p_Doc_Ref=SPD_CCON-AYCEFJ_EN>,
DCE mass configuration <https://community.se.com/t5/DCE-configuration/Mass-Configuration-of-APC-Network-Management-Card-type-devices/ta-p/446837>,
EcoStruxure IT SCP note <https://community.se.com/t5/ITE-FAQ/How-to-enable-SCP-on-APC-NMC-devices-in-IT-Expert/ta-p/446929>,
.csf over SCP bug <https://community.se.com/t5/APC-UPS-Data-Center-Enterprise/Update-config-using-SCP/td-p/353270>,
FTP example <https://github.com/DiData/pdumgr>, PyPI scp <https://pypi.org/project/scp/>.

## 3. SNMP (PowerNet MIB)

* The PowerNet MIB (enterprise 1.3.6.1.4.1.318; checked v4.0.9, v4.5.8 and the current v4.6.0
  dated July 2026) contains **no objects for DNS, NTP, SMTP/e-mail, RADIUS, hostname or domain**.
  The only DNS/hostname objects (`cpsDNSpriserv`, `cpsHostName`, ...) belong to the AP930x
  console port server, not the NMC. An anonymous forum reply agrees ("I went through the mib and
  couldn't find any way of setting it"); the MIB object inventory is the primary evidence.
* What the `apcmgmt` branch does let you write: TFTP server IP, clock date/time,
  `mcontrolRestartAgent` (restart, or reset-network-and-restart, destructive) and a deprecated
  `mfiletransfer` group that can make the card pull a config.ini from TFTP/FTP (whether current
  NMC3 firmware still honours it is unverified). Outlet control on Rack PDUs is well supported.
* Defaults: SNMPv1 and SNMPv3 are both **disabled by default** on NMC2 6.8+ and all NMC3. SNMPv1
  communities have access types Read / Write / Write+ / Disable; plain *Write* rejects SETs while
  anyone is logged in to the UI or CLI, so automation needs *Write+*. NMC3 3.6.x supports SNMPv3
  SHA-256/AES-256.
* Python tooling in 2026: `pysnmp` 7.x (LeXtudio, asyncio-only, Python 3.10+) is the mainline;
  `pysnmp-lextudio` is deprecated; `easysnmp` is dead and `ezsnmp` 2.x is its maintained,
  synchronous Net-SNMP-backed fork; `puresnmp` is pure Python without MIB support. Nautobot
  Secrets Groups have an `SNMP` access type for storing communities/USM credentials.
* Verdict: useful for read-side verification (sysName, model, serial, outlet state) and for
  triggering a restart, not for these settings.

Sources: PowerNet MIB download <https://www.se.com/us/en/download/document/APC_POWERNETMIB_EN/>,
MIB object index <https://mibs.observium.org/mib/PowerNet-MIB/>,
NTP-via-SNMP thread <https://community.se.com/t5/APC-UPS-Data-Center-Enterprise/PDU-set-NTP-server-via-SNMP/td-p/287453>,
NMC3 user guide <https://download.se.com/files?p_Doc_Ref=SPD_CCON-AYCEFJ_EN>,
<https://pypi.org/project/pysnmp/>, <https://pypi.org/project/ezsnmp/>.

## 4. REST / JSON / Redfish

* **NMC2 and NMC3 have no REST or JSON API.** Full-text searches of the current NMC3 user guide
  (990-91148R, 08/2026), the Easy-UPS NMC3 guide, the NMC2 user guide (990-3402L) and the
  2025-2026 NMC3 firmware release notes find no occurrence of REST, API, JSON or Redfish. Supported
  management protocols are HTTPS, SSH, SCP, Telnet, FTP, SNMP v1/v3, Modbus, BACnet, Syslog,
  LDAP/TACACS+/RADIUS, EAPoL. Third-party catalog claims of Redfish on AP9640 are heuristic and
  uncorroborated.
* **Redfish exists only on the NetShelter Rack PDU Advanced** platform (APDU9xxx/10xxx/11xxx,
  guide 990-91564B): enabled under *Network Settings > RESTapi Access*, HTTPS, basic auth or
  `X-Auth-Token` sessions. It is almost entirely GET (`/redfish/v1/PowerEquipment/RackPDUs/...`,
  Managers, AccountService); documented POSTs are account creation, outlet control and event
  subscriptions. No PATCH, so no network/DNS/NTP/SMTP configuration. Whether units later
  "upgraded with NMC3" firmware keep the endpoint is unknown.
* No OpenAPI/Swagger spec exists for any APC device. The only Schneider OpenAPI document is the
  cloud **EcoStruxure IT Expert API** (<https://api.ecostruxureit.com/rest/>): bearer API key,
  paid subscription, eleven read-only GET operations (organizations, inventory, alarms, sensors,
  measurements). Good for pulling inventory into Nautobot, useless for pushing settings.
* **EcoStruxure IT Gateway** has an unpublished local REST API used by its own UI; its "Device
  configuration" feature pushes config.ini templates to NMC2/NMC3 over FTP/SCP but only from the
  GUI. **Data Center Expert** 8.1+ has a REST API documented only on the appliance (`/isxg/rest`),
  earlier versions a SOAP API; neither documents a configuration-push method, while the DCE desktop
  client's "APC SNMP Device Configuration" does mass config.ini pushes.
* PowerChute Network Shutdown exposes a tiny REST endpoint (`/REST/remoteShutdown`) that really
  shuts down the OS. Not relevant here, listed for completeness.

Sources: NMC3 user guide <https://download.se.com/files?p_Doc_Ref=SPD_CCON-AYCEFJ_EN>,
NetShelter Advanced guide (990-91564B) <https://inquirecontent2.ingrammicro.com/User-Manual/1072294017.pdf>,
IT Expert API <https://github.com/EcoStruxureIT-Public/IT-Expert-Rest-API>,
Gateway REST statement <https://community.se.com/t5/EcoStruxure-IT-forum/StruxureOn-Gateway-Alarms-via-REST/td-p/220779>,
DCE web services <https://community.se.com/t5/DCE-web-services-API/Device-Service-Methods/ta-p/446579>.

## 5. Web UI scraping

Classic form-based UI (`/logon.htm`, form `frmLogin` with `login_username`/`login_password`,
then per-session tokenised paths such as `/NMC/<token>/home.htm`, `logout.htm`). Page names
differ between NMC1/2/3 firmware, concurrent sessions are capped (8 web, 5 CLI, 3 per user when
concurrent logins are allowed; otherwise one per interface), the web timeout is 3 minutes, and a
client that fails to log out can leave the card unreachable until the session expires. The only
community tools that use it are read-only temperature scrapers. Not recommended.

Sources: <https://github.com/YZITE/APC_Temp_fetch>, <https://github.com/runZeroInc/oobscan>.

## 6. Modbus TCP, BACnet, syslog, traps

Modbus TCP (NMC2 6.x+, all NMC3) and BACnet/IP expose UPS/PDU telemetry plus a few UPS-level
settings and commands (names, transfer voltages, countdowns, load shedding); the official register
maps (990-5702, 990-9840B, Application Note 176) contain nothing about NMC network settings.
Syslog (up to four servers, UDP/TCP/TLS on NMC3), SNMP traps and EcoStruxure data export are
notification paths only.

Sources: <https://www.se.com/us/en/faqs/FAQ000279078/>,
<https://download.schneider-electric.com/files?p_Doc_Ref=SPD_LFLG-A32G3L_EN>.

## 7. Community libraries (state of the art, October 2026)

* PyPI has **no** package for NMC configuration (`apc-nmc`, `pyapc`, `apcnmc`, ... all absent;
  `apc` is an unrelated statistics library). `aioapcaccess`/`apcaccess` talk to apcupsd,
  `pyapcsc` to the SmartConnect cloud, `APC-Temp-fetch` scrapes temperatures,
  `apc-switched-rack-pdu-control-panel` toggles outlets over SNMPv3.
* GitHub: `dbzx6r/apc-nmc-tool` (paramiko GUI, waits for `apc>`), `s-celles/APC` and
  `MyElectrons/PDU-Commander` (telnet/pexpect outlet control), `gregorg/pdu`, OpenStack Ironic's
  `apc_rackpdu` SNMP power driver, Home Assistant `nugget/schneider-ups-nmc` (SNMP, read-only)
  and `Tycho-MEC/apc-pdu` (SNMP outlet control).
* Ansible: `haught.apcos` is the only configuration collection (dns/ntp/radius/smtp/snmp/system/web
  modules over `network_cli`), NMC3 >= 1.4.2.1 only, last release 2023.
* Nautobot: `jtdub/nautobot-app-pdu-manager` (alpha, Nautobot 3.x) drives APC CLIs through
  Nornir/netmiko `apc_aos` for outlet control and is a useful pattern reference.

## 8. Open questions worth a lab check

1. Does an NMC2 on the latest 7.x AOS ever offer `rsa-sha2-*` host-key signatures? One observed
   negotiation (AOS 7.1.8) chose `ssh-rsa`, which is why paramiko 5 is expected to fail.
2. Does current NMC3 firmware still honour the deprecated SNMP `mfiletransfer` objects
   (config.ini pull triggered by SNMP SET)?
3. Exact config.ini section/key names for DNS, NTP, SMTP and RADIUS on current NMC2 7.x and
   NMC3 3.x firmware. Schneider publishes no complete reference; download one card's
   `config.ini` per generation and read it.
4. Whether the PyPI `scp` library (which relies on the SSH exec channel) can upload to NMC2 at
   all, and which settings need a reboot after a config.ini upload (an SMTP change on NMC2 6.4.0
   reportedly needed one without showing the banner).
5. Whether NetShelter Advanced PDUs that were "upgraded with NMC3" firmware keep Redfish.
6. Whether DCE 8.1+'s REST API adds a config-push endpoint beyond the legacy SOAP services.
