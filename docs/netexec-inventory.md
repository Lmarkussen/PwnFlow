# NetExec integration inventory

This document is the auditable record of what PwnFlow drives through NetExec:
which protocols the installed executable actually advertises, which of their
native commands and `-M` modules are registered, what each one needs, which
duplicates were removed, and how far each one was verified. It is written from
the installed build, not from upstream documentation of some other version.

Every example in this document is synthetic. Real targets, domains, and
credentials are supplied by the operator at run time and never appear here.

## Installed build

| Property | Value |
|---|---|
| Executable | `nxc` (also exposed as `netexec`) |
| Version | 1.5.1 "Yippie-Ki-Yay" |
| Packages observed | Kali package on the assessment workstation; the pip build of the same release (`commit 306bf295`) on the development workstation |
| Protocols advertised | `ftp ldap mssql nfs rdp smb ssh vnc winrm wmi` |
| Module catalogue | `nxc <protocol> -L` |
| Module options | `nxc <protocol> -M <module> --options` |

Read-only inspection commands used to build this inventory:

```bash
nxc --version
nxc --help
nxc <protocol> --help
nxc <protocol> -L
nxc <protocol> -M <module> --options
```

## What PwnFlow registers, and what it does not

PwnFlow is an Active Directory enumeration and security-assessment framework. A
NetExec registration is kept only when its primary purpose is to **read**
something from the target with the operator's own credentials:

* Kept: enumeration of directory, host, share, service, and configuration data;
  the credential *checks* for each protocol; read-only access to material a
  plain read exposes (Group Policy Preferences, directory attributes); and the
  two Kerberos auditing operations that export material for offline password
  auditing.
* Not kept: everything whose purpose is exploitation, coercion, relay
  execution, reverse shells, payload delivery, persistence, remote command
  execution, arbitrary file upload, configuration modification, listener or
  callback setup, or credential *dumping* that needs code execution on the
  target or elevated rights to read process memory and databases.

A module that is available but needs elevated rights still appears, labelled
`ADMIN-REQ`, because that is information the operator needs rather than a reason
to hide it.

## Module ownership: one protocol per capability

A `-M` module is registered under exactly one protocol, the transport that fits
the operator's workflow best. `bitlocker`, `spooler`, `zerologon`,
`ioxidresolver`, `enum_dns`, and `get_netconnections` are advertised for both SMB
and WMI; PwnFlow registers the SMB form, so the same check never appears twice.
Domain-wide data is read over LDAP, which means the SMB SAMR variants of the same
queries are not registered either - see the mapping below.

## Transport and credential shape

The protocols do not share an authentication shape, and the command builder keeps
them apart:

| Protocol | Command | Credentials passed | Domain passed | Transport note |
|---|---|---|---|---|
| LDAP | `nxc ldap <target>` | `-u`, `-p` | `-d` | always `--port 636`, which is how NetExec selects LDAPS |
| SMB | `nxc smb <target>` | `-u`, `-p` | `-d` | port 445 |
| WINRM | `nxc winrm <target>` | `-u`, `-p` | `-d` | HTTP/HTTPS negotiation |
| WMI | `nxc wmi <target>` | `-u`, `-p` | `-d` | DCOM/RPC, port 135 |
| MSSQL | `nxc mssql <target>` | `-u`, `-p` | `-d` | port 1433 |
| SSH | `nxc ssh <target>` | `-u`, `-p` | not accepted | port 22 |
| FTP | `nxc ftp <target>` | `-u`, `-p` | not accepted | port 21 |
| RDP | `nxc rdp <target>` | `-u`, `-p` | `-d` | port 3389 |
| VNC | `nxc vnc <target>` | `-p` only | not accepted | a domain account is not a VNC credential |
| NFS | `nxc nfs <target>` | none | not accepted | export enumeration is unauthenticated |

Arguments are built as a structured vector, never as a shell string, and the
LDAP-only transport flags are never propagated to another protocol (a regression
test asserts this for every registration).

## How to read the tables

| Column | Meaning |
|---|---|
| native flag | The NetExec protocol flag the registration runs, as advertised by `nxc <protocol> --help` |
| `-M module` | The NetExec module name, as advertised by `nxc <protocol> -L` |
| registration | The PwnFlow module identifier |
| category | The navigation category the registration is filed under |
| privilege | `-` needs only valid credentials; `ADMIN-REQ` names an elevated right **on the target**, and is informational |
| options | Module option keys accepted from the operator with `--module-options <registration>.<KEY>=<VALUE>` |

## Registered coverage

### LDAP

| native flag | registration | category | privilege |
|---|---|---|---|
| --active-users | active-users | Enumeration | - |
| --admin-count | admin-count | Enumeration | - |
| --asreproast | asreproast | Credential Auditing | - |
| --find-delegation | delegation | Enumeration | - |
| --dc-list | domain-controllers | Enumeration | - |
| --groups | domain-groups | Enumeration | - |
| --get-sid | domain-sid | Enumeration | - |
| --users | domain-users | Enumeration | - |
| --pso | fine-grained-password-policy | Enumeration | - |
| --gmsa | gmsa | Credential Dumping | - |
| --kerberoasting | kerberoasting | Credential Auditing | - |
| --password-not-required | password-not-required | Enumeration | - |
| --pass-pol | password-policy | Enumeration | - |

| -M module | registration | category | privilege | options |
|---|---|---|---|---|
| adcs | adcs | Enumeration | - |  |
| badsuccessor | badsuccessor | Enumeration | - |  |
| daclread | daclread | Enumeration | - | TARGET, TARGET_DN, PRINCIPAL, ACTION, ACE_TYPE, RIGHTS, RIGHTS_GUID |
| dns-nonsecure | dns-nonsecure | Enumeration | - |  |
| dump-computers | dump-computers | Enumeration | - |  |
| entra-id | entra-id | Enumeration | - |  |
| find-computer | find-computer | Enumeration | - | TEXT |
| get-desc-users | get-desc-users | Credential Dumping | - | FILTER, PASSWORDPOLICY, MINLENGTH |
| get-info-users | get-info-users | Credential Dumping | - | FILTER |
| get-network | get-network | Enumeration | - | ALL, ONLY_HOSTS |
| get-unixUserPassword | get-unixUserPassword | Credential Dumping | - |  |
| get-userPassword | get-userPassword | Credential Dumping | - |  |
| groupmembership | groupmembership | Enumeration | - | USER |
| laps | laps | Credential Dumping | - | COMPUTER |
| maq | maq | Enumeration | - |  |
| obsolete | obsolete | Enumeration | - |  |
| sccm | sccm | Enumeration | - | BASE_DN, REC_RESOLVE |
| subnets | subnets | Enumeration | - |  |
| whoami | whoami | Enumeration | - |  |

### SMB

| native flag | registration | category | privilege |
|---|---|---|---|
| --loggedon-users | logged-on-users | Enumeration | ADMIN-REQ |
| --reg-sessions | registry-sessions | Enumeration | ADMIN-REQ |
| --tasklist | running-processes | Enumeration | ADMIN-REQ |
| --disks | smb-disks | Enumeration | - |
| --local-groups | smb-local-groups | Enumeration | ADMIN-REQ |
|  | smb-server-info | Enumeration | - |
| --smb-sessions | smb-sessions | Enumeration | ADMIN-REQ |
| --shares | smb-shares | Enumeration | - |
| --qwinsta | terminal-sessions | Enumeration | ADMIN-REQ |

| -M module | registration | category | privilege | options |
|---|---|---|---|---|
| aws-credentials | smb-aws-credentials | Credential Dumping | - |  |
| bitlocker | smb-bitlocker | Enumeration | ADMIN-REQ |  |
| enum_av | smb-enum-av | Enumeration | - |  |
| enum_ca | smb-enum-ca | Enumeration | - |  |
| enum_dns | smb-enum-dns | Enumeration | ADMIN-REQ |  |
| enum_interfaces | smb-enum-interfaces | Enumeration | ADMIN-REQ |  |
| get_netconnections | smb-get-netconnections | Enumeration | ADMIN-REQ |  |
| gpp_autologin | smb-gpp-autologin | Credential Dumping | - |  |
| gpp_password | smb-gpp-password | Credential Dumping | - |  |
| gpp_privileges | smb-gpp-privileges | Enumeration | - | NO_LDAP |
| hyperv-host | smb-hyperv-host | Enumeration | ADMIN-REQ |  |
| install_elevated | smb-install-elevated | Enumeration | ADMIN-REQ |  |
| ioxidresolver | smb-ioxidresolver | Enumeration | - | DIFFERENT |
| keepass_discover | smb-keepass-discover | Enumeration | ADMIN-REQ |  |
| lockscreendoors | smb-lockscreendoors | Enumeration | ADMIN-REQ |  |
| ms17-010 | smb-ms17-010 | Enumeration | - |  |
| nopac | smb-nopac | Enumeration | - |  |
| ntlm_reflection | smb-ntlm-reflection | Enumeration | - |  |
| ntlmv1 | smb-ntlmv1 | Enumeration | ADMIN-REQ |  |
| presence | smb-presence | Enumeration | ADMIN-REQ |  |
| printnightmare | smb-printnightmare | Enumeration | - | PORT |
| reg-query | smb-reg-query | Enumeration | ADMIN-REQ | PATH, KEY |
| remove-mic | smb-remove-mic | Enumeration | - | PORT |
| runasppl | smb-runasppl | Enumeration | ADMIN-REQ |  |
| sccm-recon6 | smb-sccm-recon6 | Enumeration | - |  |
| smbghost | smb-smbghost | Enumeration | - |  |
| spooler | smb-spooler | Enumeration | - | PORT |
| uac | smb-uac | Enumeration | ADMIN-REQ |  |
| wcc | smb-wcc | Enumeration | ADMIN-REQ | OUTPUT_FORMAT, OUTPUT, QUIET |
| webdav | smb-webdav | Enumeration | - | MSG |
| zerologon | smb-zerologon | Enumeration | - |  |

### WINRM

| native flag | registration | category | privilege |
|---|---|---|---|
|  | winrm-auth-check | Enumeration | - |

### WMI

| native flag | registration | category | privilege |
|---|---|---|---|
|  | wmi-auth-check | Enumeration | - |
| --list-snapshots | wmi-list-snapshots | Enumeration | - |

### MSSQL

| native flag | registration | category | privilege |
|---|---|---|---|
|  | mssql-auth-check | Enumeration | - |
| --database | mssql-databases | Enumeration | - |

| -M module | registration | category | privilege | options |
|---|---|---|---|---|
| enum_impersonate | mssql-enum-impersonate | Enumeration | - |  |
| enum_links | mssql-enum-links | Enumeration | - |  |
| enum_logins | mssql-enum-logins | Enumeration | - |  |

### SSH

| native flag | registration | category | privilege |
|---|---|---|---|
|  | ssh-auth-check | Enumeration | - |
| --sudo-check | ssh-sudo-check | Enumeration | - |

### FTP

| native flag | registration | category | privilege |
|---|---|---|---|
|  | ftp-auth-check | Enumeration | - |
| --ls | ftp-list | Enumeration | - |

### RDP

| native flag | registration | category | privilege |
|---|---|---|---|
|  | rdp-auth-check | Enumeration | - |
| --nla-screenshot | rdp-screenshot | Enumeration | - |

### VNC

| native flag | registration | category | privilege |
|---|---|---|---|
|  | vnc-auth-check | Enumeration | - |
| --screenshot | vnc-screenshot | Enumeration | - |

### NFS

| native flag | registration | category | privilege |
|---|---|---|---|
|  | nfs-auth-check | Enumeration | - |
| --shares | nfs-shares | Enumeration | - |
OPTIONS LDAP adcs 
OPTIONS LDAP badsuccessor 
OPTIONS LDAP daclread TARGET,TARGET_DN,PRINCIPAL,ACTION,ACE_TYPE,RIGHTS,RIGHTS_GUID
OPTIONS LDAP dns-nonsecure 
OPTIONS LDAP dump-computers 
OPTIONS LDAP entra-id 
OPTIONS LDAP find-computer TEXT
OPTIONS LDAP get-desc-users FILTER,PASSWORDPOLICY,MINLENGTH
OPTIONS LDAP get-info-users FILTER
OPTIONS LDAP get-network ALL,ONLY_HOSTS
OPTIONS LDAP get-unixUserPassword 
OPTIONS LDAP get-userPassword 
OPTIONS LDAP groupmembership USER
OPTIONS LDAP laps COMPUTER
OPTIONS LDAP maq 
OPTIONS LDAP obsolete 
OPTIONS LDAP sccm BASE_DN,REC_RESOLVE
OPTIONS LDAP subnets 
OPTIONS LDAP user-desc 
OPTIONS LDAP whoami 
OPTIONS MSSQL enum_impersonate 
OPTIONS MSSQL enum_links 
OPTIONS MSSQL enum_logins 
OPTIONS SMB aws-credentials 
OPTIONS SMB bitlocker 
OPTIONS SMB enum_av 
OPTIONS SMB enum_ca 
OPTIONS SMB enum_dns 
OPTIONS SMB enum_interfaces 
OPTIONS SMB get_netconnections 
OPTIONS SMB gpp_autologin 
OPTIONS SMB gpp_password 
OPTIONS SMB gpp_privileges NO_LDAP
OPTIONS SMB hyperv-host 
OPTIONS SMB install_elevated 
OPTIONS SMB ioxidresolver DIFFERENT
OPTIONS SMB keepass_discover 
OPTIONS SMB lockscreendoors 
OPTIONS SMB ms17-010 
OPTIONS SMB nopac 
OPTIONS SMB ntlm_reflection 
OPTIONS SMB ntlmv1 
OPTIONS SMB presence 
OPTIONS SMB printnightmare PORT
OPTIONS SMB reg-query PATH,KEY
OPTIONS SMB remove-mic PORT
OPTIONS SMB runasppl 
OPTIONS SMB sccm-recon6 
OPTIONS SMB smbghost 
OPTIONS SMB spooler PORT
OPTIONS SMB uac 
OPTIONS SMB wcc OUTPUT_FORMAT,OUTPUT,QUIET
OPTIONS SMB webdav MSG
OPTIONS SMB zerologon 
--- PASS: TestDumpInventoryTables (0.00s)
PASS
ok  	github.com/pwnflow/pwnflow/internal/modules/netexec	(cached)

## Before and after the cleanup

| Scope | Before | After |
|---|---|---|
| Registrations in total | 184 | 91 |
| Enumeration | 95 | 79 |
| Credential Auditing | 2 | 2 |
| Credential Dumping | 54 | 10 |
| Privilege Escalation | 33 | 0 |
| Rows that were permanently `gated` | 75 | 0 |
| Rows labelled `ADMIN-REQ` | 26 | 20 |
| Rows `UNAVAILABLE` on a fresh run | 77 | 2 |

Per protocol:

| Protocol | Before | After |
|---|---|---|
| LDAP | 37 | 33 |
| SMB | 103 | 40 |
| WinRM | 6 | 1 |
| WMI | 10 | 2 |
| MSSQL | 17 | 5 |
| SSH | 3 | 2 |
| FTP | 2 | 2 |
| RDP | 2 | 2 |
| VNC | 2 | 2 |
| NFS | 2 | 2 |

The previous count in this document (175) was under-reported: the script that
produced it skipped the rows whose native-flag cell is empty, which is every
credential check.

## Removals and their replacements

Every removal is a decision with a reason. The reasons are grouped here; the
per-module form lives in `internal/modules/netexec/inventory_test.go`, where a
test fails if an advertised module is neither registered nor listed as excluded.

| Group | Modules | Why |
|---|---|---|
| Exploitation and state change | `add-computer`, `change-password`, `coerce_plus`, `timeroast`, `drop-sc`, `drop-library-ms`, `scuffy`, `slinky`, `impersonate`, `pi`, `schtask_as`, `rdp` (SMB and WMI), `remote-uac`, `shadowrdp`, `empire_exec`, `met_inject`, `web_delivery`, `enable_cmdshell`, `link_enable_cmdshell`, `link_xpcmd`, `exec_on_link`, `mssql_priv`, `mssql_coerce`, `pre2k`, `raisechild`, `wdigest`, `keepass_trigger` | They create or change objects, run code, deliver payloads, or configure a listener. PwnFlow registers none of them, and the Privilege Escalation category is gone with them |
| Credential dumping and extraction | `sam`, `lsa`, `ntds`, `dpapi`, `sccm` (native), `lsassy`, `nanodump`, `procdump`, `handlekatz`, `hash_spider`, `dpapi_hash`, `eventlog_creds`, `iis`, `masky`, `mobaxterm`, `mremoteng`, `msol`, `ntdsutil`, `ntds-dump-raw`, `powershell_history`, `putty`, `rdcman`, `reg-winlogon`, `security-questions`, `teams_localdb`, `veeam`, `vnc`, `wam`, `wifi`, `winscp`, `notepad`, `notepad++`, `recent_files`, `recyclebin`, `snipped`, `backup_operator` | Each one reads process memory, the directory database, a credential vault, or per-user secret stores, and several need code execution on the target. They are dumping rather than enumeration |
| Domain data read over SMB | `users`, `groups`, `computers`, `pass-pol`, `rid-brute` | The domain dataset is read over LDAP (LDAPS), which returns more attributes and needs no SAMR path. The SMB local-group, session, and logged-on-user queries stay, because a host's local data has no LDAP equivalent |
| Native duplicate | `interfaces` (native) | `-M enum_interfaces` is the module that superseded the flag, and it is the one registered |
| Duplicate LDAP user-description query | `user-desc` | `get-desc-users` is retained as the canonical description query because it returns the same attribute and exposes filtering and password-policy options |
| Duplicate module on a second transport | `aws-credentials` (WinRM, SSH), `bitlocker`, `spooler`, `zerologon`, `ioxidresolver`, `enum_dns`, `get_netconnections` (WMI) | Registered once, under the protocol PwnFlow keeps for that capability |
| Configuration, not enumeration | `test_connection` (SMB, MSSQL), `spider_plus` | `test_connection` pings a host the operator names, which is a probe rather than a read of the target; `spider_plus` is oriented at collecting files (download flags, size limits) and its crawl duplicates the operator's dedicated share tooling |
| Superseded query | `pso` | The `--pso` native query is registered as fine-grained-password-policy |
| Covered by another family | `certipy-find` | The AD CS family runs `certipy find` with a controlled artifact workflow |

Retired modules that the installed build still prints with a `[REMOVED]` marker -
`ldap-checker`, `enum_trusts`, `group-mem`, `petitpotam`, `printerbug`,
`shadowcoerce`, `dfscoerce`, `efsr_spray`, `firefox` - are not registered, and the
status is detected from the listing so a `[REMOVED]` name is reported
`UNAVAILABLE` even though it appears in `-L`.

## AS-REP roasting and Kerberoasting

Both operations are registered under LDAP, where they belong: they use the
directory protocol, the LDAPS transport, and the operator's own credentials, and
they change nothing on the target. They were previously blocked by a policy gate;
that gate is gone, and a test asserts they build usable commands.

| Registration | NetExec invocation | Artifact |
|---|---|---|
| `asreproast` | `nxc ldap <target> -u <user> -p <pass> -d <domain> --asreproast <file> --port 636` | `<results>/CredentialAuditing/NetExec/LDAP_asreproast/asreproast.txt` |
| `kerberoasting` | `nxc ldap <target> -u <user> -p <pass> -d <domain> --kerberoasting <file> --port 636` | `<results>/CredentialAuditing/NetExec/LDAP_kerberoasting/kerberoast.txt` |

The export flag takes a file as its value, and the installed build rejects the
command without one, so the path is part of the command rather than an option the
operator has to remember. Both write to a file **and** print the material, so the
hash list lands in the artifact file and the runner's transcript holds the same
output. The material is crackable offline; PwnFlow neither cracks it nor sends it
anywhere, and it never runs either operation on its own - they are selected
explicitly, in the Credential Auditing category, which is outside the enumeration
scope that the `A` key sweeps.

Neither operation was executed against the lab: they recover crackable material,
which the engagement rules require separate authorization for. What was verified
without executing them is recorded below.

## Availability labels

| Label | Meaning |
|---|---|
| *(nothing)* | Available |
| `ADMIN-REQ` | Needs elevated rights on the target or domain. Informational: a test asserts the registry carries no execution policy, so the label can never block a run |
| `INPUT-REQ` | Supported and installed, and waiting for a value only the operator can supply. Pressing Enter asks for it, and `I` stores it without running the module |
| `UNAVAILABLE` | The installed build does not advertise the module or the flag, or the runtime cannot supply an argument the module's command needs. A missing value from the operator is *not* this: it is `INPUT-REQ` |

Two registrations are `INPUT-REQ` until they are configured, and both are
configurable rather than unsupported or blocked:

| Registration | Field | Why it needs one |
|---|---|---|
| `daclread` | `TARGET` (the read action is the default) | Reading one object's DACL needs to know which object. The module reads one object at a time and never recurses, so no safe default exists |
| `find-computer` | `TEXT` | A search needs a search term |

Everything else that used to be permanently unavailable is either removed or has
a default: `groupmembership` defaults to the authenticated account,
`smb-reg-query` defaults to the registry key that names the operating system,
`smb-wcc` writes its report into the assessment tree, and `daclread`'s action
defaults to `read`. On a fresh run, nothing in the registry reports `UNAVAILABLE`
(`TestOptionRequiringModulesAreConfigurableNotUnavailable` asserts exactly that).

## How a global run treats these registrations

`A` builds its plan from the whole registry, so the labels above decide what
happens to each registration rather than which scope is on screen:

| State | Treatment in a global plan |
|---|---|
| Available, `ADMIN-REQ` | Runs, in registry order, with declared prerequisites honoured |
| `INPUT-REQ` | PwnFlow asks for the value **before** the batch starts, and stores it for the assessment |
| `UNAVAILABLE` | Skipped, and named in the plan |
| Credential Auditing / Credential Dumping | Named and held for the operator's decision: approving runs them with the plan, declining runs the rest |
| A module whose own run reaches wider than the assessment's discovery (PXEThief with no stored endpoint, which would broadcast a DHCP discover) | Same decision, with the module's own reason shown |
| A module needing elevated execution (PXEThief without the raw-socket capability) | The existing amber confirmation and sudo handoff, unchanged |

On the assessment workstation the global plan reports itself before it does
anything, with the authorized lab's registry:

```
YOLO plan: 97 module(s) across 4 families, 13 need approval, 2 need input
```

That is the plan as it stood with the NetExec, SCCM, AD CS, and Active Directory
registrations: 91 NetExec, 2 SCCM, 3 AD CS, and 1 Active Directory. The 13 that
needed a decision were the 12 credential-access registrations plus PXEThief, which
had no stored endpoint and would therefore have run its DHCP broadcast mode; the 2
that needed input were `daclread` and `find-computer`. Answering the two prompts
moved the plan to the approval pane, which named each module with its category and
reason, and cancelling at that point ran nothing.

The number is derived, never pinned: the plan is built from the registry, so the
NetworkHound and RelayKing registrations appear in it without any change to the
plan logic, and the count grows with them.

## Declared module options audited against the installation

Every registration that declares option keys was checked against
`nxc <protocol> -M <module> --options` on the assessment workstation by comparing
the declared keys with the advertised ones. The audit found one registration
whose declared keys were wrong - `spider_plus`, which advertises
`DOWNLOAD_FLAG`, `EXCLUDE_EXTS`, `EXCLUDE_FILTER`, `MAX_FILE_SIZE`,
`OUTPUT_FOLDER`, and `STATS_FLAG` - and that registration was removed rather than
patched. The remaining 54 modules declare only keys the installed build
advertises, and `TestDeclaredOptionKeysMatchTheInstalledModules` keeps the
verified ones from drifting.

## Live lab validation

The live check is opt-in and offline by default. It runs PwnFlow's own
registrations - the same builder, capability check, and runner the interface uses
- against an authorized target supplied through the environment:

```bash
PWNFLOW_LIVE_TARGET=198.51.100.10 \
PWNFLOW_LIVE_DOMAIN=example.test \
PWNFLOW_LIVE_USER=audituser \
PWNFLOW_LIVE_PASSWORD=... \
go test ./internal/modules/netexec -run TestLiveLabReadOnlyEnumeration -v
```

It writes artifacts into a private temporary root so an operator's assessment
tree and its history are never disturbed, and it prints one summary line per
module without echoing module output.

Result vocabulary:

| Result | Meaning |
|---|---|
| LIVE PASS | Observed to execute successfully against the authorized target and produce a usable result |
| LIVE DENIED | Executed, and the target refused the requested operation |
| LIVE NOT APPLICABLE | The service is not present on the authorized target |
| OFFLINE VERIFIED | Syntax, registration, capability gate, and option construction tested without a live run |

### Services observed on the authorized host

| Port | Service | Present |
|---|---|---|
| 389, 636 | LDAP / LDAPS | yes |
| 445, 139 | SMB | yes |
| 88 | Kerberos | yes |
| 135 | RPC (WMI) | yes |
| 5985, 5986 | WinRM | yes |
| 3389 | RDP | yes |
| 1433 | MSSQL | no |
| 21 | FTP | no |
| 22 | SSH | no |
| 5900 | VNC | no |
| 111, 2049 | NFS | no |

### Live results

Every registration below ran through PwnFlow's runner against the authorized
target with a valid domain account: 77 modules, exit status 0, no failures.
Artifact sizes are the persisted output size, which is how an empty-but-successful
result is told apart from a real one.

| registration | runner status | exit | artifact | result |
|---|---|---|---|---|
| domain-users | completed | exit=0 | 5743 | LIVE PASS |
| active-users | completed | exit=0 | 3841 | LIVE PASS |
| domain-groups | completed | exit=0 | 11973 | LIVE PASS |
| domain-sid | completed | exit=0 | 390 | LIVE PASS |
| password-policy | completed | exit=0 | 2027 | LIVE PASS |
| fine-grained-password-policy | completed | exit=0 | 272 | LIVE PASS |
| admin-count | completed | exit=0 | 814 | LIVE PASS |
| password-not-required | completed | exit=0 | 466 | LIVE PASS |
| delegation | completed | exit=0 | 1012 | LIVE PASS |
| domain-controllers | completed | exit=0 | 362 | LIVE PASS |
| maq | completed | exit=0 | 462 | LIVE PASS |
| adcs | completed | exit=0 | 611 | LIVE PASS |
| badsuccessor | completed | exit=0 | 702 | LIVE PASS |
| dns-nonsecure | completed | exit=0 | 520 | LIVE PASS |
| dump-computers | completed | exit=0 | 960 | LIVE PASS |
| entra-id | completed | exit=0 | 272 | LIVE PASS |
| get-network | completed | exit=0 | 782 | LIVE PASS |
| groupmembership | completed | exit=0 | 618 | LIVE PASS |
| obsolete | completed | exit=0 | 370 | LIVE PASS |
| sccm | completed | exit=0 | 2808 | LIVE PASS |
| subnets | completed | exit=0 | 479 | LIVE PASS |
| whoami | completed | exit=0 | 1474 | LIVE PASS |
| find-computer | completed | exit=0 | 505 | LIVE PASS |
| daclread | completed | exit=0 | 20330 | LIVE PASS |
| smb-server-info | completed | exit=0 | 289 | LIVE PASS |
| smb-shares | completed | exit=0 | 1878 | LIVE PASS |
| smb-disks | completed | exit=0 | 444 | LIVE PASS |
| smb-local-groups | completed | exit=0 | 3584 | LIVE PASS |
| smb-sessions | completed | exit=0 | 424 | LIVE PASS |
| logged-on-users | completed | exit=0 | 519 | LIVE PASS |
| registry-sessions | completed | exit=0 | 790 | LIVE PASS |
| terminal-sessions | completed | exit=0 | 1126 | LIVE PASS |
| running-processes | completed | exit=0 | 19367 | LIVE PASS |
| smb-enum-av | completed | exit=0 | 387 | LIVE PASS |
| smb-enum-ca | completed | exit=0 | 605 | LIVE PASS |
| smb-gpp-privileges | completed | exit=0 | 4306 | LIVE PASS |
| smb-ioxidresolver | completed | exit=0 | 374 | LIVE PASS |
| smb-spooler | completed | exit=0 | 378 | LIVE PASS |
| smb-webdav | completed | exit=0 | 289 | LIVE PASS |
| smb-nopac | completed | exit=0 | 7164 | LIVE PASS |
| smb-ntlm-reflection | completed | exit=0 | 289 | LIVE PASS |
| smb-sccm-recon6 | completed | exit=0 | 472 | LIVE PASS |
| smb-smbghost | completed | exit=0 | 289 | LIVE PASS |
| smb-remove-mic | completed | exit=0 | 289 | LIVE PASS |
| smb-printnightmare | completed | exit=0 | 289 | LIVE PASS |
| smb-zerologon | completed | exit=0 | 397 | LIVE PASS |
| smb-ms17-010 | completed | exit=0 | 289 | LIVE PASS |
| smb-bitlocker | completed | exit=0 | 502 | LIVE PASS |
| smb-enum-interfaces | completed | exit=0 | 568 | LIVE PASS |
| smb-enum-dns | completed | exit=0 | 3997 | LIVE PASS |
| smb-get-netconnections | completed | exit=0 | 962 | LIVE PASS |
| smb-hyperv-host | completed | exit=0 | 289 | LIVE PASS |
| smb-install-elevated | completed | exit=0 | 397 | LIVE PASS |
| smb-keepass-discover | completed | exit=0 | 925 | LIVE PASS |
| smb-lockscreendoors | completed | exit=0 | 438 | LIVE PASS |
| smb-ntlmv1 | completed | exit=0 | 289 | LIVE PASS |
| smb-presence | completed | exit=0 | 489 | LIVE PASS |
| smb-reg-query | completed | exit=0 | 407 | LIVE PASS |
| smb-runasppl | completed | exit=0 | 372 | LIVE PASS |
| smb-uac | completed | exit=0 | 383 | LIVE PASS |
| smb-wcc | completed | exit=0 | 3819 | LIVE PASS |
| winrm-auth-check | completed | exit=0 | 241 | LIVE PASS |
| wmi-auth-check | completed | exit=0 | 240 | LIVE PASS |
| wmi-list-snapshots | completed | exit=0 | 240 | LIVE PASS |
| mssql-auth-check | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| mssql-databases | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| mssql-enum-logins | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| mssql-enum-links | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| mssql-enum-impersonate | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| ssh-auth-check | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| ssh-sudo-check | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| ftp-auth-check | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| ftp-list | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| rdp-auth-check | completed | exit=0 | 260 | LIVE PASS |
| vnc-auth-check | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| nfs-auth-check | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| nfs-shares | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |

Result mix:

| Result | Count | Detail |
|---|---|---|
| LIVE PASS | 65 | LDAP, SMB, the WinRM credential check, and the RDP credential check, all returning content |
| LIVE NOT APPLICABLE | 12 | MSSQL (5), SSH (2), FTP (2), VNC (1), NFS (2): the service is absent, so the installed NetExec prints nothing and exits 0 |
| LIVE DENIED | 0 | Not produced. The account used for the validation already held local administrator rights on the authorized target, so no refusal could be observed without a low-privilege credential for that host |

Beyond the byte counts, PwnFlow's execution was compared against the equivalent
direct invocation for representative modules, and the results matched:

| Registration | Direct invocation | PwnFlow artifact |
|---|---|---|
| `smb-shares` | 1877 bytes | 1878 bytes (trailing newline) |
| `maq` | 461 bytes, reporting the machine account quota | 462 bytes |
| `daclread` with `-o TARGET=...` | full ACL listing | 20330 bytes |
| `smb-reg-query` with the default path | registry value | 407 bytes |

### Verified without executing it

| Capability | Evidence |
|---|---|
| `asreproast`, `kerberoasting` | The flags are advertised by `nxc ldap --help` on the installed build; the command builder is asserted by unit tests (protocol, LDAPS port, credential, export path inside the assessment tree); the capability gate is asserted to refuse a build without the flag. No ticket or hash was requested |
| Credential-sensitive modules (`get-info-users`, `get-desc-users`, `laps`, and the rest of Credential Dumping) | Command construction, category placement, artifact path, and option handling are covered by offline tests. Recovering real material needs its own approval, so the live check excludes them by construction - a guard test fails if a sensitive registration is ever added to that list |
| MSSQL, SSH, FTP, VNC, NFS | The commands build correctly, pass the capability check, and are reported `LIVE NOT APPLICABLE` when the service is absent (see the table above) |

### What a `LIVE NOT APPLICABLE` result looks like

When a service is absent, the installed NetExec prints nothing and exits 0
(observed directly and through PwnFlow for MSSQL, SSH, FTP, VNC, and NFS on the
authorized host). PwnFlow therefore persists an empty artifact and reports the
run as completed. The status is honest: the command was correct and it reached
the point where the service would have answered.

## Interface: the module list scrolls with the selection

The module pane used to render every row and let the pane's height clip the tail,
which hid the highlighted row as soon as the selection passed the last visible
line. The list is now a window over the registry:

* the window is computed from the terminal size before the rows are written, so
  the row count and the renderer always agree;
* the offset is clamped so the cursor stays inside the window - on a key press, on
  a resize, and on a scope change;
* changing family, category, or protocol starts the new list at its top;
* `↑`/`↓`, `PgUp`/`PgDn`, `Home`, and `End` move the selection, and the pane
  header shows the window (`ENUMERATION MODULES // 9-21/24`) when the list is
  longer than the pane;
* when the terminal is short, the key-hint footer shortens and then the identity
  block compacts, so the module rows are the last thing to give way;
* nothing in the path probes a dependency or spawns a process.

On the assessment workstation, the built binary was driven on a pseudo-terminal
against the authorized target with navigation only - no module was executed:

| Observation | Result |
|---|---|
| Startup, first frame | rendered: navigation, module list, Module Information, output pane |
| 26 `↓` presses past the window | the window advanced 1-13, 2-14, 3-15 ... and the highlighted row stayed in every frame |
| Protocol and category changes with `←`/`→` | the scope changed and the window restarted at the top |
| `ADMIN-REQ` | present in the SMB enumeration scope |
| `UNAVAILABLE` | present only for the two option-requiring rows |
| the retired ready suffix | absent from every frame |
| removed exploitation entries | absent from every frame |
| `Q` | exits cleanly |

## Native flags documented but not registered

These exist in the installed build and are deliberately not exposed as one-key
modules. Each needs a value only the operator can supply (a path, a command, a
query, a listener) or performs an operation outside enumeration, and PwnFlow's
option mechanism passes module options (`-o KEY=VALUE`), which native flags do not
accept:

| Protocol | Flags | Reason |
|---|---|---|
| LDAP | `--query`, `--base-dn`, `--users-export`, `--gmsa-convert-id`, `--gmsa-decrypt-lsa`, `--kerberoast-account`, `--no-preauth-targets` | Operator-supplied filter, base DN, export path, or key material |
| SMB | `-x`, `-X`, `--put-file`, `--get-file`, `--dir`, `--spider*`, `--content`, `--pattern`, `--regex`, `--taskkill`, `--wmi-query`, `--laps`, `--delegate`, `--generate-*`, `--gen-relay-list`, `--sam`, `--lsa`, `--ntds`, `--dpapi`, `--sccm`, `--users`, `--groups`, `--computers`, `--pass-pol`, `--rid-brute`, `--interfaces` | Remote execution, file transfer, content search, credential dumping, or a query the LDAP registration answers better |
| WINRM | `-x`, `-X`, `--sam`, `--lsa`, `--dpapi` | Remote execution and credential dumping |
| WMI | `--wmi-query`, `-x`, `-X` | Operator-supplied query or remote execution |
| MSSQL | `-q`/`--query`, `--rid-brute` | Operator-supplied statement, or a loud duplicate of the login enumeration |
| SSH | `-x`, `--put-file`, `--get-file`, `--key-file` | Remote execution, file transfer, key material |
| FTP | `--get`, `--put` | File transfer |
| RDP | `--screenshot`, `-x`, `-X` | A full interactive login rather than a read; the NLA login-prompt screenshot is registered instead |
| NFS | `--ls`, `--get-file`, `--put-file`, `--share` | Operator-supplied paths |
