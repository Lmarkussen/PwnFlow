# NetExec integration inventory

This document is the auditable record of what PwnFlow drives through NetExec:
which protocols the installed executable actually advertises, which of their
native commands and `-M` modules are registered, what each one needs, and how far
it was verified. It is written from the installed build, not from upstream
documentation of some other version.

Every example in this document is synthetic. Real targets, domains, and
credentials are supplied by the operator at run time and never appear here.

## Installed build

| Property | Value |
|---|---|
| Executable | `nxc` (also exposed as `netexec`) |
| Version | 1.5.1 "Yippie-Ki-Yay" |
| Packages observed | Kali package on the assessment workstation; the pip build of the same release (`commit 306bf295`) on the development workstation |
| Protocols advertised | `ftp ldap mssql nfs rdp smb ssh vnc winrm wmi` |
| Module catalogue | `nxc <protocol> -L`, per protocol |
| Module options | `nxc <protocol> -M <module> --options` |

Read-only inspection commands used to build this inventory:

```bash
nxc --version
nxc --help
nxc <protocol> --help
nxc <protocol> -L
nxc <protocol> -M <module> --options
```

## How to read the tables

| Column | Meaning |
|---|---|
| native flag | The NetExec protocol flag the registration runs, as advertised by `nxc <protocol> --help` |
| `-M module` | The NetExec module name, as advertised by `nxc <protocol> -L` |
| registration | The PwnFlow module identifier |
| category | The navigation category the registration is filed under |
| privilege | `-` needs only valid credentials; `ADMIN-REQ` names an elevated right **on the target**; `gated` means the registration is listed with its requirement and refuses to run |
| options | Module option keys accepted from the operator with `--module-options <registration>.<KEY>=<VALUE>` |

`ADMIN-REQ` is informational and never blocks execution. `UNAVAILABLE` is shown
when the installed build does not advertise the module or the protocol, when the
module needs an option the operator has not supplied, or when the registration is
gated. An available module carries no suffix at all.

## Module ownership

A `-M` module is registered under the protocol that advertises it and nowhere
else. `bitlocker` therefore exists under SMB and under WMI as two registrations,
because the installed build advertises it for both, and a module that only SMB
advertises (`reg-query`, `spooler`, `enum_dns`, and the rest) never appears under
LDAP merely because both protocols can reach Active Directory.

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

## Registered coverage

### LDAP

| native flag | registration | category | privilege |
|---|---|---|---|
| --active-users | active-users | Enumeration | - |
| --admin-count | admin-count | Enumeration | - |
| --asreproast | asreproast | Credential Auditing | gated |
| --find-delegation | delegation | Enumeration | - |
| --computers | domain-computers | Enumeration | - |
| --dc-list | domain-controllers | Enumeration | - |
| --groups | domain-groups | Enumeration | - |
| --get-sid | domain-sid | Enumeration | - |
| --users | domain-users | Enumeration | - |
| --pso | fine-grained-password-policy | Enumeration | - |
| --gmsa | gmsa | Credential Dumping | - |
| --kerberoasting | kerberoasting | Credential Auditing | gated |
| --password-not-required | password-not-required | Enumeration | - |
| --pass-pol | password-policy | Enumeration | - |
| --trusted-for-delegation | trusted-for-delegation | Enumeration | - |

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
| pre2k | pre2k | Privilege Escalation | gated |  |
| raisechild | raisechild | Privilege Escalation | gated |  |
| sccm | sccm | Enumeration | - | BASE_DN, REC_RESOLVE |
| subnets | subnets | Enumeration | - |  |
| user-desc | user-desc | Credential Dumping | - |  |
| whoami | whoami | Enumeration | - |  |

### SMB

| native flag | registration | category | privilege |
|---|---|---|---|
| --loggedon-users | logged-on-users | Enumeration | ADMIN-REQ |
| --interfaces | network-interfaces | Enumeration | ADMIN-REQ |
| --reg-sessions | registry-sessions | Enumeration | ADMIN-REQ |
| --tasklist | running-processes | Enumeration | ADMIN-REQ |
| --disks | smb-disks | Enumeration | - |
| --computers | smb-domain-computers | Enumeration | - |
| --groups | smb-domain-groups | Enumeration | - |
| --users | smb-domain-users | Enumeration | - |
| --dpapi | smb-dpapi | Credential Dumping | gated |
| --local-groups | smb-local-groups | Enumeration | ADMIN-REQ |
| --lsa | smb-lsa | Credential Dumping | gated |
| --ntds | smb-ntds | Credential Dumping | gated |
| --pass-pol | smb-password-policy | Enumeration | - |
| --rid-brute | smb-rid-brute | Enumeration | - |
| --sam | smb-sam | Credential Dumping | gated |
| --sccm | smb-sccm-secrets | Credential Dumping | gated |
|  | smb-server-info | Enumeration | - |
| --smb-sessions | smb-sessions | Enumeration | ADMIN-REQ |
| --shares | smb-shares | Enumeration | - |
| --qwinsta | terminal-sessions | Enumeration | ADMIN-REQ |

| -M module | registration | category | privilege | options |
|---|---|---|---|---|
| add-computer | smb-add-computer | Privilege Escalation | gated |  |
| aws-credentials | smb-aws-credentials | Credential Dumping | - |  |
| backup_operator | smb-backup-operator | Privilege Escalation | gated |  |
| bitlocker | smb-bitlocker | Enumeration | ADMIN-REQ |  |
| change-password | smb-change-password | Privilege Escalation | gated |  |
| coerce_plus | smb-coerce-plus | Privilege Escalation | gated | LISTENER, TECHNIQUE |
| dpapi_hash | smb-dpapi-hash | Credential Dumping | gated |  |
| drop-library-ms | smb-drop-library-ms | Privilege Escalation | gated | NAME, CLEANUP |
| drop-sc | smb-drop-sc | Privilege Escalation | gated | URL, CLEANUP |
| empire_exec | smb-empire-exec | Privilege Escalation | gated |  |
| enum_av | smb-enum-av | Enumeration | - |  |
| enum_ca | smb-enum-ca | Enumeration | - |  |
| enum_dns | smb-enum-dns | Enumeration | ADMIN-REQ |  |
| enum_interfaces | smb-enum-interfaces | Enumeration | ADMIN-REQ |  |
| eventlog_creds | smb-eventlog-creds | Credential Dumping | gated |  |
| get_netconnections | smb-get-netconnections | Enumeration | ADMIN-REQ |  |
| gpp_autologin | smb-gpp-autologin | Credential Dumping | - |  |
| gpp_password | smb-gpp-password | Credential Dumping | - |  |
| gpp_privileges | smb-gpp-privileges | Enumeration | - | NO_LDAP |
| handlekatz | smb-handlekatz | Credential Dumping | gated |  |
| hash_spider | smb-hash-spider | Privilege Escalation | gated |  |
| hyperv-host | smb-hyperv-host | Enumeration | ADMIN-REQ |  |
| iis | smb-iis | Credential Dumping | gated |  |
| impersonate | smb-impersonate | Privilege Escalation | gated |  |
| install_elevated | smb-install-elevated | Enumeration | ADMIN-REQ |  |
| ioxidresolver | smb-ioxidresolver | Enumeration | - | DIFFERENT |
| keepass_discover | smb-keepass-discover | Enumeration | ADMIN-REQ |  |
| keepass_trigger | smb-keepass-trigger | Credential Dumping | gated |  |
| lockscreendoors | smb-lockscreendoors | Enumeration | ADMIN-REQ |  |
| lsassy | smb-lsassy | Credential Dumping | gated |  |
| masky | smb-masky | Credential Dumping | gated |  |
| met_inject | smb-met-inject | Privilege Escalation | gated |  |
| mobaxterm | smb-mobaxterm | Credential Dumping | gated |  |
| mremoteng | smb-mremoteng | Credential Dumping | gated |  |
| ms17-010 | smb-ms17-010 | Enumeration | - |  |
| msol | smb-msol | Credential Dumping | gated |  |
| nanodump | smb-nanodump | Credential Dumping | gated |  |
| nopac | smb-nopac | Enumeration | - |  |
| notepad | smb-notepad | Credential Dumping | gated |  |
| notepad++ | smb-notepad-plus-plus | Credential Dumping | gated |  |
| ntds-dump-raw | smb-ntds-dump-raw | Credential Dumping | gated |  |
| ntdsutil | smb-ntdsutil | Credential Dumping | gated |  |
| ntlm_reflection | smb-ntlm-reflection | Enumeration | - |  |
| ntlmv1 | smb-ntlmv1 | Enumeration | ADMIN-REQ |  |
| pi | smb-process-injection | Privilege Escalation | gated |  |
| powershell_history | smb-powershell-history | Credential Dumping | gated |  |
| presence | smb-presence | Enumeration | ADMIN-REQ |  |
| printnightmare | smb-printnightmare | Enumeration | - | PORT |
| procdump | smb-procdump | Credential Dumping | gated |  |
| putty | smb-putty | Credential Dumping | gated |  |
| rdcman | smb-rdcman | Credential Dumping | gated |  |
| rdp | smb-rdp-toggle | Privilege Escalation | gated |  |
| recent_files | smb-recent-files | Credential Dumping | gated |  |
| recyclebin | smb-recyclebin | Credential Dumping | gated |  |
| reg-query | smb-reg-query | Enumeration | ADMIN-REQ | PATH, KEY |
| reg-winlogon | smb-reg-winlogon | Credential Dumping | gated |  |
| remote-uac | smb-remote-uac | Privilege Escalation | gated |  |
| remove-mic | smb-remove-mic | Enumeration | - | PORT |
| runasppl | smb-runasppl | Enumeration | ADMIN-REQ |  |
| sccm-recon6 | smb-sccm-recon6 | Enumeration | - |  |
| schtask_as | smb-schtask-as | Privilege Escalation | gated |  |
| scuffy | smb-scuffy | Privilege Escalation | gated | URL, CLEANUP |
| security-questions | smb-security-questions | Credential Dumping | gated |  |
| shadowrdp | smb-shadowrdp | Privilege Escalation | gated |  |
| slinky | smb-slinky | Privilege Escalation | gated | URL, CLEANUP |
| smbghost | smb-smbghost | Enumeration | - |  |
| snipped | smb-snipped | Credential Dumping | gated |  |
| spider_plus | smb-spider-plus | Credential Dumping | - | OUTPUT_FOLDER, SHARE, EXCLUDE_DIRS, DEPTH, PATTERN, REGEX, CONTENT, ONLY_FILES, SILENT |
| spooler | smb-spooler | Enumeration | - | PORT |
| teams_localdb | smb-teams-localdb | Credential Dumping | gated |  |
| test_connection | smb-test-connection | Enumeration | ADMIN-REQ | HOST |
| timeroast | smb-timeroast | Privilege Escalation | gated |  |
| uac | smb-uac | Enumeration | ADMIN-REQ |  |
| veeam | smb-veeam | Credential Dumping | gated |  |
| vnc | smb-vnc-passwords | Credential Dumping | gated |  |
| wam | smb-wam | Credential Dumping | gated |  |
| wcc | smb-wcc | Enumeration | ADMIN-REQ | OUTPUT_FORMAT, OUTPUT, QUIET |
| wdigest | smb-wdigest | Credential Dumping | gated |  |
| web_delivery | smb-web-delivery | Privilege Escalation | gated |  |
| webdav | smb-webdav | Enumeration | - | MSG |
| wifi | smb-wifi | Credential Dumping | gated |  |
| winscp | smb-winscp | Credential Dumping | gated |  |
| zerologon | smb-zerologon | Enumeration | - |  |

### WINRM

| native flag | registration | category | privilege |
|---|---|---|---|
|  | winrm-auth-check | Enumeration | - |
| --dpapi | winrm-dpapi | Credential Dumping | gated |
| --lsa | winrm-lsa | Credential Dumping | gated |
| --sam | winrm-sam | Credential Dumping | gated |

| -M module | registration | category | privilege | options |
|---|---|---|---|---|
| aws-credentials | winrm-aws-credentials | Credential Dumping | - |  |
| ntds-dump-raw | winrm-ntds-dump-raw | Credential Dumping | gated |  |

### WMI

| native flag | registration | category | privilege |
|---|---|---|---|
|  | wmi-auth-check | Enumeration | - |
| --list-snapshots | wmi-list-snapshots | Enumeration | - |

| -M module | registration | category | privilege | options |
|---|---|---|---|---|
| bitlocker | wmi-bitlocker | Enumeration | ADMIN-REQ |  |
| enum_dns | wmi-enum-dns | Enumeration | ADMIN-REQ |  |
| get_netconnections | wmi-get-netconnections | Enumeration | ADMIN-REQ |  |
| ioxidresolver | wmi-ioxidresolver | Enumeration | - |  |
| ntds-dump-raw | wmi-ntds-dump-raw | Credential Dumping | gated |  |
| rdp | wmi-rdp-toggle | Privilege Escalation | gated |  |
| spooler | wmi-spooler | Enumeration | - |  |
| zerologon | wmi-zerologon | Enumeration | - |  |

### MSSQL

| native flag | registration | category | privilege |
|---|---|---|---|
|  | mssql-auth-check | Enumeration | - |
| --database | mssql-databases | Enumeration | - |
| --rid-brute | mssql-rid-brute | Enumeration | - |

| -M module | registration | category | privilege | options |
|---|---|---|---|---|
| empire_exec | mssql-empire-exec | Privilege Escalation | gated |  |
| enable_cmdshell | mssql-enable-cmdshell | Privilege Escalation | gated |  |
| enum_impersonate | mssql-enum-impersonate | Enumeration | - |  |
| enum_links | mssql-enum-links | Enumeration | - |  |
| enum_logins | mssql-enum-logins | Enumeration | - |  |
| exec_on_link | mssql-exec-on-link | Privilege Escalation | gated |  |
| link_enable_cmdshell | mssql-link-enable-cmdshell | Privilege Escalation | gated |  |
| link_xpcmd | mssql-link-xpcmd | Privilege Escalation | gated |  |
| met_inject | mssql-met-inject | Privilege Escalation | gated |  |
| mssql_coerce | mssql-coerce | Privilege Escalation | gated | LISTENER |
| mssql_priv | mssql-priv | Privilege Escalation | gated |  |
| nanodump | mssql-nanodump | Privilege Escalation | gated |  |
| test_connection | mssql-test-connection | Enumeration | ADMIN-REQ | HOST |
| web_delivery | mssql-web-delivery | Privilege Escalation | gated |  |

### SSH

| native flag | registration | category | privilege |
|---|---|---|---|
|  | ssh-auth-check | Enumeration | - |
| --sudo-check | ssh-sudo-check | Privilege Escalation | - |

| -M module | registration | category | privilege | options |
|---|---|---|---|---|
| aws-credentials | ssh-aws-credentials | Credential Dumping | - |  |

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
--- PASS: TestDumpInventoryTables (0.00s)
PASS
ok  	github.com/pwnflow/pwnflow/internal/modules/netexec	(cached)

## Removed, renamed, and superseded

| Name | Protocol | Status | Handling |
|---|---|---|---|
| `ldap-checker` | LDAP | Retired; still printed by `-L` with a `[REMOVED]` marker | Registration removed. The status is detected from the listing, so a `[REMOVED]` module is reported `UNAVAILABLE` even though its name appears |
| `enum_trusts` | LDAP | Retired | Not registered |
| `group-mem` | LDAP | Retired, replaced by `groupmembership` | `groupmembership` registered; the retired name is not |
| `petitpotam`, `printerbug`, `shadowcoerce`, `dfscoerce`, `efsr_spray` | SMB | Retired coercion modules | Not registered. The coercion registrations that remain are the ones the installed build advertises normally |
| `firefox` | SMB | Retired | Not registered |
| `certipy-find` | LDAP | Advertised and usable | Not registered: it duplicates the AD CS family's certipy integration and writes its own artifact files. The omission is asserted by a test so it stays a decision, not an oversight |
| `pso` | LDAP | Advertised and usable | Not registered: it duplicates the `--pso` native query, which is registered as fine-grained-password-policy |
| `--bloodhound` / `--collection` | LDAP | Deliberately unsupported in PwnFlow | No registration builds them |
| `--interfaces` | SMB | Superseded by `enum_interfaces` but still advertised | Both are registered, and Module Information says which is which |

## Native flags that are documented but not registered

These flags exist in the installed build and are deliberately not exposed as
one-key modules, because each one needs a value only the operator can supply
(a path, a command, a query) and PwnFlow's option mechanism passes module options
(`-o KEY=VALUE`), which the native flags do not accept:

| Protocol | Flags | Reason |
|---|---|---|
| LDAP | `--query`, `--base-dn`, `--users-export`, `--gmsa-convert-id`, `--gmsa-decrypt-lsa`, `--kerberoast-account`, `--no-preauth-targets` | Operator-supplied filter, base DN, export path, or key material |
| SMB | `-x`, `-X`, `--put-file`, `--get-file`, `--dir`, `--spider*`, `--content`, `--pattern`, `--regex`, `--taskkill`, `--wmi-query`, `--laps`, `--delegate`, `--generate-*`, `--gen-relay-list` | Remote execution, file transfer, content search, or Kerberos artifact generation |
| WINRM | `-x`, `-X` | Remote execution |
| WMI | `--wmi-query` | Operator-supplied WQL query |
| MSSQL | `-q`/`--query` | Operator-supplied SQL statement |
| SSH | `-x`, `--put-file`, `--get-file`, `--key-file` | Remote execution, file transfer, key material |
| FTP | `--get`, `--put` | File transfer |
| RDP | `--screenshot`, `-x`, `-X` | A full interactive login rather than a read; the NLA login-prompt screenshot is registered instead |
| NFS | `--ls`, `--get-file`, `--put-file`, `--share` | Operator-supplied paths |

## Privilege classification and its evidence

`ADMIN-REQ` is set from the `HIGH PRIVILEGE MODULES (requires admin privs)`
sectioning of `nxc <protocol> -L` together with the module's own implementation,
and the reason text names the right so a local administrator requirement is never
confused with a domain administrator one:

| Reason text | Meaning | Examples |
|---|---|---|
| `local administrator on the target` | Membership of the target's local Administrators group | `smb-sessions`, `logged-on-users`, `running-processes`, `smb-bitlocker`, `smb-lsassy` |
| `local administrator with remote registry or service access` | The target's registry or service control manager has to be reachable with administrative rights | `registry-sessions`, `network-interfaces`, `smb-reg-query`, `smb-ntlmv1` |
| `local administrator on the domain controller` | The dump paths read directory database files, so the right has to hold on a domain controller | `smb-ntds`, `smb-ntdsutil`, `smb-ntds-dump-raw` |
| `domain administrator or equivalent directory rights` | A directory-wide right, for example reconfiguring xp_cmdshell on a link or abusing a forest trust | `raisechild`, `mssql-enable-cmdshell` |

The classification is informational. A module that the target refuses still runs,
reports the refusal, and keeps whatever partial result it produced; nothing in
the interface blocks a labelled module, and a regression test asserts that.

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
| UNAVAILABLE | The installed build does not support it, or the operator has not supplied what it needs |

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
target with a valid domain account: 91 modules, exit status 0, no failures.
Artifact sizes are the persisted output size, which is how an empty-but-successful
result is told apart from a real one.

| registration | runner status | exit | artifact | result |
|---|---|---|---|---|
| domain-users | completed | exit=0 | 5743 | LIVE PASS |
| active-users | completed | exit=0 | 3841 | LIVE PASS |
| domain-groups | completed | exit=0 | 11973 | LIVE PASS |
| domain-computers | completed | exit=0 | 812 | LIVE PASS |
| domain-sid | completed | exit=0 | 390 | LIVE PASS |
| password-policy | completed | exit=0 | 2027 | LIVE PASS |
| fine-grained-password-policy | completed | exit=0 | 272 | LIVE PASS |
| admin-count | completed | exit=0 | 814 | LIVE PASS |
| password-not-required | completed | exit=0 | 466 | LIVE PASS |
| delegation | completed | exit=0 | 1012 | LIVE PASS |
| trusted-for-delegation | completed | exit=0 | 421 | LIVE PASS |
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
| smb-domain-users | completed | exit=0 | 4434 | LIVE PASS |
| smb-domain-groups | completed | exit=0 | 399 | LIVE PASS |
| smb-domain-computers | completed | exit=0 | 399 | LIVE PASS |
| smb-password-policy | completed | exit=0 | 2029 | LIVE PASS |
| smb-local-groups | completed | exit=0 | 3584 | LIVE PASS |
| smb-sessions | completed | exit=0 | 424 | LIVE PASS |
| logged-on-users | completed | exit=0 | 519 | LIVE PASS |
| terminal-sessions | completed | exit=0 | 1126 | LIVE PASS |
| running-processes | completed | exit=0 | 22100 | LIVE PASS |
| network-interfaces | completed | exit=0 | 1046 | LIVE PASS |
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
| smb-get-netconnections | completed | exit=0 | 962 | LIVE PASS |
| smb-hyperv-host | completed | exit=0 | 289 | LIVE PASS |
| smb-install-elevated | completed | exit=0 | 397 | LIVE PASS |
| smb-keepass-discover | completed | exit=0 | 925 | LIVE PASS |
| smb-lockscreendoors | completed | exit=0 | 438 | LIVE PASS |
| smb-ntlmv1 | completed | exit=0 | 289 | LIVE PASS |
| smb-presence | completed | exit=0 | 489 | LIVE PASS |
| smb-reg-query | completed | exit=0 | 407 | LIVE PASS |
| smb-runasppl | completed | exit=0 | 372 | LIVE PASS |
| smb-test-connection | completed | exit=0 | 588 | LIVE PASS |
| smb-uac | completed | exit=0 | 383 | LIVE PASS |
| smb-wcc | completed | exit=0 | 3788 | LIVE PASS |
| winrm-auth-check | completed | exit=0 | 241 | LIVE PASS |
| wmi-auth-check | completed | exit=0 | 240 | LIVE PASS |
| wmi-ioxidresolver | completed | exit=0 | 325 | LIVE PASS |
| wmi-spooler | completed | exit=0 | 329 | LIVE PASS |
| wmi-zerologon | completed | exit=0 | 348 | LIVE PASS |
| wmi-list-snapshots | completed | exit=0 | 240 | LIVE PASS |
| wmi-bitlocker | completed | exit=0 | 4983 | LIVE PASS |
| wmi-enum-dns | completed | exit=0 | 3948 | LIVE PASS |
| wmi-get-netconnections | completed | exit=0 | 913 | LIVE PASS |
| mssql-auth-check | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| mssql-databases | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| mssql-enum-logins | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| mssql-enum-links | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| mssql-rid-brute | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| mssql-enum-impersonate | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| mssql-test-connection | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| ssh-auth-check | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| ssh-sudo-check | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| ftp-auth-check | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| ftp-list | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| rdp-auth-check | completed | exit=0 | 260 | LIVE PASS |
| vnc-auth-check | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| nfs-auth-check | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |
| nfs-shares | completed | exit=0 | 0 | LIVE NOT APPLICABLE (no service) |

Beyond the byte counts, PwnFlow's execution was compared against the equivalent
direct invocation for representative modules, and the results matched:

| Registration | Direct invocation | PwnFlow artifact |
|---|---|---|
| `smb-shares` | 1877 bytes | 1878 bytes (trailing newline) |
| `maq` | 461 bytes, reporting the machine account quota | 462 bytes |
| `daclread` with `-o TARGET=... ACTION=read` | full ACL listing | 20330 bytes |

Result mix over those 91 registrations:

| Result | Count | Detail |
|---|---|---|
| LIVE PASS | 77 | LDAP, SMB, WMI, the WinRM credential check, and the RDP credential check, all returning content |
| LIVE NOT APPLICABLE | 14 | MSSQL (7), SSH (2), FTP (2), VNC (1), NFS (2): the service is absent, so the installed NetExec prints nothing and exits 0 |
| LIVE DENIED | 0 | Not produced. The account used for the validation already held local administrator rights on the authorized target, so no refusal could be observed without a low-privilege credential for that host. The `ADMIN-REQ` classification therefore rests on NetExec's own high-privilege sectioning and on the module implementations rather than on an observed denial, and it remains informational either way |

Two of the runs are worth calling out:

* `smb-wcc` and `daclread` exercised the option mechanism end to end: the
  operator-supplied value arrived as `-o KEY=VALUE`, and the module used it.
* In the first pass, `groupmembership` failed because the module refuses to run
  without the user it should query. That turned into a required option, which is
  now reported as `UNAVAILABLE` with the exact `--module-options` syntax until it
  is supplied, and the live check passes once it is.

### Runs that are not authorized in this session

These registrations are listed, labelled, and gated, and were only exercised
offline. Running any of them needs an explicit operator decision for the specific
operation and target:

| Group | Registrations | What is needed before it may run |
|---|---|---|
| Credential extraction | The `Credential Dumping` category: `--sam`, `--lsa`, `--ntds`, `--dpapi`, `--sccm`, the LSASS dump modules, browser and vault looters, and the directory attribute readers such as `laps` and `get-userPassword` | Approval for credential access on the named target, and an artifact workflow for the material it recovers |
| Kerberos ticket export | `asreproast`, `kerberoasting` | Approval, plus the protected artifact workflow their output requires |
| State-changing and execution | The `Privilege Escalation` category, for example `add-computer`, `change-password`, `coerce_plus`, `timeroast`, `smb-rdp-toggle`, `schtask_as`, and the Empire/Meterpreter delivery modules | Approval for the specific technique and target |
| Loud enumeration | `smb-rid-brute`, `mssql-rid-brute` | Approval, because the target's logs will show the walk |
| Authentication testing | `--rid-brute`, `--delegate`, and anything that would spray or guess | Approval for the account and lockout policy in scope |

The gate is a single field per registration (`gated` above): enabling one is a
deliberate edit, not a side effect of navigation, and the guarantee that a
category-wide run can never include one is enforced by tests.

### Offline-only coverage and why

| Registrations | Reason |
|---|---|
| MSSQL credential and escalation modules (`mssql_priv`, `enable_cmdshell`, `link_*`, `mssql_coerce`, `nanodump`, `empire_exec`, `met_inject`, `web_delivery`) | The authorized host runs no MSSQL service, and the modules change state or execute code |
| FTP, SSH, VNC, NFS registrations | The authorized host runs none of those services; the commands were verified to build correctly, to pass the capability check, and to be reported `LIVE NOT APPLICABLE` when run |
| Credential extraction and coercion modules | Approval-sensitive, as above |

### What a `LIVE NOT APPLICABLE` result looks like

When a service is absent, the installed NetExec prints nothing and exits 0
(observed directly and through PwnFlow for MSSQL, SSH, FTP, VNC, and NFS on the
authorized host). PwnFlow therefore persists an empty artifact and reports the
run as completed. The status is honest: the command was correct and it reached
the point where the service would have answered.
