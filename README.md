<p align="center">
  <img src="assets/pwnflow.png" width="400" alt="PwnFlow logo">
</p>

<p align="center"><strong>Active Directory Enumeration &amp; Security Evidence — From Discovery to Findings.</strong></p>

## What is PwnFlow?

PwnFlow is a Go/Bubble Tea terminal application for authorized Active Directory enumeration, evidence collection, and Findings review. It discovers and organizes source-backed evidence for operator decisions; it does not automatically exploit vulnerabilities.

Original assessment artifacts remain available for review, while Findings provide structured, provenance-aware summaries and navigation.

## Features

- Protected 45-module automatic enumeration profile with GhostSPN immediately after Kerberoasting.
- Terminal Tool Runner with approvals, cancellation, availability checks, and watcher output.
- Per-assessment evidence collection with access to original artifacts.
- Source-backed Findings with recovered material and uncertainty preserved.
- Confirmed Critical and Potential Critical — Not Verified projections over original Findings.
- Offline Findings review through `--findings`, without network access or execution.

## Installation

Kali Linux is the supported installation target. Go 1.22 or newer is required for development builds.

```bash
git clone git@github.com:Lmarkussen/PwnFlow.git
cd PwnFlow
./install.sh
make build
```

The installer checks and installs supported external tools. Use its documented `--with-*` selectors when a targeted installation is required.

## Usage

```bash
# Start an authenticated assessment; enter the password at the terminal prompt.
./bin/pwnflow --dc-ip <DOMAIN_CONTROLLER> --domain <DOMAIN> --username <USER>

# Start the application, then use Ctrl+A for the protected automatic profile.
./bin/pwnflow --dc-ip <DOMAIN_CONTROLLER> --domain <DOMAIN> --username <USER>

# Start the Tool Runner and select an individual module with Enter.
./bin/pwnflow --dc-ip <DOMAIN_CONTROLLER> --domain <DOMAIN> --username <USER>

# Browse an existing assessment without network access or execution.
pwnflow --findings --domain local.lab
```

Use `--module-options MODULE.KEY=VALUE` for supported module inputs. Avoid `--password` on shared systems because external tools may expose command-line arguments to local process inspection.

## Architecture

```text
Discovery → Enumeration → Evidence → Findings → Operator
```

PwnFlow keeps retained artifacts and source provenance intact. The Critical view is a read-only, in-memory projection that prioritizes confirmed attack paths and separates potential, not-verified candidates without replacing the original Finding details.

## Documentation

- [Operator guide](docs/operator-guide.md) — installation, controls, modules, scope, and troubleshooting.
- [Findings engine](docs/findings-engine.md) — analysis lifecycle, evidence boundaries, and Critical Findings.
- [NetExec inventory](docs/netexec-inventory.md) — protocols, capabilities, and options.
- [RustHound artifact schema](docs/rusthound-artifact-schema.md) — retained directory evidence and analysis limits.
- [Specialized tools](docs/specialized-tools.md) — integrated external tool versions and scope.
