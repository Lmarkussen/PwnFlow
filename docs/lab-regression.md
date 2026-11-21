# Lab regression

`scripts/regression.sh` runs Default Enumeration against an authorized lab and
checks the resulting Findings against an expectations file. It turns the manual
"run Ctrl+A, then look" validation into one command whose exit status says
whether every expected condition was found and nothing unexpected appeared.

```sh
scripts/regression.sh run   --env LAB.env --expect LAB.expect [--timeout SECONDS]
scripts/regression.sh check --db results/DOMAIN/enumeration.db --domain DOMAIN --expect LAB.expect [--since TIMESTAMP]
```

`run` builds PwnFlow, starts it in a detached tmux session, presses `Ctrl+A`,
declines every elevation prompt (so modules that need local sudo, such as
PXEThief discovery, are skipped), waits until the batch and its analysis jobs
have finished, quits, and calls `check` for the Findings observed since the run
started. `check` can also be pointed at an existing assessment database.

Both files describe one lab and contain hosts, accounts and credentials. Keep
them outside the repository with restrictive permissions.

## Env file

```sh
PWNFLOW_DC_IP=192.0.2.10
PWNFLOW_DOMAIN=corp.example
PWNFLOW_USERNAME=auditor
PWNFLOW_PASSWORD='...'
PWNFLOW_INSECURE_SKIP_VERIFY=1          # optional
PWNFLOW_EXTRA_PATH=$HOME/.cargo/bin     # optional, prepended to PATH
```

## Expectations file

```text
# comment
present smb_spooler_service_running
present ad_account_reversible_encryption SVC-LEGACY
absent  smb_webclient_service_running
```

`present` and `absent` take a Finding type and, optionally, text that must
appear in the affected object or the title. Only Findings observed at or after
the run start (`--since`) count, so rows kept from earlier runs neither satisfy
nor break an expectation. Any execution or analysis job that failed since then
also fails the check.

Seed the lab with one object per condition you want to keep covered, write a
`present` line for it, and add `absent` lines for conditions the lab must not
show. A failed check after a code change is then either a regression or a lab
change, and the output names which expectation moved.

Requirements: `tmux`, `sqlite3`, and the tools Default Enumeration uses.
