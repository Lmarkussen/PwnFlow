# Lab regression

`scripts/regression.sh` runs Default Enumeration against an authorized lab and
checks the resulting Findings against an expectations file. It turns the manual
"run Ctrl+A, then look" validation into one command whose exit status says
whether every expected condition was found and nothing unexpected appeared.

```sh
scripts/regression.sh run   --env LAB.env --expect LAB.expect [--timeout SECONDS] [--history LAB.csv]
scripts/regression.sh check --db results/DOMAIN/enumeration.db --domain DOMAIN --expect LAB.expect [--since TIMESTAMP]
scripts/regression.sh trend --history LAB.csv [--last N]
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

## History and trends

With `--history`, every run appends one CSV line: time, duration, the Findings
observed by that run by severity, the number of failed checks and the exit
status. `trend` prints the latest runs and exits 1 when the newest one
regressed: more failed checks than the run before, a duration above 1.5 times
the median of the previous five, or a total Finding count that moved by more
than 10%. A slow or flaky module shows up as a duration or failure trend before
it shows up as a missing Finding.

## Scheduling

Run it unattended with a systemd user timer on the lab host, for example a
oneshot service whose script calls `run ... --history` followed by `trend`, and
a timer with `OnCalendar=*-*-* 03:30:00` and `Persistent=true`. Enable
lingering (`loginctl enable-linger USER`) so the timer fires without a login,
and give the service an explicit `PATH`, since it does not run a login shell.
The run uses whatever tree is deployed on the lab host, so it tracks lab
drift; deploy a new tree to regression-test a change.

Requirements: `tmux`, `sqlite3`, and the tools Default Enumeration uses.
