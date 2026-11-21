#!/usr/bin/env bash
# Repeatable Default Enumeration regression for an authorized lab.
#
#   scripts/regression.sh run   --env FILE --expect FILE [--timeout SECONDS] [--history FILE]
#   scripts/regression.sh check --db FILE --domain DOMAIN --expect FILE [--since TIMESTAMP]
#   scripts/regression.sh trend --history FILE [--last N]
#
# run builds PwnFlow, starts it in a detached tmux session with the settings in
# the env file, presses Ctrl+A, declines every elevation prompt, waits for the
# batch and its analysis to finish, quits, and then runs check against the
# assessment database.
#
# The env file and the expectations file describe a specific lab. Keep them
# outside the repository: they name hosts, accounts and credentials.
#
# Env file (shell syntax):
#   PWNFLOW_DC_IP=...  PWNFLOW_DOMAIN=...  PWNFLOW_USERNAME=...  PWNFLOW_PASSWORD=...
#   PWNFLOW_INSECURE_SKIP_VERIFY=1   (optional)
#   PWNFLOW_EXTRA_PATH=...           (optional, prepended to PATH for the tools)
#
# Expectations file, one per line ('#' starts a comment):
#   present <finding_type> [<text in the affected object or title>]
#   absent  <finding_type> [<text in the affected object or title>]
# Only Findings observed at or after --since count, so rows left by earlier
# runs cannot satisfy or break an expectation. Any failed execution or
# analysis job since then also fails the check.
#
# --history appends one CSV line per run (time, duration, Findings by
# severity, failed checks, exit status). trend prints the latest runs and
# exits 1 when the newest one regressed: more failed checks, a duration over
# 1.5x the median of the five before it, or a total Finding count that moved
# by more than 10%.
set -euo pipefail

usage() {
  sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

die() { echo "regression: $*" >&2; exit 2; }

sql_quote() { printf "'%s'" "${1//\'/\'\'}"; }

check() {
  local db="" domain="" expect="" since="1970-01-01T00:00:00Z"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --db) db="$2"; shift 2 ;;
      --domain) domain="$2"; shift 2 ;;
      --expect) expect="$2"; shift 2 ;;
      --since) since="$2"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -f "$db" && -f "$expect" && -n "$domain" ]] || usage
  command -v sqlite3 >/dev/null || die "sqlite3 is required"
  # Stored times carry fractional seconds ("...:05.2Z"), which sort before
  # "...:05Z"; comparing against the timestamp without its Z keeps them.
  since="${since%Z}"
  local scope failures=0 line kind type text count where
  scope="f.assessment_id IN (SELECT id FROM targets WHERE lower(domain)=lower($(sql_quote "$domain"))) AND f.last_seen >= $(sql_quote "$since")"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    read -r kind type text <<<"$line" || true
    [[ -z "${kind:-}" ]] && continue
    where="$scope AND f.finding_type=$(sql_quote "$type")"
    if [[ -n "${text:-}" ]]; then
      where="$where AND (instr(lower(f.affected_object_name), lower($(sql_quote "$text"))) > 0 OR instr(lower(f.title), lower($(sql_quote "$text"))) > 0)"
    fi
    count="$(sqlite3 -readonly "$db" "SELECT count(*) FROM findings f WHERE $where;")"
    case "$kind" in
      present) if [[ "$count" -gt 0 ]]; then echo "PASS present $type ${text:-}"; else echo "FAIL present $type ${text:-}"; failures=$((failures + 1)); fi ;;
      absent) if [[ "$count" -eq 0 ]]; then echo "PASS absent  $type ${text:-}"; else echo "FAIL absent  $type ${text:-} ($count found)"; failures=$((failures + 1)); fi ;;
      *) die "unknown expectation '$kind' in $expect" ;;
    esac
  done <"$expect"
  local failed_executions failed_jobs
  failed_executions="$(sqlite3 -readonly "$db" "SELECT count(*) FROM executions e WHERE e.target_id IN (SELECT id FROM targets WHERE lower(domain)=lower($(sql_quote "$domain"))) AND e.started_at >= $(sql_quote "$since") AND lower(e.status) IN ('failed','error','timeout');")"
  failed_jobs="$(sqlite3 -readonly "$db" "SELECT count(*) FROM analysis_jobs a WHERE a.assessment_id IN (SELECT id FROM targets WHERE lower(domain)=lower($(sql_quote "$domain"))) AND a.updated_at >= $(sql_quote "$since") AND upper(a.status)='FAILED';")"
  if [[ "$failed_executions" -gt 0 ]]; then echo "FAIL $failed_executions failed execution(s)"; failures=$((failures + 1)); else echo "PASS no failed executions"; fi
  if [[ "$failed_jobs" -gt 0 ]]; then echo "FAIL $failed_jobs failed analysis job(s)"; failures=$((failures + 1)); else echo "PASS no failed analysis jobs"; fi
  if [[ $failures -gt 0 ]]; then
    echo "regression: $failures check(s) failed"
    return 1
  fi
  echo "regression: all checks passed"
}

run() {
  local env="" expect="" timeout=1800 history=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --env) env="$2"; shift 2 ;;
      --expect) expect="$2"; shift 2 ;;
      --timeout) timeout="$2"; shift 2 ;;
      --history) history="$2"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -f "$env" && -f "$expect" ]] || usage
  command -v tmux >/dev/null || die "tmux is required"
  # shellcheck disable=SC1090
  source "$env"
  : "${PWNFLOW_DC_IP:?} ${PWNFLOW_DOMAIN:?} ${PWNFLOW_USERNAME:?} ${PWNFLOW_PASSWORD:?}"
  local root session="pwnflow-regression" since screen deadline
  root="$(cd "$(dirname "$0")/.." && pwd)"
  make -C "$root" build >/dev/null
  local args=(--dc-ip "$PWNFLOW_DC_IP" --domain "$PWNFLOW_DOMAIN" --username "$PWNFLOW_USERNAME" --password "$PWNFLOW_PASSWORD")
  [[ "${PWNFLOW_INSECURE_SKIP_VERIFY:-0}" == 1 ]] && args+=(--insecure-skip-verify)
  local command
  printf -v command '%q ' "$root/bin/pwnflow" "${args[@]}"
  tmux kill-session -t "$session" 2>/dev/null || true
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  tmux new-session -d -s "$session" -x 200 -y 50 "cd $(printf '%q' "$root") && PATH=${PWNFLOW_EXTRA_PATH:+$PWNFLOW_EXTRA_PATH:}\$PATH $command; sleep 5"
  # The trap runs after run() returns, so the session name is expanded now.
  # shellcheck disable=SC2064
  trap "tmux kill-session -t $(printf '%q' "$session") 2>/dev/null || true" EXIT
  deadline=$((SECONDS + 60))
  until tmux capture-pane -p -t "$session" | grep -q "Ctrl+A"; do
    [[ $SECONDS -lt $deadline ]] || die "PwnFlow did not reach its main screen"
    sleep 2
  done
  tmux send-keys -t "$session" C-a
  local batch_started=$SECONDS
  deadline=$((SECONDS + timeout))
  while :; do
    screen="$(tmux capture-pane -p -t "$session")"
    if grep -q '\[y/N\]' <<<"$screen"; then
      tmux send-keys -t "$session" n
      echo "regression: declined an elevation prompt"
      sleep 3
      continue
    fi
    if grep -qE 'RUNNING 0 +QUEUED 0' <<<"$screen" && grep -qE '(^|[^0-9])0 pending' <<<"$screen"; then
      break
    fi
    [[ $SECONDS -lt $deadline ]] || die "Default Enumeration did not finish within ${timeout}s"
    sleep 10
  done
  grep -E '^(PROGRESS|Requested:|COMPLETED [0-9]|Elapsed:|Findings:)' <<<"$screen" || true
  tmux send-keys -t "$session" q
  sleep 2
  local db="$root/results/$PWNFLOW_DOMAIN/enumeration.db" report status=0 duration=$((SECONDS - batch_started))
  report="$(mktemp)"
  check --db "$db" --domain "$PWNFLOW_DOMAIN" --expect "$expect" --since "$since" | tee "$report" || status=$?
  if [[ -n "$history" ]]; then
    record_history "$history" "$db" "$PWNFLOW_DOMAIN" "$since" "$duration" "$(grep -c '^FAIL' "$report" || true)" "$status"
  fi
  rm -f "$report"
  return "$status"
}

record_history() {
  local history="$1" db="$2" domain="$3" since="$4" duration="$5" failed="$6" status="$7" counts
  counts="$(sqlite3 -readonly -separator , "$db" "SELECT count(*), sum(lower(severity)='high'), sum(lower(severity)='medium'), sum(lower(severity)='low'), sum(lower(severity)='informational') FROM findings WHERE assessment_id IN (SELECT id FROM targets WHERE lower(domain)=lower($(sql_quote "$domain"))) AND last_seen >= $(sql_quote "${since%Z}");")"
  [[ -s "$history" ]] || echo "time,duration_s,findings,high,medium,low,informational,failed_checks,status" >"$history"
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$duration,${counts:-0,0,0,0,0},$failed,$status" >>"$history"
}

trend() {
  local history="" last=10
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --history) history="$2"; shift 2 ;;
      --last) last="$2"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -f "$history" ]] || usage
  awk -F, -v last="$last" '
    NR == 1 { next }
    { n++; time[n]=$1; duration[n]=$2; findings[n]=$3; failed[n]=$8; status[n]=$9 }
    END {
      if (n == 0) { print "regression: no runs recorded"; exit 0 }
      start = n - last + 1; if (start < 1) start = 1
      printf "%-21s %9s %9s %7s %7s\n", "time", "duration", "findings", "failed", "status"
      for (i = start; i <= n; i++) printf "%-21s %8ss %9s %7s %7s\n", time[i], duration[i], findings[i], failed[i], status[i]
      flags = 0
      if (n >= 2) {
        if (failed[n] > failed[n-1]) { print "REGRESSION: failed checks rose from " failed[n-1] " to " failed[n]; flags++ }
        m = 0; for (i = n - 1; i >= 1 && i >= n - 5; i--) sample[++m] = duration[i]
        for (i = 1; i <= m; i++) for (j = i + 1; j <= m; j++) if (sample[j] < sample[i]) { t = sample[i]; sample[i] = sample[j]; sample[j] = t }
        median = (m % 2) ? sample[(m + 1) / 2] : (sample[m / 2] + sample[m / 2 + 1]) / 2
        if (median > 0 && duration[n] > 1.5 * median) { print "REGRESSION: duration " duration[n] "s is over 1.5x the median " median "s"; flags++ }
        if (findings[n-1] > 0) {
          change = (findings[n] - findings[n-1]) / findings[n-1]; if (change < 0) change = -change
          if (change > 0.10) { print "REGRESSION: Finding count moved from " findings[n-1] " to " findings[n]; flags++ }
        }
      }
      if (flags == 0) print "regression: latest run in line with history"
      exit (flags > 0)
    }' "$history"
}

case "${1:-}" in
  run) shift; run "$@" ;;
  check) shift; check "$@" ;;
  trend) shift; trend "$@" ;;
  *) usage ;;
esac
