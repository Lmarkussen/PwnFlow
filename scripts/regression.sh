#!/usr/bin/env bash
# Repeatable Default Enumeration regression for an authorized lab.
#
#   scripts/regression.sh run   --env FILE --expect FILE [--timeout SECONDS]
#   scripts/regression.sh check --db FILE --domain DOMAIN --expect FILE [--since TIMESTAMP]
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
set -euo pipefail

usage() {
  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
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
  local env="" expect="" timeout=1800
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --env) env="$2"; shift 2 ;;
      --expect) expect="$2"; shift 2 ;;
      --timeout) timeout="$2"; shift 2 ;;
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
  check --db "$root/results/$PWNFLOW_DOMAIN/enumeration.db" --domain "$PWNFLOW_DOMAIN" --expect "$expect" --since "$since"
}

case "${1:-}" in
  run) shift; run "$@" ;;
  check) shift; check "$@" ;;
  *) usage ;;
esac
