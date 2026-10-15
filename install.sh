#!/usr/bin/env bash
set -euo pipefail

install_rusthound_ce=0
install_netexec_requested=0
install_certipy=0
netexec_status="Skipped"
rusthound_ce_status="Skipped"
certipy_status="Skipped"
cargo_status="Skipped"
sudo_authenticated=0
for argument in "$@"; do
  case "$argument" in
    --with-netexec) install_netexec_requested=1 ;;
    --with-rusthound-ce) install_rusthound_ce=1 ;;
    --with-certipy) install_certipy=1 ;;
    --with-bloodhound|--with-bloodhound-ce|--with-bloodhound-python)
      echo "This installer no longer installs BloodHound CE or BloodHound CE Python; ${argument} is retired." >&2
      echo "BloodHound CE is the separate graph application and is installed with its official application procedure." >&2
      echo "RustHound-CE is the supported BloodHound CE collector: use --with-rusthound-ce." >&2
      exit 2
      ;;
    --help|-h)
      echo "Usage: $0 [--with-netexec] [--with-rusthound-ce] [--with-certipy]"
      echo ""
      echo "Installs the supported Kali dependencies: NetExec, RustHound-CE, and"
      echo "Certipy (AD CS enumeration, from the certipy-ad package)."
      echo "Kali Linux is the only supported installation target."
      exit 0
      ;;
    *) echo "Unknown option: $argument" >&2; exit 2 ;;
  esac
done

# The standalone default checks and installs every supported dependency.
# Explicit flags remain available for selective tool-group installation.
if [[ $# -eq 0 ]]; then
  install_netexec_requested=1
  install_rusthound_ce=1
  install_certipy=1
fi

ensure_sudo_authenticated() {
  if [[ ${EUID} -eq 0 ]]; then
    return 0
  fi
  if [[ ${sudo_authenticated} -eq 1 ]]; then
    if sudo -n -v >/dev/null 2>&1; then
      return 0
    fi
    echo "sudo privilege expired during dependency installation; authenticate again in this terminal." >&2
    sudo_authenticated=0
    return 1
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    echo "APT installation requires sudo, but sudo is unavailable." >&2
    return 1
  fi
  if sudo -n -v >/dev/null 2>&1; then
    sudo_authenticated=1
    return 0
  fi
  echo "Sudo privileges are required for system package installation."
  if ! sudo -v; then
    echo "sudo authentication was cancelled or failed." >&2
    return 1
  fi
  if ! sudo -n -v >/dev/null 2>&1; then
    echo "sudo authentication did not establish a usable cached privilege." >&2
    return 1
  fi
  sudo_authenticated=1
}
run_apt() {
  # Keep debconf and needrestart noninteractive for this child operation only.
  # NEEDRESTART_MODE=l lists affected services instead of prompting or restarting.
  local apt_environment=(DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l)
  if ! ensure_sudo_authenticated; then
    return 1
  fi
  if [[ ${EUID} -eq 0 ]]; then
    env "${apt_environment[@]}" apt-get -o DPkg::Lock::Timeout=30 "$@" </dev/null
  else
    if ! sudo -n env "${apt_environment[@]}" apt-get -o DPkg::Lock::Timeout=30 "$@" </dev/null; then
      if ! sudo -n -v >/dev/null 2>&1; then
        echo "sudo privilege expired during dependency installation." >&2
      else
        echo "APT operation failed while installing dependencies." >&2
      fi
      return 1
    fi
  fi
}

run_apt_install() {
  local packages=("$@")
  echo "APT simulation for: ${packages[*]}"
  run_apt -s install "${packages[@]}"
  if ! confirm_install "Apply this APT transaction?"; then
    echo "APT transaction cancelled." >&2
    return 1
  fi
  run_apt install -y "${packages[@]}"
}

prepend_path_once() {
  local directory="$1"
  case ":${PATH}:" in
    *":${directory}:"*) ;;
    *) PATH="${directory}:${PATH}"; export PATH ;;
  esac
}

confirm_install() {
  local prompt="$1"
  if [[ "${PWNFlow_ASSUME_YES:-0}" == "1" ]]; then
    return 0
  fi
  local tty_fd
  if ! exec {tty_fd}<>/dev/tty 2>/dev/null; then
    echo "${prompt} Operator consent requires a controlling terminal." >&2
    return 1
  fi
  printf '%s [y/N] ' "$prompt" >&"$tty_fd"
  local answer=""
  if ! IFS= read -r answer <&"$tty_fd"; then
    echo "ERROR: Could not read operator confirmation." >&2
    exec {tty_fd}>&-
    return 1
  fi
  exec {tty_fd}>&-
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

cargo_bin_directory() {
  if [[ -n "${CARGO_HOME:-}" ]]; then
    printf '%s/bin\n' "$CARGO_HOME"
  else
    printf '%s/.cargo/bin\n' "$HOME"
  fi
}

refresh_cargo_path() {
  local cargo_bin
  cargo_bin="$(cargo_bin_directory)"
  prepend_path_once "$cargo_bin"
  echo "Cargo applications available immediately from: ${cargo_bin}"
}

# Minimum free space the RustHound-CE release build needs in its build directory.
cargo_build_min_free_kb() {
  printf '%s\n' 2097152 # 2 GiB
}

filesystem_free_kb() {
  local directory="$1" line value=""
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*([0-9]+)[[:space:]]*$ ]]; then
      value="${BASH_REMATCH[1]}"
    fi
  done < <(df -k --output=avail "$directory" 2>/dev/null || true)
  if [[ -n "$value" ]]; then
    printf '%s\n' "$value"
  fi
}

free_space_description() {
  local free
  free="$(filesystem_free_kb "$1")"
  if [[ -z "$free" ]]; then
    printf '%s\n' "free space unknown"
  else
    printf '%s\n' "$((free / 1024)) MiB free"
  fi
}

cargo_build_dir=""

# Chooses where Cargo builds RustHound-CE and records it in cargo_build_dir.
# Cargo performs every install build under TMPDIR, and Kali's /tmp is a tmpfs
# limited to about half of RAM, so the installer prefers a disk-backed cache
# directory. An operator-supplied TMPDIR is used when it is usable and is never
# replaced silently; this function narrates its own diagnostics on stdout so an
# operator sees them in the same stream as the installation summary.
cargo_build_directory() {
  local preferred="${HOME}/.cache/pwnflow/cargo-tmp" minimum free
  minimum="$(cargo_build_min_free_kb)"
  cargo_build_dir=""
  if [[ -n "${TMPDIR:-}" ]]; then
    if [[ ! -d "$TMPDIR" || ! -w "$TMPDIR" ]]; then
      echo "TMPDIR is set to '${TMPDIR}', which is not a writable directory."
      echo "Point TMPDIR at a writable, disk-backed directory, or unset it so Cargo can use ${preferred}."
      return 1
    fi
    free="$(filesystem_free_kb "$TMPDIR")"
    if [[ -n "$free" ]] && (( free < minimum )); then
      echo "TMPDIR is set to '${TMPDIR}' with $((free / 1024)) MiB free; the RustHound-CE release build needs at least $((minimum / 1024)) MiB."
      echo "Point TMPDIR at a larger filesystem, or unset it so Cargo can use ${preferred}."
      return 1
    fi
    cargo_build_dir="$TMPDIR"
    return 0
  fi
  if [[ ! -d "$preferred" ]] && ! mkdir -p "$preferred" 2>/dev/null; then
    echo "Could not create the Cargo build directory ${preferred}."
    return 1
  fi
  free="$(filesystem_free_kb "$preferred")"
  if [[ -n "$free" ]] && (( free < minimum )); then
    echo "${preferred} has $((free / 1024)) MiB free; the RustHound-CE release build needs at least $((minimum / 1024)) MiB."
    echo "Free space on that filesystem, or set TMPDIR to a directory with more room."
    return 1
  fi
  cargo_build_dir="$preferred"
}

package_installed() {
  command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}

ensure_cargo_dependencies() {
  local missing=()
  if ! command -v cargo >/dev/null 2>&1 || ! cargo --version >/dev/null 2>&1; then
    missing+=(cargo)
  fi
  command -v cc >/dev/null 2>&1 || missing+=(build-essential)
  command -v pkg-config >/dev/null 2>&1 || missing+=(pkg-config)
  command -v clang >/dev/null 2>&1 || missing+=(clang)
  package_installed gcc || missing+=(gcc)
  package_installed libclang-dev || missing+=(libclang-dev)
  package_installed libgssapi-krb5-2 || missing+=(libgssapi-krb5-2)
  package_installed libkrb5-dev || missing+=(libkrb5-dev)
  package_installed libsasl2-modules-gssapi-mit || missing+=(libsasl2-modules-gssapi-mit)
  if [[ ${#missing[@]} -eq 0 ]]; then
    cargo_status="Already installed"
    refresh_cargo_path
    echo "Cargo available: $(cargo --version 2>/dev/null || true)"
    return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "RustHound-CE requires Cargo and build dependencies: ${missing[*]}; APT is unavailable." >&2
    return 1
  fi
  run_apt update
  run_apt_install "${missing[@]}"
  if ! command -v cargo >/dev/null 2>&1 || ! cargo --version >/dev/null 2>&1; then
    echo "APT completed but did not provide a functional Cargo executable." >&2
    return 1
  fi
  cargo_status="Installed"
  refresh_cargo_path
  echo "Cargo available: $(cargo --version 2>/dev/null || true)"
}

netexec_functional() {
  command -v nxc >/dev/null 2>&1 && nxc --help >/dev/null 2>&1
}

install_netexec() {
  if command -v nxc >/dev/null 2>&1; then
    if netexec_functional; then
      echo "NetExec already installed and functional: $(nxc --version 2>/dev/null || nxc --help 2>&1 | head -n 1)"
      netexec_status="Already installed"
    else
      echo "NetExec is installed but its --help capability check failed; refusing to replace or upgrade it automatically." >&2
      return 1
    fi
    return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "No supported package manager found. Install NetExec (nxc) using Kali's package manager." >&2
    return 1
  fi
  echo "Installing missing NetExec from the Kali APT repository."
  run_apt update
  run_apt_install netexec
  netexec_functional || { echo "NetExec installation did not provide a working nxc --help capability" >&2; return 1; }
  echo "NetExec installed: $(nxc --help 2>&1 | head -n 1)"
  netexec_status="Installed"
}

rusthound_executable() {
  command -v rusthound-ce 2>/dev/null
}

rusthound_functional() {
  local executable
  executable="$(rusthound_executable)" || return 1
  "$executable" --help >/dev/null 2>&1
}

install_rusthound_ce() {
  # Cargo installs into $CARGO_HOME/bin, which Kali does not place on PATH by
  # default, so refresh it before deciding whether RustHound-CE is already here.
  refresh_cargo_path
  if command -v rusthound-ce >/dev/null 2>&1; then
    if rusthound_functional; then
      echo "RustHound-CE already installed and functional: $(rusthound-ce --version 2>/dev/null || echo version unavailable)"
      rusthound_ce_status="Already installed"
      return 0
    fi
    echo "RustHound-CE is installed but its --help capability check failed; refusing to replace or upgrade it automatically." >&2
    return 1
  fi
  if ! ensure_cargo_dependencies; then
    return 1
  fi
  refresh_cargo_path
  local build_directory
  if ! cargo_build_directory; then
    rusthound_ce_status="Failed (no usable Cargo build directory)"
    return 1
  fi
  build_directory="${cargo_build_dir}"
  echo "Cargo build directory: ${build_directory} ($(free_space_description "$build_directory"))"
  echo "Installing missing RustHound-CE with Cargo."
  local cargo_exit=0
  if TMPDIR="$build_directory" cargo install rusthound-ce; then
    :
  else
    cargo_exit=$?
    rusthound_ce_status="Failed (cargo install exit ${cargo_exit})"
    echo "RustHound-CE Cargo installation failed (exit ${cargo_exit}). Review the Cargo output above; the build ran in ${build_directory}. Verify clang, libclang-dev, libkrb5-dev, and GSSAPI development packages are installed, and that the build directory has enough free space and memory."
    return 1
  fi
  local executable
  if ! executable="$(rusthound_executable)"; then
    rusthound_ce_status="Failed (cargo succeeded but rusthound-ce was not found in $(cargo_bin_directory))"
    echo "Cargo reported success, but rusthound-ce was not found in $(cargo_bin_directory)."
    return 1
  fi
  if ! "$executable" --help; then
    rusthound_ce_status="Failed (rusthound-ce installed at ${executable} but its --help capability check failed)"
    echo "Cargo installed rusthound-ce at ${executable}, but its --help capability check failed."
    return 1
  fi
  rusthound_ce_status="Installed"
  echo "RustHound-CE installed and functional at ${executable}: $("$executable" --version 2>/dev/null || echo version unavailable)"
}

# Certipy's AD CS tool is installed by Kali's certipy-ad package as `certipy-ad`;
# the pipx/PyPI distribution exposes the same tool as `certipy`. Both names are
# detection candidates, and whichever is found has to identify itself as the AD
# CS tool before it is accepted: unrelated programs named certipy exist.
certipy_adcs_marker="Active Directory Certificate Services"

# The arguments the installed Certipy must document for the enumeration modules
# PwnFlow registers. A version that renames or drops one is reported instead of
# being accepted and then producing a different command in the TUI.
certipy_find_options=(-dc-ip -u -p -dc-only -ldap-scheme -ldap-port -json -text -output -enabled -vulnerable)

certipy_reports_adcs() {
  local executable="$1" help
  help="$("$executable" --help 2>&1)" || return 1
  [[ "$help" == *"$certipy_adcs_marker"* ]]
}

certipy_find_help() {
  local executable="$1" help
  help="$("$executable" find --help 2>&1)" || return 1
  # The shipped find subcommand describes itself in terms of these components;
  # the shorter "Enumerate AD CS" phrase appears only in the top-level action
  # list, so it cannot be used to recognise the subcommand's own help.
  [[ "$help" == *"$certipy_adcs_marker"* ]] || return 1
  local option
  for option in "${certipy_find_options[@]}"; do
    [[ "$help" == *"$option"* ]] || return 1
  done
  printf '%s\n' "$help"
}

certipy_candidate() {
  local candidate path
  for candidate in certipy-ad certipy; do
    path="$(command -v "$candidate" 2>/dev/null)" || continue
    if [[ -n "$path" ]] && certipy_reports_adcs "$path"; then
      printf '%s\n' "$path"
      return 0
    fi
  done
  return 1
}

# certipy_functional accepts only an AD CS Certipy that documents the arguments
# PwnFlow passes; anything else is reported rather than silently reused.
certipy_functional() {
  local executable="$1"
  certipy_find_help "$executable" >/dev/null
}

# certipy_banner reports the first line of the version banner. Certipy writes it
# to standard error, so both streams are captured, and the line is cut in the
# shell so the detection path needs nothing beyond the interpreter.
certipy_banner() {
  local banner
  banner="$("$1" --version 2>&1 || true)"
  printf '%s\n' "${banner%%$'\n'*}"
}

install_certipy() {
  local executable
  if executable="$(certipy_candidate)"; then
    if ! certipy_functional "$executable"; then
      echo "Certipy is present at ${executable} but does not document the find arguments PwnFlow uses; refusing to replace or upgrade it automatically." >&2
      certipy_status="Failed (${executable} is not a supported Certipy version)"
      return 1
    fi
    echo "Certipy already installed and functional: $(certipy_banner "$executable") at ${executable}"
    certipy_status="Already installed"
    return 0
  fi
  if command -v certipy-ad >/dev/null 2>&1; then
    echo "certipy-ad is installed but does not identify itself as AD CS Certipy; refusing to replace or upgrade it automatically." >&2
    certipy_status="Failed (the installed certipy-ad is not AD CS Certipy)"
    return 1
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "No supported package manager found. Install Certipy (AD CS) with Kali's certipy-ad package." >&2
    certipy_status="Failed (APT is unavailable)"
    return 1
  fi
  echo "Installing missing Certipy (AD CS) from the Kali APT repository."
  if ! run_apt update; then
    certipy_status="Failed (APT update failed)"
    return 1
  fi
  if ! run_apt_install certipy-ad; then
    certipy_status="Failed (APT transaction not applied)"
    return 1
  fi
  if ! executable="$(certipy_candidate)"; then
    echo "APT completed but no functional AD CS Certipy executable was found on PATH (expected certipy-ad)." >&2
    certipy_status="Failed (APT completed without a functional certipy-ad)"
    return 1
  fi
  if ! certipy_functional "$executable"; then
    echo "APT installed ${executable}, but it does not document the find arguments PwnFlow uses." >&2
    certipy_status="Failed (${executable} does not support the required find arguments)"
    return 1
  fi
  certipy_status="Installed"
  echo "Certipy installed and functional at ${executable}: $(certipy_banner "$executable")"
}

print_summary() {
  echo ""
  echo "Installation summary:"
  echo "  NetExec: ${netexec_status}"
  echo "  RustHound-CE: ${rusthound_ce_status}"
  echo "  Cargo: ${cargo_status}"
  echo "  Certipy: ${certipy_status}"
}

if [[ ${install_netexec_requested} -eq 1 ]]; then
  if ! install_netexec; then
    netexec_status="Failed"
    print_summary
    exit 1
  fi
fi
if [[ ${install_rusthound_ce} -eq 1 ]]; then
  if ! install_rusthound_ce; then
    # install_rusthound_ce records the specific failure reason; only fall back to a
    # generic status when it returned early without setting one.
    if [[ ${rusthound_ce_status} == "Skipped" ]]; then
      rusthound_ce_status="Failed"
    fi
    print_summary
    exit 1
  fi
fi
if [[ ${install_certipy} -eq 1 ]]; then
  if ! install_certipy; then
    if [[ ${certipy_status} == "Skipped" ]]; then
      certipy_status="Failed"
    fi
    print_summary
    exit 1
  fi
fi
print_summary
