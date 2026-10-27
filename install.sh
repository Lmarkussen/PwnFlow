#!/usr/bin/env bash
set -euo pipefail

install_rusthound_ce=0
install_netexec_requested=0
install_certipy=0
install_sccmhunter=0
install_pxethief=0
install_networkhound=0
install_relayking=0
install_sccmsecrets=0
install_mssqlrelay=0
install_mssqlpwner=0
install_gpoparser=0
install_ghostspn=0
install_masscan=0
install_failures=0
install_all_requested=0
netexec_status="Skipped"
rusthound_ce_status="Skipped"
certipy_status="Skipped"
sccmhunter_status="Skipped"
pxethief_status="Skipped"
networkhound_status="Skipped"
relayking_status="Skipped"
sccmsecrets_status="Skipped"
mssqlrelay_status="Skipped"
mssqlpwner_status="Skipped"
gpoparser_status="Skipped"
ghostspn_status="Skipped"
masscan_status="Skipped"
cargo_status="Skipped"
sudo_authenticated=0
installer_os_release="${PWNFlow_OS_RELEASE:-/etc/os-release}"
installer_distribution=""
installer_id=""
installer_id_like=""
for argument in "$@"; do
  case "$argument" in
    --with-netexec) install_netexec_requested=1 ;;
    --with-rusthound-ce) install_rusthound_ce=1 ;;
    --with-certipy) install_certipy=1 ;;
    --with-sccmhunter) install_sccmhunter=1 ;;
    --with-pxethief) install_pxethief=1 ;;
    --with-networkhound) install_networkhound=1 ;;
    --with-relayking) install_relayking=1 ;;
    --with-sccmsecrets) install_sccmsecrets=1 ;;
    --with-mssqlrelay) install_mssqlrelay=1 ;;
    --with-mssqlpwner) install_mssqlpwner=1 ;;
    --with-gpoparser) install_gpoparser=1 ;;
    --with-ghostspn) install_ghostspn=1 ;;
    --with-masscan) install_masscan=1 ;;
    --with-bloodhound|--with-bloodhound-ce|--with-bloodhound-python)
      echo "This installer no longer installs BloodHound CE or BloodHound CE Python; ${argument} is retired." >&2
      echo "BloodHound CE is the separate graph application and is installed with its official application procedure." >&2
      echo "RustHound-CE is the supported BloodHound CE collector: use --with-rusthound-ce." >&2
      exit 2
      ;;
    --help|-h)
      echo "Usage: $0 [--with-netexec] [--with-rusthound-ce] [--with-certipy] [--with-sccmhunter] [--with-pxethief] [--with-networkhound] [--with-relayking] [--with-sccmsecrets] [--with-mssqlrelay] [--with-mssqlpwner] [--with-gpoparser] [--with-ghostspn] [--with-masscan]"
      echo ""
      echo "Installs supported dependencies on Arch Linux or Kali Linux: NetExec, RustHound-CE, and"
      echo "Certipy (AD CS enumeration, from the certipy-ad package), plus the SCCM"
      echo "tooling SCCMhunter and PXEThief, and the network assessment tools"
      echo "NetworkHound, RelayKing, and Masscan. NetworkHound and RelayKing are source checkouts with their own virtual"
      echo "environments. No shell activation is required."
      echo "Supported targets: Arch Linux (pacman) and Kali Linux (APT)."
      exit 0
      ;;
    *) echo "Unknown option: $argument" >&2; exit 2 ;;
  esac
done

detect_distribution() {
  if [[ ! -r "$installer_os_release" ]]; then
    echo "Cannot read ${installer_os_release}; distribution detection requires /etc/os-release." >&2
    return 1
  fi
  while IFS='=' read -r key value; do
    value="${value%\"}"; value="${value#\"}"
    value="${value%\'}"; value="${value#\'}"
    case "$key" in
      ID) installer_id="${value,,}" ;;
      ID_LIKE) installer_id_like="${value,,}" ;;
    esac
  done < "$installer_os_release"
  case "$installer_id" in
    kali) installer_distribution="kali" ;;
    arch|omarchy) installer_distribution="arch" ;;
    *)
      echo "Unsupported distribution (ID=${installer_id:-unknown}, ID_LIKE=${installer_id_like:-none}). Supported targets are Arch Linux and Kali Linux." >&2
      return 1
      ;;
  esac
  echo "Detected distribution: ${installer_distribution} (ID=${installer_id}${installer_id_like:+, ID_LIKE=${installer_id_like}})"
}

if [[ $# -gt 0 && " $* " == *" --help "* ]]; then
  : # Help remains usable without requiring a supported host.
else
  detect_distribution || exit 1
fi

# The standalone default checks and installs every supported dependency.
# Explicit flags remain available for selective tool-group installation.
if [[ $# -eq 0 ]]; then
  install_all_requested=1
  install_netexec_requested=1
  install_rusthound_ce=1
  install_certipy=1
  install_sccmhunter=1
  install_pxethief=1
  install_networkhound=1
  install_relayking=1
  install_sccmsecrets=1
  install_mssqlrelay=1
  install_mssqlpwner=1
  install_gpoparser=1
  install_ghostspn=1
  install_masscan=1
fi

ensure_sudo_authenticated() {
  if [[ ${EUID} -eq 0 ]]; then
    return 0
  fi
  if [[ ${sudo_authenticated} -eq 1 ]]; then
    if sudo -n -v >/dev/null 2>&1; then
      return 0
    fi
    echo "sudo privilege expired during dependency installation; authenticate again." >&2
    sudo_authenticated=0
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    echo "System package installation requires sudo, but sudo is unavailable." >&2
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
  run_apt -s install "${packages[@]}" || { echo "APT could not resolve the requested packages: ${packages[*]}" >&2; return 1; }
  if ! confirm_install "Apply this APT transaction?"; then
    echo "APT transaction cancelled." >&2
    return 1
  fi
  run_apt install -y "${packages[@]}"
}

arch_package_for() {
  case "$1" in
    build-essential) echo base-devel ;;
    pkg-config) echo pkgconf ;;
    libclang-dev) echo clang ;;
    libgssapi-krb5-2|libkrb5-dev) echo krb5 ;;
    libsasl2-modules-gssapi-mit) echo cyrus-sasl ;;
    python3) echo python ;;
    python3-venv) echo python ;;
    python3-pip) echo python-pip ;;
    python3-pipx|pipx) echo python-pipx ;;
    golang-go) echo go ;;
    cargo) echo rust ;;
    *) echo "$1" ;;
  esac
}

map_packages() {
  local package
  for package in "$@"; do
    if [[ "$installer_distribution" == arch ]]; then
      arch_package_for "$package"
    else
      printf '%s\n' "$package"
    fi
  done
}

package_manager_available() {
  if [[ "$installer_distribution" == arch ]]; then command -v pacman >/dev/null 2>&1
  else command -v apt-get >/dev/null 2>&1
  fi
}

run_system_update() {
  if [[ "$installer_distribution" == kali ]]; then
    run_apt update
  else
    echo "Using the current pacman sync database; no partial system upgrade will be run."
    echo "If package resolution fails, run 'sudo pacman -Syu' and rerun this installer."
  fi
}

run_system_install() {
  local packages=() package
  while IFS= read -r package; do
    [[ -n "$package" ]] || continue
    case " ${packages[*]} " in *" ${package} "*) ;; *) packages+=("$package") ;; esac
  done < <(map_packages "$@")
  ((${#packages[@]})) || return 0
  if [[ "$installer_distribution" == kali ]]; then
    run_apt_install "${packages[@]}"
    return
  fi
  echo "Pacman preview for: ${packages[*]}"
  pacman -Sp --needed --print-format '%n %v' "${packages[@]}" || { echo "Pacman could not resolve required packages: ${packages[*]}" >&2; return 1; }
  if ! confirm_install "Apply this pacman transaction?"; then
    echo "Pacman transaction cancelled." >&2
    return 1
  fi
  if [[ ${EUID} -eq 0 ]]; then
    pacman --sync --needed --noconfirm "${packages[@]}" || { echo "Pacman failed to install: ${packages[*]}" >&2; return 1; }
  else
    ensure_sudo_authenticated || return 1
    if ! sudo -n pacman --sync --needed --noconfirm "${packages[@]}"; then
      if ! sudo -n -v >/dev/null 2>&1; then
        echo "sudo privilege expired before pacman could apply the transaction; authenticate again." >&2
        sudo_authenticated=0
        ensure_sudo_authenticated || return 1
        sudo -n pacman --sync --needed --noconfirm "${packages[@]}" || { echo "Pacman failed to install: ${packages[*]}" >&2; return 1; }
      else
        echo "Pacman failed to install: ${packages[*]}" >&2
        return 1
      fi
    fi
  fi
  echo "Pacman installed required packages: ${packages[*]}"
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
  if [[ "$installer_distribution" == arch ]]; then
    command -v pacman >/dev/null 2>&1 && pacman -Q "$(arch_package_for "$1")" >/dev/null 2>&1
  else
    command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
  fi
}

version_at_least() {
  local actual="$1" required="$2" actual_major actual_minor required_major required_minor
  actual_major="${actual%%.*}"; actual_minor="${actual#*.}"; actual_minor="${actual_minor%%.*}"
  required_major="${required%%.*}"; required_minor="${required#*.}"; required_minor="${required_minor%%.*}"
  [[ "$actual_major" =~ ^[0-9]+$ && "$actual_minor" =~ ^[0-9]+$ && "$required_major" =~ ^[0-9]+$ && "$required_minor" =~ ^[0-9]+$ ]] || return 1
  (( actual_major > required_major || (actual_major == required_major && actual_minor >= required_minor) ))
}

ensure_project_build_tools() {
  local required_go actual_go="" go_output make_output make_line missing=() key value
  echo "Checking Go (required by go.mod) and Make (required by the documented build)."
  while read -r key value _; do [[ "$key" == go ]] && { required_go="$value"; break; }; done < go.mod
  [[ -n "$required_go" ]] || required_go="1.22"
  if command -v go >/dev/null 2>&1; then
    go_output="$(go version 2>/dev/null)"; go_output="${go_output#* go}"
    actual_go="${go_output%% *}"; actual_go="${actual_go%.*}"
    if ! version_at_least "$actual_go" "$required_go"; then
      echo "Go ${actual_go:-unknown} is installed but PwnFlow requires Go ${required_go} or newer. Update your managed Go toolchain, then rerun; the installer will not replace it." >&2
      return 1
    fi
    echo "Go: already available ($(go version))."
  else
    echo "Go: missing; installation required."
    missing+=(golang-go)
  fi
  if command -v make >/dev/null 2>&1 && make_output="$(make --version 2>/dev/null)" && [[ -n "$make_output" ]]; then
    IFS= read -r make_line <<< "$make_output"
    echo "Make: already available (${make_line})."
  else
    echo "Make: missing or unusable; installation required."
    missing+=(make)
  fi
  if ((${#missing[@]})); then
    package_manager_available || { echo "Cannot install ${missing[*]}: selected package manager is unavailable." >&2; return 1; }
    run_system_update || { echo "Package database update failed; could not install ${missing[*]}." >&2; return 1; }
    run_system_install "${missing[@]}" || { echo "Package installation failed for ${missing[*]}; install them manually and rerun." >&2; return 1; }
  fi
  command -v go >/dev/null && command -v make >/dev/null || { echo "Go or Make is still unavailable after installation." >&2; return 1; }
  go_output="$(go version 2>/dev/null)"; go_output="${go_output#* go}"
  actual_go="${go_output%% *}"; actual_go="${actual_go%.*}"
  version_at_least "$actual_go" "$required_go" || { echo "Installed Go ${actual_go:-unknown} is below required ${required_go}. Update Go manually." >&2; return 1; }
  make_output="$(make --version 2>/dev/null)" || { echo "Make remains unusable after installation." >&2; return 1; }
  [[ -n "$make_output" ]] || { echo "Make remains unusable after installation." >&2; return 1; }
  IFS= read -r make_line <<< "$make_output"
  echo "Build prerequisites verified: Go ${actual_go}, ${make_line}."
}

ensure_pipx() {
  echo "Checking pipx and Python 3."
  ensure_python_venv || return 1
  if ! command -v pipx >/dev/null 2>&1 || ! pipx --version >/dev/null 2>&1; then
    echo "pipx: missing or unusable; installing it from the distribution repository."
    package_manager_available || { echo "Cannot install pipx: package manager unavailable." >&2; return 1; }
    run_system_update && run_system_install pipx || { echo "pipx installation failed; install pipx using ${installer_distribution}'s package manager." >&2; return 1; }
  else
    echo "pipx: already available ($(pipx --version))."
  fi
  command -v pipx >/dev/null 2>&1 && pipx --version >/dev/null 2>&1 || { echo "pipx did not become available on PATH after installation." >&2; return 1; }
}

ensure_git() {
  if command -v git >/dev/null 2>&1 && git --version >/dev/null 2>&1; then
    echo "Git: already available ($(git --version))."
    return 0
  fi
  echo "Git: missing; installation required."
  package_manager_available || { echo "Cannot install git: selected package manager is unavailable." >&2; return 1; }
  run_system_update && run_system_install git || { echo "Git installation failed; install git manually and rerun." >&2; return 1; }
  command -v git >/dev/null 2>&1 && git --version >/dev/null 2>&1 || { echo "Git remains unavailable after installation." >&2; return 1; }
}

ensure_python_venv() {
  if ! command -v python3 >/dev/null 2>&1 || ! python3 -m venv --help >/dev/null 2>&1; then
    echo "Python 3 with venv support is missing; installation required."
    package_manager_available || { echo "Cannot install Python: package manager unavailable." >&2; return 1; }
    run_system_update && run_system_install python3 python3-venv || { echo "Python 3 installation failed; install Python 3 with venv support manually." >&2; return 1; }
  else
    echo "Python 3: already available ($(python3 --version))."
  fi
  command -v python3 >/dev/null 2>&1 && python3 -m venv --help >/dev/null 2>&1 || { echo "Python 3 venv support is still unavailable after installation." >&2; return 1; }
}

ensure_cargo_dependencies() {
  local missing=()
  if ! command -v cargo >/dev/null 2>&1 || ! cargo --version >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1 || ! rustc --version >/dev/null 2>&1; then
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
    echo "Rust toolchain available: $(rustc --version 2>/dev/null); $(cargo --version 2>/dev/null)"
    return 0
  fi
  if ! package_manager_available; then
    echo "RustHound-CE requires Cargo and build dependencies: ${missing[*]}, but the selected package manager is unavailable." >&2
    return 1
  fi
  run_system_update || { echo "Package database update failed." >&2; return 1; }
  run_system_install "${missing[@]}" || { echo "Could not install RustHound-CE prerequisites: ${missing[*]}" >&2; return 1; }
  if ! command -v cargo >/dev/null 2>&1 || ! cargo --version >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1 || ! rustc --version >/dev/null 2>&1; then
    echo "Package installation completed but did not provide a functional Rust/Cargo toolchain." >&2
    return 1
  fi
  cargo_status="Installed"
  refresh_cargo_path
  echo "Rust toolchain available: $(rustc --version 2>/dev/null); $(cargo --version 2>/dev/null)"
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
  if [[ "$installer_distribution" == arch ]]; then
    ensure_pipx || return 1
    command -v git >/dev/null 2>&1 || { run_system_update && run_system_install git || return 1; }
    local arch_build_packages=()
    if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then arch_build_packages+=(rust); fi
    if ! command -v cc >/dev/null 2>&1 || ! command -v gcc >/dev/null 2>&1; then arch_build_packages+=(base-devel); fi
    if ((${#arch_build_packages[@]})); then
      echo "NetExec build prerequisites missing: ${arch_build_packages[*]}"
      run_system_install "${arch_build_packages[@]}" || { echo "Could not install the Rust/C build prerequisites needed for NetExec." >&2; return 1; }
    fi
    echo "Installing NetExec with pipx in an isolated environment."
    pipx install git+https://github.com/Pennyw0rth/NetExec || return 1
    netexec_functional || { echo "NetExec installation did not provide a working nxc --help capability" >&2; return 1; }
    netexec_status="Installed"
    echo "NetExec installed and functional: $(command -v nxc)"
    return 0
  fi
  if ! package_manager_available; then
    echo "APT is unavailable; install NetExec from Kali's APT repository." >&2
    return 1
  fi
  echo "Installing missing NetExec from the Kali APT repository."
  run_system_update || { echo "APT update failed; NetExec was not installed." >&2; return 1; }
  run_system_install netexec || { echo "NetExec package installation failed." >&2; return 1; }
  netexec_functional || { echo "NetExec installation did not provide a working nxc --help capability" >&2; return 1; }
  echo "NetExec installed: $(nxc --help 2>&1 | head -n 1)"
  netexec_status="Installed"
}

masscan_functional() {
  local version
  command -v masscan >/dev/null 2>&1 || return 1
  version="$(masscan --version 2>&1 || true)"
  [[ "${version,,}" == *masscan* ]]
}

masscan_version() {
  local version
  if [[ "$installer_distribution" == arch ]]; then
    version="$(pacman -Q masscan 2>/dev/null || true)"
  else
    version="$(dpkg-query -W -f='${Version}' masscan 2>/dev/null || true)"
  fi
  if [[ -z "${version}" ]]; then
    version="version unavailable"
  fi
  printf '%s\n' "${version%%$'\n'*}"
}

install_masscan() {
  if masscan_functional; then
    echo "Masscan already installed and functional: $(masscan_version)"
    masscan_status="Already installed"
    return 0
  fi
  if ! package_manager_available; then
    echo "The selected package manager is unavailable; install Masscan manually." >&2
    return 1
  fi
  echo "Installing missing Masscan from the ${installer_distribution} repository."
  run_system_update || { masscan_status="Failed (package database update failed)"; echo "Package database update failed; Masscan was not installed." >&2; return 1; }
  run_system_install masscan || { masscan_status="Failed (package install or sudo authentication failed)"; echo "Masscan package installation failed. Reauthenticate if sudo expired, then rerun ./install.sh --with-masscan." >&2; return 1; }
  masscan_functional || { masscan_status="Failed (package installed but executable verification failed)"; echo "Masscan installation did not provide a working masscan --version capability" >&2; return 1; }
  echo "Masscan installed: $(masscan_version)"
  masscan_status="Installed"
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
  if [[ "$installer_distribution" == arch ]]; then
    ensure_pipx || return 1
    command -v git >/dev/null 2>&1 || { run_system_update && run_system_install git || return 1; }
    echo "Installing Certipy (AD CS) with pipx in an isolated environment."
    if ! pipx install certipy-ad; then certipy_status="Failed (pipx install failed)"; return 1; fi
  else
    if ! package_manager_available; then
      echo "APT is unavailable; install Certipy (AD CS) manually." >&2
      certipy_status="Failed (APT unavailable)"
      return 1
    fi
    echo "Installing missing Certipy (AD CS) from the Kali APT repository."
    if ! run_system_update || ! run_system_install certipy-ad; then
      certipy_status="Failed (APT transaction failed)"
      return 1
    fi
  fi
  if ! executable="$(certipy_candidate)"; then
    echo "Installation completed but no functional AD CS Certipy executable was found on PATH." >&2
    certipy_status="Failed (installation did not provide functional Certipy)"
    return 1
  fi
  if ! certipy_functional "$executable"; then
    echo "The package manager installed ${executable}, but it does not document the find arguments PwnFlow uses." >&2
    certipy_status="Failed (${executable} does not support the required find arguments)"
    return 1
  fi
  certipy_status="Installed"
  echo "Certipy installed and functional at ${executable}: $(certipy_banner "$executable")"
}

# SCCMhunter and PXEThief are source checkouts with their own virtual
# environment. They are invoked through that environment's interpreter by path, so
# nothing depends on shell activation, and PwnFlow resolves the same roots.
pwnflow_tools_root() {
  if [[ -n "${PWNFLOW_TOOLS_DIR:-}" ]]; then
    printf '%s\n' "${PWNFLOW_TOOLS_DIR}"
  elif [[ -n "${XDG_DATA_HOME:-}" ]]; then
    printf '%s/pwnflow/tools\n' "${XDG_DATA_HOME}"
  else
    printf '%s/.local/share/pwnflow/tools\n' "${HOME}"
  fi
}

sccmhunter_root() { printf '%s/sccmhunter\n' "$(pwnflow_tools_root)"; }
pxethief_root() { printf '%s/PXEThief\n' "$(pwnflow_tools_root)"; }
networkhound_root() { printf '%s/NetworkHound\n' "$(pwnflow_tools_root)"; }
relayking_root() { printf '%s/RelayKing\n' "$(pwnflow_tools_root)"; }
sccmsecrets_root() { printf '%s/SCCMSecrets\n' "$(pwnflow_tools_root)"; }

install_pipx_source() {
  local package="$1" url="$2" executable="$3" status_name="$4" expected="$5" current help
  local executable_path
  executable_path="$(resolve_user_executable "${executable}")"
  if [[ -n "${executable_path}" ]] && "${executable_path}" --help >/dev/null 2>&1; then
    printf -v "${status_name}" '%s' "Already installed"
    return 0
  fi
  if ! ensure_pipx; then
    printf -v "${status_name}" '%s' "Failed (pipx unavailable)"
    return 1
  fi
  prepend_path_once "${HOME}/.local/bin"
  echo "Installing ${package} in an isolated pipx environment."
  if ! pipx install "${url}"; then
    printf -v "${status_name}" '%s' "Failed (pipx install failed)"
    return 1
  fi
  executable_path="$(resolve_user_executable "${executable}")"
  if [[ -z "${executable_path}" ]]; then
    echo "${package} installed but its executable was not found in PATH or ~/.local/bin." >&2
    printf -v "${status_name}" '%s' "Failed (entry point not found)"
    return 1
  fi
  help="$(${executable_path} --help 2>&1 || true)"
  if [[ -n "${expected}" && "${help}" != *"${expected}"* ]]; then
    echo "${package} installed but its help output did not contain ${expected@Q}." >&2
    printf -v "${status_name}" '%s' "Failed (capability probe failed)"
    return 1
  fi
  current="$(printf '%s\n' "${help}" | head -n 1)"
  echo "${package} installed: ${current}"
  printf -v "${status_name}" '%s' "Installed"
}

resolve_user_executable() {
  local executable="$1" candidate
  candidate="$(command -v "${executable}" 2>/dev/null || true)"
  if [[ -n "${candidate}" ]]; then
    printf '%s\n' "${candidate}"
    return 0
  fi
  if [[ -x "${HOME}/.local/bin/${executable}" ]]; then
    printf '%s\n' "${HOME}/.local/bin/${executable}"
    return 0
  fi
  return 1
}

install_sccmsecrets() {
  local root="$(sccmsecrets_root)"
  if [[ -x "${root}/.venv/bin/python3" && -f "${root}/SCCMSecrets.py" ]] && "${root}/.venv/bin/python3" "${root}/SCCMSecrets.py" --help >/dev/null 2>&1; then
    sccmsecrets_status="Already installed"
    echo "SCCMSecrets checkout already present at ${root} (live workflows remain disabled)."
    return 0
  fi
  ensure_git || { sccmsecrets_status="Failed (git unavailable)"; return 1; }
  mkdir -p "$(dirname "${root}")"
  git clone --branch master https://github.com/synacktiv/SCCMSecrets.git "${root}" || { sccmsecrets_status="Failed (git clone failed)"; return 1; }
  ensure_checkout_environment "${root}"
  "${root}/.venv/bin/python3" "${root}/SCCMSecrets.py" --help >/dev/null
  sccmsecrets_status="Installed"
}

# checkout_interpreter reports the interpreter to use for a checkout, or nothing.
checkout_interpreter() {
  local root="$1" interpreter="${1}/.venv/bin/python3"
  if [[ -x "${interpreter}" && -f "${root}/${2}" ]]; then
    printf '%s\n' "${interpreter}"
  fi
}

# checkout_functional requires a usable interpreter, the entry script, and a
# working help command: a present but damaged environment is not "installed".
checkout_functional() {
  local root="$1" script="$2" interpreter
  interpreter="$(checkout_interpreter "${root}" "${script}")" || return 1
  [[ -n "${interpreter}" ]] || return 1
  "${interpreter}" "${root}/${script}" --help >/dev/null 2>&1
}

# ensure_checkout_environment creates the virtual environment and installs the
# checkout's requirements, reporting whatever the tools say on failure.
ensure_checkout_environment() {
  local root="$1" diagnostics
  if [[ ! -x "${root}/.venv/bin/python3" ]]; then
    if ! ensure_python_venv; then return 1; fi
    echo "Creating the virtual environment in ${root}/.venv"
    if ! python3 -m venv "${root}/.venv"; then
      echo "python3 -m venv failed for ${root}." >&2
      return 1
    fi
  fi
  if [[ ! -f "${root}/requirements.txt" ]]; then
    echo "${root} has no requirements.txt; the checkout looks incomplete." >&2
    return 1
  fi
  echo "Installing the Python requirements of ${root} into its own environment."
  if ! diagnostics="$("${root}/.venv/bin/pip3" install -r "${root}/requirements.txt" 2>&1)"; then
    printf '%s\n' "${diagnostics}" >&2
    return 1
  fi
  return 0
}

# sccmhunter_workflow_supported requires the checkout to document the find options
# the discovery workflow uses. SCCMhunter lists its subcommands at the top level and
# the find options on the find subcommand, so this validates the same thing the
# runtime checks before it runs a discovery.
sccmhunter_workflow_supported() {
  local root="$1" interpreter help option
  interpreter="$(checkout_interpreter "${root}" sccmhunter.py)" || return 1
  [[ -n "${interpreter}" ]] || return 1
  help="$("${interpreter}" "${root}/sccmhunter.py" find --help 2>&1)" || return 1
  for option in -u -p -d -dc-ip -ldaps; do
    [[ "$help" == *"$option"* ]] || return 1
  done
  return 0
}

install_sccmhunter() {
  local root interpreter
  root="$(sccmhunter_root)"
  interpreter="$(checkout_interpreter "${root}" sccmhunter.py)"
  if [[ -n "${interpreter}" ]] && checkout_functional "${root}" sccmhunter.py; then
    # Existence and the workflow are checked together, so the installer never calls a
    # tool functional that the runtime would refuse to run.
    if ! sccmhunter_workflow_supported "${root}"; then
      echo "SCCMhunter at ${root} runs, but does not document the find options the PwnFlow discovery module uses; it is not usable as installed." >&2
      sccmhunter_status="Failed (the installed SCCMhunter does not document the find options PwnFlow uses)"
      return 1
    fi
    echo "SCCMhunter already installed and functional: ${interpreter} ${root}/sccmhunter.py"
    sccmhunter_status="Already installed"
    return 0
  fi
  if command -v sccmhunter >/dev/null 2>&1 && sccmhunter --help >/dev/null 2>&1; then
    echo "SCCMhunter already installed and functional: $(command -v sccmhunter)"
    sccmhunter_status="Already installed"
    return 0
  fi
  if [[ -d "${root}" ]]; then
    if [[ ! -f "${root}/sccmhunter.py" ]]; then
      echo "${root} exists but is not an SCCMhunter checkout; move it aside and re-run." >&2
      sccmhunter_status="Failed (${root} is not an SCCMhunter checkout)"
      return 1
    fi
    echo "Reusing the existing SCCMhunter checkout at ${root}."
  else
    if ! ensure_git; then
      echo "git is unavailable; SCCMhunter is installed from its repository." >&2
      sccmhunter_status="Failed (git is unavailable)"
      return 1
    fi
    echo "Cloning SCCMhunter into ${root}."
    mkdir -p "$(dirname "${root}")"
    if ! git clone https://github.com/garrettfoster13/sccmhunter.git "${root}"; then
      sccmhunter_status="Failed (git clone failed)"
      return 1
    fi
  fi
  if ! ensure_checkout_environment "${root}"; then
    sccmhunter_status="Failed (the Python environment could not be prepared)"
    return 1
  fi
  if ! checkout_functional "${root}" sccmhunter.py; then
    echo "SCCMhunter was installed at ${root} but does not run; check the output above." >&2
    sccmhunter_status="Failed (${root}/.venv/bin/python3 ${root}/sccmhunter.py failed)"
    return 1
  fi
  if ! sccmhunter_workflow_supported "${root}"; then
    echo "SCCMhunter was installed at ${root} but does not document the find options PwnFlow uses." >&2
    sccmhunter_status="Failed (the installed SCCMhunter does not document the find options PwnFlow uses)"
    return 1
  fi
  sccmhunter_status="Installed"
  echo "SCCMhunter installed and functional: $(checkout_interpreter "${root}" sccmhunter.py) ${root}/sccmhunter.py"
}

# pxethief_verified reports the recorded pull/11 revision when the checkout is at
# exactly that commit. The marker is written only after a successful fetch and
# checkout, so a checkout on another revision is never treated as verified.
pxethief_verified() {
  local root="$1" recorded head
  [[ -f "${root}/.pwnflow-pr11" ]] || return 1
  # Read in the shell so verification needs nothing beyond the interpreter.
  IFS= read -r recorded < "${root}/.pwnflow-pr11" || return 1
  [[ -n "${recorded}" ]] || return 1
  head="$(git -C "${root}" rev-parse HEAD 2>/dev/null)" || return 1
  [[ "${head}" == "${recorded}" ]]
}

install_pxethief() {
  local root pr_head diagnostics
  root="$(pxethief_root)"
  if pxethief_verified "${root}" && checkout_functional "${root}" pxethief.py; then
    local recorded
    IFS= read -r recorded < "${root}/.pwnflow-pr11"
    echo "PXEThief already installed at the required revision: ${recorded} in ${root}"
    pxethief_status="Already installed"
    return 0
  fi
  if [[ -f "${root}/.pwnflow-pr11" ]]; then
    echo "The PXEThief checkout at ${root} is incomplete or no longer at its recorded revision; re-fetching pull/11."
  fi
  if ! ensure_git; then
    echo "git is unavailable; PXEThief is installed from its repository." >&2
    pxethief_status="Failed (git is unavailable)"
    return 1
  fi
  if [[ -d "${root}/.git" ]]; then
    echo "Reusing the existing PXEThief checkout at ${root}."
  elif [[ -e "${root}" ]]; then
    echo "${root} exists but is not a git checkout; move it aside and re-run." >&2
    pxethief_status="Failed (${root} is not a git checkout)"
    return 1
  else
    echo "Cloning PXEThief into ${root}."
    mkdir -p "$(dirname "${root}")"
    if ! git clone https://github.com/MWR-CyberSec/PXEThief.git "${root}"; then
      pxethief_status="Failed (git clone failed)"
      return 1
    fi
  fi
  # The operational version is the pull request, never the default branch.
  if ! diagnostics="$(git -C "${root}" fetch origin pull/11/head:pr-11 2>&1)"; then
    printf '%s\n' "${diagnostics}" >&2
    echo "The required pull/11 revision could not be fetched; no other revision was substituted." >&2
    pxethief_status="Failed (pull/11 could not be fetched)"
    return 1
  fi
  if ! diagnostics="$(git -C "${root}" checkout pr-11 2>&1)"; then
    printf '%s\n' "${diagnostics}" >&2
    pxethief_status="Failed (pull/11 could not be checked out)"
    return 1
  fi
  if ! pr_head="$(git -C "${root}" rev-parse HEAD 2>/dev/null)"; then
    echo "The pull/11 checkout has no readable commit." >&2
    pxethief_status="Failed (the pull/11 revision could not be read)"
    return 1
  fi
  printf '%s\n' "${pr_head}" > "${root}/.pwnflow-pr11"
  chmod 600 "${root}/.pwnflow-pr11"
  if ! ensure_checkout_environment "${root}"; then
    pxethief_status="Failed (the Python environment could not be prepared)"
    return 1
  fi
  if ! checkout_functional "${root}" pxethief.py; then
    echo "PXEThief was installed at ${root} but does not run; check the output above." >&2
    pxethief_status="Failed (${root}/.venv/bin/python3 ${root}/pxethief.py failed)"
    return 1
  fi
  pxethief_status="Installed"
  echo "PXEThief installed at pull/11 (${pr_head}) in ${root}"
}

# NetworkHound and RelayKing are upstream checkouts with their own virtual
# environments, installed the same way SCCMhunter and PXEThief are. Neither is
# pinned to a revision: PwnFlow checks that the installed checkout documents the
# options its registrations use, so a newer upstream revision is accepted when it
# still supports them, and a checkout that does not is reported rather than used.
# checkout_help prints a checkout's usage text. The exit status is deliberately not
# the test: several tools in this family print their usage and then exit non-zero,
# so what matters is the text, which is what checkout_documents matches against.
checkout_help() {
  local root="$1" script="$2" flag="${3:---help}" interpreter output
  interpreter="$(checkout_interpreter "${root}" "${script}")" || return 1
  [[ -n "${interpreter}" ]] || return 1
  output="$("${interpreter}" "${root}/${script}" "${flag}" 2>&1)" || true
  [[ -n "${output}" ]] || return 1
  printf '%s\n' "${output}"
  return 0
}

checkout_documents() {
  local root="$1" script="$2" flag="$3" help
  shift 3
  help="$(checkout_help "${root}" "${script}" "${flag}")" || return 1
  local option
  for option in "$@"; do
    [[ "${help}" == *"${option}"* ]] || return 1
  done
  return 0
}

# recorded_revision prints the checkout's revision, which is what the report and
# the runtime detection quote. A checkout without git metadata is still usable; the
# revision is then simply unknown.
checkout_revision() {
  local root="$1"
  git -C "${root}" rev-parse --short HEAD 2>/dev/null || printf 'unknown\n'
}

install_networkhound() {
  local root revision diagnostics
  root="$(networkhound_root)"
  # The options PwnFlow builds: the LDAP topology collection, and the explicitly
  # scoped service validation that only runs on an operator-supplied scope.
  local required=(--dc --domain --user --password --output --port-scan --networks --scan-threads)
  if checkout_documents "${root}" NetworkHound.py --help "${required[@]}"; then
    revision="$(checkout_revision "${root}")"
    echo "NetworkHound already installed and functional: ${revision} in ${root}"
    networkhound_status="Already installed"
    return 0
  fi
  if ! ensure_git; then
    echo "git is unavailable; NetworkHound is installed from its repository." >&2
    networkhound_status="Failed (git is unavailable)"
    return 1
  fi
  if [[ -d "${root}/.git" ]]; then
    echo "Reusing the existing NetworkHound checkout at ${root}."
  elif [[ -e "${root}" ]]; then
    echo "${root} exists but is not a git checkout; move it aside and re-run." >&2
    networkhound_status="Failed (${root} is not a git checkout)"
    return 1
  else
    echo "Cloning NetworkHound into ${root}."
    mkdir -p "$(dirname "${root}")"
    if ! git clone https://github.com/MorDavid/NetworkHound.git "${root}"; then
      networkhound_status="Failed (git clone failed)"
      return 1
    fi
  fi
  if ! ensure_checkout_environment "${root}"; then
    networkhound_status="Failed (the Python environment could not be prepared)"
    return 1
  fi
  if ! checkout_documents "${root}" NetworkHound.py --help "${required[@]}"; then
    echo "The NetworkHound checkout at ${root} does not document the options the PwnFlow registrations use." >&2
    networkhound_status="Failed (the installed NetworkHound does not document the options PwnFlow uses)"
    return 1
  fi
  if ! diagnostics="$(git -C "${root}" rev-parse HEAD 2>/dev/null)"; then
    diagnostics="unknown"
  fi
  printf '%s\n' "${diagnostics}" > "${root}/.pwnflow-revision"
  chmod 600 "${root}/.pwnflow-revision"
  networkhound_status="Installed"
  echo "NetworkHound installed at ${diagnostics} in ${root}"
}

install_relayking() {
  local root revision diagnostics
  root="$(relayking_root)"
  # The options the PwnFlow registration builds, including the audit profile the
  # operator asked for. Coercion flags are deliberately not required: PwnFlow does
  # not register them.
  local required=(--audit --protocols --dc-ip --output-file --proto-portscan --ntlmv1 --gen-relay-list --threads -o)
  if checkout_documents "${root}" relayking.py -h "${required[@]}"; then
    revision="$(checkout_revision "${root}")"
    echo "RelayKing already installed and functional: ${revision} in ${root}"
    relayking_status="Already installed"
    return 0
  fi
  if ! ensure_git; then
    echo "git is unavailable; RelayKing is installed from its repository." >&2
    relayking_status="Failed (git is unavailable)"
    return 1
  fi
  if [[ -d "${root}/.git" ]]; then
    echo "Reusing the existing RelayKing checkout at ${root}."
  elif [[ -e "${root}" ]]; then
    echo "${root} exists but is not a git checkout; move it aside and re-run." >&2
    relayking_status="Failed (${root} is not a git checkout)"
    return 1
  else
    echo "Cloning RelayKing into ${root}."
    mkdir -p "$(dirname "${root}")"
    if ! git clone https://github.com/depthsecurity/RelayKing-Depth.git "${root}"; then
      relayking_status="Failed (git clone failed)"
      return 1
    fi
  fi
  if ! ensure_checkout_environment "${root}"; then
    relayking_status="Failed (the Python environment could not be prepared)"
    return 1
  fi
  if ! checkout_documents "${root}" relayking.py -h "${required[@]}"; then
    echo "The RelayKing checkout at ${root} does not document the options the PwnFlow registrations use." >&2
    relayking_status="Failed (the installed RelayKing does not document the options PwnFlow uses)"
    return 1
  fi
  if ! diagnostics="$(git -C "${root}" rev-parse HEAD 2>/dev/null)"; then
    diagnostics="unknown"
  fi
  printf '%s\n' "${diagnostics}" > "${root}/.pwnflow-revision"
  chmod 600 "${root}/.pwnflow-revision"
  relayking_status="Installed"
  echo "RelayKing installed at ${diagnostics} in ${root}"
}

print_summary() {
  echo ""
  echo "Installation summary:"
  echo "  NetExec: ${netexec_status}"
  echo "  RustHound-CE: ${rusthound_ce_status}"
  echo "  Cargo: ${cargo_status}"
  echo "  Certipy: ${certipy_status}"
  echo "  SCCMhunter: ${sccmhunter_status}"
  echo "  PXEThief: ${pxethief_status}"
  echo "  NetworkHound: ${networkhound_status}"
  echo "  RelayKing: ${relayking_status}"
  echo "  SCCMSecrets: ${sccmsecrets_status}"
  echo "  mssqlrelay: ${mssqlrelay_status}"
  echo "  MSSqlPwner: ${mssqlpwner_status}"
  echo "  gpoParser: ${gpoparser_status}"
  echo "  ghostSPN: ${ghostspn_status}"
  echo "  Masscan: ${masscan_status}"
}

run_install_attempt() {
  local function_name="$1" status_name="$2"
  shift 2
  if ! "${function_name}" "$@"; then
    if [[ "${!status_name}" == "Skipped" ]]; then
      printf -v "${status_name}" '%s' "Failed"
    fi
    install_failures=1
  fi
}

if [[ ${install_all_requested} -eq 1 ]] && ! ensure_project_build_tools; then install_failures=1; fi
if [[ ${install_netexec_requested} -eq 1 ]]; then run_install_attempt install_netexec netexec_status; fi
if [[ ${install_rusthound_ce} -eq 1 ]]; then run_install_attempt install_rusthound_ce rusthound_ce_status; fi
if [[ ${install_certipy} -eq 1 ]]; then run_install_attempt install_certipy certipy_status; fi
if [[ ${install_sccmhunter} -eq 1 ]]; then run_install_attempt install_sccmhunter sccmhunter_status; fi
if [[ ${install_pxethief} -eq 1 ]]; then run_install_attempt install_pxethief pxethief_status; fi
if [[ ${install_networkhound} -eq 1 ]]; then run_install_attempt install_networkhound networkhound_status; fi
if [[ ${install_relayking} -eq 1 ]]; then run_install_attempt install_relayking relayking_status; fi
if [[ ${install_sccmsecrets} -eq 1 ]]; then run_install_attempt install_sccmsecrets sccmsecrets_status; fi
if [[ ${install_mssqlrelay} -eq 1 ]]; then run_install_attempt install_pipx_source mssqlrelay_status mssqlrelay git+https://github.com/CompassSecurity/mssqlrelay.git mssqlrelay mssqlrelay_status Microsoft; fi
if [[ ${install_mssqlpwner} -eq 1 ]]; then run_install_attempt install_pipx_source mssqlpwner_status MSSqlPwner git+https://github.com/ScorpionesLabs/MSSqlPwner.git mssqlpwner mssqlpwner_status mssqlpwner; fi
if [[ ${install_gpoparser} -eq 1 ]]; then run_install_attempt install_pipx_source gpoparser_status gpoParser git+https://github.com/synacktiv/gpoParser.git gpoParser gpoparser_status GPO; fi
if [[ ${install_ghostspn} -eq 1 ]]; then run_install_attempt install_pipx_source ghostspn_status ghostSPN git+https://github.com/mverschu/ghostSPN.git@f5df2cd072d9c3ba81b01590e433b21449d91394 ghostspn ghostspn_status ghost; fi
if [[ ${install_masscan} -eq 1 ]]; then run_install_attempt install_masscan masscan_status; fi
print_summary
if [[ ${install_failures} -ne 0 ]]; then
  exit 1
fi
