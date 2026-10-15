#!/usr/bin/env bash
set -euo pipefail

install_bloodhound_ce=0
install_bloodhound_python=0
install_rusthound_ce=0
install_netexec_requested=0
netexec_status="Skipped"
bloodhound_ce_status="Skipped"
bloodhound_python_status="Skipped"
rusthound_ce_status="Skipped"
cargo_status="Skipped"
sudo_authenticated=0
for argument in "$@"; do
  case "$argument" in
    --with-netexec) install_netexec_requested=1 ;;
    --with-bloodhound) install_bloodhound_ce=1; install_bloodhound_python=1 ;;
    --with-bloodhound-ce) install_bloodhound_ce=1 ;;
    --with-bloodhound-python) install_bloodhound_python=1 ;;
    --with-rusthound-ce) install_rusthound_ce=1 ;;
    --help|-h)
      echo "Usage: $0 [--with-netexec] [--with-bloodhound-ce] [--with-bloodhound-python] [--with-bloodhound] [--with-rusthound-ce]"
      exit 0
      ;;
    *) echo "Unknown option: $argument" >&2; exit 2 ;;
  esac
done

# The standalone default checks and installs every supported dependency.
# Explicit flags remain available for selective tool-group installation.
if [[ $# -eq 0 ]]; then
  install_netexec_requested=1
  install_bloodhound_ce=1
  install_bloodhound_python=1
  install_rusthound_ce=1
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

install_pipx() {
  if command -v pipx >/dev/null 2>&1; then
    echo "pipx already installed: $(pipx --version 2>/dev/null || echo version unavailable)"
  else
    if ! command -v apt-get >/dev/null 2>&1; then
      echo "pipx is missing and no supported APT package manager was found." >&2
      return 1
    fi
    echo "Installing pipx from the configured Kali APT repository."
    run_apt update
    run_apt_install pipx
  fi
  command -v pipx >/dev/null 2>&1 || { echo "pipx installation did not provide pipx" >&2; return 1; }
  pipx ensurepath
  local pipx_bin
  pipx_bin="$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || true)"
  if [[ -z "$pipx_bin" ]]; then
    pipx_bin="${HOME}/.local/bin"
  fi
  prepend_path_once "$pipx_bin"
  echo "pipx applications available immediately from: ${pipx_bin}"
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

bloodhound_python_functional() {
  local executable
  for executable in bloodhound-ce-python bloodhound-python; do
    if command -v "$executable" >/dev/null 2>&1 && "$executable" --help >/dev/null 2>&1; then
      echo "$executable"
      return 0
    fi
  done
  return 1
}

install_bloodhound_python() {
  local executable
  if executable="$(bloodhound_python_functional)"; then
    echo "BloodHound CE Python ingestor already installed and functional: ${executable}"
    bloodhound_python_status="Already installed"
    return 0
  fi
  install_pipx
  echo "Installing BloodHound CE Python ingestor with pipx (package: bloodhound-ce)."
	if ! pipx install bloodhound-ce; then
		echo "pipx installation failed for package bloodhound-ce; no existing installation was changed." >&2
		return 1
	fi
  if ! executable="$(bloodhound_python_functional)"; then
    echo "pipx completed but no working bloodhound-ce-python or bloodhound-python executable was found." >&2
    return 1
  fi
  echo "BloodHound CE Python ingestor installed and functional: ${executable}"
  bloodhound_python_status="Installed"
}

bloodhound_ce_package_version() {
  local query
  if ! command -v dpkg-query >/dev/null 2>&1; then
    return 2
  fi
  if ! query="$(dpkg-query -W -f='${db:Status-Abbrev} ${Version}\n' bloodhound 2>&1)"; then
    case "$query" in
      *"no packages found matching"*) return 1 ;;
      *) return 2 ;;
    esac
  fi
  if [[ ${query:0:3} != "ii " ]]; then
    return 2
  fi
  local version
  read -r _ version _ <<< "$query"
  if [[ -z "${version:-}" ]]; then
    return 2
  fi
  printf '%s\n' "$version"
}

install_bloodhound_ce() {
  local version
  if version="$(bloodhound_ce_package_version)"; then
    echo "BloodHound CE package already installed and configured: ${version}"
    bloodhound_ce_status="Already installed"
    return 0
  else
    local package_state=$?
    if [[ ${package_state} -eq 2 ]]; then
      echo "BloodHound CE package verification failed; refusing to reinstall an uncertain package state." >&2
      return 1
    fi
  fi
  if ! command -v apt-get >/dev/null 2>&1 || ! command -v apt-cache >/dev/null 2>&1; then
    echo "BloodHound CE requires its official application installation method; APT tooling is unavailable." >&2
    return 1
  fi
  if ! apt-cache show bloodhound >/dev/null 2>&1; then
    echo "BloodHound CE is not available in the configured repositories; use its official application installation procedure." >&2
    return 1
  fi
  echo "Installing missing BloodHound CE from the configured official application package."
  run_apt update
  run_apt_install bloodhound
  if ! version="$(bloodhound_ce_package_version)"; then
    echo "APT completed but dpkg does not confirm a fully installed/configured BloodHound CE package." >&2
    return 1
  fi
  bloodhound_ce_status="Installed"
  echo "BloodHound CE package installed and configured: ${version}"
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
  echo "Installing missing RustHound-CE with Cargo."
  local cargo_exit=0
  if cargo install rusthound-ce; then
    :
  else
    cargo_exit=$?
    rusthound_ce_status="Failed (cargo install exit ${cargo_exit})"
    echo "RustHound-CE Cargo installation failed (exit ${cargo_exit}). Review the Cargo output above; verify clang, libclang-dev, libkrb5-dev, and GSSAPI development packages are installed, and that Cargo's build directory (TMPDIR, default /tmp) has enough free space."
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

print_summary() {
  echo ""
  echo "Installation summary:"
  echo "  NetExec: ${netexec_status}"
  echo "  BloodHound CE: ${bloodhound_ce_status}"
  echo "  BloodHound CE Python: ${bloodhound_python_status}"
  echo "  RustHound-CE: ${rusthound_ce_status}"
  echo "  Cargo: ${cargo_status}"
}

if [[ ${install_netexec_requested} -eq 1 ]]; then
  if ! install_netexec; then
    netexec_status="Failed"
    print_summary
    exit 1
  fi
fi
if [[ ${install_bloodhound_ce} -eq 1 ]]; then
  if ! install_bloodhound_ce; then
    bloodhound_ce_status="Failed"
    print_summary
    exit 1
  fi
fi
if [[ ${install_bloodhound_python} -eq 1 ]]; then
  if ! install_bloodhound_python; then
    bloodhound_python_status="Failed"
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
if [[ ${install_bloodhound_ce} -eq 0 && ${install_bloodhound_python} -eq 0 && ${install_rusthound_ce} -eq 0 ]]; then
  echo "BloodHound components are optional and unchanged. Use --with-bloodhound-ce and/or --with-bloodhound-python for explicit installation."
else
  echo "BloodHound services were not started; configure local-only binding before launching any CE application."
fi
print_summary
