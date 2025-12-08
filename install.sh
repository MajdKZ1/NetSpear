#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ_FILE="$ROOT_DIR/NetSpear/requirements.txt"

log() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*" >&2; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

detect_platform() {
  local uname_out
  uname_out="$(uname -s 2>/dev/null || true)"
  case "${uname_out}" in
    Linux*)   OS_TYPE="linux" ;;
    Darwin*)  OS_TYPE="mac" ;;
    CYGWIN*|MINGW*|MSYS*) OS_TYPE="windows" ;;
    *)        OS_TYPE="unknown" ;;
  esac
}

detect_package_manager() {
  case "$OS_TYPE" in
    mac)
      if command_exists brew; then PKG_MGR="brew"; else PKG_MGR=""; fi
      ;;
    linux)
      if command_exists apt-get; then PKG_MGR="apt"; elif command_exists pacman; then PKG_MGR="pacman"; else PKG_MGR=""; fi
      ;;
    windows)
      if command_exists winget; then PKG_MGR="winget"; else PKG_MGR=""; fi
      ;;
    *) PKG_MGR="" ;;
  esac
}

find_python() {
  if command_exists python3; then
    PYTHON_BIN="python3"
  elif command_exists python; then
    PYTHON_BIN="python"
  elif command_exists py; then
    PYTHON_BIN="py -3"
  else
    PYTHON_BIN=""
  fi
}

pkg_install() {
  local tool="$1" pkg_name="$2"
  if command_exists "$tool"; then
    log "Found $tool; skipping."
    return
  fi
  if [[ -z "$PKG_MGR" ]]; then
    warn "No supported package manager detected. Please install $tool manually (package: $pkg_name)."
    return
  fi
  log "Installing $tool via $PKG_MGR..."
  case "$PKG_MGR" in
    apt)
      sudo apt-get update -y || warn "apt-get update failed; continuing."
      if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg_name"; then
        warn "Failed to install $tool via apt (package: $pkg_name). Continuing."
      fi
      ;;
    pacman)
      if ! sudo pacman -Syu --noconfirm "$pkg_name"; then
        warn "Failed to install $tool via pacman (package: $pkg_name). Continuing."
      fi
      ;;
    brew)
      brew update || warn "brew update failed; continuing."
      if ! brew install "$pkg_name"; then
        warn "Failed to install $tool via brew (package: $pkg_name). Continuing."
      fi
      ;;
    winget)
      winget install --id "$pkg_name" -e --source winget || warn "winget install failed for $tool ($pkg_name)."
      ;;
  esac
}

npm_install() {
  local tool="$1" pkg_name="$2"
  if command_exists "$tool"; then
    log "Found $tool; skipping."
    return
  fi
  if ! command_exists npm; then
    warn "npm not found; cannot install $pkg_name. Install Node.js/npm first."
    return
  fi
  log "Installing $pkg_name via npm..."
  npm install -g "$pkg_name"
}

pip_install_requirements() {
  if [[ -f "$REQ_FILE" ]]; then
    if command_exists python3; then
      log "Installing Python requirements from $REQ_FILE..."
      python3 -m pip install --upgrade pip
      python3 -m pip install -r "$REQ_FILE"
    else
      warn "python3 not found; skipping Python requirements."
    fi
  else
    warn "requirements.txt not found at $REQ_FILE; skipping."
  fi
}

install_stack() {
  # Core frameworks
  pkg_install msfconsole metasploit-framework
  pkg_install msfvenom metasploit-framework
  pkg_install hydra hydra

  # Recon and web
  pkg_install whatweb whatweb
  pkg_install wafw00f wafw00f
  pkg_install nuclei nuclei
  pkg_install ffuf ffuf
  pkg_install gobuster gobuster
  pkg_install feroxbuster feroxbuster
  pkg_install sqlmap sqlmap
  pkg_install rustscan rustscan || pkg_install masscan masscan
  pkg_install sfcli spiderfoot

  # Wappalyzer CLI via npm
  npm_install wappalyzer wappalyzer

  # SpiderFoot Python deps (if CLI was not available via package)
  if ! command_exists sfcli && command_exists pip3; then
    warn "sfcli not detected; attempting pip install spiderfoot..."
    pip3 install spiderfoot || warn "pip install spiderfoot failed; install sfcli manually."
  fi

  pip_install_requirements
}

install_launcher() {
  find_python
  if [[ -z "$PYTHON_BIN" ]]; then
    warn "No python interpreter found; skipping launcher creation."
    return
  fi

  if [[ "$OS_TYPE" == "mac" || "$OS_TYPE" == "linux" ]]; then
    local bin_dir="/usr/local/bin"
    if [[ ! -w "$bin_dir" ]]; then
      bin_dir="$HOME/.local/bin"
      mkdir -p "$bin_dir"
    fi
    local launcher="$bin_dir/netspear"
    if ! cat > "$launcher" <<EOF
#!/usr/bin/env bash
"$PYTHON_BIN" "$ROOT_DIR/NetSpear/main.py" "\$@"
EOF
    then
      warn "Failed to write launcher to $launcher."
      return
    fi
    chmod +x "$launcher" || warn "Could not chmod +x $launcher"
    log "Launcher installed to $launcher (ensure $bin_dir is on your PATH)."
  elif [[ "$OS_TYPE" == "windows" ]]; then
    local win_bin="$HOME/AppData/Local/Microsoft/WindowsApps"
    if [[ ! -d "$win_bin" || ! -w "$win_bin" ]]; then
      win_bin="$HOME/bin"
      mkdir -p "$win_bin"
    fi
    local launcher="$win_bin/netspear.cmd"
    local main_path="$ROOT_DIR/NetSpear/main.py"
    if command_exists cygpath; then
      main_path="$(cygpath -w "$main_path")"
    fi
    if ! cat > "$launcher" <<EOF
@echo off
"${PYTHON_BIN}" "${main_path}" %*
EOF
    then
      warn "Failed to write launcher to $launcher."
      return
    fi
    log "Launcher installed to $launcher. Add $win_bin to PATH if needed."
  else
    warn "Skipping launcher creation on unsupported platform."
  fi
}

main() {
  detect_platform
  detect_package_manager
  find_python

  case "$OS_TYPE" in
    mac|linux)
      log "Detected platform: $OS_TYPE (pkg manager: ${PKG_MGR:-none})"
      install_launcher
      install_stack
      ;;
    windows)
      log "Windows detected."
      if [[ "$PKG_MGR" == "winget" ]]; then
        log "Using winget where packages exist; some tools may require manual install."
        pkg_install msfconsole Rapid7.Metasploit
        pkg_install msfvenom Rapid7.Metasploit
        pkg_install hydra olex.Rubytools.Hydra
        pkg_install whatweb WhatWeb.WhatWeb
        pkg_install wafw00f wafw00f.wafw00f
        pkg_install nuclei ProjectDiscovery.Nuclei
        pkg_install ffuf gklplayer.ffuf
        pkg_install gobuster OJ.Recon.Gobuster
        pkg_install feroxbuster Feroxbuster.Feroxbuster
        pkg_install sqlmap DBCreatorTeam.SqlMap
        pkg_install rustscan Rustscan.Rustscan
        pkg_install masscan Masscan.Masscan
        pkg_install sfcli SpiderFoot.SpiderFoot
        npm_install wappalyzer wappalyzer
        pip_install_requirements
        install_launcher
        warn "If any winget installs failed or packages were missing, install those tools manually or use WSL2."
      else
        err "winget not detected. Use WSL2 or install tools manually: metasploit-framework, hydra, whatweb, wappalyzer (npm), wafw00f, nuclei, ffuf/gobuster/feroxbuster, sqlmap, rustscan or masscan, sfcli (SpiderFoot), plus Python requirements."
      fi
      ;;
    *)
      err "Unsupported platform. Install dependencies manually."
      exit 1
      ;;
  esac

  log "Installation routine completed."
}

main "$@"
