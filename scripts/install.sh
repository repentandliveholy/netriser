#!/usr/bin/env sh
# NetRiser installer for Linux and macOS. Safe to run from a pipe.
set -eu

DIST_URL="${NETRISER_URL:-${WATCHDOG_URL:-https://netriser.repentandliveholy.org}}"
OS_RAW="$(uname -s)"
case "$OS_RAW" in Linux*) OS=linux ;; Darwin*) OS=darwin ;; *) echo "Unsupported OS: $OS_RAW" >&2; exit 1 ;; esac
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "Unsupported architecture: $ARCH_RAW" >&2; exit 1 ;; esac
if [ "$OS" = linux ]; then BIN_DIR=/usr/local/sbin; else BIN_DIR=/usr/local/bin; fi
BIN="$BIN_DIR/netriser"
LEGACY_BIN=/usr/local/bin/mesh-watchdog
DOC_DIR=/usr/local/share/doc/netriser
LEGACY_MAIN=mesh-watchdog.service
LEGACY_POLICY=mesh-watchdog-policy.service
LEGACY_POLICY_OVERRIDE=""
if [ "$OS" = linux ]; then
  NEW_CONFIG=/etc/netriser/config.yaml
  LEGACY_CONFIG=/etc/mesh-watchdog/config.yaml
  LEGACY_STATE=/var/lib/mesh-watchdog
  LEGACY_UNIT_DIR=/etc/systemd/system
  LEGACY_POLICY_OVERRIDE=/run/systemd/system/mesh-watchdog-policy.service.d/90-netriser-migration.conf
else
  NEW_CONFIG=/etc/netriser/config.yaml
  LEGACY_CONFIG=/etc/mesh-watchdog/config.yaml
  LEGACY_STATE="/Library/Application Support/mesh-watchdog"
  LEGACY_UNIT_DIR=/Library/LaunchDaemons
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || { echo 'Administrator privileges (sudo) are required.' >&2; exit 1; }
  SUDO=sudo
fi
run_root() { if [ -n "$SUDO" ]; then sudo "$@"; else "$@"; fi; }
fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fL --progress-bar "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -O "$2" "$1"
  else echo 'Install curl or wget and retry.' >&2; return 1; fi
}

# stdin contains the installer when invoked as curl | sh. Never read answers
# from it: use the controlling terminal and leave the rest of the script intact.
choose_setting() {
  label="$1"; supplied="$2"; fallback="$3"
  case "$supplied" in
    true|yes|y|1|on) printf 'true\n'; return ;;
    false|no|n|0|off) printf 'false\n'; return ;;
    '') ;;
    *) echo "Invalid setting for $label: use true or false." >&2; return 1 ;;
  esac
  if [ "${NETRISER_NONINTERACTIVE:-0}" = 1 ] || ! ( : <>/dev/tty ) 2>/dev/null; then
    echo "$label: no interactive prompt; using $fallback (keep = preserve existing setting)." >&2
    printf '%s\n' "$fallback"
    return
  fi
  case "$fallback" in
    true) hint='Y/n' ;;
    false) hint='y/N' ;;
    keep) hint='y/n, Enter = keep current setting' ;;
  esac
  while :; do
    printf '%s [%s]: ' "$label" "$hint" >/dev/tty
    if ! IFS= read -r reply </dev/tty; then
      echo "Cannot read installation choice; set NETRISER_OBSERVATION_MODE, NETRISER_AUTO_UPDATE and NETRISER_ENABLE_REBOOT for unattended installation." >&2
      return 1
    fi
    case "$reply" in
      [Yy]|[Yy][Ee][Ss]) printf 'true\n'; return ;;
      [Nn]|[Nn][Oo]) printf 'false\n'; return ;;
      '') printf '%s\n' "$fallback"; return ;;
      *) printf 'Please answer y or n (or Enter for the default).\n' >/dev/tty ;;
    esac
  done
}

discover_config() {
  awk '
    /^ExecStart=/ && match($0, /--config(=|[[:space:]]+)/) {
      v = substr($0, RSTART + RLENGTH)
      q = substr(v, 1, 1)
      if (q == "\"" || q == sprintf("%c", 39)) {
        v = substr(v, 2); n = index(v, q); if (n) v = substr(v, 1, n-1)
      } else sub(/[[:space:]].*$/, "", v)
      print v
    }' "$1" | tail -n 1
}

ASSET="netriser-${OS}-${ARCH}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/netriser-install.XXXXXX")"
STAGED="$WORK/$ASSET"
SUMS="$WORK/sha256sums.txt"
BACKUP=""
SUCCESS=0
MUTATING=0
OLD_MAIN_ACTIVE=0
OLD_POLICY_ACTIVE=0
OLD_MAIN_ENABLED=0
OLD_POLICY_ENABLED=0
NEW_WAS_ACTIVE=0
NEW_EXISTS=0
LEGACY_DAEMON_LOADED=0
LEGACY_CONFIG_ARG="${CONF_FILE:-}"
cleanup() { rm -rf "$WORK"; }

backup_path() {
  src="$1"
  [ -e "$src" ] || [ -L "$src" ] || return 0
  dest="$BACKUP/${src#/}"
  if [ -e "$dest" ] || [ -L "$dest" ]; then return 0; fi
  run_root mkdir -p "$(dirname "$dest")"
  run_root cp -a "$src" "$dest"
}
restore_path() {
  [ -n "${1:-}" ] || return 0
  src="$1"
  saved="$BACKUP/${src#/}"
  run_root rm -rf "$src"
  if [ -e "$saved" ] || [ -L "$saved" ]; then
    run_root mkdir -p "$(dirname "$src")"
    run_root cp -a "$saved" "$src"
  fi
}
rollback() {
  [ -n "$BACKUP" ] || return 0
  echo 'NetRiser installation failed; restoring the previous service and files.' >&2
  if [ "$OS" = linux ]; then
    run_root systemctl stop netriser.service netriser-policy.service >/dev/null 2>&1 || true
  else
    run_root launchctl unload -w /Library/LaunchDaemons/com.netriser.daemon.plist >/dev/null 2>&1 || true
  fi
  for p in "$DOC_DIR" "$BIN" /usr/local/bin/netriser /usr/local/bin/nr "$LEGACY_BIN" "$NEW_CONFIG" "$LEGACY_CONFIG" "$LEGACY_CONFIG_ARG" "$LEGACY_STATE" /var/lib/netriser /Library/Application\ Support/mesh-watchdog /Library/Application\ Support/netriser /var/log/mesh-watchdog.log /var/log/mesh-watchdog /var/log/netriser.log /var/log/netriser /run/mesh-watchdog/mesh-watchdog.lock /run/netriser/netriser.lock /var/run/mesh-watchdog.lock /var/run/netriser.lock; do restore_path "$p"; done
  [ -z "$LEGACY_POLICY_OVERRIDE" ] || restore_path "$LEGACY_POLICY_OVERRIDE"
  if [ "$OS" = linux ]; then
    for p in /etc/systemd/system/netriser.service /etc/systemd/system/netriser-policy.service /etc/systemd/system/mesh-watchdog.service /etc/systemd/system/mesh-watchdog-policy.service; do restore_path "$p"; done
    run_root systemctl daemon-reload >/dev/null 2>&1 || true
    [ "$OLD_POLICY_ENABLED" -eq 1 ] && run_root systemctl enable "$LEGACY_POLICY" >/dev/null 2>&1 || true
    [ "$OLD_MAIN_ENABLED" -eq 1 ] && run_root systemctl enable "$LEGACY_MAIN" >/dev/null 2>&1 || true
    [ "$OLD_POLICY_ACTIVE" -eq 1 ] && run_root systemctl start "$LEGACY_POLICY" >/dev/null 2>&1 || true
    [ "$OLD_MAIN_ACTIVE" -eq 1 ] && run_root systemctl start "$LEGACY_MAIN" >/dev/null 2>&1 || true
    [ "$NEW_WAS_ACTIVE" -eq 1 ] && run_root systemctl start netriser.service >/dev/null 2>&1 || true
  else
    restore_path /Library/LaunchDaemons/com.mesh.watchdog.plist
    restore_path /Library/LaunchDaemons/com.netriser.daemon.plist
    [ "$LEGACY_DAEMON_LOADED" -eq 1 ] && run_root launchctl load -w /Library/LaunchDaemons/com.mesh.watchdog.plist >/dev/null 2>&1 || true
    [ "$NEW_WAS_ACTIVE" -eq 1 ] && run_root launchctl load -w /Library/LaunchDaemons/com.netriser.daemon.plist >/dev/null 2>&1 || true
  fi
}
on_exit() {
  result=$?
  if [ "$result" -ne 0 ] && [ "$SUCCESS" -eq 0 ] && [ "$MUTATING" -eq 1 ]; then rollback; fi
  cleanup
  exit "$result"
}
trap on_exit EXIT
trap 'exit 1' HUP INT TERM

URL="${DIST_URL%/}/bin/${ASSET}"
echo "[1/8] NetRiser installation for ${OS}/${ARCH}; checking administrator access"
run_root true
echo "[2/8] Downloading binary: ${URL}"
fetch "$URL" "$STAGED"
echo '[2/8] Downloading MIT license and third-party notices'
fetch "${DIST_URL%/}/LICENSE" "$WORK/LICENSE"
fetch "${DIST_URL%/}/THIRD_PARTY_NOTICES" "$WORK/THIRD_PARTY_NOTICES"
echo '[3/8] Downloading checksums and verifying SHA-256'
fetch "${DIST_URL%/}/sha256sums.txt" "$SUMS"
EXPECTED_HASH="$(awk -v name="$ASSET" '$2 == name {print $1; exit}' "$SUMS")"
case "$EXPECTED_HASH" in *[!0123456789abcdefABCDEF]*|'') echo "Missing or invalid SHA-256 entry for ${ASSET}" >&2; exit 1 ;; esac
if command -v sha256sum >/dev/null 2>&1; then printf '%s  %s\n' "$EXPECTED_HASH" "$STAGED" | sha256sum -c - >/dev/null
else printf '%s  %s\n' "$EXPECTED_HASH" "$STAGED" | shasum -a 256 -c - >/dev/null; fi
chmod 755 "$STAGED"
"$STAGED" version
echo '[4/8] Detecting existing services and configuration'

if [ "$OS" = linux ]; then
  OLD_MAIN_ACTIVE=0; OLD_POLICY_ACTIVE=0; OLD_MAIN_ENABLED=0; OLD_POLICY_ENABLED=0
  systemctl is-active --quiet "$LEGACY_MAIN" 2>/dev/null && OLD_MAIN_ACTIVE=1 || true
  systemctl is-active --quiet "$LEGACY_POLICY" 2>/dev/null && OLD_POLICY_ACTIVE=1 || true
  systemctl is-enabled --quiet "$LEGACY_MAIN" 2>/dev/null && OLD_MAIN_ENABLED=1 || true
  systemctl is-enabled --quiet "$LEGACY_POLICY" 2>/dev/null && OLD_POLICY_ENABLED=1 || true
  systemctl is-active --quiet netriser.service 2>/dev/null && NEW_WAS_ACTIVE=1 || true
  # Preserve a custom --config from the old systemd unit, or an existing
  # canonical unit on an idempotent rerun.
  if [ -z "$LEGACY_CONFIG_ARG" ] && [ -r "/etc/systemd/system/$LEGACY_MAIN" ]; then
    LEGACY_CONFIG_ARG="$(discover_config "/etc/systemd/system/$LEGACY_MAIN")"
    if [ -z "$LEGACY_CONFIG_ARG" ]; then
      LEGACY_CONFIG_ARG="$(sed -n -E 's/^Environment=.*CONF_FILE="?([^ " ]+)"?.*/\1/p' "/etc/systemd/system/$LEGACY_MAIN" | tail -n 1)"
    fi
  fi
  if [ -z "$LEGACY_CONFIG_ARG" ] && [ -r /etc/systemd/system/netriser.service ]; then
    LEGACY_CONFIG_ARG="$(discover_config /etc/systemd/system/netriser.service)"
    if [ -z "$LEGACY_CONFIG_ARG" ]; then
      LEGACY_CONFIG_ARG="$(sed -n -E 's/^Environment=.*CONF_FILE="?([^ " ]+)"?.*/\1/p' /etc/systemd/system/netriser.service | tail -n 1)"
    fi
  fi
  [ -f /etc/systemd/system/netriser.service ] && NEW_EXISTS=1 || true
else
  if [ -f /Library/LaunchDaemons/com.mesh.watchdog.plist ]; then
    run_root launchctl list com.mesh.watchdog >/dev/null 2>&1 && LEGACY_DAEMON_LOADED=1 || true
    LEGACY_CONFIG_ARG="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments' /Library/LaunchDaemons/com.mesh.watchdog.plist 2>/dev/null | awk 'prev {gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit} /--config/ {prev=1}')"
    if [ -z "$LEGACY_CONFIG_ARG" ]; then LEGACY_CONFIG_ARG="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:CONF_FILE' /Library/LaunchDaemons/com.mesh.watchdog.plist 2>/dev/null || true)"; fi
  fi
  if [ -f /Library/LaunchDaemons/com.netriser.daemon.plist ]; then
    NEW_EXISTS=1
    LEGACY_CONFIG_ARG="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments' /Library/LaunchDaemons/com.netriser.daemon.plist 2>/dev/null | awk 'prev {gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit} /--config/ {prev=1}')"
    if [ -z "$LEGACY_CONFIG_ARG" ]; then LEGACY_CONFIG_ARG="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:CONF_FILE' /Library/LaunchDaemons/com.netriser.daemon.plist 2>/dev/null || true)"; fi
  fi
  run_root launchctl list com.netriser.daemon >/dev/null 2>&1 && NEW_WAS_ACTIVE=1 || true
fi

OBSERVE_DEFAULT=false
AUTO_DEFAULT=true
REBOOT_DEFAULT=false
EFFECTIVE_CONFIG="${LEGACY_CONFIG_ARG:-$NEW_CONFIG}"
if run_root test -f "$EFFECTIVE_CONFIG" || run_root test -f "$LEGACY_CONFIG" || run_root test -d "$LEGACY_STATE"; then
  OBSERVE_DEFAULT=keep
  AUTO_DEFAULT=keep
  REBOOT_DEFAULT=keep
fi
echo 'Observation mode is read-only: NetRiser records incidents but does not change routes, services, DNS or updates.'
echo 'Turn on recovery later with: nr observe off'
OBSERVE_CHOICE="$(choose_setting 'Start in observation (read-only) mode' "${NETRISER_OBSERVATION_MODE:-}" "$OBSERVE_DEFAULT")"
AUTO_CHOICE="$(choose_setting 'Enable automatic updates' "${NETRISER_AUTO_UPDATE:-}" "$AUTO_DEFAULT")"
REBOOT_CHOICE="$(choose_setting 'Allow emergency host reboot (off by default; fresh installs wait at least 5 minutes)' "${NETRISER_ENABLE_REBOOT:-}" "$REBOOT_DEFAULT")"
echo "Installation choices: observation mode=$OBSERVE_CHOICE; automatic updates=$AUTO_CHOICE; emergency reboot=$REBOOT_CHOICE"

# Create a durable backup before stopping services or changing any installed file.
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [ "$OS" = linux ]; then BACKUP_ROOT=/var/backups; else BACKUP_ROOT="/Library/Application Support/NetRiser-Backups"; fi
BACKUP="$BACKUP_ROOT/netriser-migration-$STAMP-$$"
echo "[5/8] Saving rollback backup: $BACKUP"
run_root mkdir -p "$BACKUP"
run_root chmod 700 "$BACKUP"
for p in "$DOC_DIR" "$BIN" /usr/local/bin/netriser /usr/local/bin/nr "$LEGACY_BIN" "$NEW_CONFIG" "$LEGACY_CONFIG" "$LEGACY_CONFIG_ARG" "$LEGACY_STATE" /var/lib/netriser /Library/Application\ Support/mesh-watchdog /Library/Application\ Support/netriser /var/log/mesh-watchdog.log /var/log/mesh-watchdog /var/log/netriser.log /var/log/netriser /run/mesh-watchdog/mesh-watchdog.lock /run/netriser/netriser.lock /var/run/mesh-watchdog.lock /var/run/netriser.lock; do backup_path "$p"; done
if [ -n "$LEGACY_POLICY_OVERRIDE" ]; then backup_path "$LEGACY_POLICY_OVERRIDE"; fi
if [ "$OS" = linux ]; then
  for p in /etc/systemd/system/netriser.service /etc/systemd/system/netriser-policy.service /etc/systemd/system/mesh-watchdog.service /etc/systemd/system/mesh-watchdog-policy.service; do backup_path "$p"; done
else
  backup_path /Library/LaunchDaemons/com.mesh.watchdog.plist
  backup_path /Library/LaunchDaemons/com.netriser.daemon.plist
fi

run_root mkdir -p "$BIN_DIR"
run_root mkdir -p /usr/local/bin
MUTATING=1
echo '[6/8] Stopping existing daemon and installing verified binary'
if [ "$OS" = linux ]; then
  [ "$NEW_WAS_ACTIVE" -eq 1 ] && run_root systemctl stop netriser.service
  # Stop the legacy policy process without running its route-removal ExecStop.
  run_root mkdir -p "$(dirname "$LEGACY_POLICY_OVERRIDE")"
  run_root sh -c 'printf "[Service]\\nExecStop=\\n" > "$1"' sh "$LEGACY_POLICY_OVERRIDE"
  run_root systemctl daemon-reload
  run_root systemctl disable --now "$LEGACY_MAIN" "$LEGACY_POLICY" >/dev/null 2>&1 || true
else
  [ "$NEW_WAS_ACTIVE" -eq 1 ] && run_root launchctl unload -w /Library/LaunchDaemons/com.netriser.daemon.plist
  [ "$LEGACY_DAEMON_LOADED" -eq 1 ] && run_root launchctl unload -w /Library/LaunchDaemons/com.mesh.watchdog.plist
fi

# The new daemon is stopped before an atomic replacement, so self-update or a
# rerun cannot leave a running service on an older executable.
run_root install -m 0755 "$STAGED" "$BIN_DIR/.netriser.new"
run_root mv -f "$BIN_DIR/.netriser.new" "$BIN"
run_root mkdir -p "$DOC_DIR"
run_root install -m 0644 "$WORK/LICENSE" "$DOC_DIR/LICENSE"
run_root install -m 0644 "$WORK/THIRD_PARTY_NOTICES" "$DOC_DIR/THIRD_PARTY_NOTICES"
if [ -n "$LEGACY_CONFIG_ARG" ]; then
  run_root "$BIN" --config "$LEGACY_CONFIG_ARG" migrate
else
  run_root "$BIN" migrate
fi
echo "[7/8] Creating or preserving configuration: $EFFECTIVE_CONFIG"
set -- "$BIN" --config "$EFFECTIVE_CONFIG" init-config
[ "$OBSERVE_CHOICE" = keep ] || set -- "$@" "--observation-mode=$OBSERVE_CHOICE"
[ "$AUTO_CHOICE" = keep ] || set -- "$@" "--auto-update=$AUTO_CHOICE"
[ "$REBOOT_CHOICE" = keep ] || set -- "$@" "--enable-reboot=$REBOOT_CHOICE"
run_root "$@"
echo '[8/8] Starting NetRiser and verifying service state'
if [ "$NEW_EXISTS" -eq 1 ]; then
  run_root "$BIN" service restart
elif [ -n "$LEGACY_CONFIG_ARG" ]; then
  run_root "$BIN" --config "$LEGACY_CONFIG_ARG" service install
else
  run_root "$BIN" service install
fi

# Confirm the canonical service remains active before retiring the old unit.
if [ "$OS" = linux ]; then
  run_root systemctl is-active --quiet netriser.service
  run_root ln -sfn "$BIN" /usr/local/bin/netriser
  run_root ln -sfn "$BIN" /usr/local/bin/nr
  run_root ln -sfn "$BIN" "$LEGACY_BIN"
  run_root systemctl disable "$LEGACY_MAIN" "$LEGACY_POLICY" >/dev/null 2>&1 || true
  run_root rm -f "/etc/systemd/system/$LEGACY_MAIN" "/etc/systemd/system/$LEGACY_POLICY"
  run_root rm -f "$LEGACY_POLICY_OVERRIDE"
  run_root rmdir "$(dirname "$LEGACY_POLICY_OVERRIDE")" 2>/dev/null || true
  run_root systemctl daemon-reload
else
  run_root launchctl list com.netriser.daemon >/dev/null
  run_root ln -sfn "$BIN" /usr/local/bin/nr
  run_root ln -sfn "$BIN" "$LEGACY_BIN"
  run_root rm -f /Library/LaunchDaemons/com.mesh.watchdog.plist
fi
run_root "$BIN" version
echo "NetRiser installed. Rollback backup: $BACKUP"
echo "License: MIT; license texts installed in $DOC_DIR"
echo "Commands: nr status; nr observe on|off|status; nr autoupdate on|off|status; nr reboot on|off|status"
echo "Logs: $(if [ "$OS" = linux ]; then echo 'journalctl -u netriser -f; /var/log/netriser.log'; else echo '/var/log/netriser.log'; fi)"
SUCCESS=1
