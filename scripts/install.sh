#!/usr/bin/env sh
# NetRiser installer for Linux and macOS. Safe to run from a pipe.
set -eu

DIST_URL="${NETRISER_URL:-${WATCHDOG_URL:-https://netriser.repentandliveholy.org}}"

# ---------------------------------------------------------------------------
# Output: colors (only on a terminal, never with NO_COLOR) and translated
# messages (English, Russian, French).
# ---------------------------------------------------------------------------
C_OFF=""; C_STEP=""; C_OK=""; C_WARN=""; C_DIM=""; E_ERR=""; E_OFF=""
if [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != dumb ]; then
  if [ -t 1 ]; then
    C_OFF="$(printf '\033[0m')"; C_STEP="$(printf '\033[1;36m')"; C_OK="$(printf '\033[32m')"
    C_WARN="$(printf '\033[33m')"; C_DIM="$(printf '\033[2m')"
  fi
  if [ -t 2 ]; then E_ERR="$(printf '\033[31m')"; E_OFF="$(printf '\033[0m')"; fi
fi

msg_en() {
  case "$1" in
    os_bad) printf '%s' 'Unsupported operating system: %s' ;;
    arch_bad) printf '%s' 'Unsupported processor architecture: %s' ;;
    sudo_need) printf '%s' 'Administrator privileges are required, but sudo was not found. Run the installer as root or install sudo.' ;;
    fetch_need) printf '%s' 'Neither curl nor wget was found. Install one of them and run the installer again.' ;;
    choice_bad) printf '%s' 'Invalid setting for %s: use true or false.' ;;
    lang_env_bad) printf '%s' 'Invalid NETRISER_LANG value "%s": use en, ru or fr.' ;;
    lang_retry) printf '%s' 'Please enter 1, 2 or 3 (or en, ru, fr).  /  Введите 1, 2 или 3 (или en, ru, fr).  /  Saisissez 1, 2 ou 3 (ou en, ru, fr).' ;;
    s1) printf '%s' '[1/8] Installing NetRiser for %s/%s: checking administrator access (sudo may ask for your password)' ;;
    s2a) printf '%s' '[2/8] Downloading the program: %s' ;;
    s2b) printf '%s' '[2/8] Downloading the license and third-party notices' ;;
    s3) printf '%s' '[3/8] Downloading checksums and verifying the SHA-256 of the program (protects against a damaged or tampered file)' ;;
    sum_bad) printf '%s' 'No valid SHA-256 entry for %s in the checksum list. Nothing was installed.' ;;
    s4) printf '%s' '[4/8] Looking for an existing installation and its configuration' ;;
    cfg_file) printf '%s' 'Configuration file: %s' ;;
    noint) printf '%s' 'No interactive terminal: a new installation starts in observation mode; existing settings are kept unless NETRISER_* variables select them.' ;;
    ask) printf '%s' 'Installation questions follow (you can answer them again at any time with: nr setup)' ;;
    setup_fail) printf '%s' 'Setup was cancelled or failed; nothing was changed.' ;;
    s5) printf '%s' '[5/8] Saving a rollback backup (everything is restored from it if something fails): %s' ;;
    s6) printf '%s' '[6/8] Stopping the old service and installing the verified program' ;;
    s7) printf '%s' '[7/8] Writing the configuration (existing settings are kept): %s' ;;
    s8) printf '%s' '[8/8] Starting NetRiser and checking that the service is running' ;;
    rb_fail) printf '%s' 'NetRiser installation failed; restoring the previous service and files from the backup.' ;;
    rb_done) printf '%s' 'The previous state has been restored.' ;;
    done) printf '%s' 'NetRiser is installed and running.' ;;
    backup) printf '%s' 'Rollback backup (safe to delete once everything works): %s' ;;
    license) printf '%s' 'License: MIT; license texts are installed in %s' ;;
    cmds_title) printf '%s' 'Useful commands:' ;;
    c_status) printf '%s' 'show the current state' ;;
    c_logs) printf '%s' 'show recent log entries' ;;
    c_live) printf '%s' 'follow the log in real time (Ctrl+C to stop)' ;;
    c_setup) printf '%s' 'answer the installation questions again' ;;
    c_observe) printf '%s' 'observation mode: only records incidents, changes nothing' ;;
    c_autoupdate) printf '%s' 'automatic updates' ;;
    c_reboot) printf '%s' 'emergency reboot of this computer' ;;
    obs_notice) printf '%s' 'NetRiser is in observation mode: it records incidents but changes nothing. Enable recovery with: nr observe off' ;;
    logs_hint) printf '%s' 'Logs: nr logs (recent entries), nr live (real time); the log file path is listed in the summary above.' ;;
    logs_journal) printf '%s' 'Service journal: journalctl -u netriser -f' ;;
    *) printf '%s' "$1" ;;
  esac
}
msg_ru() {
  case "$1" in
    os_bad) printf '%s' 'Операционная система не поддерживается: %s' ;;
    arch_bad) printf '%s' 'Архитектура процессора не поддерживается: %s' ;;
    sudo_need) printf '%s' 'Нужны права администратора, но команда sudo не найдена. Запустите установщик от имени root или установите sudo.' ;;
    fetch_need) printf '%s' 'Не найдены ни curl, ни wget. Установите одну из этих программ и запустите установщик снова.' ;;
    choice_bad) printf '%s' 'Неверное значение для %s: допустимо true или false.' ;;
    lang_env_bad) printf '%s' 'Неверное значение NETRISER_LANG "%s": допустимо en, ru или fr.' ;;
    s1) printf '%s' '[1/8] Установка NetRiser для %s/%s: проверяю права администратора (sudo может запросить пароль)' ;;
    s2a) printf '%s' '[2/8] Скачиваю программу: %s' ;;
    s2b) printf '%s' '[2/8] Скачиваю лицензию и сведения о сторонних компонентах' ;;
    s3) printf '%s' '[3/8] Скачиваю контрольные суммы и проверяю SHA-256 программы (защита от повреждённого или подменённого файла)' ;;
    sum_bad) printf '%s' 'Для %s в списке контрольных сумм нет корректной записи SHA-256. Ничего не установлено.' ;;
    s4) printf '%s' '[4/8] Ищу прежнюю установку и её настройки' ;;
    cfg_file) printf '%s' 'Файл настроек: %s' ;;
    noint) printf '%s' 'Интерактивного терминала нет: новая установка запустится в режиме наблюдения; существующие настройки сохранятся, если их не задают переменные NETRISER_*.' ;;
    ask) printf '%s' 'Далее вопросы об установке (позже на них можно ответить снова командой: nr setup)' ;;
    setup_fail) printf '%s' 'Настройка отменена или не удалась; ничего не изменено.' ;;
    s5) printf '%s' '[5/8] Сохраняю резервную копию для отката (если что-то пойдёт не так, всё вернётся как было): %s' ;;
    s6) printf '%s' '[6/8] Останавливаю старую службу и устанавливаю проверенную программу' ;;
    s7) printf '%s' '[7/8] Записываю настройки (существующие сохраняются): %s' ;;
    s8) printf '%s' '[8/8] Запускаю NetRiser и проверяю, что служба работает' ;;
    rb_fail) printf '%s' 'Установка NetRiser не удалась; возвращаю прежнюю службу и файлы из резервной копии.' ;;
    rb_done) printf '%s' 'Прежнее состояние восстановлено.' ;;
    done) printf '%s' 'NetRiser установлен и запущен.' ;;
    backup) printf '%s' 'Резервная копия для отката (можно удалить, когда убедитесь, что всё работает): %s' ;;
    license) printf '%s' 'Лицензия: MIT; тексты лицензий установлены в %s' ;;
    cmds_title) printf '%s' 'Полезные команды:' ;;
    c_status) printf '%s' 'показать текущее состояние' ;;
    c_logs) printf '%s' 'показать последние записи журнала' ;;
    c_live) printf '%s' 'следить за журналом в реальном времени (Ctrl+C - выход)' ;;
    c_setup) printf '%s' 'ответить на вопросы об установке заново' ;;
    c_observe) printf '%s' 'режим наблюдения: только записывает инциденты, ничего не меняет' ;;
    c_autoupdate) printf '%s' 'автоматические обновления' ;;
    c_reboot) printf '%s' 'аварийная перезагрузка этого компьютера' ;;
    obs_notice) printf '%s' 'NetRiser работает в режиме наблюдения: он записывает инциденты, но ничего не меняет. Чтобы включить восстановление, выполните: nr observe off' ;;
    logs_hint) printf '%s' 'Журнал: nr logs (последние записи), nr live (в реальном времени); путь к файлу журнала указан выше, в сводке.' ;;
    logs_journal) printf '%s' 'Журнал службы: journalctl -u netriser -f' ;;
  esac
}
msg_fr() {
  case "$1" in
    os_bad) printf '%s' "Système d'exploitation non pris en charge : %s" ;;
    arch_bad) printf '%s' "Architecture de processeur non prise en charge : %s" ;;
    sudo_need) printf '%s' "Les droits d'administrateur sont nécessaires, mais sudo est introuvable. Lancez l'installateur en tant que root ou installez sudo." ;;
    fetch_need) printf '%s' "Ni curl ni wget n'ont été trouvés. Installez l'un des deux puis relancez l'installateur." ;;
    choice_bad) printf '%s' 'Valeur incorrecte pour %s : utilisez true ou false.' ;;
    lang_env_bad) printf '%s' 'Valeur incorrecte de NETRISER_LANG "%s" : utilisez en, ru ou fr.' ;;
    s1) printf '%s' "[1/8] Installation de NetRiser pour %s/%s : vérification des droits d'administrateur (sudo peut demander votre mot de passe)" ;;
    s2a) printf '%s' '[2/8] Téléchargement du programme : %s' ;;
    s2b) printf '%s' '[2/8] Téléchargement de la licence et des mentions des composants tiers' ;;
    s3) printf '%s' '[3/8] Téléchargement des sommes de contrôle et vérification du SHA-256 du programme (protège contre un fichier endommagé ou altéré)' ;;
    sum_bad) printf '%s' "Aucune entrée SHA-256 valide pour %s dans la liste des sommes de contrôle. Rien n'a été installé." ;;
    s4) printf '%s' "[4/8] Recherche d'une installation existante et de sa configuration" ;;
    cfg_file) printf '%s' 'Fichier de configuration : %s' ;;
    noint) printf '%s' "Aucun terminal interactif : une nouvelle installation démarre en mode observation ; les réglages existants sont conservés, sauf si des variables NETRISER_* les modifient." ;;
    ask) printf '%s' "Les questions d'installation suivent (vous pourrez y répondre à nouveau à tout moment avec : nr setup)" ;;
    setup_fail) printf '%s' "La configuration a été annulée ou a échoué ; rien n'a été modifié." ;;
    s5) printf '%s' "[5/8] Création d'une sauvegarde de retour arrière (tout en est restauré en cas de problème) : %s" ;;
    s6) printf '%s' "[6/8] Arrêt de l'ancien service et installation du programme vérifié" ;;
    s7) printf '%s' '[7/8] Écriture de la configuration (les réglages existants sont conservés) : %s' ;;
    s8) printf '%s' '[8/8] Démarrage de NetRiser et vérification que le service fonctionne' ;;
    rb_fail) printf '%s' "L'installation de NetRiser a échoué ; restauration de l'ancien service et des fichiers depuis la sauvegarde." ;;
    rb_done) printf '%s' "L'état précédent a été restauré." ;;
    done) printf '%s' "NetRiser est installé et en cours d'exécution." ;;
    backup) printf '%s' 'Sauvegarde de retour arrière (vous pouvez la supprimer quand tout fonctionne) : %s' ;;
    license) printf '%s' 'Licence : MIT ; les textes des licences sont installés dans %s' ;;
    cmds_title) printf '%s' 'Commandes utiles :' ;;
    c_status) printf '%s' "afficher l'état actuel" ;;
    c_logs) printf '%s' 'afficher les dernières entrées du journal' ;;
    c_live) printf '%s' 'suivre le journal en temps réel (Ctrl+C pour arrêter)' ;;
    c_setup) printf '%s' "répondre de nouveau aux questions d'installation" ;;
    c_observe) printf '%s' "mode observation : enregistre les incidents sans rien modifier" ;;
    c_autoupdate) printf '%s' 'mises à jour automatiques' ;;
    c_reboot) printf '%s' "redémarrage d'urgence de cet ordinateur" ;;
    obs_notice) printf '%s' "NetRiser est en mode observation : il enregistre les incidents mais ne modifie rien. Pour activer la réparation, exécutez : nr observe off" ;;
    logs_hint) printf '%s' "Journaux : nr logs (dernières entrées), nr live (temps réel) ; le chemin du fichier journal figure dans le résumé ci-dessus." ;;
    logs_journal) printf '%s' 'Journal du service : journalctl -u netriser -f' ;;
  esac
}
# msg KEY [ARG...]: the text for KEY in the chosen language (English if missing).
NR_LANG=en
msg() {
  key="$1"; shift
  fmt=""
  case "$NR_LANG" in ru) fmt="$(msg_ru "$key")" ;; fr) fmt="$(msg_fr "$key")" ;; esac
  [ -n "$fmt" ] || fmt="$(msg_en "$key")"
  # shellcheck disable=SC2059
  printf "$fmt" "$@"
}
say()      { printf '%s\n' "$(msg "$@")"; }
say_step() { printf '%s%s%s\n' "$C_STEP" "$(msg "$@")" "$C_OFF"; }
say_ok()   { printf '%s%s%s\n' "$C_OK" "$(msg "$@")" "$C_OFF"; }
say_warn() { printf '%s%s%s\n' "$C_WARN" "$(msg "$@")" "$C_OFF"; }
say_hint() { printf '%s%s%s\n' "$C_DIM" "$(msg "$@")" "$C_OFF"; }
say_err()  { printf '%s%s%s\n' "$E_ERR" "$(msg "$@")" "$E_OFF" >&2; }
die()      { say_err "$@"; exit 1; }
cmd_line() { printf '  %s%-26s%s %s\n' "$C_OK" "$1" "$C_OFF" "$(msg "$2")"; }

# normalize_lang VALUE: print en, ru or fr for 1/2/3, en/ru/fr or a language name.
normalize_lang() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    1|en|english) printf 'en\n' ;;
    2|ru|russian|русский) printf 'ru\n' ;;
    3|fr|french|francais|français) printf 'fr\n' ;;
    *) return 1 ;;
  esac
}
if [ -n "${NETRISER_LANG:-}" ]; then
  NR_LANG="$(normalize_lang "$NETRISER_LANG")" || die lang_env_bad "$NETRISER_LANG"
fi

OS_RAW="$(uname -s)"
case "$OS_RAW" in Linux*) OS=linux ;; Darwin*) OS=darwin ;; *) die os_bad "$OS_RAW" ;; esac
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) die arch_bad "$ARCH_RAW" ;; esac
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
  command -v sudo >/dev/null 2>&1 || die sudo_need
  SUDO=sudo
fi
run_root() { if [ -n "$SUDO" ]; then sudo "$@"; else "$@"; fi; }
fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fL --progress-bar "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -O "$2" "$1"
  else say_err fetch_need; return 1; fi
}

# Unattended choices from the environment: true, false, or empty (not set).
normalize_choice() {
  case "$2" in
    true|yes|y|1|on) printf 'true\n' ;;
    false|no|n|0|off) printf 'false\n' ;;
    '') printf '\n' ;;
    *) say_err choice_bad "$1"; return 1 ;;
  esac
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

# Find the --config path used by an existing service (read-only; no changes).
# Preserves a custom --config from the old systemd unit / launchd plist, or from
# an existing canonical service on an idempotent rerun.
detect_config_arg() {
  if [ "$OS" = linux ]; then
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
  else
    if [ -f /Library/LaunchDaemons/com.mesh.watchdog.plist ]; then
      LEGACY_CONFIG_ARG="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments' /Library/LaunchDaemons/com.mesh.watchdog.plist 2>/dev/null | awk 'prev {gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit} /--config/ {prev=1}')"
      if [ -z "$LEGACY_CONFIG_ARG" ]; then LEGACY_CONFIG_ARG="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:CONF_FILE' /Library/LaunchDaemons/com.mesh.watchdog.plist 2>/dev/null || true)"; fi
    fi
    if [ -f /Library/LaunchDaemons/com.netriser.daemon.plist ]; then
      LEGACY_CONFIG_ARG="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments' /Library/LaunchDaemons/com.netriser.daemon.plist 2>/dev/null | awk 'prev {gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit} /--config/ {prev=1}')"
      if [ -z "$LEGACY_CONFIG_ARG" ]; then LEGACY_CONFIG_ARG="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:CONF_FILE' /Library/LaunchDaemons/com.netriser.daemon.plist 2>/dev/null || true)"; fi
    fi
  fi
  return 0
}

# config_language FILE: the "language:" value of an existing config, if readable
# (also via a passwordless "sudo -n", which never prompts).
config_language() {
  [ -n "$1" ] || return 0
  {
    cat "$1" 2>/dev/null || { [ -z "$SUDO" ] || sudo -n cat "$1" 2>/dev/null; } || true
  } | sed -n -E 's/^language:[[:space:]]*"?([A-Za-z]+)"?.*/\1/p' | head -n 1
}

# Interactive means a usable terminal (stdin is the script with curl | sh, so
# questions use /dev/tty) and no NETRISER_NONINTERACTIVE=1.
INTERACTIVE=1
if [ "${NETRISER_NONINTERACTIVE:-0}" = 1 ] || ! ( : <>/dev/tty ) 2>/dev/null; then INTERACTIVE=0; fi

# Language: NETRISER_LANG, else "language:" of the config this install will use,
# else English. Asked once (all three languages on one line) only interactively.
choose_language() {
  detect_config_arg
  EFFECTIVE_CONFIG="${LEGACY_CONFIG_ARG:-$NEW_CONFIG}"
  [ -z "${NETRISER_LANG:-}" ] || return 0
  default_lang=en
  found="$(config_language "$EFFECTIVE_CONFIG")"
  if [ -n "$found" ] && picked="$(normalize_lang "$found")"; then default_lang="$picked"; fi
  NR_LANG="$default_lang"
  [ "$INTERACTIVE" -eq 1 ] || return 0
  case "$default_lang" in ru) default_label='2 (Русский)' ;; fr) default_label='3 (Français)' ;; *) default_label='1 (English)' ;; esac
  while :; do
    printf 'Language / Язык / Langue: 1) English  2) Русский  3) Français [Enter = %s]: ' "$default_label" >/dev/tty
    answer=""
    IFS= read -r answer </dev/tty || answer=""
    if [ -z "$answer" ]; then return 0; fi
    if picked="$(normalize_lang "$answer")"; then NR_LANG="$picked"; return 0; fi
    say_warn lang_retry
  done
}

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
  say_err rb_fail
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
  say_warn rb_done >&2
}
on_exit() {
  result=$?
  if [ "$result" -ne 0 ] && [ "$SUCCESS" -eq 0 ] && [ "$MUTATING" -eq 1 ]; then rollback; fi
  cleanup
  exit "$result"
}
trap on_exit EXIT
trap 'exit 1' HUP INT TERM

choose_language

URL="${DIST_URL%/}/bin/${ASSET}"
say_step s1 "$OS" "$ARCH"
run_root true
say_step s2a "$URL"
fetch "$URL" "$STAGED"
say_step s2b
fetch "${DIST_URL%/}/LICENSE" "$WORK/LICENSE"
fetch "${DIST_URL%/}/THIRD_PARTY_NOTICES" "$WORK/THIRD_PARTY_NOTICES"
say_step s3
fetch "${DIST_URL%/}/sha256sums.txt" "$SUMS"
EXPECTED_HASH="$(awk -v name="$ASSET" '$2 == name {print $1; exit}' "$SUMS")"
case "$EXPECTED_HASH" in *[!0123456789abcdefABCDEF]*|'') die sum_bad "$ASSET" ;; esac
if command -v sha256sum >/dev/null 2>&1; then printf '%s  %s\n' "$EXPECTED_HASH" "$STAGED" | sha256sum -c - >/dev/null
else printf '%s  %s\n' "$EXPECTED_HASH" "$STAGED" | shasum -a 256 -c - >/dev/null; fi
chmod 755 "$STAGED"
"$STAGED" version
say_step s4

if [ "$OS" = linux ]; then
  OLD_MAIN_ACTIVE=0; OLD_POLICY_ACTIVE=0; OLD_MAIN_ENABLED=0; OLD_POLICY_ENABLED=0
  systemctl is-active --quiet "$LEGACY_MAIN" 2>/dev/null && OLD_MAIN_ACTIVE=1 || true
  systemctl is-active --quiet "$LEGACY_POLICY" 2>/dev/null && OLD_POLICY_ACTIVE=1 || true
  systemctl is-enabled --quiet "$LEGACY_MAIN" 2>/dev/null && OLD_MAIN_ENABLED=1 || true
  systemctl is-enabled --quiet "$LEGACY_POLICY" 2>/dev/null && OLD_POLICY_ENABLED=1 || true
  systemctl is-active --quiet netriser.service 2>/dev/null && NEW_WAS_ACTIVE=1 || true
  [ -f /etc/systemd/system/netriser.service ] && NEW_EXISTS=1 || true
else
  if [ -f /Library/LaunchDaemons/com.mesh.watchdog.plist ]; then
    run_root launchctl list com.mesh.watchdog >/dev/null 2>&1 && LEGACY_DAEMON_LOADED=1 || true
  fi
  if [ -f /Library/LaunchDaemons/com.netriser.daemon.plist ]; then NEW_EXISTS=1; fi
  run_root launchctl list com.netriser.daemon >/dev/null 2>&1 && NEW_WAS_ACTIVE=1 || true
fi

say_hint cfg_file "$EFFECTIVE_CONFIG"
OBSERVE_CHOICE="$(normalize_choice NETRISER_OBSERVATION_MODE "${NETRISER_OBSERVATION_MODE:-}")"
AUTO_CHOICE="$(normalize_choice NETRISER_AUTO_UPDATE "${NETRISER_AUTO_UPDATE:-}")"
REBOOT_CHOICE="$(normalize_choice NETRISER_ENABLE_REBOOT "${NETRISER_ENABLE_REBOOT:-}")"
BYPASS_CHOICE="$(normalize_choice NETRISER_ALLOW_VPN_BYPASS "${NETRISER_ALLOW_VPN_BYPASS:-}")"
FULL_TUNNEL_CHOICE="$(normalize_choice NETRISER_FULL_TUNNEL "${NETRISER_FULL_TUNNEL:-}")"
ANSWERS="$WORK/answers.yaml"
# Questions are asked by the verified binary before anything is stopped or
# changed; the answers are applied in step 7. Unix prompts use the terminal,
# because stdin is the installer script with curl | sh.
set -- "$STAGED" --config "$EFFECTIVE_CONFIG" setup "--save-answers=$ANSWERS" "--lang=$NR_LANG"
[ -z "$OBSERVE_CHOICE" ] || set -- "$@" "--observation-mode=$OBSERVE_CHOICE"
[ -z "$AUTO_CHOICE" ] || set -- "$@" "--auto-update=$AUTO_CHOICE"
[ -z "$REBOOT_CHOICE" ] || set -- "$@" "--enable-reboot=$REBOOT_CHOICE"
[ -z "$BYPASS_CHOICE" ] || set -- "$@" "--allow-vpn-bypass=$BYPASS_CHOICE"
[ -z "$FULL_TUNNEL_CHOICE" ] || set -- "$@" "--full-tunnel=$FULL_TUNNEL_CHOICE"
if [ "$INTERACTIVE" -eq 0 ]; then
  say_hint noint
  set -- "$@" --non-interactive
else
  say ask
fi
if ! run_root "$@"; then
  die setup_fail
fi

# Create a durable backup before stopping services or changing any installed file.
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [ "$OS" = linux ]; then BACKUP_ROOT=/var/backups; else BACKUP_ROOT="/Library/Application Support/NetRiser-Backups"; fi
BACKUP="$BACKUP_ROOT/netriser-migration-$STAMP-$$"
say_step s5 "$BACKUP"
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
say_step s6
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
say_step s7 "$EFFECTIVE_CONFIG"
run_root "$BIN" --config "$EFFECTIVE_CONFIG" setup "--answers=$ANSWERS" "--lang=$NR_LANG" --no-restart
say_step s8
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
printf '\n'
say_ok done
say_hint backup "$BACKUP"
say_hint license "$DOC_DIR"
printf '\n'
say cmds_title
cmd_line 'nr status' c_status
cmd_line 'nr logs' c_logs
cmd_line 'nr live' c_live
cmd_line 'nr setup' c_setup
cmd_line 'nr observe on|off|status' c_observe
cmd_line 'nr autoupdate on|off|status' c_autoupdate
cmd_line 'nr reboot on|off|status' c_reboot
printf '\n'
# The status text may be localized by the binary, so also look at the config.
if run_root "$BIN" --config "$EFFECTIVE_CONFIG" observe status 2>/dev/null | grep -q 'Observation mode: ON' \
  || run_root cat "$EFFECTIVE_CONFIG" 2>/dev/null | grep -Eq '^observation_mode:[[:space:]]*true'; then
  say_warn obs_notice
fi
say_hint logs_hint
if [ "$OS" = linux ]; then say_hint logs_journal; fi
SUCCESS=1
