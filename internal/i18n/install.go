package i18n

// Texts of `netriser install` (double-clicking netriser.exe on Windows).
func init() {
	for k, v := range installCatalog {
		catalog[k] = v
	}
}

var installCatalog = map[string]msg{
	"inst_title": {"NetRiser %s: installation", "NetRiser %s: установка", "NetRiser %s : installation"},
	"inst_admin_need": {
		"Administrator rights are required. Double-click the file again and answer Yes, or run it from PowerShell opened as Administrator.",
		"Нужны права администратора. Запустите файл двойным щелчком ещё раз и ответьте «Да» или запустите его из PowerShell, открытого от имени администратора.",
		"Les droits d'administrateur sont nécessaires. Double-cliquez de nouveau sur le fichier et répondez Oui, ou lancez-le depuis PowerShell ouvert en tant qu'administrateur."},
	"inst_uac_declined": {"Administrator rights were not granted; nothing was changed.", "Права администратора не выданы; ничего не изменено.", "Les droits d'administrateur n'ont pas été accordés ; rien n'a été modifié."},
	"inst_s1":           {"[1/6] Checking this computer", "[1/6] Проверка компьютера", "[1/6] Vérification de cet ordinateur"},
	"inst_existing":     {"NetRiser is already installed (%s); it is updated and keeps its settings.", "NetRiser уже установлен (%s): он будет обновлён, настройки сохранятся.", "NetRiser est déjà installé (%s) ; il est mis à jour et garde ses réglages."},
	"inst_legacy":       {"Mesh Watchdog is installed; it is replaced by NetRiser and its settings are kept.", "Установлен Mesh Watchdog: его заменит NetRiser, настройки сохранятся.", "Mesh Watchdog est installé ; NetRiser le remplace et garde ses réglages."},
	"inst_cfg":          {"Configuration file: %s", "Файл настроек: %s", "Fichier de configuration : %s"},
	"inst_s2":           {"[2/6] Checking that this computer accepts connections (SSH, RDP)", "[2/6] Проверка, принимает ли компьютер подключения (SSH, RDP)", "[2/6] Vérification que cet ordinateur accepte les connexions (SSH, RDP)"},
	"inst_access_ok":    {"This computer accepts connections to its own ports (%s).", "Компьютер принимает подключения к своим портам (%s).", "Cet ordinateur accepte les connexions vers ses propres ports (%s)."},
	"inst_access_none":  {"Not tested: neither SSH (22) nor RDP (3389) listens on this computer.", "Не проверено: на компьютере не работают ни SSH (22), ни RDP (3389).", "Non vérifié : ni SSH (22) ni RDP (3389) n'écoute sur cet ordinateur."},
	"inst_access_blocked": {
		"This computer cannot connect to its own ports (%s): something on it blocks connections.",
		"Компьютер не может подключиться к своим же портам (%s): что-то на нём блокирует подключения.",
		"Cet ordinateur ne peut pas se connecter à ses propres ports (%s) : quelque chose sur lui bloque les connexions."},
	"inst_found":     {"Found software that can block connections:", "Найдены программы, которые могут блокировать подключения:", "Logiciels trouvés qui peuvent bloquer les connexions :"},
	"inst_kind_drv":  {"driver", "драйвер", "pilote"},
	"inst_kind_svc":  {"service", "служба", "service"},
	"inst_disable_q": {"Disable it now? The files stay; undo later with: nr blockers restore all", "Отключить сейчас? Файлы останутся; вернуть потом можно командой: nr blockers restore all", "Le désactiver maintenant ? Les fichiers restent ; annulation plus tard avec : nr blockers restore all"},
	"inst_disabled_ok": {
		"Disabled; connections work again (%s).",
		"Отключено; подключения снова работают (%s).",
		"Désactivé ; les connexions fonctionnent de nouveau (%s)."},
	"inst_disabled_restart": {
		"Disabled. It is still loaded: Windows must restart to unload it (asked at the end).",
		"Отключено. Оно ещё загружено: чтобы выгрузить его, нужно перезапустить Windows (вопрос в конце).",
		"Désactivé. Il est encore chargé : Windows doit redémarrer pour le décharger (question à la fin)."},
	"inst_not_found": {
		"Nothing to disable was found; after installation NetRiser keeps checking this.",
		"Отключать нечего; после установки NetRiser продолжит это проверять.",
		"Rien à désactiver ; après l'installation NetRiser continue de le vérifier."},
	"inst_skip_disable": {"Not disabled. To disable later: nr blockers disable", "Не отключено. Отключить позже: nr blockers disable", "Non désactivé. Pour le désactiver plus tard : nr blockers disable"},
	"inst_scan_failed":  {"Could not check the services and drivers: %s", "Не удалось проверить службы и драйверы: %s", "Impossible de vérifier les services et les pilotes : %s"},
	"inst_settings_new_q": {
		"Use the recommended settings (recovery on, emergency reboot off, automatic updates on)? n = answer all setup questions",
		"Использовать рекомендуемые настройки (восстановление включено, аварийная перезагрузка выключена, автообновление включено)? n = ответить на все вопросы настройки",
		"Utiliser les réglages recommandés (réparation activée, redémarrage d'urgence désactivé, mises à jour automatiques activées) ? n = répondre à toutes les questions"},
	"inst_settings_keep_q": {"Keep the current settings? n = answer all setup questions", "Оставить текущие настройки? n = ответить на все вопросы настройки", "Garder les réglages actuels ? n = répondre à toutes les questions"},
	"inst_s3":              {"[3/6] Saving a backup for rollback: %s", "[3/6] Резервная копия для отката: %s", "[3/6] Sauvegarde pour le retour arrière : %s"},
	"inst_s4":              {"[4/6] Stopping the old service and installing the program: %s", "[4/6] Остановка старой службы и установка программы: %s", "[4/6] Arrêt de l'ancien service et installation du programme : %s"},
	"inst_s5":              {"[5/6] Writing the configuration: %s", "[5/6] Запись настроек: %s", "[5/6] Écriture de la configuration : %s"},
	"inst_s6":              {"[6/6] Starting NetRiser and checking that the service runs", "[6/6] Запуск NetRiser и проверка, что служба работает", "[6/6] Démarrage de NetRiser et vérification du service"},
	"inst_done":            {"NetRiser is installed and running.", "NetRiser установлен и работает.", "NetRiser est installé et fonctionne."},
	"inst_failed":          {"Installation failed: %s", "Установка не удалась: %s", "L'installation a échoué : %s"},
	"inst_rolled_back":     {"The previous state was restored from the backup.", "Прежнее состояние восстановлено из резервной копии.", "L'état précédent a été restauré depuis la sauvegarde."},
	"inst_rollback_failed": {"Restoring the backup failed: %s. The backup is kept in %s", "Восстановить резервную копию не удалось: %s. Копия сохранена в %s", "La restauration de la sauvegarde a échoué : %s. La sauvegarde est conservée dans %s"},
	"inst_backup_hint":     {"Rollback backup (safe to delete once everything works): %s", "Резервная копия для отката (можно удалить, когда всё работает): %s", "Sauvegarde de retour arrière (supprimable quand tout fonctionne) : %s"},
	"inst_cmds":            {"Useful commands (in a new terminal window):", "Полезные команды (в новом окне терминала):", "Commandes utiles (dans une nouvelle fenêtre de terminal) :"},
	"inst_c_status":        {"show the current state", "показать текущее состояние", "afficher l'état actuel"},
	"inst_c_logs":          {"show recent log entries", "показать последние записи журнала", "afficher les dernières entrées du journal"},
	"inst_c_blockers":      {"software on this computer that blocks connections", "программы на компьютере, блокирующие подключения", "logiciels de cet ordinateur qui bloquent les connexions"},
	"inst_c_setup":         {"answer the setup questions again", "ответить на вопросы настройки заново", "répondre de nouveau aux questions de configuration"},
	"inst_restart_q":       {"Restart Windows now to finish?", "Перезапустить Windows сейчас, чтобы закончить?", "Redémarrer Windows maintenant pour terminer ?"},
	"inst_restarting":      {"Windows restarts in 10 seconds (cancel: shutdown /a).", "Windows перезапустится через 10 секунд (отмена: shutdown /a).", "Windows redémarre dans 10 secondes (annuler : shutdown /a)."},
	"inst_restart_later":   {"Restart Windows later to finish: shutdown /r /t 0", "Перезапустите Windows позже, чтобы закончить: shutdown /r /t 0", "Redémarrez Windows plus tard pour terminer : shutdown /r /t 0"},
	"inst_press_enter":     {"Press Enter to close this window.", "Нажмите Enter, чтобы закрыть окно.", "Appuyez sur Entrée pour fermer cette fenêtre."},
	"inst_yn":              {"[Y/n · Enter = yes]", "[Y/n · Enter = да]", "[Y/n · Entrée = oui]"},
	"inst_other_os": {
		"netriser install runs on Windows; on Linux and macOS use: curl -fsSL https://netriser.repentandliveholy.org/install.sh | sh",
		"netriser install работает в Windows; в Linux и macOS используйте: curl -fsSL https://netriser.repentandliveholy.org/install.sh | sh",
		"netriser install fonctionne sous Windows ; sous Linux et macOS utilisez : curl -fsSL https://netriser.repentandliveholy.org/install.sh | sh"},
}
