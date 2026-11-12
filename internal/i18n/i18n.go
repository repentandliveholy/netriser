// Package i18n holds the texts of `netriser setup` in English, Russian and
// French. Keys missing in a language fall back to English.
package i18n

import (
	"fmt"
	"os"
	"strings"
)

// Languages lists the supported language codes in menu order.
var Languages = []string{"en", "ru", "fr"}

// Names are the language names shown in the language menu.
var Names = map[string]string{"en": "English", "ru": "Русский", "fr": "Français"}

// Normalize returns a supported language code, or "" for unsupported input.
// It accepts codes, menu numbers and locale strings such as "ru_RU.UTF-8".
func Normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "1":
		return "en"
	case "2":
		return "ru"
	case "3":
		return "fr"
	}
	if len(s) >= 2 {
		switch s[:2] {
		case "en", "ru", "fr":
			if len(s) == 2 || s[2] == '_' || s[2] == '-' || s[2] == '.' {
				return s[:2]
			}
		}
	}
	return ""
}

// FromEnvironment guesses the language from LC_ALL, LC_MESSAGES or LANG.
func FromEnvironment() string {
	for _, v := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if l := Normalize(os.Getenv(v)); l != "" {
			return l
		}
	}
	return ""
}

type msg struct{ en, ru, fr string }

func (m msg) in(lang string) string {
	switch lang {
	case "ru":
		if m.ru != "" {
			return m.ru
		}
	case "fr":
		if m.fr != "" {
			return m.fr
		}
	}
	return m.en
}

// T returns the text for key in lang, formatted with args.
func T(lang, key string, args ...any) string {
	m, ok := catalog[key]
	if !ok {
		return key
	}
	text := m.in(lang)
	if len(args) > 0 {
		return fmt.Sprintf(text, args...)
	}
	return text
}

// YesWords and NoWords are the answers in every language: y/n is kept in
// English like command names.
var (
	YesWords = []string{"y", "yes"}
	NoWords  = []string{"n", "no"}
)

var catalog = map[string]msg{
	// Prompt hints.
	"yes":            {"yes", "да", "oui"},
	"no":             {"no", "нет", "non"},
	"yn_default_yes": {"Y/n", "Y/n", "Y/n"},
	"yn_default_no":  {"y/N", "y/N", "y/N"},
	"enter_is":       {"Enter = %s", "Enter = %s", "Enter = %s"},
	"recommended":    {"recommended", "рекомендуется", "recommandé"},
	"current":        {"current", "текущее", "actuel"},
	"recommended_is": {"recommended: %s", "рекомендуется: %s", "recommandé : %s"},
	"none":           {"none", "пусто", "aucun"},
	"required":       {"required, type a value", "обязательно, введите значение", "obligatoire, saisissez une valeur"},
	"list_hint":      {"comma separated", "через запятую", "séparés par des virgules"},
	"list_keep":      {"keep: %s", "оставить: %s", "conserver : %s"},
	"list_clear":     {"- = none", "- = пусто", "- = aucun"},
	"yesno_retry":    {"Please answer y (yes) or n (no), or press Enter for the value shown after \"Enter =\".", "Ответьте y (yes, да) или n (no, нет), либо нажмите Enter, чтобы выбрать значение после «Enter =».", "Répondez y (yes, oui) ou n (no, non), ou appuyez sur Enter pour la valeur indiquée après « Enter = »."},
	"integer_retry":  {"Please enter a whole number of at least %d.", "Введите целое число не меньше %d.", "Saisissez un nombre entier d'au moins %d."},
	"cancelled":      {"Setup cancelled: nothing was changed.", "Настройка отменена: ничего не изменено.", "Configuration annulée : rien n'a été modifié."},

	// Introduction.
	"intro_saved":    {"NetRiser setup. Answers are saved to %s.", "Настройка NetRiser. Ответы будут сохранены в %s.", "Configuration de NetRiser. Les réponses sont enregistrées dans %s."},
	"intro_existing": {"Defaults are your current settings: press Enter to keep each one.", "По умолчанию предлагаются ваши текущие настройки: нажмите Enter, чтобы оставить каждую из них.", "Les valeurs par défaut sont vos réglages actuels : appuyez sur Enter pour les conserver."},
	"intro_new":      {"Defaults are the recommended values: press Enter to accept each one.", "По умолчанию предлагаются рекомендуемые значения: нажмите Enter, чтобы принять каждое из них.", "Les valeurs par défaut sont celles recommandées : appuyez sur Enter pour les accepter."},
	"intro_howto":    {"How to answer: choose with ←/→ or y (yes) / n (no) and confirm with Enter. Enter alone accepts the highlighted or shown value. Ctrl+C cancels without changing anything.", "Как отвечать: выберите стрелками ←/→ или клавишами y (yes, да) / n (no, нет) и подтвердите Enter. Просто Enter принимает выделенное или указанное значение. Ctrl+C отменяет настройку без изменений.", "Comment répondre : choisissez avec ←/→ ou y (yes, oui) / n (no, non) et validez avec Enter. Enter seul accepte la valeur sélectionnée ou indiquée. Ctrl+C annule sans rien modifier."},
	"intro_rerun":    {"Answer these questions again at any time with: netriser setup (short: nr setup)", "Ответить на эти вопросы заново можно в любой момент командой: netriser setup (коротко: nr setup)", "Vous pouvez répondre de nouveau à ces questions à tout moment avec : netriser setup (abrégé : nr setup)"},

	// Operating mode.
	"sec_mode":    {"Operating mode", "Режим работы", "Mode de fonctionnement"},
	"obs_explain": {"Observation mode is a safe trial run: NetRiser watches the connection and logs what it would do, but changes nothing (no routes, services, DNS or updates). It is a good start on an important machine; switch it off later with: nr observe off", "Режим наблюдения — безопасный пробный запуск: NetRiser следит за связью и записывает в журнал, что он сделал бы, но ничего не меняет (ни маршруты, ни службы, ни DNS, ни обновления). С него удобно начинать на важной машине. Позже его можно выключить командой: nr observe off", "Le mode observation est un essai sans risque : NetRiser surveille la connexion et note ce qu'il ferait, sans rien modifier (ni routes, ni services, ni DNS, ni mises à jour). Idéal pour commencer sur une machine importante ; vous pourrez le désactiver plus tard avec : nr observe off"},
	"obs_q":       {"Start in observation (read-only) mode", "Начать в режиме наблюдения (только чтение)", "Démarrer en mode observation (lecture seule)"},

	// Probes.
	"sec_probes":     {"Connectivity probes", "Проверка связи", "Sondes de connectivité"},
	"probes_explain": {"To know whether the internet works, NetRiser regularly connects to a few well-known addresses (probes), by default public DNS servers. They are tested now from this machine.", "Чтобы понять, работает ли интернет, NetRiser регулярно подключается к нескольким известным адресам в интернете — контрольным адресам; по умолчанию это публичные DNS-серверы. Сейчас они будут проверены с этой машины.", "Pour savoir si Internet fonctionne, NetRiser se connecte régulièrement à quelques adresses connues (sondes), par défaut des serveurs DNS publics. Elles sont testées maintenant depuis cette machine."},
	"probes_testing": {"Testing internet probes...", "Проверяю контрольные адреса интернета...", "Test des sondes Internet..."},
	"probe_ok":       {"ok", "ok", "ok"},
	"probe_fail":     {"FAIL", "СБОЙ", "ÉCHEC"},
	"probe_noanswer": {"no answer", "нет ответа", "pas de réponse"},
	"probes_short":   {"Only %d of the required %d probes answered. This network may block them: enter addresses it can reach (host:port), for example your own DNS server.", "Ответили только %d из %d необходимых контрольных адресов. Возможно, эта сеть их блокирует: укажите адреса, которые здесь доступны (host:port), например ваш собственный DNS-сервер.", "Seules %d sondes sur %d requises ont répondu. Ce réseau les bloque peut-être : indiquez des adresses qu'il peut joindre (host:port), par exemple votre propre serveur DNS."},
	"probes_q":       {"Use these internet probes", "Использовать эти контрольные адреса интернета", "Utiliser ces sondes Internet"},
	"probes_list_q":  {"Internet probes (host:port)", "Контрольные адреса интернета (host:port)", "Sondes Internet (host:port)"},
	"probes_needed":  {"At least one internet probe is required.", "Нужен хотя бы один контрольный адрес интернета.", "Au moins une sonde Internet est nécessaire."},
	"probes_kept":    {"Keeping the current probes.", "Оставляю текущие контрольные адреса.", "Les sondes actuelles sont conservées."},
	"mesh_explain":   {"Access check (optional). Internet probes show whether this machine reaches the internet, not whether you can reach this machine. If you connect to it through Tailscale, NetBird, ZeroTier or a WireGuard network, list 2-3 always-on hosts in that network: your server, Headscale, a Nebula lighthouse. If at least one answers, the path to this machine works. An address alone (100.101.102.103) is checked with ping; host:port (100.101.102.103:22) by connecting to that port. Windows machines do not answer ping by default, so give them a port such as :3389 or :22.", "Проверка доступа (необязательно). Контрольные адреса интернета показывают, выходит ли машина в интернет, но не то, можете ли вы подключиться к ней. Если вы заходите на неё через Tailscale, NetBird, ZeroTier или сеть WireGuard, укажите 2–3 всегда включённых узла этой сети: ваш сервер, Headscale, маяк Nebula. Если отвечает хотя бы один, путь к этой машине работает. Адрес без порта (100.101.102.103) проверяется через ping, адрес с портом (100.101.102.103:22) — подключением к этому порту. Windows-машины по умолчанию не отвечают на ping, для них укажите порт, например :3389 или :22.", "Vérification de l'accès (facultatif). Les sondes Internet montrent si cette machine atteint Internet, pas si vous pouvez atteindre cette machine. Si vous vous y connectez via Tailscale, NetBird, ZeroTier ou un réseau WireGuard, indiquez 2 ou 3 hôtes toujours allumés de ce réseau : votre serveur, Headscale, un phare Nebula. Si au moins un répond, le chemin vers cette machine fonctionne. Une adresse seule (100.101.102.103) est vérifiée par ping ; hôte:port (100.101.102.103:22) en se connectant à ce port. Les machines Windows ne répondent pas au ping par défaut : indiquez-leur un port comme :3389 ou :22."},
	"mesh_q":         {"Addresses for checking access to this machine (host or host:port)", "Адреса для проверки доступа к этой машине (host или host:port)", "Adresses pour vérifier l'accès à cette machine (hôte ou hôte:port)"},

	// VPNs and overlays.
	"sec_overlays":        {"VPNs and overlay networks", "VPN и оверлейные сети", "VPN et réseaux overlay"},
	"ov_none":             {"No VPN or overlay interfaces are active right now. NetRiser recognises WireGuard, OpenVPN, IPsec, Tailscale, ZeroTier, NetBird, Nebula, commercial VPN clients and generic tunnels.", "Сейчас нет активных интерфейсов VPN или оверлейных сетей. NetRiser распознаёт WireGuard, OpenVPN, IPsec, Tailscale, ZeroTier, NetBird, Nebula, коммерческие VPN-клиенты и типовые туннели.", "Aucune interface VPN ou de réseau overlay n'est active pour le moment. NetRiser reconnaît WireGuard, OpenVPN, IPsec, Tailscale, ZeroTier, NetBird, Nebula, les clients VPN commerciaux et les tunnels génériques."},
	"ov_detected":         {"Detected on this host:", "Найдено на этой машине:", "Détecté sur cette machine :"},
	"kind_mesh":           {"mesh network", "mesh-сеть", "réseau maillé"},
	"kind_vpn":            {"VPN", "VPN", "VPN"},
	"ft_explain":          {"Full tunnel means this machine deliberately sends ALL of its internet traffic through a VPN or an exit node (for example a commercial VPN for privacy). If the VPN or mesh network is only used to reach other machines answer no.", "Полный туннель — это когда машина намеренно отправляет ВЕСЬ свой интернет-трафик через VPN или выходной узел (например, коммерческий VPN ради приватности). Если VPN или mesh-сеть нужны только для доступа к другим машинам, ответьте «no».", "Tunnel complet signifie que cette machine envoie volontairement TOUT son trafic Internet par un VPN ou un nœud de sortie (par exemple un VPN commercial pour la confidentialité). Si le VPN ou le réseau maillé sert seulement à joindre d'autres machines, répondez « no »."},
	"ft_q":                {"Does this host route all of its traffic through a VPN or exit node", "Идёт ли весь трафик этой машины через VPN или выходной узел", "Tout le trafic de cette machine passe-t-il par un VPN ou un nœud de sortie"},
	"ft_no_explain":       {"Only the physical connection may carry this machine's traffic. A VPN, exit node or tunnel that takes it over is removed immediately, even while the internet still works, and a VPN stopped for this is not turned back on.", "Трафик этой машины может идти только через основное (физическое) подключение. VPN, выходной узел или туннель, который перехватит трафик, сразу убирается — даже если интернет ещё работает, — а остановленный из-за этого VPN снова не запускается.", "Seule la connexion principale (physique) peut transporter le trafic de cette machine. Un VPN, un nœud de sortie ou un tunnel qui s'en empare est retiré immédiatement, même si Internet fonctionne encore, et un VPN arrêté pour cette raison n'est pas relancé."},
	"ft_allowed_explain":  {"Which interfaces carry all traffic on purpose? The detected VPN interfaces are suggested.", "Какие интерфейсы намеренно пропускают весь трафик? Предлагаются найденные интерфейсы VPN.", "Quelles interfaces transportent volontairement tout le trafic ? Les interfaces VPN détectées sont proposées."},
	"ft_allowed_q":        {"Interfaces allowed to carry the default route", "Интерфейсы, которым разрешён маршрут по умолчанию (весь трафик)", "Interfaces autorisées à porter la route par défaut"},
	"bypass_explain":      {"If the VPN cuts this machine off (its server is unreachable, or its kill-switch blocks everything else), NetRiser can restore access by removing the VPN's routes or stopping it: traffic then goes outside the VPN until it works again. Answer yes if remote access matters most; answer no if this machine must never send traffic outside the VPN, even at the cost of losing access.", "Если VPN отрезает эту машину от сети (его сервер недоступен или kill-switch блокирует всё остальное), NetRiser может вернуть доступ: убрать маршруты VPN или остановить его. Тогда трафик пойдёт мимо VPN, пока тот снова не заработает. Ответьте «yes», если важнее удалённый доступ; «no» — если трафик ни при каких условиях не должен идти мимо VPN, даже ценой потери доступа.", "Si le VPN coupe cette machine du réseau (serveur injoignable, ou kill-switch qui bloque tout le reste), NetRiser peut rétablir l'accès en retirant les routes du VPN ou en l'arrêtant : le trafic passe alors hors du VPN jusqu'à ce qu'il fonctionne de nouveau. Répondez « yes » si l'accès à distance compte le plus ; « no » si cette machine ne doit jamais envoyer de trafic hors du VPN, même au prix de perdre l'accès."},
	"bypass_q":            {"Is access to this host more important than keeping all traffic in the VPN", "Важнее ли доступ к этой машине, чем удержание всего трафика внутри VPN", "L'accès à cette machine est-il plus important que de garder tout le trafic dans le VPN"},
	"custom_list":         {"Custom VPN/overlay definitions:", "Ваши описания VPN и оверлейных сетей:", "Vos définitions de VPN/overlay :"},
	"custom_item":         {"  %s: interface %q, kind %s, services %s", "  %s: интерфейс %q, тип %s, службы %s", "  %s : interface %q, type %s, services %s"},
	"custom_keep_q":       {"Keep these definitions", "Оставить эти описания", "Conserver ces définitions"},
	"custom_explain":      {"If you use a VPN that NetRiser did not list above, describe it so that NetRiser recognises its interface.", "Если вы используете VPN, которого нет в списке выше, опишите его, чтобы NetRiser распознавал его интерфейс.", "Si vous utilisez un VPN que NetRiser n'a pas listé ci-dessus, décrivez-le pour qu'il reconnaisse son interface."},
	"custom_add_q":        {"Do you use a VPN or overlay that NetRiser does not recognise", "Используете ли вы VPN или оверлейную сеть, которую NetRiser не распознаёт", "Utilisez-vous un VPN ou un overlay que NetRiser ne reconnaît pas"},
	"custom_more_q":       {"Add another one", "Добавить ещё одно", "En ajouter un autre"},
	"custom_name_q":       {"Name", "Название", "Nom"},
	"custom_iface_q":      {"Interface name pattern (regular expression, e.g. ^corp[0-9]+$)", "Шаблон имени интерфейса (регулярное выражение, например ^corp[0-9]+$)", "Motif du nom d'interface (expression régulière, par ex. ^corp[0-9]+$)"},
	"custom_iface_bad":    {"Please enter a valid regular expression.", "Введите корректное регулярное выражение.", "Saisissez une expression régulière valide."},
	"custom_mesh_q":       {"Is it a mesh overlay that should never carry the default route (no = full-tunnel VPN)", "Это mesh-сеть, которая никогда не должна забирать весь трафик (нет = VPN с полным туннелем)", "Est-ce un réseau maillé qui ne doit jamais porter la route par défaut (non = VPN à tunnel complet)"},
	"custom_services_q":   {"Services that run it ({iface} = interface name)", "Службы, которые его запускают ({iface} = имя интерфейса)", "Services qui le font fonctionner ({iface} = nom de l'interface)"},
	"custom_services_bad": {"Service names may contain letters, digits, spaces and @ . _ : - $ { }.", "Имена служб могут содержать буквы, цифры, пробелы и @ . _ : - $ { }.", "Les noms de services peuvent contenir des lettres, chiffres, espaces et @ . _ : - $ { }."},

	// Recovery.
	"sec_recovery":         {"Recovery actions", "Действия по восстановлению", "Actions de rétablissement"},
	"rec_explain":          {"When checks fail several times in a row, NetRiser escalates step by step, from the gentlest action to the strongest. Each stage can be switched off; keeping all three on is recommended.", "Если проверки не проходят несколько раз подряд, NetRiser действует поэтапно — от самого мягкого действия к самому сильному. Каждый этап можно отключить; рекомендуется оставить все три.", "Quand les vérifications échouent plusieurs fois de suite, NetRiser agit par étapes, de l'action la plus douce à la plus forte. Chaque étape peut être désactivée ; il est recommandé de garder les trois."},
	"s1_explain":           {"Stage 1 (safest) removes routes through which a VPN or mesh network wrongly took over all traffic, and restores the route through your normal connection.", "Этап 1 (самый безопасный) убирает маршруты, через которые VPN или mesh-сеть ошибочно забрали весь трафик, и возвращает маршрут через обычное подключение.", "L'étape 1 (la plus sûre) retire les routes par lesquelles un VPN ou un réseau maillé a pris à tort tout le trafic, et rétablit la route par votre connexion normale."},
	"s1_q":                 {"Stage 1: remove rogue default routes published by overlays and restore the uplink route", "Этап 1: убирать посторонние маршруты по умолчанию, добавленные оверлейными сетями, и возвращать маршрут основного подключения", "Étape 1 : retirer les routes par défaut indésirables publiées par les réseaux overlay et rétablir la route de la connexion principale"},
	"s2_explain":           {"Stage 2 temporarily stops the VPN or mesh service that took over the traffic. It is started again later, at most %d times if it keeps breaking the connection.", "Этап 2 временно останавливает службу VPN или mesh-сети, которая перехватила трафик. Позже она запускается снова — не больше %d раз, если продолжает нарушать связь.", "L'étape 2 arrête temporairement le service VPN ou réseau maillé qui a pris le trafic. Il est relancé plus tard, au plus %d fois s'il continue de couper la connexion."},
	"s2_q":                 {"Stage 2: stop an overlay service that publishes a rogue route (restarted after recovery)", "Этап 2: останавливать службу оверлейной сети, добавляющую посторонний маршрут (после восстановления запускается снова)", "Étape 2 : arrêter un service overlay qui publie une route indésirable (relancé après le rétablissement)"},
	"s2_explain_unlimited": {"Stage 2 temporarily stops the VPN or mesh service that took over the traffic. It is started again later.", "Этап 2 временно останавливает службу VPN или mesh-сети, которая перехватила трафик. Позже она запускается снова.", "L'étape 2 arrête temporairement le service VPN ou réseau maillé qui a pris le trafic. Il est relancé plus tard."},
	"s3_explain":           {"Stage 3 restarts network components and switches a disabled network adapter back on.", "Этап 3 перезапускает сетевые компоненты и снова включает отключённый сетевой адаптер.", "L'étape 3 redémarre les composants réseau et réactive une carte réseau désactivée."},
	"s3_q":                 {"Stage 3: restart network components and re-enable a disabled uplink", "Этап 3: перезапускать сетевые компоненты и снова включать отключённый сетевой адаптер", "Étape 3 : redémarrer les composants réseau et réactiver une carte réseau désactivée"},
	"dns_explain":          {"If the internet works but names (like example.com) stop resolving, NetRiser restores the last DNS settings that worked.", "Если интернет работает, но имена (например, example.com) перестали преобразовываться в адреса, NetRiser вернёт последние рабочие настройки DNS.", "Si Internet fonctionne mais que les noms (comme example.com) ne se résolvent plus, NetRiser rétablit les derniers réglages DNS qui fonctionnaient."},
	"dns_q":                {"Restore the last working DNS resolver configuration when name resolution fails", "Восстанавливать последнюю рабочую конфигурацию DNS-преобразователя, если не удаётся преобразовать имена в адреса", "Rétablir la dernière configuration DNS fonctionnelle quand la résolution de noms échoue"},
	"uplink_explain":       {"The uplink is the physical connection to your router or provider (Ethernet or Wi-Fi). NetRiser detects it automatically; type a name only if it picks the wrong one.", "Основное подключение — это физическая связь с роутером или провайдером (Ethernet или Wi-Fi). NetRiser определяет его сам; вводите имя, только если он выбрал неправильно.", "La connexion principale est le lien physique vers votre routeur ou votre fournisseur d'accès (Ethernet ou Wi-Fi). NetRiser la détecte automatiquement ; saisissez un nom seulement s'il se trompe."},
	"uplink_detected":      {"Detected physical uplink: %s", "Найдено основное (физическое) подключение: %s", "Connexion principale (physique) détectée : %s"},
	"uplink_gateway":       {"%s (gateway %s)", "%s (шлюз %s)", "%s (passerelle %s)"},
	"uplink_q":             {"Uplink interface (auto = detect automatically)", "Интерфейс основного подключения (auto = определять автоматически)", "Interface de la connexion principale (auto = détection automatique)"},
	"reboot_explain":       {"Emergency reboot is the last resort: if nothing else brings the connection back after a long continuous outage, the machine restarts. After the restart NetRiser checks again and repeats the recovery stages if needed. If access still does not return, it does not reboot again and only keeps checking until the connection is back.", "Аварийная перезагрузка — последнее средство: если после долгого непрерывного сбоя ничто другое не вернуло связь, машина перезагружается. После перезагрузки NetRiser снова проверяет связь и при необходимости повторяет этапы восстановления. Если доступ так и не вернулся, повторной перезагрузки не будет: NetRiser только продолжает проверять связь, пока она не появится.", "Le redémarrage d'urgence est le dernier recours : si rien d'autre ne rétablit la connexion après une longue coupure continue, la machine redémarre. Après le redémarrage, NetRiser vérifie de nouveau et répète les étapes de rétablissement si nécessaire. Si l'accès ne revient toujours pas, il ne redémarre plus et se contente de vérifier jusqu'au retour de la connexion."},
	"reboot_q":             {"Allow emergency host reboot", "Разрешить аварийную перезагрузку машины", "Autoriser le redémarrage d'urgence de la machine"},
	"reboot_min_q":         {"Minimum continuous outage before reboot, seconds", "Минимальная длительность непрерывного сбоя перед перезагрузкой, секунд", "Durée minimale de coupure continue avant redémarrage, en secondes"},

	// Updates.
	"sec_updates": {"Updates", "Обновления", "Mises à jour"},
	"upd_explain": {"Updates come from %s. They are installed only with a valid NetRiser release signature, never as a downgrade, and not in observation mode.", "Обновления приходят с %s. Они устанавливаются только при действительной подписи выпуска NetRiser, никогда не понижают версию и не устанавливаются в режиме наблюдения.", "Les mises à jour viennent de %s. Elles ne sont installées qu'avec une signature de version NetRiser valide, jamais vers une version plus ancienne, et pas en mode observation."},
	"upd_q":       {"Enable automatic updates", "Включить автоматические обновления", "Activer les mises à jour automatiques"},

	// Summary.
	"sec_summary":  {"Summary", "Итог", "Résumé"},
	"sum_new":      {"A new configuration is created with the answers above.", "Будет создана новая конфигурация с этими ответами.", "Une nouvelle configuration est créée avec les réponses ci-dessus."},
	"sum_new_diff": {"A new configuration is created with the answers above (changes from the defaults are listed).", "Будет создана новая конфигурация с этими ответами (отличия от значений по умолчанию перечислены выше).", "Une nouvelle configuration est créée avec les réponses ci-dessus (les écarts par rapport aux valeurs par défaut sont listés)."},
	"sum_nochange": {"No changes to the current settings.", "Текущие настройки не меняются.", "Aucune modification des réglages actuels."},
	"save_q":       {"Save these settings", "Сохранить эти настройки", "Enregistrer ces réglages"},

	// Result printed after the settings are applied.
	"res_config":                     {"Configuration: %s (%s)", "Конфигурация: %s (%s)", "Configuration : %s (%s)"},
	"res_updated":                    {"updated", "обновлена", "mise à jour"},
	"res_unchanged":                  {"unchanged", "без изменений", "inchangée"},
	"res_observation":                {"Observation mode (no recovery actions): %s", "Режим наблюдения (без действий по восстановлению): %s", "Mode observation (aucune action de rétablissement) : %s"},
	"res_autoupdate":                 {"Automatic updates: %s", "Автоматические обновления: %s", "Mises à jour automatiques : %s"},
	"res_reboot":                     {"Emergency reboot: %s", "Аварийная перезагрузка: %s", "Redémarrage d'urgence : %s"},
	"res_route":                      {"Default route: %s", "Маршрут по умолчанию: %s", "Route par défaut : %s"},
	"res_allowed":                    {"Interfaces allowed to carry the default route: %s", "Интерфейсы, которым разрешён маршрут по умолчанию (весь трафик): %s", "Interfaces autorisées à porter la route par défaut : %s"},
	"res_checks":                     {"Checks: every %ds while healthy, every %ds during an outage", "Проверки: каждые %d с при нормальной связи, каждые %d с во время сбоя", "Vérifications : toutes les %d s en temps normal, toutes les %d s pendant une coupure"},
	"res_log":                        {"Log file: %s (view with: nr logs, nr live)", "Журнал: %s (просмотр: nr logs, nr live)", "Journal : %s (consulter : nr logs, nr live)"},
	"res_incidents":                  {"Incident reports: %s", "Отчёты о сбоях: %s", "Rapports d'incident : %s"},
	"res_restarted":                  {"Service restarted to apply the new settings.", "Служба перезапущена, чтобы применить новые настройки.", "Service redémarré pour appliquer les nouveaux réglages."},
	"res_restart_fail":               {"Settings saved, but the service restart failed: %v", "Настройки сохранены, но перезапустить службу не удалось: %v", "Réglages enregistrés, mais le redémarrage du service a échoué : %v"},
	"policy_uplink":                  {"physical uplink only; a VPN or exit node that takes it over is removed immediately", "только основное (физическое) подключение; VPN или выходной узел, перехвативший трафик, сразу убирается", "connexion principale (physique) uniquement ; un VPN ou nœud de sortie qui s'en empare est retiré immédiatement"},
	"policy_unset":                   {"not set by setup; overlay routes are handled only when checks fail (VPN bypass: %s)", "не задано при настройке; маршруты оверлейных сетей обрабатываются только при сбое проверок (обход VPN: %s)", "non défini par la configuration ; les routes des réseaux overlay ne sont traitées qu'en cas d'échec des vérifications (contournement du VPN : %s)"},
	"policy_access":                  {"full tunnel; access has priority: a VPN that cuts the host off is bypassed", "полный туннель; приоритет у доступа: VPN, отрезавший машину от сети, обходится", "tunnel complet ; l'accès est prioritaire : un VPN qui coupe la machine est contourné"},
	"policy_privacy":                 {"full tunnel; privacy has priority: the VPN is never bypassed", "полный туннель; приоритет у приватности: VPN никогда не обходится", "tunnel complet ; la confidentialité est prioritaire : le VPN n'est jamais contourné"},
	"menu_hint":                      {"←/→ or y/n to choose · Enter to confirm", "←/→ или y/n — выбор · Enter — подтвердить", "←/→ ou y/n pour choisir · Enter pour valider"},
	"choice_retry":                   {"Please choose one of the options shown.", "Выберите один из показанных вариантов.", "Choisissez l'une des options proposées."},
	"section":                        {"%d/%d · %s", "%d/%d · %s", "%d/%d · %s"},
	"sum_explain":                    {"All answers. Changed values show the previous one.", "Все ответы. У изменённых значений показано прежнее.", "Toutes les réponses. Les valeurs modifiées indiquent l'ancienne."},
	"sum_unchanged":                  {"not changed", "не изменено", "inchangé"},
	"sum_default":                    {"default", "по умолчанию", "par défaut"},
	"sum_was":                        {"was: %s", "было: %s", "avant : %s"},
	"val_auto":                       {"auto", "auto", "auto"},
	"lbl_language":                   {"Language", "Язык", "Langue"},
	"lbl_observation_mode":           {"Observation mode", "Режим наблюдения", "Mode observation"},
	"lbl_canary_targets":             {"Internet probes", "Контрольные адреса интернета", "Sondes Internet"},
	"lbl_mesh_canaries":              {"Access check addresses", "Адреса проверки доступа", "Adresses de vérification d'accès"},
	"lbl_full_tunnel":                {"Full tunnel", "Полный туннель", "Tunnel complet"},
	"lbl_allowed_default_interfaces": {"Interfaces for all traffic", "Интерфейсы для всего трафика", "Interfaces pour tout le trafic"},
	"lbl_allow_vpn_bypass":           {"Access before VPN", "Доступ важнее VPN", "Accès avant le VPN"},
	"lbl_overlays":                   {"Custom VPNs", "Свои VPN", "VPN personnalisés"},
	"lbl_allow_route_sanitation":     {"Stage 1: routes", "Этап 1: маршруты", "Étape 1 : routes"},
	"lbl_allow_service_quarantine":   {"Stage 2: services", "Этап 2: службы", "Étape 2 : services"},
	"lbl_allow_network_restart":      {"Stage 3: network restart", "Этап 3: перезапуск сети", "Étape 3 : redémarrage réseau"},
	"lbl_allow_dns_recovery":         {"DNS recovery", "Восстановление DNS", "Rétablissement DNS"},
	"lbl_management_interface":       {"Main connection", "Основное подключение", "Connexion principale"},
	"lbl_enable_reboot":              {"Emergency reboot", "Аварийная перезагрузка", "Redémarrage d'urgence"},
	"lbl_reboot_min_outage_sec":      {"Outage before reboot, s", "Сбой до перезагрузки, с", "Coupure avant redémarrage, s"},
	"lbl_auto_update":                {"Automatic updates", "Автоматические обновления", "Mises à jour automatiques"},
	"lbl_update_url":                 {"Update server", "Сервер обновлений", "Serveur de mises à jour"},
	"sum_default_was":                {"default: %s", "по умолчанию: %s", "par défaut : %s"},
	"access_effect_bypass":           {"If none of them answers in two checks in a row while the internet works, the VPN that carries all traffic is stopped (it is turned back on at most three times).", "Если ни один не ответит две проверки подряд, а интернет работает, VPN, через который идёт весь трафик, будет остановлен (вернуть его попробуют не больше трёх раз).", "Si aucun ne répond lors de deux vérifications consécutives alors qu'Internet fonctionne, le VPN qui transporte tout le trafic est arrêté (il est relancé au plus trois fois)."},
	"access_effect_log":              {"If none of them answers while the internet works, NetRiser records it in its log and in nr status.", "Если ни один не отвечает, а интернет работает, NetRiser записывает это в журнал и показывает в nr status.", "Si aucun ne répond alors qu'Internet fonctionne, NetRiser le consigne dans son journal et dans nr status."},
}
