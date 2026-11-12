# NetRiser installer for Windows PowerShell. Run from an elevated shell.
# Messages are available in English, Russian and French. Non-ASCII text is kept as
# \uXXXX escapes (decoded by U/Msg) so the script works however it is downloaded
# (irm | iex, file with or without a BOM).
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Output: colors (not with NO_COLOR) and translated messages.
# ---------------------------------------------------------------------------
$UseColor = -not $env:NO_COLOR
$Lang = 'en'
function U([string]$Text) { return [regex]::Unescape($Text) }
$Messages = @{
    en = @{
        admin_need   = 'Administrator privileges are required. Reopen PowerShell as Administrator and run the installer again.'
        choice_bad   = 'Invalid setting for {0}: use true or false.'
        lang_env_bad = 'Invalid NETRISER_LANG value "{0}": use en, ru or fr.'
        lang_retry   = 'Please enter 1, 2 or 3 (or en, ru, fr).  /  \u0412\u0432\u0435\u0434\u0438\u0442\u0435 1, 2 \u0438\u043b\u0438 3 (\u0438\u043b\u0438 en, ru, fr).  /  Saisissez 1, 2 ou 3 (ou en, ru, fr).'
        s1           = '[1/8] Installing NetRiser for windows/amd64: administrator access confirmed'
        s2a          = '[2/8] Downloading the program: {0}'
        s2b          = '[2/8] Downloading the license and third-party notices'
        s3           = '[3/8] Downloading checksums and verifying the SHA-256 of the program (protects against a damaged or tampered file)'
        sum_bad      = 'No valid SHA-256 entry for {0} in sha256sums.txt. Nothing was installed.'
        hash_bad     = 'The SHA-256 of the downloaded program does not match the release checksum. The file may be damaged or tampered with; nothing was installed.'
        s4           = '[4/8] Looking for an existing installation and its configuration'
        cfg_file     = 'Configuration file: {0}'
        bin_run_bad  = 'The downloaded program could not run.'
        noint        = 'No interactive console: a new installation starts in observation mode; existing settings are kept unless NETRISER_* variables select them.'
        ask          = 'Installation questions follow (you can answer them again at any time with: nr setup)'
        setup_fail   = 'Setup was cancelled or failed; nothing was changed.'
        s5           = '[5/8] Saving a rollback backup (everything is restored from it if something fails): {0}'
        s6           = '[6/8] Stopping the old service and installing the verified program'
        migrate_bad  = 'Configuration migration failed (exit {0}).'
        s7           = '[7/8] Writing the configuration (existing settings are kept): {0}'
        cfg_bad      = 'Configuration update failed (exit {0}).'
        s8           = '[8/8] Starting NetRiser and checking that the service is running'
        svc_bad      = 'The NetRiser service operation failed (exit {0}).'
        svc_down     = 'The NetRiser service did not stay running.'
        legacy_bad   = 'Could not remove the old stopped service (exit {0}).'
        rb_fail      = 'NetRiser installation failed; restoring the previous files and service state from {0}'
        rb_done      = 'The previous state has been restored.'
        done         = 'NetRiser is installed and running.'
        backup       = 'Rollback backup (safe to delete once everything works): {0}'
        license      = 'License: MIT; license texts are installed in {0}'
        cmds_title   = 'Useful commands:'
        c_status     = 'show the current state'
        c_logs       = 'show recent log entries'
        c_live       = 'follow the log in real time (Ctrl+C to stop)'
        c_setup      = 'answer the installation questions again'
        c_observe    = 'observation mode: only records incidents, changes nothing'
        c_autoupdate = 'automatic updates'
        c_reboot     = 'emergency reboot of this computer'
        obs_notice   = 'NetRiser is in observation mode: it records incidents but changes nothing. Enable recovery with: nr observe off'
        logs_hint    = 'Logs: nr logs (recent entries), nr live (real time); the log file path is listed in the summary above.'
    }
    ru = @{
        admin_need   = '\u041d\u0443\u0436\u043d\u044b \u043f\u0440\u0430\u0432\u0430 \u0430\u0434\u043c\u0438\u043d\u0438\u0441\u0442\u0440\u0430\u0442\u043e\u0440\u0430. \u041e\u0442\u043a\u0440\u043e\u0439\u0442\u0435 PowerShell \u043e\u0442 \u0438\u043c\u0435\u043d\u0438 \u0430\u0434\u043c\u0438\u043d\u0438\u0441\u0442\u0440\u0430\u0442\u043e\u0440\u0430 \u0438 \u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u0449\u0438\u043a \u0441\u043d\u043e\u0432\u0430.'
        choice_bad   = '\u041d\u0435\u0432\u0435\u0440\u043d\u043e\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0435 \u0434\u043b\u044f {0}: \u0434\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u043e true \u0438\u043b\u0438 false.'
        lang_env_bad = '\u041d\u0435\u0432\u0435\u0440\u043d\u043e\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0435 NETRISER_LANG "{0}": \u0434\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u043e en, ru \u0438\u043b\u0438 fr.'
        s1           = '[1/8] \u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 NetRiser \u0434\u043b\u044f windows/amd64: \u043f\u0440\u0430\u0432\u0430 \u0430\u0434\u043c\u0438\u043d\u0438\u0441\u0442\u0440\u0430\u0442\u043e\u0440\u0430 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u044b'
        s2a          = '[2/8] \u0421\u043a\u0430\u0447\u0438\u0432\u0430\u044e \u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u0443: {0}'
        s2b          = '[2/8] \u0421\u043a\u0430\u0447\u0438\u0432\u0430\u044e \u043b\u0438\u0446\u0435\u043d\u0437\u0438\u044e \u0438 \u0441\u0432\u0435\u0434\u0435\u043d\u0438\u044f \u043e \u0441\u0442\u043e\u0440\u043e\u043d\u043d\u0438\u0445 \u043a\u043e\u043c\u043f\u043e\u043d\u0435\u043d\u0442\u0430\u0445'
        s3           = '[3/8] \u0421\u043a\u0430\u0447\u0438\u0432\u0430\u044e \u043a\u043e\u043d\u0442\u0440\u043e\u043b\u044c\u043d\u044b\u0435 \u0441\u0443\u043c\u043c\u044b \u0438 \u043f\u0440\u043e\u0432\u0435\u0440\u044f\u044e SHA-256 \u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u044b (\u0437\u0430\u0449\u0438\u0442\u0430 \u043e\u0442 \u043f\u043e\u0432\u0440\u0435\u0436\u0434\u0451\u043d\u043d\u043e\u0433\u043e \u0438\u043b\u0438 \u043f\u043e\u0434\u043c\u0435\u043d\u0451\u043d\u043d\u043e\u0433\u043e \u0444\u0430\u0439\u043b\u0430)'
        sum_bad      = '\u0414\u043b\u044f {0} \u0432 sha256sums.txt \u043d\u0435\u0442 \u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u043e\u0439 \u0437\u0430\u043f\u0438\u0441\u0438 SHA-256. \u041d\u0438\u0447\u0435\u0433\u043e \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043e.'
        hash_bad     = 'SHA-256 \u0441\u043a\u0430\u0447\u0430\u043d\u043d\u043e\u0439 \u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u044b \u043d\u0435 \u0441\u043e\u0432\u043f\u0430\u0434\u0430\u0435\u0442 \u0441 \u043a\u043e\u043d\u0442\u0440\u043e\u043b\u044c\u043d\u043e\u0439 \u0441\u0443\u043c\u043c\u043e\u0439 \u0432\u044b\u043f\u0443\u0441\u043a\u0430. \u0424\u0430\u0439\u043b \u043c\u043e\u0433 \u0431\u044b\u0442\u044c \u043f\u043e\u0432\u0440\u0435\u0436\u0434\u0451\u043d \u0438\u043b\u0438 \u043f\u043e\u0434\u043c\u0435\u043d\u0451\u043d; \u043d\u0438\u0447\u0435\u0433\u043e \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043e.'
        s4           = '[4/8] \u0418\u0449\u0443 \u043f\u0440\u0435\u0436\u043d\u044e\u044e \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0443 \u0438 \u0435\u0451 \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438'
        cfg_file     = '\u0424\u0430\u0439\u043b \u043d\u0430\u0441\u0442\u0440\u043e\u0435\u043a: {0}'
        bin_run_bad  = '\u0421\u043a\u0430\u0447\u0430\u043d\u043d\u0443\u044e \u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u0443 \u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u044c.'
        noint        = '\u0418\u043d\u0442\u0435\u0440\u0430\u043a\u0442\u0438\u0432\u043d\u043e\u0439 \u043a\u043e\u043d\u0441\u043e\u043b\u0438 \u043d\u0435\u0442: \u043d\u043e\u0432\u0430\u044f \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 \u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0441\u044f \u0432 \u0440\u0435\u0436\u0438\u043c\u0435 \u043d\u0430\u0431\u043b\u044e\u0434\u0435\u043d\u0438\u044f; \u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u044e\u0449\u0438\u0435 \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 \u0441\u043e\u0445\u0440\u0430\u043d\u044f\u0442\u0441\u044f, \u0435\u0441\u043b\u0438 \u0438\u0445 \u043d\u0435 \u0437\u0430\u0434\u0430\u044e\u0442 \u043f\u0435\u0440\u0435\u043c\u0435\u043d\u043d\u044b\u0435 NETRISER_*.'
        ask          = '\u0414\u0430\u043b\u0435\u0435 \u0432\u043e\u043f\u0440\u043e\u0441\u044b \u043e\u0431 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0435 (\u043f\u043e\u0437\u0436\u0435 \u043d\u0430 \u043d\u0438\u0445 \u043c\u043e\u0436\u043d\u043e \u043e\u0442\u0432\u0435\u0442\u0438\u0442\u044c \u0441\u043d\u043e\u0432\u0430 \u043a\u043e\u043c\u0430\u043d\u0434\u043e\u0439: nr setup)'
        setup_fail   = '\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0430 \u043e\u0442\u043c\u0435\u043d\u0435\u043d\u0430 \u0438\u043b\u0438 \u043d\u0435 \u0443\u0434\u0430\u043b\u0430\u0441\u044c; \u043d\u0438\u0447\u0435\u0433\u043e \u043d\u0435 \u0438\u0437\u043c\u0435\u043d\u0435\u043d\u043e.'
        s5           = '[5/8] \u0421\u043e\u0445\u0440\u0430\u043d\u044f\u044e \u0440\u0435\u0437\u0435\u0440\u0432\u043d\u0443\u044e \u043a\u043e\u043f\u0438\u044e \u0434\u043b\u044f \u043e\u0442\u043a\u0430\u0442\u0430 (\u0435\u0441\u043b\u0438 \u0447\u0442\u043e-\u0442\u043e \u043f\u043e\u0439\u0434\u0451\u0442 \u043d\u0435 \u0442\u0430\u043a, \u0432\u0441\u0451 \u0432\u0435\u0440\u043d\u0451\u0442\u0441\u044f \u043a\u0430\u043a \u0431\u044b\u043b\u043e): {0}'
        s6           = '[6/8] \u041e\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u044e \u0441\u0442\u0430\u0440\u0443\u044e \u0441\u043b\u0443\u0436\u0431\u0443 \u0438 \u0443\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u044e \u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u043d\u0443\u044e \u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u0443'
        migrate_bad  = '\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u0435\u0440\u0435\u043d\u0435\u0441\u0442\u0438 \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 (\u043a\u043e\u0434 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u044f {0}).'
        s7           = '[7/8] \u0417\u0430\u043f\u0438\u0441\u044b\u0432\u0430\u044e \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 (\u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u044e\u0449\u0438\u0435 \u0441\u043e\u0445\u0440\u0430\u043d\u044f\u044e\u0442\u0441\u044f): {0}'
        cfg_bad      = '\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043e\u0431\u043d\u043e\u0432\u0438\u0442\u044c \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 (\u043a\u043e\u0434 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u044f {0}).'
        s8           = '[8/8] \u0417\u0430\u043f\u0443\u0441\u043a\u0430\u044e NetRiser \u0438 \u043f\u0440\u043e\u0432\u0435\u0440\u044f\u044e, \u0447\u0442\u043e \u0441\u043b\u0443\u0436\u0431\u0430 \u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442'
        svc_bad      = '\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0432\u044b\u043f\u043e\u043b\u043d\u0438\u0442\u044c \u043e\u043f\u0435\u0440\u0430\u0446\u0438\u044e \u0441\u043e \u0441\u043b\u0443\u0436\u0431\u043e\u0439 NetRiser (\u043a\u043e\u0434 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u044f {0}).'
        svc_down     = '\u0421\u043b\u0443\u0436\u0431\u0430 NetRiser \u043d\u0435 \u043e\u0441\u0442\u0430\u043b\u0430\u0441\u044c \u0437\u0430\u043f\u0443\u0449\u0435\u043d\u043d\u043e\u0439.'
        legacy_bad   = '\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0443\u0434\u0430\u043b\u0438\u0442\u044c \u0441\u0442\u0430\u0440\u0443\u044e \u043e\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043d\u0443\u044e \u0441\u043b\u0443\u0436\u0431\u0443 (\u043a\u043e\u0434 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u044f {0}).'
        rb_fail      = '\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 NetRiser \u043d\u0435 \u0443\u0434\u0430\u043b\u0430\u0441\u044c; \u0432\u043e\u0437\u0432\u0440\u0430\u0449\u0430\u044e \u043f\u0440\u0435\u0436\u043d\u0438\u0435 \u0444\u0430\u0439\u043b\u044b \u0438 \u0441\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u0435 \u0441\u043b\u0443\u0436\u0431\u044b \u0438\u0437 \u0440\u0435\u0437\u0435\u0440\u0432\u043d\u043e\u0439 \u043a\u043e\u043f\u0438\u0438: {0}'
        rb_done      = '\u041f\u0440\u0435\u0436\u043d\u0435\u0435 \u0441\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u0435 \u0432\u043e\u0441\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043e.'
        done         = 'NetRiser \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d \u0438 \u0437\u0430\u043f\u0443\u0449\u0435\u043d.'
        backup       = '\u0420\u0435\u0437\u0435\u0440\u0432\u043d\u0430\u044f \u043a\u043e\u043f\u0438\u044f \u0434\u043b\u044f \u043e\u0442\u043a\u0430\u0442\u0430 (\u043c\u043e\u0436\u043d\u043e \u0443\u0434\u0430\u043b\u0438\u0442\u044c, \u043a\u043e\u0433\u0434\u0430 \u0443\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044c, \u0447\u0442\u043e \u0432\u0441\u0451 \u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442): {0}'
        license      = '\u041b\u0438\u0446\u0435\u043d\u0437\u0438\u044f: MIT; \u0442\u0435\u043a\u0441\u0442\u044b \u043b\u0438\u0446\u0435\u043d\u0437\u0438\u0439 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u044b \u0432 {0}'
        cmds_title   = '\u041f\u043e\u043b\u0435\u0437\u043d\u044b\u0435 \u043a\u043e\u043c\u0430\u043d\u0434\u044b:'
        c_status     = '\u043f\u043e\u043a\u0430\u0437\u0430\u0442\u044c \u0442\u0435\u043a\u0443\u0449\u0435\u0435 \u0441\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u0435'
        c_logs       = '\u043f\u043e\u043a\u0430\u0437\u0430\u0442\u044c \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0435 \u0437\u0430\u043f\u0438\u0441\u0438 \u0436\u0443\u0440\u043d\u0430\u043b\u0430'
        c_live       = '\u0441\u043b\u0435\u0434\u0438\u0442\u044c \u0437\u0430 \u0436\u0443\u0440\u043d\u0430\u043b\u043e\u043c \u0432 \u0440\u0435\u0430\u043b\u044c\u043d\u043e\u043c \u0432\u0440\u0435\u043c\u0435\u043d\u0438 (Ctrl+C - \u0432\u044b\u0445\u043e\u0434)'
        c_setup      = '\u043e\u0442\u0432\u0435\u0442\u0438\u0442\u044c \u043d\u0430 \u0432\u043e\u043f\u0440\u043e\u0441\u044b \u043e\u0431 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0435 \u0437\u0430\u043d\u043e\u0432\u043e'
        c_observe    = '\u0440\u0435\u0436\u0438\u043c \u043d\u0430\u0431\u043b\u044e\u0434\u0435\u043d\u0438\u044f: \u0442\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u043f\u0438\u0441\u044b\u0432\u0430\u0435\u0442 \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u044b, \u043d\u0438\u0447\u0435\u0433\u043e \u043d\u0435 \u043c\u0435\u043d\u044f\u0435\u0442'
        c_autoupdate = '\u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438\u0435 \u043e\u0431\u043d\u043e\u0432\u043b\u0435\u043d\u0438\u044f'
        c_reboot     = '\u0430\u0432\u0430\u0440\u0438\u0439\u043d\u0430\u044f \u043f\u0435\u0440\u0435\u0437\u0430\u0433\u0440\u0443\u0437\u043a\u0430 \u044d\u0442\u043e\u0433\u043e \u043a\u043e\u043c\u043f\u044c\u044e\u0442\u0435\u0440\u0430'
        obs_notice   = 'NetRiser \u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442 \u0432 \u0440\u0435\u0436\u0438\u043c\u0435 \u043d\u0430\u0431\u043b\u044e\u0434\u0435\u043d\u0438\u044f: \u043e\u043d \u0437\u0430\u043f\u0438\u0441\u044b\u0432\u0430\u0435\u0442 \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u044b, \u043d\u043e \u043d\u0438\u0447\u0435\u0433\u043e \u043d\u0435 \u043c\u0435\u043d\u044f\u0435\u0442. \u0427\u0442\u043e\u0431\u044b \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u044c \u0432\u043e\u0441\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u0438\u0435, \u0432\u044b\u043f\u043e\u043b\u043d\u0438\u0442\u0435: nr observe off'
        logs_hint    = '\u0416\u0443\u0440\u043d\u0430\u043b: nr logs (\u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0435 \u0437\u0430\u043f\u0438\u0441\u0438), nr live (\u0432 \u0440\u0435\u0430\u043b\u044c\u043d\u043e\u043c \u0432\u0440\u0435\u043c\u0435\u043d\u0438); \u043f\u0443\u0442\u044c \u043a \u0444\u0430\u0439\u043b\u0443 \u0436\u0443\u0440\u043d\u0430\u043b\u0430 \u0443\u043a\u0430\u0437\u0430\u043d \u0432\u044b\u0448\u0435, \u0432 \u0441\u0432\u043e\u0434\u043a\u0435.'
    }
    fr = @{
        admin_need   = 'Les droits d''administrateur sont n\u00e9cessaires. Rouvrez PowerShell en tant qu''administrateur puis relancez l''installateur.'
        choice_bad   = 'Valeur incorrecte pour {0} : utilisez true ou false.'
        lang_env_bad = 'Valeur incorrecte de NETRISER_LANG "{0}" : utilisez en, ru ou fr.'
        s1           = '[1/8] Installation de NetRiser pour windows/amd64 : droits d''administrateur confirm\u00e9s'
        s2a          = '[2/8] T\u00e9l\u00e9chargement du programme : {0}'
        s2b          = '[2/8] T\u00e9l\u00e9chargement de la licence et des mentions des composants tiers'
        s3           = '[3/8] T\u00e9l\u00e9chargement des sommes de contr\u00f4le et v\u00e9rification du SHA-256 du programme (prot\u00e8ge contre un fichier endommag\u00e9 ou alt\u00e9r\u00e9)'
        sum_bad      = 'Aucune entr\u00e9e SHA-256 valide pour {0} dans sha256sums.txt. Rien n''a \u00e9t\u00e9 install\u00e9.'
        hash_bad     = 'Le SHA-256 du programme t\u00e9l\u00e9charg\u00e9 ne correspond pas \u00e0 la somme de contr\u00f4le de la version. Le fichier est peut-\u00eatre endommag\u00e9 ou alt\u00e9r\u00e9 ; rien n''a \u00e9t\u00e9 install\u00e9.'
        s4           = '[4/8] Recherche d''une installation existante et de sa configuration'
        cfg_file     = 'Fichier de configuration : {0}'
        bin_run_bad  = 'Le programme t\u00e9l\u00e9charg\u00e9 n''a pas pu s''ex\u00e9cuter.'
        noint        = 'Aucune console interactive : une nouvelle installation d\u00e9marre en mode observation ; les r\u00e9glages existants sont conserv\u00e9s, sauf si des variables NETRISER_* les modifient.'
        ask          = 'Les questions d''installation suivent (vous pourrez y r\u00e9pondre \u00e0 nouveau \u00e0 tout moment avec : nr setup)'
        setup_fail   = 'La configuration a \u00e9t\u00e9 annul\u00e9e ou a \u00e9chou\u00e9 ; rien n''a \u00e9t\u00e9 modifi\u00e9.'
        s5           = '[5/8] Cr\u00e9ation d''une sauvegarde de retour arri\u00e8re (tout en est restaur\u00e9 en cas de probl\u00e8me) : {0}'
        s6           = '[6/8] Arr\u00eat de l''ancien service et installation du programme v\u00e9rifi\u00e9'
        migrate_bad  = 'La migration de la configuration a \u00e9chou\u00e9 (code {0}).'
        s7           = '[7/8] \u00c9criture de la configuration (les r\u00e9glages existants sont conserv\u00e9s) : {0}'
        cfg_bad      = 'La mise \u00e0 jour de la configuration a \u00e9chou\u00e9 (code {0}).'
        s8           = '[8/8] D\u00e9marrage de NetRiser et v\u00e9rification que le service fonctionne'
        svc_bad      = 'L''op\u00e9ration sur le service NetRiser a \u00e9chou\u00e9 (code {0}).'
        svc_down     = 'Le service NetRiser n''est pas rest\u00e9 en cours d''ex\u00e9cution.'
        legacy_bad   = 'Impossible de supprimer l''ancien service arr\u00eat\u00e9 (code {0}).'
        rb_fail      = 'L''installation de NetRiser a \u00e9chou\u00e9 ; restauration des fichiers et de l''\u00e9tat du service depuis la sauvegarde : {0}'
        rb_done      = 'L''\u00e9tat pr\u00e9c\u00e9dent a \u00e9t\u00e9 restaur\u00e9.'
        done         = 'NetRiser est install\u00e9 et en cours d''ex\u00e9cution.'
        backup       = 'Sauvegarde de retour arri\u00e8re (vous pouvez la supprimer quand tout fonctionne) : {0}'
        license      = 'Licence : MIT ; les textes des licences sont install\u00e9s dans {0}'
        cmds_title   = 'Commandes utiles :'
        c_status     = 'afficher l''\u00e9tat actuel'
        c_logs       = 'afficher les derni\u00e8res entr\u00e9es du journal'
        c_live       = 'suivre le journal en temps r\u00e9el (Ctrl+C pour arr\u00eater)'
        c_setup      = 'r\u00e9pondre de nouveau aux questions d''installation'
        c_observe    = 'mode observation : enregistre les incidents sans rien modifier'
        c_autoupdate = 'mises \u00e0 jour automatiques'
        c_reboot     = 'red\u00e9marrage d''urgence de cet ordinateur'
        obs_notice   = 'NetRiser est en mode observation : il enregistre les incidents mais ne modifie rien. Pour activer la r\u00e9paration, ex\u00e9cutez : nr observe off'
        logs_hint    = 'Journaux : nr logs (derni\u00e8res entr\u00e9es), nr live (temps r\u00e9el) ; le chemin du fichier journal figure dans le r\u00e9sum\u00e9 ci-dessus.'
    }
}
# Msg KEY [ARG...]: the text for KEY in the chosen language (English if missing).
function Msg {
    param([string]$Key)
    $table = $Messages[$script:Lang]
    $text = if ($table -and $table.ContainsKey($Key)) { $table[$Key] } else { $Messages['en'][$Key] }
    $text = [regex]::Unescape($text)
    if ($args.Count -gt 0) { return ($text -f $args) }
    return $text
}
function Say([string]$Text, [string]$Color) {
    if ($Color -and $UseColor) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}
function Write-Step { Say (Msg @args) 'Cyan' }
function Write-Ok { Say (Msg @args) 'Green' }
function Write-Warn { Say (Msg @args) 'Yellow' }
function Write-Err { Say (Msg @args) 'Red' }
function Write-Hint { Say (Msg @args) 'DarkGray' }
function Write-Info { Say (Msg @args) '' }
function Write-Cmd([string]$Command, [string]$Key) {
    $label = '  ' + $Command.PadRight(28) + ' '
    if ($UseColor) {
        Write-Host $label -NoNewline -ForegroundColor Green
        Write-Host (Msg $Key)
    } else {
        Write-Host ($label + (Msg $Key))
    }
}
function Normalize-Lang([string]$Value) {
    if (-not $Value) { return $null }
    switch ($Value.Trim().ToLowerInvariant()) {
        { $_ -in @('1', 'en', 'english') } { return 'en' }
        { $_ -in @('2', 'ru', 'russian') } { return 'ru' }
        { $_ -in @('3', 'fr', 'french', 'francais') } { return 'fr' }
        default { return $null }
    }
}
if ($env:NETRISER_LANG) {
    $envLang = Normalize-Lang $env:NETRISER_LANG
    if (-not $envLang) { throw (Msg 'lang_env_bad' $env:NETRISER_LANG) }
    $Lang = $envLang
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw (Msg 'admin_need')
}

$DistUrl = if ($env:NETRISER_URL) { $env:NETRISER_URL } elseif ($env:WATCHDOG_URL) { $env:WATCHDOG_URL } else { 'https://netriser.repentandliveholy.org' }
$BinDir = Join-Path $env:ProgramFiles 'NetRiser'
$BinPath = Join-Path $BinDir 'netriser.exe'
$LicenseDir = Join-Path $BinDir 'licenses'
$StagePath = Join-Path $BinDir ".netriser-$([guid]::NewGuid().ToString('N')).new"
$LegacyDir = Join-Path $env:ProgramFiles 'mesh-watchdog'
$LegacyPath = Join-Path $LegacyDir 'mesh-watchdog.exe'
$ProgramData = $env:ProgramData
$NewData = Join-Path $ProgramData 'netriser'
$LegacyData = Join-Path $ProgramData 'mesh-watchdog'
$TempDir = Join-Path $env:TEMP "netriser-$([guid]::NewGuid().ToString('N'))"
$TempPath = Join-Path $TempDir 'netriser-windows-amd64.exe'
$LegacyService = Get-CimInstance Win32_Service -Filter "Name='mesh-watchdog'" -ErrorAction SilentlyContinue
$NewService = Get-CimInstance Win32_Service -Filter "Name='netriser'" -ErrorAction SilentlyContinue
$LegacyWasRunning = $LegacyService -and $LegacyService.State -eq 'Running'
$NewWasRunning = $NewService -and $NewService.State -eq 'Running'
$LegacyConfig = $env:CONF_FILE
$Backup = $null
$Mutating = $false
$MachinePathBefore = $null
$ProcessPathBefore = $env:Path
$MachinePathChanged = $false
$ProcessPathChanged = $false

if (-not $LegacyConfig -and $LegacyService -and $LegacyService.PathName -match '--config(?:=|\s+)(?:"([^"]+)"|(\S+))') {
    $LegacyConfig = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
}
if (-not $LegacyConfig -and $NewService -and $NewService.PathName -match '--config(?:=|\s+)(?:"([^"]+)"|(\S+))') {
    $LegacyConfig = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
}
$EffectiveConfig = if ($LegacyConfig) { $LegacyConfig } else { Join-Path $NewData 'config.yaml' }

# Interactive means a real console (not redirected) and no NETRISER_NONINTERACTIVE=1.
$Interactive = -not ($env:NETRISER_NONINTERACTIVE -eq '1' -or -not [Environment]::UserInteractive -or [Console]::IsInputRedirected)

# The "language:" value of an existing configuration file, or $null.
function Get-ConfigLanguage([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction Stop)) {
            if ($line -match '^language:\s*"?([A-Za-z]+)"?') { return (Normalize-Lang $Matches[1]) }
        }
    } catch { }
    return $null
}
# Language: NETRISER_LANG (already applied above), else the "language:" of the
# configuration this install will use, else English. Asked once (all three
# languages on one line) only when a console is available.
function Select-Language {
    if ($env:NETRISER_LANG) { return }
    $default = Get-ConfigLanguage $EffectiveConfig
    if (-not $default) { $default = 'en' }
    $script:Lang = $default
    if (-not $Interactive) { return }
    $label = switch ($default) {
        'ru' { U '2 (\u0420\u0443\u0441\u0441\u043a\u0438\u0439)' }
        'fr' { U '3 (Fran\u00e7ais)' }
        default { '1 (English)' }
    }
    $prompt = (U 'Language / \u042f\u0437\u044b\u043a / Langue: 1) English  2) \u0420\u0443\u0441\u0441\u043a\u0438\u0439  3) Fran\u00e7ais [Enter = ') + $label + ']'
    while ($true) {
        $answer = Read-Host $prompt
        if (-not $answer -or -not $answer.Trim()) { return }
        $picked = Normalize-Lang $answer
        if ($picked) { $script:Lang = $picked; return }
        Write-Warn 'lang_retry'
    }
}

function Copy-BackupPath([string]$Path) {
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $relative = $Path -replace '^[A-Za-z]:\\', ''
        $destination = Join-Path $Backup (Join-Path 'files' $relative)
        $parent = Split-Path -Parent $destination
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        Copy-Item -LiteralPath $Path -Destination $destination -Recurse -Force
    }
}
function Normalize-Choice([string]$Label, [string]$Supplied) {
    if (-not $Supplied) { return '' }
    switch ($Supplied.ToLowerInvariant()) {
        { $_ -in @('true', 'yes', 'y', '1', 'on') } { return 'true' }
        { $_ -in @('false', 'no', 'n', '0', 'off') } { return 'false' }
        default { throw (Msg 'choice_bad' $Label) }
    }
}
function Restore-BackupPath([string]$Path) {
    if (-not $Path) { return }
    $relative = $Path -replace '^[A-Za-z]:\\', ''
    $saved = Join-Path $Backup (Join-Path 'files' $relative)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
    if (Test-Path -LiteralPath $saved) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
        Copy-Item -LiteralPath $saved -Destination $Path -Recurse -Force
    }
}
function Restore-LegacyService {
    if (-not $LegacyService) { return }
    if ($LegacyService.StartMode -eq 'Auto') { Set-Service mesh-watchdog -StartupType Automatic -ErrorAction SilentlyContinue }
    elseif ($LegacyService.StartMode -eq 'Disabled') { Set-Service mesh-watchdog -StartupType Disabled -ErrorAction SilentlyContinue }
    else { Set-Service mesh-watchdog -StartupType Manual -ErrorAction SilentlyContinue }
    if ($LegacyWasRunning) { Start-Service mesh-watchdog -ErrorAction SilentlyContinue }
}
function Rollback-Install {
    if (-not $Backup -or -not $Mutating) { return }
    Write-Err 'rb_fail' $Backup
    Stop-Service netriser -Force -ErrorAction SilentlyContinue
    if (-not $NewService) { & sc.exe delete netriser | Out-Null }
    if ($StagePath) { Remove-Item -LiteralPath $StagePath -Force -ErrorAction SilentlyContinue }
    foreach ($path in @($LicenseDir, $BinPath, (Join-Path $BinDir 'nr.cmd'), (Join-Path $BinDir 'mesh-watchdog.cmd'), $NewData, $LegacyData, $LegacyPath, $LegacyConfig)) {
        Restore-BackupPath $path
    }
    if ($NewWasRunning) { Start-Service netriser -ErrorAction SilentlyContinue }
    Restore-LegacyService
    if ($MachinePathChanged) { [Environment]::SetEnvironmentVariable('Path', $MachinePathBefore, 'Machine') }
    if ($ProcessPathChanged) { $env:Path = $ProcessPathBefore }
    Write-Warn 'rb_done'
}

try {
    Select-Language
    Write-Step 's1'
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    $asset = 'netriser-windows-amd64.exe'
    $base = $DistUrl.TrimEnd('/')
    Write-Step 's2a' "$base/bin/$asset"
    Invoke-WebRequest -Uri "$base/bin/$asset" -OutFile $TempPath
    Write-Step 's2b'
    foreach ($name in @('LICENSE', 'THIRD_PARTY_NOTICES')) {
        Invoke-WebRequest -Uri "$base/$name" -OutFile (Join-Path $TempDir $name)
    }
    $sumsPath = Join-Path $TempDir 'sha256sums.txt'
    Write-Step 's3'
    Invoke-WebRequest -Uri "$base/sha256sums.txt" -OutFile $sumsPath
    $sumLine = Get-Content $sumsPath | Where-Object { $_ -match "\s+$([regex]::Escape($asset))$" } | Select-Object -First 1
    if (-not $sumLine -or $sumLine -notmatch '^([0-9a-fA-F]{64})\s+') { throw (Msg 'sum_bad' $asset) }
    $expectedHash = $Matches[1].ToLowerInvariant()
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $TempPath).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) { throw (Msg 'hash_bad') }
    Write-Step 's4'
    & $TempPath version
    if ($LASTEXITCODE -ne 0) { throw (Msg 'bin_run_bad') }
    Write-Hint 'cfg_file' $EffectiveConfig
    # Questions are asked by the verified binary before anything is stopped or
    # changed; the answers are applied in step 7.
    $AnswersPath = Join-Path $TempDir 'answers.yaml'
    $setupArgs = @('--config', $EffectiveConfig, 'setup', "--save-answers=$AnswersPath", "--lang=$($script:Lang)")
    foreach ($choice in @(
            @('NETRISER_OBSERVATION_MODE', '--observation-mode'),
            @('NETRISER_AUTO_UPDATE', '--auto-update'),
            @('NETRISER_ENABLE_REBOOT', '--enable-reboot'),
            @('NETRISER_ALLOW_VPN_BYPASS', '--allow-vpn-bypass'),
            @('NETRISER_FULL_TUNNEL', '--full-tunnel'))) {
        $value = Normalize-Choice $choice[0] ([Environment]::GetEnvironmentVariable($choice[0]))
        if ($value) { $setupArgs += "$($choice[1])=$value" }
    }
    if (-not $Interactive) {
        Write-Hint 'noint'
        $setupArgs += '--non-interactive'
    } else {
        Write-Info 'ask'
    }
    & $TempPath @setupArgs
    if ($LASTEXITCODE -ne 0) { throw (Msg 'setup_fail') }

    $Backup = Join-Path $ProgramData "NetRiser-Backups\migration-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))-$([guid]::NewGuid().ToString('N'))"
    Write-Step 's5' $Backup
    New-Item -ItemType Directory -Path $Backup -Force | Out-Null
    foreach ($path in @($LicenseDir, $BinPath, (Join-Path $BinDir 'nr.cmd'), (Join-Path $BinDir 'mesh-watchdog.cmd'), $LegacyPath, $NewData, $LegacyData, $LegacyConfig)) { Copy-BackupPath $path }
    if ($LegacyService) { & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\mesh-watchdog' (Join-Path $Backup 'legacy-service.reg') /y | Out-Null }
    if ($NewService) { & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\netriser' (Join-Path $Backup 'netriser-service.reg') /y | Out-Null }

    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    $Mutating = $true
    Write-Step 's6'
    if ($NewWasRunning) { Stop-Service netriser -Force }
    if ($LegacyWasRunning) { Stop-Service mesh-watchdog -Force }
    if ($LegacyService) { Set-Service mesh-watchdog -StartupType Disabled }

    Copy-Item -LiteralPath $TempPath -Destination $StagePath -Force
    if (Test-Path -LiteralPath $BinPath) {
        # Windows PowerShell converts $null to "" for .NET string arguments;
        # File.Replace rejects "" as a backup path. Pass a real null instead.
        [System.IO.File]::Replace($StagePath, $BinPath, [NullString]::Value, $true)
    } else {
        Move-Item -LiteralPath $StagePath -Destination $BinPath
    }
    New-Item -ItemType Directory -Path $LicenseDir -Force | Out-Null
    foreach ($name in @('LICENSE', 'THIRD_PARTY_NOTICES')) {
        Copy-Item -LiteralPath (Join-Path $TempDir $name) -Destination (Join-Path $LicenseDir $name) -Force
    }

    if ($LegacyConfig) {
        & $BinPath --config $LegacyConfig migrate
    } else {
        & $BinPath migrate
    }
    if ($LASTEXITCODE -ne 0) { throw (Msg 'migrate_bad' $LASTEXITCODE) }

    Write-Step 's7' $EffectiveConfig
    & $BinPath --config $EffectiveConfig setup "--answers=$AnswersPath" "--lang=$($script:Lang)" --no-restart
    if ($LASTEXITCODE -ne 0) { throw (Msg 'cfg_bad' $LASTEXITCODE) }

    Write-Step 's8'
    if ($NewService) {
        Restart-Service netriser -ErrorAction Stop
    } elseif ($LegacyConfig) {
        & $BinPath --config $LegacyConfig service install
    } else {
        & $BinPath service install
    }
    if ($LASTEXITCODE -ne 0) { throw (Msg 'svc_bad' $LASTEXITCODE) }
    $serviceNow = Get-Service netriser -ErrorAction Stop
    if ($serviceNow.Status -ne 'Running') { throw (Msg 'svc_down') }

    # Command wrappers always execute the service binary, so self-update also
    # updates what the terminal command invokes.
    $wrapper = @('@echo off', '"%~dp0netriser.exe" %*', 'exit /b %ERRORLEVEL%') -join "`r`n"
    Set-Content -LiteralPath (Join-Path $BinDir 'nr.cmd') -Encoding ASCII -Value $wrapper
    Set-Content -LiteralPath (Join-Path $BinDir 'mesh-watchdog.cmd') -Encoding ASCII -Value $wrapper

    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $MachinePathBefore = $machinePath
    $pathParts = @($machinePath -split ';' | Where-Object { $_ })
    if (-not ($pathParts | Where-Object { $_.TrimEnd('\') -ieq $BinDir.TrimEnd('\') })) {
        $newPath = (@($pathParts) + @($BinDir)) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
        $MachinePathChanged = $true
    }
    if (-not (($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $BinDir.TrimEnd('\') })) {
        $env:Path = "$BinDir;$env:Path"
        $ProcessPathChanged = $true
    }

    & $BinPath version
    if ($LegacyService) {
        & sc.exe delete mesh-watchdog | Out-Null
        if ($LASTEXITCODE -ne 0) { throw (Msg 'legacy_bad' $LASTEXITCODE) }
    }
    Write-Host ''
    Write-Ok 'done'
    Write-Hint 'backup' $Backup
    Write-Hint 'license' $LicenseDir
    Write-Host ''
    Write-Info 'cmds_title'
    Write-Cmd 'nr status' 'c_status'
    Write-Cmd 'nr logs' 'c_logs'
    Write-Cmd 'nr live' 'c_live'
    Write-Cmd 'nr setup' 'c_setup'
    Write-Cmd 'nr observe on|off|status' 'c_observe'
    Write-Cmd 'nr autoupdate on|off|status' 'c_autoupdate'
    Write-Cmd 'nr reboot on|off|status' 'c_reboot'
    Write-Host ''
    # The status text may be localized by the binary, so also look at the config.
    $observing = ((& $BinPath --config $EffectiveConfig observe status) -join "`n") -match 'Observation mode: ON'
    if (-not $observing -and (Test-Path -LiteralPath $EffectiveConfig)) {
        $observing = (Get-Content -LiteralPath $EffectiveConfig -Raw) -match '(?m)^observation_mode:\s*true'
    }
    if ($observing) { Write-Warn 'obs_notice' }
    Write-Hint 'logs_hint'
} catch {
    Rollback-Install
    throw
} finally {
    Remove-Item -LiteralPath $StagePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
