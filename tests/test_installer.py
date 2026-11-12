"""Exercise the POSIX installer with isolated paths, mocked OS services/downloads
and the real init-config CLI. No host files or network change.
Run: python3 -m unittest discover -s tests -v
"""
import hashlib
import os
from pathlib import Path
import pty
import select
import shlex
import subprocess
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]


def binary_supports_lang():
    """The language is stored by the binary itself; the stored-config assertions
    only apply when this checkout's binary implements setup --lang."""
    return any("--lang=" in f.read_text() for f in (REPO / "cmd/netriser").glob("*.go"))


class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_dir = tempfile.TemporaryDirectory(prefix="netriser-cli-")
        cls.cli = Path(os.environ.get("NETRISER_TEST_BINARY", str(Path(cls.build_dir.name) / "netriser")))
        if not os.environ.get("NETRISER_TEST_BINARY"):
            subprocess.run(["go", "build", "-o", str(cls.cli), "./cmd/netriser"], cwd=REPO, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build_dir.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="netriser-install-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commands = self.root / "commands"
        self.commands.mkdir()
        self.dist = self.root / "download"
        self.dist.mkdir()
        for name in ("LICENSE", "THIRD_PARTY_NOTICES"):
            (self.dist / name).write_bytes((REPO / name).read_bytes())
        self.config = self.root / "etc/netriser/config.yaml"
        self.installer = self.root / "install.sh"
        script = (REPO / "scripts/install.sh").read_text()
        # Relocate production paths while exercising the real control flow.
        for prefix in ("/usr/local", "/etc", "/var", "/run", "/Library"):
            script = script.replace(prefix, str(self.root) + prefix)
        self.installer.write_text(script)
        self.env = dict(os.environ, PATH=str(self.commands) + os.pathsep + os.environ["PATH"],
                        NETRISER_NONINTERACTIVE="1", NETRISER_URL="https://installer.invalid")
        for key in ("CONF_FILE", "NETRISER_AUTO_UPDATE", "NETRISER_ENABLE_REBOOT", "NETRISER_OBSERVATION_MODE",
                    "NETRISER_LANG", "NO_COLOR"):
            self.env.pop(key, None)
        self.env["TERM"] = "xterm"
        self.command("id", "echo 0\n")
        self.command("uname", 'case "$1" in -s) echo Linux;; -m) echo x86_64;; esac\n')
        self.command("systemctl", '''
case "$1" in
  is-active) [ -f "$TEST_ROOT/active" ]; exit $? ;;
  is-enabled) exit 1 ;;
  stop) rm -f "$TEST_ROOT/active" ;;
esac
exit 0
''')
        self.command("curl", '''
url=""; destination=""
while [ "$#" -gt 0 ]; do
  case "$1" in -o) shift; destination="$1";; https://*) url="$1";; esac
  shift
done
filename="$(basename "$url")"
cp "$TEST_DIST/$filename" "$destination"
''')
        self.env.update(TEST_ROOT=str(self.root), TEST_DIST=str(self.dist))
        # Stub privileged migration/service operations only; configuration and
        # version commands execute the application and strict YAML validation.
        self.asset = self.dist / "netriser-linux-amd64"
        self.asset.write_text('''#!/usr/bin/env sh
printf '%s\\n' "$*" >>"$TEST_ROOT/args.log"
case " $* " in
  *" migrate "*) exit 0 ;;
  *" service install "*|*" service restart "*)
    if [ "$TEST_FAIL_SERVICE" = 1 ]; then exit 1; fi
    mkdir -p "$TEST_ROOT/etc/systemd/system"
    printf 'ExecStart=%s run\\n' "$0" >"$TEST_ROOT/etc/systemd/system/netriser.service"
    touch "$TEST_ROOT/active"
    exit 0 ;;
esac
exec ''' + shlex.quote(str(self.cli)) + ''' "$@"
''')
        self.checksum()

    def command(self, name, body):
        path = self.commands / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def checksum(self):
        digest = hashlib.sha256(self.asset.read_bytes()).hexdigest()
        (self.dist / "sha256sums.txt").write_text(f"{digest}  {self.asset.name}\n")

    def run_pipe(self):
        return subprocess.run(["sh", "-c", 'cat "$1" | sh', "installer-test", str(self.installer)],
                              env=self.env, capture_output=True, text=True, timeout=20)

    def test_fresh_pipe_creates_config_and_reports_choices(self):
        result = self.run_pipe()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = self.config.read_text()
        # New installations start read-only and never bypass a VPN by default.
        for line in ("observation_mode: true", "allow_vpn_bypass: false", "auto_update: true", "enable_reboot: false", "recovery_interval_sec: 15", "reboot_min_outage_sec: 300", "netriser setup"):
            self.assertIn(line, config)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertIn("[8/8]", result.stdout)
        self.assertIn("Observation mode (no recovery actions): yes", result.stdout)
        self.assertIn("Enable recovery with: nr observe off", result.stdout)
        self.assertIn("Automatic updates: yes", result.stdout)
        self.assertIn("Emergency reboot: no", result.stdout)
        for name in ("LICENSE", "THIRD_PARTY_NOTICES"):
            self.assertEqual((self.root / "usr/local/share/doc/netriser" / name).read_bytes(), (REPO / name).read_bytes())

    def test_unattended_explicit_choices_and_rerun_preserve_custom_settings(self):
        self.config.parent.mkdir(parents=True)
        initial = "# existing\nauto_update: false\nenable_reboot: true\ncheck_interval_sec: 123\nstate_dir: /custom/state\n"
        self.config.write_text(initial)
        result = self.run_pipe()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.config.read_text(), initial)
        self.env.update(NETRISER_AUTO_UPDATE="true", NETRISER_ENABLE_REBOOT="false", NETRISER_OBSERVATION_MODE="true", NETRISER_ALLOW_VPN_BYPASS="false")
        result = self.run_pipe()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = self.config.read_text()
        for line in ("# existing", "observation_mode: true", "auto_update: true", "enable_reboot: false", "allow_vpn_bypass: false", "check_interval_sec: 123", "state_dir: /custom/state"):
            self.assertIn(line, config)

    def test_bad_checksum_does_not_install(self):
        self.asset.write_text(self.asset.read_text() + "# tampered\n")
        result = self.run_pipe()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.config.exists())
        self.assertFalse((self.root / "usr/local/sbin/netriser").exists())

    def test_custom_config_path_with_spaces_is_preserved(self):
        custom = self.root / "custom settings/config.yaml"
        custom.parent.mkdir()
        initial = "auto_update: false\nenable_reboot: false\ncheck_interval_sec: 98\n"
        custom.write_text(initial)
        self.env["CONF_FILE"] = str(custom)
        result = self.run_pipe()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(custom.read_text(), initial)
        self.assertFalse(self.config.exists())

    def test_invalid_choice_fails_before_modifying_installed_files(self):
        self.env["NETRISER_AUTO_UPDATE"] = "maybe"
        result = self.run_pipe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid setting", result.stderr)
        self.assertFalse((self.root / "usr/local/sbin/netriser").exists())

    def test_failed_service_restores_previous_configuration_and_binary(self):
        self.config.parent.mkdir(parents=True)
        initial = "auto_update: false\nenable_reboot: true\n"
        self.config.write_text(initial)
        binary = self.root / "usr/local/sbin/netriser"
        binary.parent.mkdir(parents=True)
        binary.write_text("previous binary\n")
        license_dir = self.root / "usr/local/share/doc/netriser"
        license_dir.mkdir(parents=True)
        (license_dir / "LICENSE").write_text("previous license\n")
        self.env.update(TEST_FAIL_SERVICE="1", NETRISER_AUTO_UPDATE="true")
        result = self.run_pipe()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_text(), initial)
        self.assertEqual(binary.read_text(), "previous binary\n")
        self.assertEqual((license_dir / "LICENSE").read_text(), "previous license\n")
        self.assertFalse((license_dir / "THIRD_PARTY_NOTICES").exists())

    def binary_args(self):
        """Command lines the downloaded binary was started with."""
        log = self.root / "args.log"
        return log.read_text().splitlines() if log.exists() else []

    def assert_lang_passed(self, code):
        calls = [line for line in self.binary_args() if " setup " in f" {line} "]
        self.assertEqual(len(calls), 2, calls)  # --save-answers, then --answers
        self.assertIn("--save-answers=", calls[0])
        self.assertIn("--answers=", calls[1])
        for line in calls:
            self.assertIn(f"--lang={code}", line)

    def run_terminal(self, answers):
        """Run the piped installer on a pseudo-terminal and answer each prompt.
        answers maps a prompt fragment to a reply; other prompts get Enter."""
        self.env.pop("NETRISER_NONINTERACTIVE", None)
        pid, fd = pty.fork()
        if pid == 0:
            os.execve("/bin/sh", ["sh", "-c", 'cat "$1" | sh', "installer-test", str(self.installer)], self.env)
        output = ""
        answered_upto = 0
        asked = []
        deadline = time.monotonic() + 30
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([fd], [], [], 0.2)
                if not ready:
                    continue
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output += chunk.decode(errors="replace")
                while True:
                    end = output.find("]: ", answered_upto)
                    if end < 0:
                        break
                    # The question is printed above the answer line (and the
                    # options line of an arrow-key menu).
                    prompt = "\n".join(output[answered_upto:end].splitlines()[-3:])
                    reply = next((r for fragment, r in answers.items() if fragment in prompt), "")
                    if isinstance(reply, list):  # one reply per time this prompt is shown
                        reply = reply.pop(0) if reply else ""
                    asked.append(prompt)
                    os.write(fd, reply.encode() + b"\n")
                    answered_upto = end + 3
            else:
                os.kill(pid, 9)
                self.fail("installer did not finish: " + output)
        finally:
            os.close(fd)
            _, status = os.waitpid(pid, 0)
        return os.waitstatus_to_exitcode(status), output, asked

    def test_questions_read_terminal_while_stdin_is_the_script(self):
        code, output, asked = self.run_terminal({
            "Start in observation (read-only) mode": "n",
            "Use these internet probes": "y",
            "Enable automatic updates": "n",
            "Allow emergency host reboot": "y",
            "route all of its traffic through a VPN": "y",
            "Interfaces allowed to carry the default route": "wg0",
            "more important than keeping all traffic in the VPN": "y",
        })
        self.assertEqual(code, 0, output)
        for question in ("observation", "internet probes", "Mesh/VPN endpoints", "traffic through a VPN",
                         "Interfaces allowed", "more important than keeping all traffic", "does not recognise", "Stage 1", "Stage 2", "Stage 3",
                         "Uplink interface", "emergency host reboot", "Minimum continuous outage",
                         "automatic updates", "Save these settings"):
            self.assertTrue(any(question in a for a in asked), f"not asked: {question}\n{output}")
        config = self.config.read_text()
        for line in ("observation_mode: false", "auto_update: false", "enable_reboot: true", "allow_vpn_bypass: true",
                     "full_tunnel: true", "- wg0"):
            self.assertIn(line, config)

    def test_rerun_offers_current_settings_and_cancel_changes_nothing(self):
        self.config.parent.mkdir(parents=True)
        initial = "# mine\nobservation_mode: false\nauto_update: false\n"
        self.config.write_text(initial)
        code, output, asked = self.run_terminal({"Use these internet probes": "y", "Save these settings": "n"})
        self.assertNotEqual(code, 0, output)
        self.assertIn("current settings", output)
        self.assertIn("nothing was changed", output)
        self.assertEqual(self.config.read_text(), initial)
        self.assertFalse((self.root / "usr/local/sbin/netriser").exists())

    def test_choosing_russian_translates_installer_and_passes_lang(self):
        code, output, asked = self.run_terminal({"Language / ": "2"})
        self.assertEqual(code, 0, output)
        self.assertTrue(any(a.startswith("Language / Язык / Langue") and a.endswith("[Enter = 1 (English)") for a in asked), asked)
        for text in ("[1/8] Установка NetRiser", "[8/8] Запускаю NetRiser", "NetRiser установлен и запущен.",
                     "Полезные команды:", "nr observe on|off|status", "nr autoupdate on|off|status",
                     "nr reboot on|off|status", "nr setup"):
            self.assertIn(text, output)
        self.assertNotIn("Installing NetRiser", output)
        self.assert_lang_passed("ru")
        if binary_supports_lang():
            self.assertIn("language: ru", self.config.read_text())

    def test_language_prompt_rejects_invalid_answers_and_accepts_names(self):
        code, output, asked = self.run_terminal({"Language / ": ["9", "FR"]})
        self.assertEqual(code, 0, output)
        self.assertEqual(len([a for a in asked if "Language / " in a]), 2, asked)
        self.assertIn("Saisissez 1, 2 ou 3", output)
        self.assertIn("NetRiser est installé et en cours d'exécution.", output)
        self.assert_lang_passed("fr")

    @unittest.skipUnless(binary_supports_lang(), "needs a binary that stores the language")
    def test_existing_config_language_is_the_prompt_default(self):
        self.config.parent.mkdir(parents=True)
        self.config.write_text("language: ru\n")
        code, output, asked = self.run_terminal({})
        self.assertEqual(code, 0, output)
        self.assertTrue(any("[Enter = 2 (Русский)" in a for a in asked), asked)
        self.assertIn("NetRiser установлен и запущен.", output)
        self.assert_lang_passed("ru")

    def test_env_language_skips_the_prompt_and_uses_french(self):
        self.env["NETRISER_LANG"] = "fr"
        result = self.run_pipe()  # NETRISER_NONINTERACTIVE=1
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for text in ("[1/8] Installation de NetRiser", "Téléchargement du programme", "[8/8] Démarrage de NetRiser",
                     "NetRiser est installé et en cours d'exécution.", "Commandes utiles :", "nr setup"):
            self.assertIn(text, result.stdout)
        self.assertNotIn("Language /", result.stdout)
        self.assert_lang_passed("fr")
        if binary_supports_lang():
            self.assertIn("language: fr", self.config.read_text())
        # An interactive run with NETRISER_LANG set does not ask either.
        (self.root / "args.log").unlink()
        code, output, asked = self.run_terminal({})
        self.assertEqual(code, 0, output)
        self.assertFalse(any("Language / " in a for a in asked), asked)
        self.assertIn("NetRiser est installé", output)

    def test_invalid_env_language_is_rejected_before_any_change(self):
        self.env["NETRISER_LANG"] = "de"
        result = self.run_pipe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NETRISER_LANG", result.stderr)
        self.assertFalse((self.root / "usr/local/sbin/netriser").exists())

    def test_default_is_english_without_a_terminal(self):
        result = self.run_pipe()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("NetRiser is installed and running.", result.stdout)
        self.assertIn("Useful commands:", result.stdout)
        self.assert_lang_passed("en")

    def test_failed_install_reports_rollback_in_the_chosen_language(self):
        self.env.update(TEST_FAIL_SERVICE="1", NETRISER_LANG="ru")
        result = self.run_pipe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Установка NetRiser не удалась", result.stderr)
        self.assertIn("Прежнее состояние восстановлено.", result.stderr)

    def test_no_color_when_disabled_or_not_a_terminal(self):
        # Piped output is not a terminal: no escape sequences at all.
        result = self.run_pipe()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("\x1b[", result.stdout + result.stderr)
        # NO_COLOR disables colors even on a terminal.
        self.env["NO_COLOR"] = "1"
        code, output, _ = self.run_terminal({})
        self.assertEqual(code, 0, output)
        self.assertIn("[8/8]", output)
        self.assertNotIn("\x1b[", output)
        # So does TERM=dumb.
        del self.env["NO_COLOR"]
        self.env["TERM"] = "dumb"
        code, output, _ = self.run_terminal({})
        self.assertEqual(code, 0, output)
        self.assertNotIn("\x1b[", output)

    def test_colors_on_a_terminal(self):
        code, output, _ = self.run_terminal({})
        self.assertEqual(code, 0, output)
        self.assertIn("\x1b[1;36m[1/8]", output)  # step headers: bold cyan
        self.assertIn("\x1b[32mNetRiser is installed and running.", output)  # success: green


if __name__ == "__main__":
    unittest.main()

