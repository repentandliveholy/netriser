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
        for key in ("CONF_FILE", "NETRISER_AUTO_UPDATE", "NETRISER_ENABLE_REBOOT", "NETRISER_OBSERVATION_MODE"):
            self.env.pop(key, None)
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
        self.assertIn("Observation mode (no recovery actions): true", result.stdout)
        self.assertIn("Enable recovery with: nr observe off", result.stdout)
        self.assertIn("Automatic updates: true", result.stdout)
        self.assertIn("Emergency reboot: false", result.stdout)
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
                    prompt = output[answered_upto:end].splitlines()[-1]
                    reply = next((r for fragment, r in answers.items() if fragment in prompt), "")
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
            "May NetRiser bypass a full-tunnel VPN": "y",
        })
        self.assertEqual(code, 0, output)
        for question in ("observation", "internet probes", "Mesh/VPN endpoints", "traffic through a VPN",
                         "bypass a full-tunnel VPN", "does not recognise", "Stage 1", "Stage 2", "Stage 3",
                         "Uplink interface", "emergency host reboot", "Minimum continuous outage",
                         "automatic updates", "Save these settings"):
            self.assertTrue(any(question in a for a in asked), f"not asked: {question}\n{output}")
        config = self.config.read_text()
        for line in ("observation_mode: false", "auto_update: false", "enable_reboot: true", "allow_vpn_bypass: true"):
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


if __name__ == "__main__":
    unittest.main()

