# Changelog

## 1.3.6 (not released yet)

Local block recovery on Linux and macOS
- The same recovery as on Windows. A connection to the host's own address
  goes over loopback there, which firewalls usually accept, so each check
  creates a temporary virtual Ethernet pair (Linux veth `nrprobe0/1`, macOS
  feth `feth3170/3171`, addresses 198.18.231.1–2), sends a TCP SYN to the
  host's address from the far side over a raw socket (AF_PACKET, BPF) and
  removes the pair (with a temporary `ip rule` so that source-based policy
  routing, NetRiser's own included, does not send the answer elsewhere; on
  macOS with `check_interface=1` the probe targets the pair's address).
  A port counts only after it has passed this check once,
  so a firewall admitting SSH only from certain networks is not a block.
- Linux: new nftables and iptables tables (legacy and nft backends) are
  removed or emptied, changed ones put back to a copy from before the change
  (kept in `rules/` in the state directory; Docker, Kubernetes, VPN and
  fail2ban/CrowdSec chains and set contents are ignored); new enabled
  services that load firewall rules are stopped and disabled; unsigned
  out-of-tree kernel modules are blocked from loading and unloaded.
- macOS: pf turned on, new or changed pf rules and anchors (not Apple's),
  the application firewall's "block all incoming connections" and firewall
  launch daemons; network extensions are reported only.
- `nr blockers` lists ports that never passed as "Not counted"; restore
  loads the saved rules, re-enables services and lets modules load again.

Offline installation on Linux and macOS
- `sudo ./netriser-<os>-<arch> install` installs from the file itself,
  without network access: the program carries `install.sh` and runs it with
  the local file (same questions, backup, migration and rollback). The
  installer lists `nr blockers` among the useful commands.

Site
- The first download button follows the visitor's system (Windows,
  macOS Apple Silicon with an Intel link, Linux x86_64 or ARM64); on Windows
  the PowerShell command is listed first. Without JavaScript it links to the
  Downloads section.

Local block recovery (Windows)
- A test-signed driver that worked for more than an hour and then began
  blocking was not suspected: the record of the working state counted it as
  known, and the untrusted-driver rule ran only without a record. Now, when
  nothing is new since the host last worked, loaded drivers without a
  trusted signature (created without a signed driver package) and the
  services that start them are chosen as well.
- New setting `local_block_untrusted_drivers` (default `true`); `false` keeps
  recovery to what changed since the host last worked. Asked in `nr setup`
  and by the `.exe` installer (`--untrusted-drivers=bool` for `setup`), shown
  in `nr status` ("Local Block Recovery") and `nr blockers` ("Rule").

## 1.3.5

Local block recovery (Windows)
- New: software on the host itself that blocks connections is found and
  disabled. Every check, the host connects to its own listening
  `access_ports` (22, 3389). When they do not accept their own host in two
  checks in a row (a firewall driver holding connections, as an RFW test
  build did on WS-OVS-010: Tailscale still answered pings, SSH and RDP did
  not), NetRiser disables the loaded drivers and automatic services that are
  new or changed since the host last worked, then checks again. Without a
  record of the working state (NetRiser installed on an already blocked
  host) only loaded drivers created without a signed driver package and
  without a trusted signature (test mode) are chosen. Services that start a
  chosen driver are disabled with it. Never touched: components signed by
  Microsoft, device drivers, boot drivers, remote access tools and VPN
  clients, and `protected_components`. If a disabled driver stays loaded, a
  restart finishes the fix, within the emergency reboot rules.
- In the field on 2026-11-24: WS-OVS-010 had been unreachable over SSH and
  RDP for days, and restarting Windows did not help because the driver
  started again with it. NetRiser was installed from a USB drive with the
  self-installing `.exe`; 84 seconds after the service started it disabled
  `RfwService` and the test-signed `RfwFilter` driver, and SSH and RDP
  answered again without a restart.
- Disabling only changes the start type (the files stay); `nr blockers
  restore <name|all>` sets it back. `nr blockers` shows the local access
  check and what would be disabled now; `nr blockers disable` disables it
  after a question (or with `--yes`). `nr status` shows "Local Access" and
  the components NetRiser disabled.
- A record of the working state is kept in `components.json` in the state
  directory, updated at most hourly while the host works.
- Settings: `local_block_recovery` (default true), `access_ports`,
  `protected_components`.

Windows installer in the program
- `netriser-windows-amd64.exe` installs itself: double-click it, or run
  `netriser install` as Administrator. It needs no network access, so it
  works from a USB drive on a computer that is cut off. Without
  administrator rights it asks Windows for them. At most three questions:
  the language, then either whether to disable software found blocking
  connections (and to restart Windows if it stays loaded) or whether to use
  the recommended settings (`n` asks every setup question).
- Same steps as `install.ps1`: backup and rollback, replacing the program in
  `%ProgramFiles%\NetRiser`, license files (now built in), moving Mesh
  Watchdog files, configuration, service, `nr` command and PATH.
- Started from a terminal without a command, the program still shows the
  status; only a double-click starts the installer.

Defaults
- New installations recover instead of starting in observation mode
  (`observation_mode: false`); setup suggests "no" for observation mode.
  Existing configurations keep their setting.

Windows service
- Restarting the service (also after an automatic update) waits until the
  service has really stopped before starting it again, and retries the start.
  Before, it waited one second; a service still finishing its check was then
  stop-pending, the start failed and the service stayed stopped.

## 1.3.4

Setup
- `nr setup` checks write access to the configuration before the first
  question. Without administrator rights it stops at once and says to run
  `sudo nr setup` (on Windows: PowerShell as Administrator); before, it asked
  every question and failed only when saving.
- The value Enter selects is marked "default" instead of "recommended".

Status
- `nr status` no longer shows "Reboot Budget (24h)": it counted reboots of
  the last 24 hours against a limit whose window is
  `reboot_budget_window_sec` (one hour by default). With emergency reboot
  on, the line now reads "Emergency Reboot: true (one per outage)".

Log
- The service writes a line when it starts (version, configuration file,
  recovery or observation mode, default route policy) and when it stops. A
  healthy service is otherwise silent, so `nr logs` did not show that it
  runs.

Mesh Watchdog paths
- State, log and incident files left at the old Mesh Watchdog paths (for
  example `C:\ProgramData\mesh-watchdog\...` or `/var/lib/mesh-watchdog`) move
  to the NetRiser locations, and the configuration is switched to them. This
  happens in the installer and when the service starts, so hosts that update
  with `nr update` move too. Only settings that still hold the old default
  path change; a path you chose stays. Nothing is overwritten: when the new
  place already holds data or the move fails, that setting keeps the old path.
  Empty Mesh Watchdog directories are removed.
- `nr migrate` reports a migration only when it changed something.

Windows recovery
- The address of the physical adapter is read from the system directly, not
  only through PowerShell. In a test on 2026-11-12 a WireGuard tunnel took
  the default route; the PowerShell query came back without a usable
  address, the uplink counted as unknown, stages 1 and 2 were skipped, and
  the tunnel was stopped only at stage 4 after 2 min 45 s instead of about
  15 s. PowerShell remains a fallback and its output is read line by line.
- A failed adapter restart (stage 3) logs what PowerShell reported instead of
  only "exit status 1".

Windows installer
- Over SSH or with output redirected to a file, Russian and French messages
  were unreadable (Windows PowerShell wrote them in the OEM code page, e.g.
  cp866). The installer writes UTF-8 there now; a console is unchanged.

## 1.3.3

Access check
- `mesh_canaries` became a real access check: always-on hosts in the network
  you use to reach this machine (tailnet, WireGuard network). The internet
  probes show whether the machine reaches the internet; these show whether
  the path to the machine works.
- If none of them answers in two consecutive checks while the internet works,
  a host with a full tunnel where access comes first stops the VPN that
  carries all traffic (restored at most `max_restore_attempts` times, and a
  restore that cuts access again counts as failed). Other hosts log it.
  `nr status` shows "Remote Access: ok / LOST".
- On such hosts a VPN listed in `allowed_default_interfaces` can now be
  bypassed during recovery, as the "access first" answer promises; before,
  the list protected it even when it cut the host off.
- An address without a port is checked with ping, `host:port` by connecting;
  a refused connection counts as an answer. Previously a port-less address
  was probed on port 53, and fast checks cancelled these probes as soon as
  the internet answered, so they often reported a false failure.

Blocked probes
- When the internet probes fail but the system resolver still resolves
  `dns_canaries` and the router answers ping, the probe addresses are
  probably blocked on this network (a national firewall, a corporate filter)
  rather than the internet being down. Stages 1-2 still run; network restart
  and the emergency reboot are held back, and NetRiser only logs and suggests
  replacing `canary_targets`. `nr status` shows "Internet Probes: look
  BLOCKED"; `nr check --dry-run` reports it too. Without `dns_canaries` or a
  known gateway escalation is unchanged.

Setup
- Numbered sections and questions; yes/no and the language are chosen in a
  highlighted menu (arrows, Tab or y/n, then Enter).
- The summary lists every answer, marking unchanged ones and showing the
  previous or default value of changed ones.
- The access check question follows the full-tunnel answers and explains
  what happens on access loss in the chosen mode.
- The full-tunnel question says to answer yes when the VPN is needed to reach
  the internet at all or to get around blocking: with no, such a VPN is
  removed as soon as it takes over the traffic.

Fixed
- The retired mesh-watchdog update host is never used; setup moves
  `update_url` to the NetRiser server. The old host now only redirects.

## 1.3.2

Changed
- The setup answer "does this host route all of its traffic through a VPN or
  exit node" is now stored as `full_tunnel` and decides the mode:
  - `false`: only the physical uplink may carry the default route. A VPN,
    exit node or tunnel that takes it over is removed immediately, even while
    the internet works, and a VPN stopped for this is never restarted. This
    also covers a working full tunnel whose kill-switch blocks remote access.
  - `true`: the VPN question asks whether access or keeping all traffic in
    the VPN matters more (`allow_vpn_bypass`).
- Hosts without a full tunnel are no longer asked about VPN bypass.
- `nr status` and `nr setup` show the default route mode.
- Installers accept `NETRISER_FULL_TUNNEL`; `setup` accepts `--full-tunnel`.

Configurations without `full_tunnel` keep their behaviour; run `nr setup` to
choose a mode.

Setup and installers
- Setup and the installers ask for the language first: English, Russian or
  French (`language`, `setup --lang`, `NETRISER_LANG`). All questions,
  explanations and the final summary follow it.
- Every question explains what it does and why, and shows what Enter selects
  and whether that is the recommended value or the current setting.
  Answers are `y`/`n` in every language, like command names.
- Emergency reboot happens once per outage. After the restart, checks and
  stages 1-3 run again; if access still does not return, NetRiser stops
  acting and only keeps checking until connectivity returns (`nr status`
  shows "Recovery Paused"). Previously it rebooted again as soon as the
  hourly budget allowed.
- Colored output in setup, the installers, `nr status`, `nr logs` and
  `nr live` on terminals (Windows 10+ consoles included); `NO_COLOR=1`
  disables it.

## 1.3.1

Changed
- A stopped overlay service (for example a WireGuard tunnel whose server is
  unreachable) is restarted at most `max_restore_attempts` times (default 3)
  when each restart cuts connectivity again; it is then left stopped and
  `nr status` says so. Previously restarts continued every two hours forever.
  An outage no longer releases a service whose restart already failed.

Added
- `nr logs [N|all]` prints the last log entries, continuing into the rotated
  log; `nr live` follows new entries in real time without blocking rotation.
- `nr setup` and `nr check-config` show the configured log file and incident
  directory.

Fixed
- Installers printed the default log path even on hosts that keep their
  Mesh Watchdog log paths.
- `nr migrate` (run by every installation) claimed to have preserved a legacy
  configuration on hosts that never had one.
- `nr update` reported a service restart on macOS hosts without the service.

## 1.3.0

Security
- Updates require an Ed25519 signature over the release manifest
  (`version.json.sig`). The manifest carries every binary's SHA-256, so a
  compromised distribution host can no longer push a binary to installed hosts.
  Extra keys for self-hosted mirrors: `update_public_keys`. Releases are signed
  with an offline key (RELEASING.md); `sha256sums.txt` is signed as well.
- Older releases are never installed, including with `update --force`.
- Full-tunnel VPNs (WireGuard, OpenVPN, IPsec, commercial VPN clients) are left
  alone unless `allow_vpn_bypass` is enabled. Bypassing a VPN sends traffic
  outside it and lifts its kill-switch, which must be an explicit choice.
- New installations start in observation mode.
- macOS: /1 routes were deleted on every interface during cleanup and
  quarantine, including routes of allowed VPNs; only routes of overlays that
  recovery may touch are removed now, and quarantine requires route evidence.

Setup
- `netriser setup` asks every installation question (observation mode, live
  probe test, VPNs and overlays on the host, VPN bypass, custom overlays,
  recovery stages, DNS recovery, uplink interface, emergency reboot, updates),
  shows a summary of changes and asks for confirmation. Rerun it at any time;
  Enter keeps the current setting and a running service is restarted.
- The installers ask the questions with the verified binary before stopping or
  changing anything and apply the answers after installation. Declining to save
  cancels the installation. New variable: `NETRISER_ALLOW_VPN_BYPASS`.
- New configurations are created from a commented template.

Protocols
- VPN/overlay detection is a single registry used on Linux, macOS and Windows:
  NetBird, Tailscale/Headscale, ZeroTier, Nebula, Yggdrasil, WireGuard, OpenVPN,
  IPsec, Mullvad, NordVPN, Cloudflare WARP, ProtonVPN, Cisco AnyConnect,
  GlobalProtect, FortiClient and generic tunnels. `ppp*` is not an overlay
  (PPPoE uplinks).
- Custom definitions: `overlays` (interface pattern, kind, services).
- Linux quarantine stops the services of the overlay that published the rogue
  route, for example `wg-quick@wg0`; `monitored_services: ["*"]` allows any.

Compatibility
- Existing configurations that do not mention `observation_mode`,
  `allow_vpn_bypass` or `monitored_services` keep their previous behaviour.
- 1.2.x installations update to 1.3.0 normally; 1.3.0 then accepts only signed
  releases.

## 1.2.6

- Connectivity now requires at least two distinct answering internet probes
  (`min_healthy_targets`, default 2, capped at the number configured). A single
  answer can be a false positive: a WireGuard kill-switch still permits DNS to
  the tunnel's DNS servers, such as 1.1.1.1, so 1.2.5 reported recovery while
  the host stayed cut off. Set `min_healthy_targets: 1` for the old behaviour.
- Windows: stop a WireGuard tunnel that captured the default route already at
  stage 1, because route cleanup cannot lift its kill-switch.
- Overlays stopped at any stage are recorded and restarted after recovery
  (previously only stage 2 recorded them).

## 1.2.5

- Windows: fix the default-route listing used by route cleanup and overlay
  quarantine. It printed the routes but always exited with status 1 when a
  prefix had no routes (normally the /1 halves), so 1.2.3 and 1.2.4 never
  identified a rogue overlay: a WireGuard kill-switch tunnel was not stopped.
  Found in a live test; a read-only live test now runs the real script.

## 1.2.4

- Windows: an overlay default route with a worse effective metric (route plus
  interface metric) than the physical default route carries no traffic and is
  no longer treated as rogue, so ZeroTier's metric-9999 route is not removed and
  its service is not stopped during unrelated outages. Split /1 routes and
  WireGuard tunnels (kill-switch) remain suspect regardless of metric.

## 1.2.3

- Windows: recover from a WireGuard tunnel that captures the default route,
  including with the kill-switch enabled, by stopping its
  `WireGuardTunnel$<name>` service; the tunnel is restarted after recovery.
- Windows: quarantine only overlays that published a rogue default route, using
  Windows service names (`Tailscale`, `ZeroTierOneService`, `netbird`, `nebula`).
  Unrelated overlays such as a Tailscale management link are no longer disabled.
- Windows: honour `allowed_default_interfaces`; Hyper-V virtual switches are not
  treated as rogue routes.
- Windows: a quarantined service removed in the meantime is not retried forever.
- Windows: recover an uplink adapter disabled by hand (for example from Network
  Connections). The last confirmed adapter stays known while it has no address;
  stage 3 enables it, waits for DHCP and restores the default route. Previously
  this case was skipped as an invalid baseline, and a reboot does not undo it.

## 1.2.2

- Ask during installation whether to start in read-only observation mode;
  `NETRISER_OBSERVATION_MODE` selects it for unattended installs.
- Add `netriser observe on|off|status` and `init-config --observation-mode=bool`.
- Document `allowed_default_interfaces` for hosts that send their own traffic
  through a Tailscale or other overlay exit node.
- Windows installer: fix upgrading an existing installation under Windows
  PowerShell 5.1 ("The path is not of a legal form" when replacing the binary).

## 1.2.1

- Ask about automatic updates and emergency reboot during installation, including
  Unix pipe installation; support explicit unattended choices and preserve existing settings.
- Create a complete config on a fresh install and report all installation steps,
  selected settings, backup location and service verification.
- Recover on a 15-second outage cadence with consecutive stage 1/2/3 defaults,
  retaining the normal 60-second healthy cadence and explicit existing thresholds.
- Require 300 seconds of measured continuous outage before enabled emergency
  reboot, independently of check frequency, while preserving budget and grace checks.
- Wait for asynchronous DHCP before verifying routes after network reconfiguration.
- Reload default auto-update configuration consistently even when the default
  file is missing; explicit missing configuration remains an error.

## 1.2.0 — NetRiser

- Rename the application, service, module and distribution to NetRiser.
- Provide `netriser` and `nr` terminal commands. Compatibility commands delegate
  to the canonical executable so updates cannot leave an alias on an old build.
- Migrate existing Mesh Watchdog settings while preserving state, incident
  history, reboot policy and custom update endpoints.
- Verify installer downloads with SHA-256 and retain migration backups.
- Use a dedicated NetRiser update endpoint while preserving historical releases
  on the legacy endpoint during migration.
- Include system DNS detection and Linux DNS recovery from 1.1.1.

## 1.1.1

- Detect failed system name resolution even when IP connectivity is available.
- Restore a known healthy resolver configuration on Linux and restart its
  managed resolver when appropriate.
- Keep DNS-only failures outside the network escalation and reboot path.

## 1.1.0

- Prefer configured or confirmed physical uplinks when routes are lost.
- Restore on-link IPv4 gateways and management policy routing.
- Require rogue-route evidence before quarantining an overlay service.
- Add configurable automatic updates with manifest checksum verification.
