# Changelog

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
