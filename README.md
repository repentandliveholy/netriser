# NetRiser

Ever broken a remote computer's network connection and lost the access you
needed to fix it? NetRiser helps you get back in. It monitors connectivity and
attempts targeted recovery before you need someone on site to restart the
machine.

NetRiser is a cross-platform network watchdog for systems that use physical and
mesh-network interfaces. It checks external and optional mesh connectivity,
records incidents, and can perform bounded recovery actions when routes or DNS
fail. The application is a standalone Go executable for Linux, Windows, and
macOS.

NetRiser does not guarantee network availability or protect against every
misconfiguration. Recovery changes system routes and may restart network or
overlay services. Review the configuration and test it on a system you can
access locally before enabling remediation on a remote host.

## Install

Linux and macOS require administrator privileges. Windows requires an elevated
PowerShell session. Installers migrate an existing Mesh Watchdog configuration
and install the NetRiser service.

```sh
curl -fsSL https://netriser.repentandliveholy.org/install.sh | sh
```

```powershell
irm https://netriser.repentandliveholy.org/install.ps1 | iex
```

Downloads, checksums, and release metadata are available from the
[distribution page](https://netriser.repentandliveholy.org). Source and release
history are published at [GitHub](https://github.com/repentandliveholy/netriser).

The installer prints download, checksum, backup, configuration and service
steps. Before it stops or changes anything, the verified binary asks every setup
question (see [Setup](#setup)). Unix prompts read from the terminal, including
with `curl | sh`. On a rerun, each question offers the current setting and Enter
keeps it. Declining to save cancels the installation without changes.

For unattended installation, choose settings with environment variables on the
`sh` process (PowerShell reads the same variables):

```sh
curl -fsSL https://netriser.repentandliveholy.org/install.sh | \
  NETRISER_NONINTERACTIVE=1 NETRISER_OBSERVATION_MODE=false \
  NETRISER_AUTO_UPDATE=true NETRISER_ENABLE_REBOOT=false \
  NETRISER_ALLOW_VPN_BYPASS=false sh
```

Without a terminal, a new installation uses the safe defaults (observation mode
on, VPN bypass off, reboot off, updates on); an existing installation keeps its
settings except those selected by the variables.

## Setup

`netriser setup` (alias `nr setup`) asks the installation questions and applies
the answers. Run it at any time to change them; it restarts a running service
when something changed. The questions cover:

1. **Observation mode**: read-only operation that records incidents and planned
   actions without changing anything. New installations start here.
2. **Connectivity probes**: the internet probes are tested live; if this network
   blocks them, enter targets it can reach. Optional mesh/VPN endpoints are
   monitored separately.
3. **VPNs and overlays**: the interfaces present on the host are listed. Hosts
   that deliberately route all traffic through a VPN or exit node name that
   interface (`allowed_default_interfaces`). A separate question decides
   whether NetRiser may bypass a full-tunnel VPN that cut the host off
   (`allow_vpn_bypass`, default no). Unrecognised VPNs can be described.
4. **Recovery actions**: route cleanup, overlay quarantine, network restart,
   DNS recovery (Linux), and the uplink interface (or auto-detection).
5. **Emergency reboot** and the minimum outage before it.
6. **Automatic updates**.

The answers end with a summary of changes and a confirmation. Comments and
unrelated settings in the configuration file are preserved.
`netriser setup --non-interactive --observation-mode=false` applies explicit
settings without questions; `netriser init-config` creates a missing
configuration without asking.

### Trying NetRiser on a production host

Keep observation mode on. NetRiser then records incidents and the actions it
would have taken, but changes no routes, services, DNS configuration or
binaries. Review the log (`nr logs`, or `nr live` in real time) and the
incident directory (`nr check-config` shows its path) for a while, then enable
recovery with `nr observe off`. Switch back at any time with `nr observe on`.

## Migration from Mesh Watchdog

The 1.2.0 installers stop and disable the legacy service before migration. They
run `netriser migrate`, install the NetRiser service, and restore the legacy
service if migration or service installation fails. Existing configuration is
retained, including reboot policy and user-selected settings. Historical state,
log, incident, and lock paths remain in place; migration does not move or erase
those files. The default update URL changes to the NetRiser distribution host;
custom update URLs remain unchanged. See [MIGRATION.md](MIGRATION.md) for the
manual procedure and platform paths.

The installed command is `netriser`. `nr` is a short alias, and
`mesh-watchdog` remains available as a compatibility alias. Windows adds the
command directory to the machine `PATH`; its `.cmd` aliases invoke the
canonical executable so updates affect the service binary. The background
service is named `netriser`.

## Configure

The default configuration is `/etc/netriser/config.yaml` on Linux and macOS,
and `%ProgramData%\netriser\config.yaml` on Windows. Copy
[config.example.yaml](config.example.yaml) as a starting point. Run commands
with `--config PATH` to use a different file.

Important settings:

| Setting | Purpose |
| --- | --- |
| `canary_targets` | Public network probes, specified as `host:port` values. |
| `min_healthy_targets` | Distinct internet probes that must answer (default 2, capped at the number configured). |
| `mesh_canaries` | Optional endpoints reachable through the mesh. |
| `dns_canaries` | Hostnames used to check system DNS resolution. |
| `allow_dns_recovery` | Permit restoration of a known healthy Linux resolver configuration. |
| `management_interface`, `management_gateway` | Optional physical uplink overrides. |
| `observation_mode` | Read-only mode: log incidents without recovery actions or updates. On for new installations. Toggle with `nr observe on\|off`. |
| `allow_route_sanitation` | Permit targeted cleanup of suspicious routes. |
| `allow_service_quarantine` | Permit stopping an overlay service that publishes a rogue route. |
| `max_restore_attempts` | Restarts of a stopped overlay that may cut connectivity again before it is left stopped (default 3, `0` = unlimited). |
| `monitored_services` | Services eligible for quarantine; `"*"` means any service of a detected overlay. |
| `allowed_default_interfaces` | Overlay interfaces allowed to carry the default route, such as `tailscale0` on a host that uses a Tailscale exit node. |
| `allow_vpn_bypass` | Permit removing the routes of, or stopping, a full-tunnel VPN that cut the host off. Off for new installations. |
| `overlays` | Definitions for VPNs and overlays that are not recognised automatically. |
| `allow_network_restart` | Permit supported network-stack recovery. |
| `enable_reboot` | Permit emergency host reboot. Defaults to `false`. |
| `auto_update`, `update_url` | Control update checks and the distribution endpoint. |
| `update_public_keys` | Extra trusted release-signing keys for a self-hosted mirror. |
| `check_interval_sec`, `recovery_interval_sec` | Wait after a completed check: 60 seconds while healthy, 15 seconds during an IP outage. |
| `reboot_min_outage_sec` | Require a measured continuous outage before an enabled reboot; defaults to 300 seconds. |

Set only recovery actions appropriate for the host. Configurations created
before 1.3.0 that do not mention `observation_mode`, `allow_vpn_bypass` or
`monitored_services` keep their previous behaviour (recovery on, VPN bypass on,
the five original overlay services); `netriser setup` can change them.

## VPNs and overlays

NetRiser recognises these protocols by interface name (on Windows also by
adapter description):

| Kind | Protocols |
| --- | --- |
| Mesh overlay | NetBird, Tailscale/Headscale, ZeroTier, Nebula, Yggdrasil |
| Full-tunnel VPN | WireGuard, OpenVPN (including DCO), IPsec (strongSwan, Libreswan, Windows IKEv2/L2TP/SSTP), Mullvad, NordVPN, Cloudflare WARP, ProtonVPN, Cisco AnyConnect, GlobalProtect, FortiClient, generic `tun`/`tap`/`utun` tunnels |

A **mesh overlay** should never carry the host's default route. If it does (for
example an exit node selected by mistake), NetRiser removes the route and, if
needed, stops the overlay's service, then restarts it after recovery. List the
interface in `allowed_default_interfaces` when the host uses an exit node on
purpose.

A **full-tunnel VPN** carries the default route on purpose, often with a
kill-switch. NetRiser leaves it alone unless `allow_vpn_bypass` is true. With
bypass enabled, a VPN that cut the host off has its routes removed or its
service stopped (WireGuard for Windows: `WireGuardTunnel$<tunnel>`, Linux:
`wg-quick@<iface>`, plus the known services of the products above); traffic then
leaves outside the VPN until the VPN is restarted after recovery. Enable it only
on hosts where regaining access matters more than keeping traffic inside the VPN.

`ppp*` interfaces are not treated as VPNs because they are often the physical
PPPoE uplink. Describe anything else under `overlays`:

```yaml
overlays:
  - name: corp-vpn
    interface: "^corp[0-9]+$"    # regular expression; Windows: alias or description
    kind: vpn                    # vpn (full tunnel) or mesh
    services: ["corp-vpn.service"] # "{iface}" expands to the interface name
```

On Windows, an overlay without a known service is contained by disabling its
adapter and re-enabling it after recovery. On macOS, Tailscale, NetBird and most
VPN clients share `utun` interfaces, so they are handled as generic tunnels.

If the physical uplink adapter is disabled by hand, NetRiser on Windows keeps
the last confirmed adapter as the uplink; at stage 3 it enables the adapter,
waits for an IPv4 address and restores the default route. If another working
connection keeps the host online, nothing is changed. Emergency reboot is
disabled by default and should remain disabled unless unattended reboot is an
explicit operational requirement.

With default thresholds, recovery stages 1, 2 and 3 occur on consecutive failed
checks, separated by 15 seconds plus probe/action time. Initial outage detection
can take up to the normal monitoring interval plus probe time. Existing explicit
stage thresholds are retained. Reboot additionally requires the configured
minimum outage, startup grace, final connectivity check and reboot budget;
DNS-only failure never triggers reboot.

## DNS recovery

DNS failures are detected separately from loss of IP connectivity. On Linux,
NetRiser can restore a previously confirmed resolver configuration and restart
its managed DNS service. On Windows and macOS, DNS diagnostics are available;
this resolver-file recovery mechanism is Linux-specific. DNS-only failures do
not trigger overlay quarantine, WAN restarts or emergency reboot.

## Commands

```sh
netriser status
nr status                    # same application, short command
netriser setup               # answer the installation questions again
netriser check-config        # validate settings; show log and incident paths
netriser logs                # last 50 log entries (nr logs 200, nr logs all)
netriser live                # log entries in real time (Ctrl+C to stop)
netriser init-config         # create defaults if missing; keep an existing config
netriser run                 # foreground mode
netriser observe on|off      # read-only observation mode or active recovery
netriser service install     # install or update the system service
netriser service stop
netriser update --check
netriser autoupdate off
```

The `--config PATH` flag can be used before the command, for example:
`netriser --config /path/to/config.yaml status`. Use `netriser --help` for the
complete command list. On Linux, service installation requires systemd.

## License

NetRiser is licensed under the [MIT License](LICENSE).
Copyright (c) 2026 Muslim Bayraktar.

Third-party components retain their own licenses. Their copyright notices and
license texts are included in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
Installers place both files in `/usr/local/share/doc/netriser` on Linux/macOS,
or the `licenses` directory beside `netriser.exe` on Windows.

## Build

Requires a Go toolchain compatible with the version in `go.mod`.

```sh
./build.sh
./scripts/build-release.sh
```

Both scripts build pure-Go binaries (`CGO_ENABLED=0`) for Linux amd64/arm64,
Windows amd64, and macOS amd64/arm64. The release script creates canonical
NetRiser asset names, SHA-256 checksums, a signed update manifest, installer
scripts, public docs, and a static distribution page in `dist/`. Signing needs
the offline release key; see [RELEASING.md](RELEASING.md). The historical
Mesh Watchdog download host remains separate during the migration so older
clients continue receiving matching legacy binaries and checksums.

## Security and limitations

- The service needs administrator/root privileges to inspect and repair routes,
  manage services, and apply network changes.
- Recovery can temporarily affect connectivity. Use observation mode and
  validate behavior before enabling actions on production or remote systems.
- IPv4 route recovery is the primary remediation scope. IPv6 information may
  appear in diagnostics, but IPv6 routes are not actively repaired.
- Updates are accepted only when the release manifest (`version.json`) carries a
  valid Ed25519 signature (`version.json.sig`) from a key built into NetRiser or
  listed in `update_public_keys`. The manifest holds each binary's SHA-256, so a
  compromised or spoofed distribution host cannot push a binary. Older releases
  are never installed, even with `--force`. Automatic updates run only outside
  observation mode, while connectivity is healthy.
- The initial `curl | sh` installation trusts HTTPS and the distribution host.
  To verify a download independently, check `sha256sums.txt` against
  `sha256sums.txt.sig` with the public key published in the repository
  (`internal/updater/releasekey.go`): `go run ./cmd/netriser-sign verify sha256sums.txt`.
- NetRiser relies on operating-system tools such as `ip` and `systemctl` on
  Linux, PowerShell networking cmdlets on Windows, and `route`/`launchctl` on
  macOS. Linux service management requires systemd.
