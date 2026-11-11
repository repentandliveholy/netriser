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
steps. It asks whether to start in read-only observation mode (default: no),
enable automatic updates (default: yes) and allow emergency host reboot
(default: no). Unix prompts read from the terminal, including with
`curl | sh`. On a rerun, Enter preserves the existing choices and custom settings.
A fresh installation always creates a complete configuration file.

For unattended Unix installation, set choices on the `sh` process:

```sh
curl -fsSL https://netriser.repentandliveholy.org/install.sh | \
  NETRISER_NONINTERACTIVE=1 NETRISER_OBSERVATION_MODE=false \
  NETRISER_AUTO_UPDATE=true NETRISER_ENABLE_REBOOT=false sh
```

PowerShell uses the same `NETRISER_NONINTERACTIVE`, `NETRISER_OBSERVATION_MODE`,
`NETRISER_AUTO_UPDATE` and `NETRISER_ENABLE_REBOOT` environment variables.
Without a terminal, fresh installs use observation off, updates on and reboot
off; existing settings are preserved unless overridden.

### Trying NetRiser on a production host

Choose observation mode during installation. NetRiser then records incidents
and the actions it would have taken, but changes no routes, services, DNS
configuration or binaries. Review `/var/log/netriser.log` and the incident
directory for a while, then enable recovery with `nr observe off`. Switch back
at any time with `nr observe on`.

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
| `mesh_canaries` | Optional endpoints reachable through the mesh. |
| `dns_canaries` | Hostnames used to check system DNS resolution. |
| `allow_dns_recovery` | Permit restoration of a known healthy Linux resolver configuration. |
| `management_interface`, `management_gateway` | Optional physical uplink overrides. |
| `observation_mode` | Read-only mode: log incidents without recovery actions or updates. Toggle with `nr observe on\|off`. |
| `allow_route_sanitation` | Permit targeted cleanup of suspicious routes. |
| `allow_service_quarantine` | Permit stopping a mesh service when a matching rogue route is detected. |
| `allowed_default_interfaces` | Overlay interfaces allowed to carry the default route, such as `tailscale0` on a host that uses a Tailscale exit node. |
| `allow_network_restart` | Permit supported network-stack recovery. |
| `enable_reboot` | Permit emergency host reboot. Defaults to `false`. |
| `auto_update`, `update_url` | Control update checks and the distribution endpoint. |
| `check_interval_sec`, `recovery_interval_sec` | Wait after a completed check: 60 seconds while healthy, 15 seconds during an IP outage. |
| `reboot_min_outage_sec` | Require a measured continuous outage before an enabled reboot; defaults to 300 seconds. |

Set only recovery actions appropriate for the host.

If the host routes its own traffic through a VPN or mesh exit node, such as a
Tailscale exit node, add that interface to `allowed_default_interfaces`.
Otherwise NetRiser treats the overlay default route as a rogue route and, with
`allow_service_quarantine` enabled, may stop the overlay service. Hosts that
only advertise an exit node for other devices keep their default route on the
physical uplink and need no change.

On Windows, a VPN or mesh client that captures the default route is contained
in stages: its routes are removed first, then its service is stopped
(`WireGuardTunnel$<tunnel>` for WireGuard, `Tailscale`, `ZeroTierOneService`,
`netbird`, `nebula`) and restarted once connectivity has recovered. Stopping a
WireGuard tunnel also lifts its kill-switch. Only overlays that published a
rogue default route are touched.

If the physical uplink adapter is disabled by hand, NetRiser on Windows keeps
the last confirmed adapter as the uplink; at stage 3 it enables the adapter,
waits for an IPv4 address and restores the default route. If another working
connection keeps the host online, nothing is changed. Emergency reboot is
disabled by default and should remain disabled unless unattended reboot is an
explicit operational requirement.

With fresh defaults, recovery stages 1, 2 and 3 occur on consecutive failed
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
netriser check-config
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
NetRiser asset names, SHA-256 checksums, an update manifest, installer scripts,
public docs, and a static distribution page in `dist/`. The historical
Mesh Watchdog download host remains separate during the migration so older
clients continue receiving matching legacy binaries and checksums.

## Security and limitations

- The service needs administrator/root privileges to inspect and repair routes,
  manage services, and apply network changes.
- Recovery can temporarily affect connectivity. Use observation mode and
  validate behavior before enabling actions on production or remote systems.
- IPv4 route recovery is the primary remediation scope. IPv6 information may
  appear in diagnostics, but IPv6 routes are not actively repaired.
- Automatic updates download release metadata and binaries from the configured
  update host and verify binary SHA-256 against the manifest. Keep the URL
  pointed at a trusted HTTPS endpoint.
- NetRiser relies on operating-system tools such as `ip` and `systemctl` on
  Linux, PowerShell networking cmdlets on Windows, and `route`/`launchctl` on
  macOS. Linux service management requires systemd.
