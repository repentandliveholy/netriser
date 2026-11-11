# Migrating from Mesh Watchdog

NetRiser 1.2.0 changes the executable and service name while preserving
existing configuration and operational state. Installers perform the sequence
below automatically. Use this guide when migrating manually or when an
installation uses a custom config path.

## What is preserved

- Existing settings, including reboot and automatic-update choices.
- Existing state, logs, incident records, and lock files at their current
  paths. Migration pins legacy paths in the config so the new service continues
  using them; the files are not moved or deleted.
- Custom update URLs. The official legacy update URL is switched to
  `https://netriser.repentandliveholy.org`.
- Backup copies of the old executable and configuration remain on disk.
  Legacy terminal commands are replaced by aliases to NetRiser.

Default legacy config paths are `/etc/mesh-watchdog/config.yaml` on Linux and
macOS and `%ProgramData%\mesh-watchdog\config.yaml` on Windows. New canonical
configuration defaults are `/etc/netriser/config.yaml` and
`%ProgramData%\netriser\config.yaml` respectively. On Windows, run the
installer in elevated PowerShell.

## Automatic installation

The platform installers stop and disable the old service before running the
migration command. They then install the NetRiser service and retire the old
service registration only after the new service starts. If migration or service
installation fails, the installer attempts to restore the previously running
legacy service. Existing files are retained for recovery.

Since 1.2.1, the installer asks about automatic updates and emergency reboot.
Enter keeps existing choices. Unattended upgrades preserve them unless the
installer environment explicitly overrides them. Fresh installations create a
complete config; `netriser init-config` can also repair a missing default config
without starting or stopping the service.

## Manual migration

1. Stop the old service and prevent it from starting during the migration.
2. Install the NetRiser executable for the host OS and architecture.
3. Run `netriser migrate` with administrator/root privileges. This creates the
   canonical config from the legacy default config if one exists. It does not
   overwrite a canonical config already present.
4. Install the service with `netriser service install`.
5. Check `netriser status` and confirm the service uses the expected config and
   preserved state locations before removing the old service registration.

For a custom configuration file, stop the old service and run:

```sh
netriser --config /path/to/existing-config.yaml migrate
netriser --config /path/to/existing-config.yaml service install
```

The explicit-path form updates that config in place, preserving comments and
settings while filling in omitted legacy state paths. YAML formatting may
change. Back up custom configuration before manual migration.

## Compatibility

The installed `nr` and `mesh-watchdog` command aliases invoke the canonical
NetRiser executable. The historical download hostname remains a separate
distribution endpoint during the migration, retaining matching legacy binaries
and checksums for older installed clients. New NetRiser release manifests
identify canonical `netriser-*` assets.
