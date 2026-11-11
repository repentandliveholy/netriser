# Changelog

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
