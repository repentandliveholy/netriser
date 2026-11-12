# Releasing NetRiser

## Signing key

Installed copies of NetRiser (1.3.0 and later) accept an update only when
`version.json` carries a valid Ed25519 signature from a trusted key. The public
key is compiled in (`internal/updater/releasekey.go`); the private key never
enters the repository or the distribution host.

The private key lives at `~/.config/netriser/release-signing.key` (mode 600) or
at the path in `NETRISER_SIGNING_KEY`. **Back it up offline.** Without it, no
update can reach installed hosts; they would have to be reinstalled with a
build that trusts a new key.

Create a key (refuses to overwrite an existing one):

```sh
go run ./cmd/netriser-sign keygen            # prints the public key
go run ./cmd/netriser-sign pubkey            # print it again later
```

## Building a release

```sh
VERSION=1.3.1 ./scripts/build-release.sh
```

The script builds the binaries, writes `version.json` and `sha256sums.txt`,
signs both (`*.sig`), verifies the signatures against the key compiled into
this source tree (so a mismatched key cannot be published), and writes the
public key to `netriser-release.pub`. Publish the whole `dist/` directory,
including the `.sig` files: a release without `version.json.sig` is ignored by
installed hosts.

Verify any published file:

```sh
go run ./cmd/netriser-sign verify version.json sha256sums.txt
```

## Rotating the key

1. Generate a new key and add its public key to `builtinPublicKeys` in
   `internal/updater/signature.go`, keeping the old one.
2. Release, signed with the **old** key, and let the fleet update.
3. Sign later releases with the new key and remove the old public key in a
   following release.

If the private key is compromised, remove its public key in a release signed
with a new key as soon as possible; hosts that have not updated yet still trust
the old key.

## Self-hosted mirrors

Organisations can serve their own builds: sign `version.json` with their own
key and add the public key to `update_public_keys` in each host's
configuration, with `update_url` pointing at the mirror.
