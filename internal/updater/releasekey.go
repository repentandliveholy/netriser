package updater

// releasePublicKey is the NetRiser release-signing public key (Ed25519).
// The private key never enters this repository; see RELEASING.md.
// Verify a download manually with: go run ./cmd/netriser-sign verify version.json
const releasePublicKey = "Jpq72VQc/dn/BrF7uvmGVXhVA8xGpx57AOdgn0X/Nzc="
