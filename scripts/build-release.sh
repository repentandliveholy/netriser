#!/usr/bin/env bash
# Release package: five canonical binaries, SHA256 sums, signed updater
# manifest, installer scripts, public docs, and a static landing page.
# The manifest is signed with the offline release key (see RELEASING.md):
#   NETRISER_SIGNING_KEY=/path/to/release-signing.key ./scripts/build-release.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
DIST_DIR="${DIST_DIR:-${SCRIPT_DIR}/dist}"
DIST_BIN="$DIST_DIR/bin"
VERSION="${VERSION:-1.3.2}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_TIME="${BUILD_TIME:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"
case "$VERSION$COMMIT" in *[!a-zA-Z0-9._+-]*) echo "Invalid release identifier" >&2; exit 2 ;; esac
RELEASE_PREFIX="releases/${VERSION}-${COMMIT}"
SIGNING_KEY="${NETRISER_SIGNING_KEY:-$HOME/.config/netriser/release-signing.key}"
if [[ ! -f "$SIGNING_KEY" ]]; then
  echo "Release signing key not found: $SIGNING_KEY (set NETRISER_SIGNING_KEY)." >&2
  echo "NetRiser 1.3+ refuses unsigned updates; see RELEASING.md." >&2
  exit 2
fi

# Refuse to clean a symlink or anything except this repository's known dist path.
EXPECTED_DIST="${SCRIPT_DIR}/dist"
if [[ "$DIST_DIR" != "$EXPECTED_DIST" ]]; then
  echo "DIST_DIR must be exactly $EXPECTED_DIST (got $DIST_DIR)" >&2
  exit 2
fi
if [[ -L "$DIST_DIR" ]]; then
  echo "Refusing to replace symlink: $DIST_DIR" >&2
  exit 2
fi
if [[ -e "$DIST_DIR" ]]; then
  rm -rf -- "$DIST_DIR"
fi
mkdir -p "$DIST_BIN"

export VERSION COMMIT BUILD_TIME
./build.sh
cp bin/netriser-* "$DIST_BIN/"

# The legacy hostname is served from its existing distribution root and is
# preserved independently during the fleet transition. Do not place v1.2
# binaries under old names in the canonical package: old manifests verify
# checksums for the historical 1.1 binaries.

cp scripts/install.sh "$DIST_DIR/install.sh"
cp scripts/install.ps1 "$DIST_DIR/install.ps1"
chmod 755 "$DIST_DIR/install.sh"
cp README.md "$DIST_DIR/README.md"
cp MIGRATION.md config.example.yaml "$DIST_DIR/"
cp LICENSE THIRD_PARTY_NOTICES "$DIST_DIR/"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
(
  cd "$DIST_BIN"
  if command -v sha256sum >/dev/null 2>&1; then sha256sum * > "$DIST_DIR/sha256sums.txt"
  else shasum -a 256 * > "$DIST_DIR/sha256sums.txt"; fi
)

cat > "$DIST_DIR/version.json" <<EOF
{
  "version": "${VERSION}",
  "commit": "${COMMIT}",
  "build_time": "${BUILD_TIME}",
  "min_version": "1.0.0",
  "release_notes": "NetRiser 1.3.2: the setup answer about a full tunnel now decides the mode. Without a full tunnel, any VPN or exit node that takes over the default route is removed immediately, even while the internet works, and not restarted; with a full tunnel, you choose whether access or keeping traffic in the VPN comes first. Existing configurations keep their behaviour until nr setup is run.",
  "files": {
    "linux/amd64": {"filename":"netriser-linux-amd64","sha256":"$(hash_file "$DIST_BIN/netriser-linux-amd64")","url":"${RELEASE_PREFIX}/bin/netriser-linux-amd64"},
    "linux/arm64": {"filename":"netriser-linux-arm64","sha256":"$(hash_file "$DIST_BIN/netriser-linux-arm64")","url":"${RELEASE_PREFIX}/bin/netriser-linux-arm64"},
    "windows/amd64": {"filename":"netriser-windows-amd64.exe","sha256":"$(hash_file "$DIST_BIN/netriser-windows-amd64.exe")","url":"${RELEASE_PREFIX}/bin/netriser-windows-amd64.exe"},
    "darwin/arm64": {"filename":"netriser-darwin-arm64","sha256":"$(hash_file "$DIST_BIN/netriser-darwin-arm64")","url":"${RELEASE_PREFIX}/bin/netriser-darwin-arm64"},
    "darwin/amd64": {"filename":"netriser-darwin-amd64","sha256":"$(hash_file "$DIST_BIN/netriser-darwin-amd64")","url":"${RELEASE_PREFIX}/bin/netriser-darwin-amd64"}
  }
}
EOF

# Sign the manifest (authenticates every binary checksum) and the checksum
# list, then verify with the key built into this release so a mismatched key
# can never be published.
SIGN=(go run ./cmd/netriser-sign)
"${SIGN[@]}" sign -key "$SIGNING_KEY" "$DIST_DIR/version.json" "$DIST_DIR/sha256sums.txt"
"${SIGN[@]}" verify "$DIST_DIR/version.json" "$DIST_DIR/sha256sums.txt"
"${SIGN[@]}" pubkey -key "$SIGNING_KEY" > "$DIST_DIR/netriser-release.pub"

# Immutable paths keep a published manifest valid during future releases.
mkdir -p "$DIST_DIR/$RELEASE_PREFIX/bin"
cp "$DIST_BIN"/* "$DIST_DIR/$RELEASE_PREFIX/bin/"
cp LICENSE THIRD_PARTY_NOTICES "$DIST_DIR/$RELEASE_PREFIX/"
cat > "$DIST_DIR/SOURCE.json" <<EOF
{"version":"${VERSION}","commit":"${COMMIT}","build_time":"${BUILD_TIME}","repository":"https://github.com/repentandliveholy/netriser"}
EOF

cat > "$DIST_DIR/index.html" <<EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Lost remote access after a network change? NetRiser attempts automatic network recovery before an on-site restart is needed.">
<title>NetRiser — network resilience</title>
<style>
:root{color-scheme:dark;--bg:#0b1220;--panel:#111c2e;--line:#26364c;--ink:#e8f0fa;--muted:#9fb0c5;--accent:#62d6b5;--blue:#85b8ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 80% 0,#18334b 0,transparent 42%),var(--bg);color:var(--ink);font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
main{width:min(1040px,calc(100% - 36px));margin:auto}.top{padding:22px 0;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}.brand{font-weight:800;letter-spacing:.04em}.top a,.links a{color:var(--blue);text-decoration:none}.hero{padding:74px 0 54px;max-width:760px}.eyebrow{color:var(--accent);text-transform:uppercase;letter-spacing:.14em;font-size:.78rem;font-weight:700}.hero h1{font-size:clamp(2.8rem,8vw,5rem);line-height:1.02;margin:14px 0}.hero p{font-size:1.2rem;color:var(--muted);max-width:650px}.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:26px}.button{display:inline-block;padding:11px 17px;border-radius:9px;background:var(--accent);color:#07131a;font-weight:750;text-decoration:none}.button.secondary{background:transparent;color:var(--ink);border:1px solid var(--line)}section{padding:28px 0 36px;border-top:1px solid var(--line)}h2{font-size:1.55rem;margin:0 0 8px}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(205px,1fr));gap:12px;margin-top:20px}.card{padding:17px;border:1px solid var(--line);background:color-mix(in srgb,var(--panel) 85%,transparent);border-radius:12px}.card h3{margin:0 0 7px;font-size:1rem}.card a{color:var(--blue)}code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#070d16;border:1px solid var(--line);border-radius:10px;padding:15px;color:#d5e4f5}.links{display:flex;gap:18px;flex-wrap:wrap}.foot{padding:28px 0 50px;color:var(--muted);font-size:.9rem}
.cmd{position:relative;margin:12px 0;cursor:pointer}
.cmd pre{margin:0;padding:14px 92px 14px 16px;background:#070d16;border:1px solid var(--line);border-radius:10px;color:#d5e4f5;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.95rem;line-height:1.5;white-space:pre-wrap;overflow-wrap:anywhere;transition:border-color .15s ease}
.cmd:hover pre{border-color:#384c66}
.copy-btn{position:absolute;top:9px;right:10px;display:inline-flex;align-items:center;gap:6px;padding:6px 11px;background:#111c2e;color:var(--muted);border:1px solid var(--line);border-radius:7px;font-family:system-ui,-apple-system,sans-serif;font-size:.78rem;font-weight:600;letter-spacing:.02em;cursor:pointer;transition:all .15s ease;user-select:none;line-height:1}
.copy-btn:hover{background:#18283f;color:var(--ink);border-color:#455e80}
.copy-btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.copy-btn:active{transform:scale(.97)}
.copy-btn .icon-check{display:none}
.copy-btn.copied{background:rgba(98,214,181,.14);color:var(--accent);border-color:var(--accent)}
.copy-btn.copied .icon-copy{display:none}
.copy-btn.copied .icon-check{display:inline-block;color:var(--accent)}
@media (max-width:480px){.cmd pre{padding-right:76px;font-size:.88rem}.copy-btn{padding:5px 8px;font-size:.74rem;gap:4px;top:8px;right:8px}}
</style></head><body><main>
<header class="top"><div class="brand">NETRISER</div><a href="https://github.com/repentandliveholy/netriser">GitHub ↗</a></header>
<section class="hero" style="border:0"><div class="eyebrow">Network resilience · v${VERSION}</div><h1>Lost access to a remote computer?</h1><p>A network change can cut off the very connection you need to fix it. NetRiser attempts automatic recovery of interfaces, routes, and DNS, helping you get back in before someone has to visit the machine and restart it.</p><div class="actions"><a class="button" href="bin/netriser-linux-amd64">Download Linux x86_64</a><a class="button secondary" href="https://github.com/repentandliveholy/netriser">Source and releases</a></div></section>
<section><h2>Install</h2><p class="muted">The installer verifies the download, then asks every setup question: observation mode, connectivity probes, VPNs and overlays on the host, recovery actions, emergency reboot and updates. New installations start in read-only observation mode and never bypass a full-tunnel VPN unless you allow it. Answer the questions again at any time with <code>nr setup</code>; Enter keeps the current setting. Linux and macOS need administrator privileges; Windows requires elevated PowerShell.</p>
<div class="cmd" title="Click to copy"><pre>curl -fsSL https://netriser.repentandliveholy.org/install.sh | sh</pre><button type="button" class="copy-btn" aria-label="Copy Linux/macOS install command" title="Copy command"><svg class="icon-copy" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg><svg class="icon-check" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg><span class="btn-text">Copy</span></button></div>
<div class="cmd" title="Click to copy"><pre>irm https://netriser.repentandliveholy.org/install.ps1 | iex</pre><button type="button" class="copy-btn" aria-label="Copy Windows PowerShell install command" title="Copy command"><svg class="icon-copy" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg><svg class="icon-check" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg><span class="btn-text">Copy</span></button></div>
</section>
<section><h2>Downloads</h2><p class="muted">Release binaries are standalone Go executables. The SHA-256 list and the update manifest carry Ed25519 signatures; installed copies accept only updates signed with the release key.</p><div class="grid">
<div class="card"><h3>Linux · x86_64</h3><a href="bin/netriser-linux-amd64">netriser-linux-amd64</a></div><div class="card"><h3>Linux · ARM64</h3><a href="bin/netriser-linux-arm64">netriser-linux-arm64</a></div><div class="card"><h3>Windows · x86_64</h3><a href="bin/netriser-windows-amd64.exe">netriser-windows-amd64.exe</a></div><div class="card"><h3>macOS · Apple Silicon</h3><a href="bin/netriser-darwin-arm64">netriser-darwin-arm64</a></div><div class="card"><h3>macOS · Intel</h3><a href="bin/netriser-darwin-amd64">netriser-darwin-amd64</a></div></div><p class="links"><a href="sha256sums.txt">SHA-256 checksums</a><a href="sha256sums.txt.sig">Checksum signature</a><a href="version.json">Update manifest</a><a href="netriser-release.pub">Release public key</a><a href="README.md">Documentation</a><a href="LICENSE">MIT license</a><a href="THIRD_PARTY_NOTICES">Third-party licenses</a></p></section>
<section><h2>Works with any VPN</h2><p class="muted">WireGuard, OpenVPN, IPsec, Tailscale/Headscale, ZeroTier, NetBird, Nebula, Yggdrasil, Mullvad, NordVPN, Cloudflare WARP, Cisco AnyConnect, GlobalProtect, FortiClient and generic tunnels are recognised out of the box; anything else can be described in the configuration.</p></section>
<section><h2>Migration</h2><p class="muted">The installer keeps the existing configuration, state, logs, reboot policy, and update settings. It stops the old service, runs <code>netriser migrate</code>, then installs and starts the new service. The old service is restored if migration or service startup fails.</p><p class="links"><a href="MIGRATION.md">Migration guide</a><a href="config.example.yaml">Example configuration</a><a href="README.md">Full documentation</a></p></section>
<footer class="foot">NetRiser ${VERSION} · Copyright &copy; 2026 Muslim Bayraktar · <a href="https://github.com/repentandliveholy/netriser">Source on GitHub</a> · <a href="README.md">Configuration and security notes</a> · <a href="LICENSE">MIT License</a></footer>
</main>
<script>
(function(){
  function copy(btn){
    var cmd=btn.closest('.cmd');
    if(!cmd)return;
    var pre=cmd.querySelector('pre');
    if(!pre)return;
    var text=(pre.innerText||pre.textContent||'').trim();
    if(!text)return;
    function success(){
      btn.classList.add('copied');
      var label=btn.querySelector('.btn-text');
      if(label)label.textContent='Copied!';
      setTimeout(function(){
        btn.classList.remove('copied');
        if(label)label.textContent='Copy';
      },2000);
    }
    if(navigator.clipboard&&window.isSecureContext){
      navigator.clipboard.writeText(text).then(success,function(){fallback(text);success();});
    }else{
      fallback(text);
      success();
    }
  }
  function fallback(text){
    var ta=document.createElement('textarea');
    ta.value=text;
    ta.style.position='fixed';
    ta.style.top='0';
    ta.style.left='-9999px';
    ta.style.opacity='0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try{document.execCommand('copy');}catch(e){}
    document.body.removeChild(ta);
  }
  document.querySelectorAll('.copy-btn').forEach(function(btn){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      copy(btn);
    });
  });
  document.querySelectorAll('.cmd').forEach(function(cmd){
    cmd.addEventListener('click',function(e){
      if(e.target.closest('.copy-btn'))return;
      var sel=window.getSelection();
      if(sel&&sel.toString().length>0)return;
      var btn=cmd.querySelector('.copy-btn');
      if(btn)copy(btn);
    });
  });
})();
</script>
</body></html>
EOF

echo "Release package assembled: $DIST_DIR"
