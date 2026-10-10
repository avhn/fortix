#!/usr/bin/env bash
# Write the human-facing pages of the GitHub Pages site next to the apt repository.
# Usage: build-pages-index.sh SITE_DIR KEY_FINGERPRINT
# apt never requests these pages; they exist so a person who opens the site or the
# repository address sees what it is and how to use it instead of a 404.
set -euo pipefail

# die fails closed before an incomplete site can be published.
die() {
    printf '%s\n' "${*}" >&2
    exit 1
}

[[ $# -eq 2 ]] || die "usage: build-pages-index.sh SITE_DIR KEY_FINGERPRINT"
FINGERPRINT="${2}"
[[ "${FINGERPRINT}" =~ ^[0-9A-F]{40}$ ]] || die "invalid signing key fingerprint"
[[ -d "${1}" && ! -L "${1}" ]] || die "invalid site directory"
SITE="$(cd "${1}" && pwd)"
[[ ! -L "${SITE}/apt" && (! -e "${SITE}/apt" || -d "${SITE}/apt") ]] || die "invalid apt directory"
mkdir -p "${SITE}/apt"

# style is shared by both pages; it follows the system light or dark appearance.
style() {
    cat <<'EOF'
<style>
:root { color-scheme: light dark; --fg: #1d1d1f; --bg: #ffffff; --muted: #6e6e73; --code: #f2f2f4; --link: #0a5bd3; }
@media (prefers-color-scheme: dark) { :root { --fg: #f5f5f7; --bg: #161617; --muted: #a1a1a6; --code: #26262a; --link: #6aa8ff; } }
body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
main { max-width: 760px; margin: 0 auto; padding: 48px 16px; }
h1 { font-size: 1.9rem; margin: 0 0 8px; }
h2 { font-size: 1.15rem; margin: 32px 0 8px; }
p, li { color: var(--fg); }
.lead { color: var(--muted); margin-top: 0; }
a { color: var(--link); }
pre { background: var(--code); padding: 14px 16px; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
EOF
}

# install_steps prints the apt setup as escaped HTML, verifying the key fingerprint first.
install_steps() {
    cat <<EOF
<pre><code>sudo apt-get update &amp;&amp; sudo apt-get install --yes ca-certificates curl gnupg
(
  set -eu
  KEYDIR="\$(mktemp -d)"; trap 'rm -rf "\$KEYDIR"' EXIT
  curl -fsSL https://avhn.github.io/fortix/apt/fortix-archive-keyring.gpg -o "\$KEYDIR/key.gpg"
  FINGERPRINT="\$(gpg --batch --with-colons --show-keys "\$KEYDIR/key.gpg" | awk -F: '\$1 == "fpr" { print \$10; exit }')"
  test "\$FINGERPRINT" = ${FINGERPRINT}
  sudo install -D -m 0644 "\$KEYDIR/key.gpg" /etc/apt/keyrings/fortix-archive-keyring.gpg
  echo 'deb [signed-by=/etc/apt/keyrings/fortix-archive-keyring.gpg] https://avhn.github.io/fortix/apt stable main' \\
    | sudo tee /etc/apt/sources.list.d/fortix.list &gt;/dev/null
)
sudo apt-get update
sudo apt-get install --yes --no-install-recommends fortix
sudo usermod -aG fortix "\$(id -un)"</code></pre>
EOF
}

{
    cat <<'EOF'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fortix</title>
<meta name="description" content="FortiGate SSL VPN profile manager for macOS, Debian/Ubuntu, and Windows (preview).">
EOF
    style
    cat <<'EOF'
</head>
<body>
<main>
<h1>fortix</h1>
<p class="lead">FortiGate SSL VPN profile manager for macOS, Debian/Ubuntu, and Windows (preview). The CLI, macOS menu-bar app, Linux tray, and Windows desktop app share a privileged helper.</p>
<p>Source, documentation and releases: <a href="https://github.com/avhn/fortix">github.com/avhn/fortix</a></p>
<h2>Homebrew</h2>
<p>Most macOS users want the app; note the <code>--cask</code> flag. Without it, Homebrew installs only the CLI and helper, with no app in <code>/Applications</code>.</p>
<pre><code># Fortix.app in /Applications (arm64 macOS 13 or later)
brew install --cask avhn/tap/fortix
# Then open Fortix.app: Settings and installation &gt; Install helper...

# CLI and helper only (Intel Macs, Linux, or command line only)
brew install avhn/tap/fortix
sudo "$(brew --prefix)/bin/fortix-helper" install</code></pre>
<h2>Debian and Ubuntu</h2>
<p>Packages for amd64 and arm64 come from the signed <a href="apt/">apt repository</a>.</p>
EOF
    install_steps
    cat <<'EOF'
<h2>Windows (preview)</h2>
<p>Download <code>fortix_&lt;version&gt;_windows_amd64.zip</code> and <code>checksums.txt</code> from the <a href="https://github.com/avhn/fortix/releases/latest">latest release</a>, verify the ZIP with <code>Get-FileHash</code>, and extract it. Then, in an elevated PowerShell inside the extracted folder:</p>
<pre><code>.\fortix-helper.exe install --user $env:USERNAME</code></pre>
<p>Sign out and back in for the <code>fortix</code> group membership, then start <code>FortixApp.exe</code> or use <code>fortix.exe</code>. The executables are unsigned, so SmartScreen warns on first launch. Windows supports native password-only profiles; <a href="https://github.com/avhn/fortix/blob/main/docs/windows.md">the Windows guide</a> covers verification, security, DNS, and recovery.</p>
</main>
</body>
</html>
EOF
} > "${SITE}/index.html"

{
    cat <<'EOF'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fortix apt repository</title>
<meta name="description" content="Signed apt repository for fortix on Debian and Ubuntu, amd64 and arm64.">
EOF
    style
    cat <<EOF
</head>
<body>
<main>
<h1>fortix apt repository</h1>
<p class="lead">Signed packages for Debian and Ubuntu, amd64 and arm64. This address is meant for apt; the steps below add it.</p>
<p>Signing key fingerprint: <code>${FINGERPRINT}</code></p>
<h2>Add the repository and install</h2>
EOF
    install_steps
    cat <<'EOF'
<h2>Files</h2>
<ul>
<li><a href="fortix-archive-keyring.gpg">fortix-archive-keyring.gpg</a> (binary key)</li>
<li><a href="fortix-archive-keyring.asc">fortix-archive-keyring.asc</a> (armored key)</li>
<li><a href="dists/stable/InRelease">dists/stable/InRelease</a> (signed index)</li>
</ul>
<p><a href="../">fortix home</a></p>
</main>
</body>
</html>
EOF
} > "${SITE}/apt/index.html"
