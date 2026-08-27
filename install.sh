#!/bin/sh
# system-administration installer.
#
#   curl -fsSL https://raw.githubusercontent.com/Nostraxiten/system-administration/main/install.sh | sh
#
# Puts a single executable named `system-administration` on PATH. A published
# release binary is used when one matches this machine; otherwise the source is
# compiled, so the installer works on any Linux distribution and architecture.
#
# Options, as flags (sh -s -- --dir /opt/bin) or environment variables:
#   --dir DIR       SYSADM_INSTALL_DIR   where to place the executable
#   --version TAG   SYSADM_VERSION       release tag to install (default: latest)
#   --source        SYSADM_FROM_SOURCE=1 always compile, never download
#
# The installer never prompts, so it is safe to pipe into sh.

set -eu

REPO="${SYSADM_REPO:-Nostraxiten/system-administration}"
BRANCH="${SYSADM_BRANCH:-main}"
BIN="system-administration"

INSTALL_DIR="${SYSADM_INSTALL_DIR:-}"
VERSION="${SYSADM_VERSION:-latest}"
FROM_SOURCE="${SYSADM_FROM_SOURCE:-}"

TMPDIR_SELF=""

# ---------------------------------------------------------------- utilities --

say() { printf '  %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*" >&2; }

die() {
    printf '\n  Error: %s\n\n' "$*" >&2
    exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
    [ -n "$TMPDIR_SELF" ] && rm -rf "$TMPDIR_SELF"
    return 0
}

# Print the SHA-256 of a file, or fail when no digest tool is installed.
sha256_of() {
    if have sha256sum; then
        sha256sum "$1" | cut -d' ' -f1
    elif have shasum; then
        shasum -a 256 "$1" | cut -d' ' -f1
    elif have openssl; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        return 1
    fi
}

# Fetch a URL to a file. Fails (non-zero) on 404 so the caller can fall back.
fetch() {
    if have curl; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
    elif have wget; then
        wget -q -O "$2" "$1"
    else
        die "curl or wget is required to download. Install either one."
    fi
}

usage() {
    printf '%s\n' \
        "system-administration installer" \
        "" \
        "  curl -fsSL https://raw.githubusercontent.com/$REPO/$BRANCH/install.sh | sh" \
        "" \
        "Options (as flags after 'sh -s --', or as environment variables):" \
        "  --dir DIR       SYSADM_INSTALL_DIR   where to place the executable" \
        "  --version TAG   SYSADM_VERSION       release tag to install (default: latest)" \
        "  --source        SYSADM_FROM_SOURCE=1 always compile, never download" \
        ""
}

# ------------------------------------------------------------------ options --

while [ $# -gt 0 ]; do
    case "$1" in
        --dir) INSTALL_DIR="${2:-}"; shift 2 ;;
        --version) VERSION="${2:-}"; shift 2 ;;
        --source) FROM_SOURCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

# ----------------------------------------------------------------- platform --

detect_platform() {
    os="$(uname -s 2>/dev/null || echo unknown)"
    arch="$(uname -m 2>/dev/null || echo unknown)"

    case "$os" in
        Linux) ;;
        Darwin)
            die "macOS is not supported: the collectors read /proc and the Windows registry.
         The supported targets are Linux and Windows Server." ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            die "on Windows use the PowerShell installer:
         irm https://raw.githubusercontent.com/$REPO/$BRANCH/install.ps1 | iex" ;;
        *) die "unsupported system: $os" ;;
    esac

    # Only these two have prebuilt binaries; anything else compiles from source.
    case "$arch" in
        x86_64|amd64) target="x86_64-unknown-linux-musl" ;;
        aarch64|arm64) target="aarch64-unknown-linux-musl" ;;
        *) target="" ;;
    esac
}

# Root installs system-wide; everybody else gets a directory they already own,
# so the installer never has to ask for a password halfway through a pipe.
choose_install_dir() {
    [ -n "$INSTALL_DIR" ] && return 0
    if [ "$(id -u 2>/dev/null || echo 1000)" = "0" ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="$HOME/.local/bin"
    fi
}

# ------------------------------------------------------------------ install --

# Check a downloaded archive against the published digest. A missing digest is
# reported and tolerated; a digest that does not match aborts the install.
verify_checksum() {
    if ! fetch "$2.sha256" "$1.sha256" 2>/dev/null; then
        warn "No published checksum for this asset; skipping verification."
        return 0
    fi

    expected="$(cut -d' ' -f1 < "$1.sha256")"
    actual="$(sha256_of "$1")" || {
        warn "No sha256 tool available; skipping verification."
        return 0
    }

    if [ "$expected" != "$actual" ]; then
        die "checksum mismatch for $(basename "$1").
         expected $expected
         got      $actual
         Refusing to install. Report this if it persists."
    fi
    say "Checksum verified."
}

download_release() {
    [ -n "$target" ] || return 1

    asset="$BIN-$target.tar.gz"
    if [ "$VERSION" = "latest" ]; then
        url="https://github.com/$REPO/releases/latest/download/$asset"
    else
        url="https://github.com/$REPO/releases/download/$VERSION/$asset"
    fi

    say "Looking for a published binary for $target..."
    if ! fetch "$url" "$TMPDIR_SELF/$asset" 2>/dev/null; then
        return 1
    fi

    verify_checksum "$TMPDIR_SELF/$asset" "$url"

    tar -xzf "$TMPDIR_SELF/$asset" -C "$TMPDIR_SELF" 2>/dev/null || return 1
    [ -f "$TMPDIR_SELF/$BIN" ] || return 1

    say "Downloaded the published binary."
    place "$TMPDIR_SELF/$BIN"
}

ensure_rust() {
    have cargo && return 0

    say "Rust is not installed; installing rustup non-interactively..."
    have curl || have wget || die "curl or wget is required to install Rust."
    fetch "https://sh.rustup.rs" "$TMPDIR_SELF/rustup-init.sh" ||
        die "could not download rustup. Install Rust 1.82+ manually and retry."
    sh "$TMPDIR_SELF/rustup-init.sh" -y --no-modify-path --profile minimal \
        >/dev/null 2>&1 || die "the rustup installation failed."

    # Use it in this shell without depending on the user's profile.
    CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
    PATH="$CARGO_HOME/bin:$PATH"
    export PATH
    have cargo || die "cargo is still unavailable after installing rustup."
}

is_termux() {
    [ -n "${TERMUX_VERSION:-}" ] || [ -d /data/data/com.termux ]
}

# Termux ships the std facade (core, alloc, compiler_builtins, panic_unwind,
# hashbrown, ...) for Android targets only as a dynamic library, not as
# individual .rlib files. Anything that links std - build scripts,
# proc-macros, the final binary - then fails with:
#   error: crate `std` required to be available in rlib format, but was not
#   found in this form
# `-C prefer-dynamic` makes rustc link against that dylib instead. Termux's
# own packaging already exports CARGO_TARGET_<TRIPLE>_RUSTFLAGS with the
# linker flags its bionic sysroot needs, so that variable is extended rather
# than replaced.
termux_rustflags_workaround() {
    # A plain RUSTFLAGS, if already set, outranks every target-specific
    # mechanism and would make our target-scoped flag inert - so extend
    # that instead of the target variable in that case.
    if [ -n "${RUSTFLAGS:-}" ]; then
        export RUSTFLAGS="$RUSTFLAGS -C prefer-dynamic"
        return 0
    fi

    have rustc || return 0
    host_triple="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
    [ -n "$host_triple" ] || return 0

    var_name="CARGO_TARGET_$(printf '%s' "$host_triple" | tr 'a-z.-' 'A-Z__')_RUSTFLAGS"
    eval "existing=\${$var_name:-}"
    eval "export $var_name=\"\$existing -C prefer-dynamic\""
}

build_from_source() {
    say "Building from source. This takes a couple of minutes..."
    ensure_rust
    is_termux && termux_rustflags_workaround

    src="$TMPDIR_SELF/src"
    mkdir -p "$src"

    if [ "$VERSION" = "latest" ]; then
        ref="$BRANCH"
    else
        ref="$VERSION"
    fi

    # A tarball avoids requiring git on the machine.
    tarball="https://codeload.github.com/$REPO/tar.gz/$ref"
    fetch "$tarball" "$TMPDIR_SELF/source.tar.gz" ||
        die "could not download the source from $tarball"
    tar -xzf "$TMPDIR_SELF/source.tar.gz" -C "$src" ||
        die "could not unpack the source."

    root="$(find "$src" -maxdepth 1 -mindepth 1 -type d | head -n 1)"
    [ -n "$root" ] || die "the downloaded source is empty."

    ( cd "$root" && cargo build --release ) || die "the build failed."
    [ -f "$root/target/release/$BIN" ] || die "no executable was produced."

    place "$root/target/release/$BIN"
}

place() {
    mkdir -p "$INSTALL_DIR" 2>/dev/null ||
        die "cannot create $INSTALL_DIR. Use --dir to choose another path."
    [ -w "$INSTALL_DIR" ] ||
        die "no write permission on $INSTALL_DIR.
         Run the installer as root, or pass --dir \$HOME/.local/bin"

    # Replacing a running executable fails on some systems; remove it first.
    rm -f "$INSTALL_DIR/$BIN" 2>/dev/null || true
    cp "$1" "$INSTALL_DIR/$BIN" || die "could not copy the executable into $INSTALL_DIR."
    chmod 755 "$INSTALL_DIR/$BIN"
}

# The tool takes no flags and starts an interactive scan when executed, so the
# installation is verified by inspecting the file, never by running it.
verify() {
    [ -x "$INSTALL_DIR/$BIN" ] || die "the installation left no executable in $INSTALL_DIR."

    printf '\n'
    say "Installed at $INSTALL_DIR/$BIN"

    case ":$PATH:" in
        *":$INSTALL_DIR:"*)
            say "Run it by typing:  $BIN"
            ;;
        *)
            printf '\n'
            warn "$INSTALL_DIR is not on your PATH."
            warn "Add it with:"
            warn "    echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.profile && . ~/.profile"
            warn "Until then, run it by full path: $INSTALL_DIR/$BIN"
            ;;
    esac
    printf '\n'
}

# --------------------------------------------------------------------- main --

main() {
    printf '\n  system-administration installer\n\n'

    detect_platform
    choose_install_dir

    TMPDIR_SELF="$(mktemp -d 2>/dev/null || mktemp -d -t sysadm)" ||
        die "could not create a temporary directory."
    trap cleanup EXIT INT TERM

    if [ -n "$FROM_SOURCE" ]; then
        build_from_source
    elif ! download_release; then
        say "No published binary for this platform."
        build_from_source
    fi

    verify
}

main
