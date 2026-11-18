#!/usr/bin/env sh

# ============================================================
# Crypto-Cold-Wallet - Universal Linux / macOS / Termux installer
# ============================================================

set -u

if [ -t 1 ]; then
    GREEN="$(printf '\033[0;32m')"
    RED="$(printf '\033[0;31m')"
    YELLOW="$(printf '\033[0;33m')"
    BOLD="$(printf '\033[1m')"
    NC="$(printf '\033[0m')"
else
    GREEN=""; RED=""; YELLOW=""; BOLD=""; NC=""
fi

info(){ printf '%s\n' "[*] $*"; }
ok(){ printf '%s\n' "${GREEN}    OK  $*${NC}"; }
warn(){ printf '%s\n' "${YELLOW}[!] $*${NC}"; }
fail(){ printf '%s\n' "${RED}[!] $*${NC}" >&2; exit 1; }

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd -P) || exit 1
cd "$SCRIPT_DIR" || exit 1

printf '%s\n' "${GREEN}${BOLD}"
printf '%s\n' "============================================================"
printf '%s\n' "===== Crypto-Cold-Wallet installation ======================"
printf '%s\n' "============================================================"
printf '%s\n' "${NC}"
printf 'Project directory : %s\n' "$SCRIPT_DIR"

OS_NAME="$(uname -s 2>/dev/null || printf 'Unknown')"
IS_MACOS=0
IS_TERMUX=0

if [ "$OS_NAME" = "Darwin" ]; then
    IS_MACOS=1
    info "Environment detected: macOS"
elif [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux/files/usr" ] || printf '%s' "${PREFIX:-}" | grep -q 'com.termux'; then
    IS_TERMUX=1
    info "Environment detected: Termux / Android"
else
    info "Environment detected: GNU/Linux"
fi

run_root(){
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    elif command -v doas >/dev/null 2>&1; then
        doas "$@"
    else
        warn "Administrator privileges required for: $*"
        return 1
    fi
}

install_system_dependencies(){
    info "Checking/installing system prerequisites ..."

    if [ "$IS_MACOS" -eq 1 ]; then
        if command -v brew >/dev/null 2>&1; then
            info "macOS: installing Python 3.13 and build prerequisites ..."
            brew install python@3.13 openssl libffi pkg-config rust gmp || true
        else
            warn "Homebrew not found. Install Python 3.13 manually or install Homebrew."
        fi
        return 0
    fi

    if [ "$IS_TERMUX" -eq 1 ]; then
        if command -v pkg >/dev/null 2>&1; then
            pkg update -y || true
            pkg install -y python clang make pkg-config rust binutils openssl libffi libgmp || true
        else
            warn "Termux detected but 'pkg' was not found."
        fi
        return 0
    fi

    if command -v apt-get >/dev/null 2>&1; then
        run_root apt-get update || true
        run_root apt-get install -y python3 python3-pip python3-venv build-essential pkg-config libssl-dev libffi-dev libgmp-dev rustc cargo || true
        return 0
    fi

    if command -v dnf >/dev/null 2>&1; then
        run_root dnf install -y python3 python3-pip gcc gcc-c++ make pkgconf-pkg-config openssl-devel libffi-devel gmp-devel rust cargo || true
        return 0
    fi

    if command -v pacman >/dev/null 2>&1; then
        run_root pacman -S --needed --noconfirm python python-pip base-devel pkgconf openssl libffi gmp rust || true
        return 0
    fi

    if command -v apk >/dev/null 2>&1; then
        run_root apk add python3 py3-pip py3-virtualenv build-base pkgconf openssl-dev libffi-dev gmp-dev rust cargo || true
        return 0
    fi

    if command -v zypper >/dev/null 2>&1; then
        run_root zypper --non-interactive install python3 python3-pip gcc gcc-c++ make pkg-config libopenssl-devel libffi-devel gmp-devel rust cargo || true
        return 0
    fi

    warn "Unknown package manager. Install Python 3.10-3.13 and build tools manually."
}

python_is_supported(){
    "$1" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if (3, 10) <= sys.version_info[:2] <= (3, 13) else 1)
PY
}

find_python(){
    for candidate in python3.13 python3.12 python3.11 python3.10; do
        if command -v "$candidate" >/dev/null 2>&1; then
            path="$(command -v "$candidate")"
            if python_is_supported "$path"; then
                printf '%s\n' "$path"
                return 0
            fi
        fi
    done

    if command -v python3 >/dev/null 2>&1; then
        path="$(command -v python3)"
        if python_is_supported "$path"; then
            printf '%s\n' "$path"
            return 0
        fi
    fi

    if command -v python >/dev/null 2>&1; then
        path="$(command -v python)"
        if python_is_supported "$path"; then
            printf '%s\n' "$path"
            return 0
        fi
    fi

    return 1
}

SYS_PY="$(find_python 2>/dev/null || true)"

if [ -z "$SYS_PY" ]; then
    warn "No compatible Python 3.10-3.13 interpreter found."
    install_system_dependencies
    hash -r 2>/dev/null || true
    SYS_PY="$(find_python 2>/dev/null || true)"
fi

[ -n "$SYS_PY" ] || fail "No supported Python found. Install Python 3.10, 3.11, 3.12 or 3.13. Python 3.14 is intentionally avoided for now."

printf 'Selected Python   : %s\n' "$SYS_PY"
printf 'Python version    : %s\n' "$("$SYS_PY" --version 2>&1)"

VENV_DIR="${VENV_DIR:-.venv}"
PYBIN="$SCRIPT_DIR/$VENV_DIR/bin/python"

venv_usable(){
    [ -x "$PYBIN" ] || return 1
    "$PYBIN" -c 'import sys; assert sys.prefix != sys.base_prefix; assert (3,10) <= sys.version_info[:2] <= (3,13)' >/dev/null 2>&1 || return 1
    "$PYBIN" -m pip --version >/dev/null 2>&1 || return 1
    return 0
}

if venv_usable; then
    ok "Existing virtualenv: $VENV_DIR"
else
    if [ -e "$VENV_DIR" ]; then
        warn "Broken, incompatible or outdated virtualenv detected."
        info "Removing $VENV_DIR ..."
        rm -rf -- "$VENV_DIR"
    fi

    info "Creating virtualenv: $VENV_DIR"
    if ! "$SYS_PY" -m venv "$VENV_DIR"; then
        warn "Initial virtualenv creation failed. Trying system prerequisites."
        install_system_dependencies
        rm -rf -- "$VENV_DIR"
        "$SYS_PY" -m venv "$VENV_DIR" || fail "Unable to create Python virtualenv."
    fi
fi

PYBIN="$SCRIPT_DIR/$VENV_DIR/bin/python"
[ -x "$PYBIN" ] || fail "Virtualenv Python does not exist: $PYBIN"

info "Checking virtualenv ..."
"$PYBIN" -c 'import sys; print("    executable :", sys.executable); print("    version    :", sys.version.split()[0]); print("    prefix     :", sys.prefix); print("    base       :", sys.base_prefix); assert sys.prefix != sys.base_prefix; assert (3,10) <= sys.version_info[:2] <= (3,13)' || fail "Virtualenv validation failed."

info "Checking pip ..."
if ! "$PYBIN" -m pip --version >/dev/null 2>&1; then
    "$PYBIN" -m ensurepip --upgrade || fail "Unable to install pip inside the virtualenv."
fi

info "Upgrading pip / setuptools / wheel ..."
"$PYBIN" -m pip install --upgrade pip setuptools wheel || fail "Unable to upgrade pip/setuptools/wheel."

[ -f requirements.txt ] || fail "requirements.txt not found in $SCRIPT_DIR"

info "Installing Python dependencies ..."
"$PYBIN" -m pip install -r requirements.txt || fail "Dependency installation failed."

printf '\n'
info "Python environment after installation"
printf '    Python : %s\n' "$PYBIN"
printf '    pip    : %s\n' "$("$PYBIN" -m pip --version)"
printf '\n'

CRITICAL_MODULES="cryptography requests socks bitcoinlib web3 solana tronpy xmr_gateway"
info "Checking critical imports ..."
IMPORT_FAILURE=0

for mod in $CRITICAL_MODULES; do
    if "$PYBIN" -c "import $mod" >/dev/null 2>&1; then
        ok "$mod"
    else
        printf '%s\n' "${RED}    FAILED  $mod${NC}"
        "$PYBIN" -c "import $mod" 2>&1 || true
        IMPORT_FAILURE=1
    fi
done

[ "$IMPORT_FAILURE" -eq 0 ] || fail "One or more required Python modules are unavailable in $VENV_DIR."

info "Checking package/interpreter association ..."
"$PYBIN" - <<'PY'
import sys
import requests
import bitcoinlib
print("    Python     :", sys.executable)
print("    requests   :", requests.__file__)
print("    bitcoinlib :", bitcoinlib.__file__)
PY
[ "$?" -eq 0 ] || fail "Package/interpreter validation failed."

info "Compiling / syntax-checking Python files ..."
for file in ./*.py; do
    [ -f "$file" ] || continue
    case "$file" in *.bak_*|*.backup|*.old) continue ;; esac
    "$PYBIN" -m py_compile "$file" || fail "Syntax error in ${file#./}"
    ok "${file#./}"
done

printf '\n'
printf '%s\n' "${GREEN}${BOLD}Installation complete.${NC}"
printf '\n'
printf '%s\n' "${GREEN}${BOLD}========== WALLET USAGE ==========${NC}"
printf '\n'
printf '%s\n' "${BOLD}VIRTUAL ENVIRONMENT${NC}"
printf '    %s\n' "$VENV_DIR"
printf '\n'
printf '%s\n' "${BOLD}Python selected${NC}"
printf '    %s\n' "$("$PYBIN" --version 2>&1)"
printf '\n'
printf '%s\n' "${BOLD}Recommended launch:${NC}"
printf '    python3 menu.py\n'
printf '\n'
printf '%s\n' "menu.py will automatically restart itself with:"
printf '    ./%s/bin/python\n' "$VENV_DIR"
printf '\n'
printf '%s\n' "${BOLD}Direct launch if needed:${NC}"
printf '    ./%s/bin/python menu.py\n' "$VENV_DIR"
printf '\n'
printf '%s\n' "${YELLOW}${BOLD}IMPORTANT:${NC}"
printf '%s\n' "    Python 3.14 is not selected automatically for now."
printf '%s\n' "    Supported range: Python 3.10 to 3.13."
printf '%s\n' "    Avoid using global pip/pip3 for this project."
printf '\n'
