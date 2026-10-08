#!/usr/bin/env bash
#
# Squawk — install or update the scanner toolbench on Unix.
#
#   ./install-tools.sh            # install what is missing   (or: squawk.py --install)
#   ./install-tools.sh --update   # update everything present (or: squawk.py --update)
#   ./install-tools.sh --detect   # say what it would do here, change nothing
#
# Idempotent and best-effort in both modes: it skips anything already present on
# install, and a single tool that fails does NOT stop the rest — the same
# "absence is a gap, not a failure" stance the tool itself takes. Re-run
# `python3 squawk.py --doctor` afterwards to see what landed.
#
# Update mode exists because of a specific silent failure: **a stale
# vulnerability database reports fewer CVEs and still looks clean.** Scanner
# binaries age slowly; their vulnerability data ages daily. So the update path
# refreshes the databases as well as the tools, and --doctor reports how old
# each database is.
#
# Portability. The scanner set is the same everywhere; only the package manager
# differs, so distribution-specific knowledge is confined to one table and one
# dispatch function. Everything after that is shared. Supported: apt (Debian,
# Kali, Ubuntu), dnf and yum (Fedora, RHEL, Rocky, Alma), apk (Alpine), pacman
# (Arch), zypper (openSUSE) and brew (macOS).
#
# The heaviest tools need no package manager at all. syft, grype and trivy come
# from vendor installers, and semgrep, bandit and checkov come from pipx, so on
# an unrecognised system most of the toolbench still lands.
#
# Privilege. It escalates only where a system install requires it, and works out
# how: nothing when already root, sudo when not. A container image running as
# root usually has no sudo at all, which used to make every privileged step fail
# with "sudo: command not found" — found by running this script in one.
#
# Read it before you run it. A security tool should not ask you to pipe an
# unread script into a shell.

set -uo pipefail

MODE=install
case "${1:-}" in
  --update) MODE=update ;;
  --detect) MODE=detect ;;
  "")       MODE=install ;;
  *) echo "usage: $0 [--update|--detect]"; exit 2 ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }

# --- privilege -------------------------------------------------------------
# Root needs no escalation and often has no sudo; a normal user needs sudo and
# has no way to proceed without it. Stating which of the three applies beats
# discovering it one failed command at a time.
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
  PRIV="already root"
elif have sudo; then
  SUDO="sudo"
  PRIV="via sudo"
else
  SUDO=""
  PRIV="none"
fi

# --- package manager -------------------------------------------------------
# One table, one dispatch. PKG_* names differ per manager because the same tool
# is packaged under different names, and a missing entry means "this manager
# does not ship it" rather than "install a package called empty string".
PM=""
for candidate in apt-get dnf yum apk pacman zypper brew; do
  if have "$candidate"; then PM="$candidate"; break; fi
done

OSNAME="$(uname -s)"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  OSNAME="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-$NAME}")"
fi

pkg_name() { # logical-name -> package name for this manager, or empty
  case "$PM:$1" in
    apt-get:gitleaks) echo gitleaks ;;
    apt-get:pipx)     echo pipx ;;
    apt-get:docker)   echo docker.io ;;
    apt-get:curl)     echo curl ;;
    apt-get:git)      echo git ;;
    apt-get:ca)       echo ca-certificates ;;
    dnf:gitleaks|yum:gitleaks) echo gitleaks ;;
    dnf:pipx|yum:pipx)         echo pipx ;;
    dnf:docker|yum:docker)     echo docker ;;
    dnf:gh|yum:gh)             echo gh ;;
    dnf:curl|yum:curl)         echo curl ;;
    dnf:git|yum:git)           echo git ;;
    dnf:ca|yum:ca)             echo ca-certificates ;;
    apk:pipx)   echo pipx ;;
    apk:docker) echo docker ;;
    apk:gh)     echo github-cli ;;
    apk:curl)   echo curl ;;
    apk:git)    echo git ;;
    apk:ca)     echo ca-certificates ;;
    pacman:pipx)   echo python-pipx ;;
    pacman:docker) echo docker ;;
    pacman:gh)     echo github-cli ;;
    pacman:curl)   echo curl ;;
    pacman:git)    echo git ;;
    pacman:ca)     echo ca-certificates ;;
    zypper:pipx)   echo python3-pipx ;;
    zypper:docker) echo docker ;;
    zypper:gh)     echo gh ;;
    zypper:curl)   echo curl ;;
    zypper:git)    echo git ;;
    zypper:ca)     echo ca-certificates ;;
    brew:gitleaks) echo gitleaks ;;
    brew:pipx)     echo pipx ;;
    brew:gh)       echo gh ;;
    brew:curl)     echo curl ;;
    brew:git)      echo git ;;
    *) echo "" ;;
  esac
}

pm_refresh() {
  case "$PM" in
    apt-get) $SUDO apt-get update -qq ;;
    dnf|yum) $SUDO "$PM" -q makecache ;;
    apk)     $SUDO apk update -q ;;
    pacman)  $SUDO pacman -Sy --noconfirm >/dev/null ;;
    zypper)  $SUDO zypper --non-interactive refresh >/dev/null ;;
    brew)    brew update >/dev/null ;;
    *) return 0 ;;
  esac
}

pm_install() { # package names
  [ "$#" -gt 0 ] || return 0
  case "$PM" in
    apt-get) $SUDO apt-get install -y "$@" ;;
    dnf|yum) $SUDO "$PM" install -y "$@" ;;
    apk)     $SUDO apk add --no-cache "$@" ;;
    pacman)  $SUDO pacman -S --noconfirm --needed "$@" ;;
    zypper)  $SUDO zypper --non-interactive install "$@" ;;
    brew)    brew install "$@" ;;
    *) return 1 ;;
  esac
}

pm_upgrade_all() {
  case "$PM" in
    apt-get) $SUDO apt-get full-upgrade -y ;;
    dnf|yum) $SUDO "$PM" upgrade -y ;;
    apk)     $SUDO apk upgrade ;;
    pacman)  $SUDO pacman -Su --noconfirm ;;
    zypper)  $SUDO zypper --non-interactive update ;;
    brew)    brew upgrade ;;
    *) return 1 ;;
  esac
}

# Count of pending upgrades, or "unknown". Reported rather than guessed: a
# number nobody measured is worse than saying it was not measured.
#
# Every branch ends in `|| true` and prints exactly one line. `grep -c` prints
# "0" AND exits 1 when nothing matches, so a caller writing
# `X="$(pm_pending || echo unknown)"` captured both, giving the literal value
# "0\nunknown" and the message "OS packages (0 unknown upgraded)". Seen in a
# container before it was seen by a user.
pm_pending() {
  case "$PM" in
    apt-get) apt-get -s full-upgrade 2>/dev/null | grep -c '^Inst ' || true ;;
    dnf|yum) "$PM" -q check-update 2>/dev/null | grep -c '^[a-zA-Z0-9]' || true ;;
    apk)     apk version -l '<' 2>/dev/null | tail -n +2 | grep -c . || true ;;
    pacman)  pacman -Qu 2>/dev/null | grep -c . || true ;;
    zypper)  zypper --non-interactive list-updates 2>/dev/null | grep -c '^v ' || true ;;
    brew)    brew outdated 2>/dev/null | grep -c . || true ;;
    *) echo unknown ;;
  esac
}
ok()   { printf '  \033[32mok\033[0m   %s\n' "$*"; }
add()  { printf '  \033[36m..\033[0m   %s\n' "$*"; }
bad()  { printf '  \033[31m!!\033[0m   %s\n' "$*"; FAILURES=$((FAILURES+1)); }

FAILURES=0

# Facts for the caller's record. squawk.py passes SQUAWK_INSTALL_FACTS and reads
# this back into install.json. Only the shell knows what it downloaded and from
# where, so only the shell can report it.
fact() {
  [ -n "${SQUAWK_INSTALL_FACTS:-}" ] || return 0
  printf '%s\n' "$1" >> "$SQUAWK_INSTALL_FACTS" 2>/dev/null || true
}

# Version of a tool, one line, or "-" when it is not installed. Printed rather
# than discarded: "ok syft" does not tell you which syft.
ver() {
  have "$1" || { printf -- '-'; return; }
  { "$1" "${2:---version}" 2>&1 || true; } | head -1 | tr -d '\r'
}

# Report a tool with its version, so the terminal shows what actually landed.
okv() { ok "$(printf '%-9s %s' "$1" "$(ver "$1" "${2:---version}")")"; }

export PATH="$HOME/.local/bin:$PATH"   # pipx installs here

case "$MODE" in
  install) echo "Squawk — installing the scanner toolbench" ;;
  update)  echo "Squawk — updating the toolbench, its databases and its images" ;;
  detect)  echo "Squawk — reporting what an install would do here (changing nothing)" ;;
esac
echo "  system     $OSNAME ($(uname -m))"
echo "  packages   ${PM:-none recognised}"
echo "  privilege  $PRIV"
fact "{\"kind\":\"system\",\"os\":\"$OSNAME\",\"arch\":\"$(uname -m)\",\"pm\":\"${PM:-none}\",\"privilege\":\"$PRIV\"}"
echo

if [ "$MODE" = detect ]; then
  # Reports and exits. Worth having on its own: the answer to "what will this
  # do on my machine" should not require running it on your machine.
  echo "Would use:"
  for logical in curl git gitleaks pipx docker gh; do
    pkg="$(pkg_name "$logical")"
    if have "$logical"; then
      printf '  %-9s present   %s\n' "$logical" "$(ver "$logical")"
    elif [ -n "$pkg" ]; then
      printf '  %-9s install   %s package "%s"\n' "$logical" "$PM" "$pkg"
    else
      printf '  %-9s no route  no %s package known\n' "$logical" "${PM:-manager}"
    fi
  done
  for logical in syft grype trivy; do
    if have "$logical"; then
      printf '  %-9s present   %s\n' "$logical" "$(ver "$logical" version)"
    else
      printf '  %-9s install   vendor installer over https (needs curl)\n' "$logical"
    fi
  done
  for logical in semgrep bandit checkov; do
    if have "$logical"; then
      printf '  %-9s present   %s\n' "$logical" "$(ver "$logical")"
    else
      printf '  %-9s install   pipx, into $HOME, no privilege needed\n' "$logical"
    fi
  done
  echo
  if ! have python3; then
    bad "python3 is missing — Squawk itself will not run here"
  else
    ok "python3    $(python3 -V 2>&1)"
  fi
  [ "$FAILURES" -gt 0 ] && exit 1
  exit 0
fi

if [ -z "$PM" ]; then
  bad "no supported package manager found (apt, dnf, yum, apk, pacman, zypper, brew)"
  echo "     Continuing anyway. pipx and the vendor installers do not need one,"
  echo "     so most of the toolbench can still land."
elif [ "$PRIV" = none ] && [ "$PM" != brew ]; then
  bad "not root and sudo is not installed — system packages cannot be installed"
  echo "     Continuing anyway: pipx tools install into \$HOME and need no"
  echo "     privilege. Anything needing the package manager will be skipped."
fi

# --- prerequisites ----------------------------------------------------------
# curl is not optional here: every vendor installer is fetched with it, and its
# absence used to surface as three separate "installer failed" lines rather
# than one "curl is missing". Found by running this script on a minimal image.
for prereq in curl git; do
  have "$prereq" && continue
  pkg="$(pkg_name "$prereq")"
  if [ -n "$pkg" ] && [ "$PRIV" != none ]; then
    add "$prereq is missing — installing $pkg first"
    pm_refresh >/dev/null 2>&1 || true
    pm_install "$pkg" >/dev/null 2>&1 || bad "could not install $prereq"
  else
    bad "$prereq is missing and cannot be installed here"
  fi
done
if ! have curl; then
  bad "curl is unavailable — syft, grype and trivy cannot be fetched"
fi
echo

# --- OS packages ------------------------------------------------------------
if [ -z "$PM" ] || { [ "$PRIV" = none ] && [ "$PM" != brew ]; }; then
  add "skipping system packages — no usable package manager or no privilege"
elif [ "$MODE" = update ]; then
  add "$PM: updating the OS and its packages"
  pm_refresh >/dev/null 2>&1 || bad "$PM refresh failed"
  PENDING="$(pm_pending 2>/dev/null | head -1)"
  [ -n "$PENDING" ] || PENDING=unknown
  add "$PM: $PENDING package(s) to upgrade"
  fact "{\"kind\":\"packages\",\"pm\":\"$PM\",\"pending_upgrades\":\"${PENDING:-unknown}\"}"
  # The upgrade list is named where the manager can name it. "47 packages were
  # upgraded" is not an answer to "what changed on this machine".
  if [ "$PM" = apt-get ]; then
    apt-get -s full-upgrade 2>/dev/null | awk '/^Inst /{print $2}' | while read -r pkg; do
      fact "{\"kind\":\"package-upgrade\",\"package\":\"$pkg\"}"
    done
  fi
  # An upgrade that failed must not be followed by a line saying it worked.
  # This printed "!! apt-get upgrade failed" and then "ok OS packages (47
  # upgraded)" on the same screen, which is the exact failure this tool exists
  # to refuse: a step that did not run looking like one that did. It also ran
  # autoremove afterwards, which is a package operation on a database the
  # manager has just said is in a bad state.
  if pm_upgrade_all; then
    [ "$PM" = apt-get ] && $SUDO apt-get autoremove -y >/dev/null 2>&1
    # What is pending AFTER the upgrade is the measurement. The number before
    # it is what we hoped to do, and reporting a hope as a result is how "47
    # upgraded" gets printed when none were.
    REMAIN="$(pm_pending 2>/dev/null | head -1)"
    [ -n "$REMAIN" ] || REMAIN=unknown
    if [ "$REMAIN" = 0 ]; then
      ok "OS packages — $PENDING upgraded, none pending"
    else
      ok "OS packages — was $PENDING pending, now $REMAIN"
    fi
    fact "{\"kind\":\"packages_after\",\"pm\":\"$PM\",\"pending_upgrades\":\"$REMAIN\"}"
    if [ -f /var/run/reboot-required ]; then
      add "a reboot is required to finish this upgrade"
      fact '{"kind":"reboot_required","value":true}'
    fi
  else
    bad "$PM upgrade failed — no OS package was upgraded"
    fact "{\"kind\":\"packages_after\",\"pm\":\"$PM\",\"ok\":false}"
    # A failure with no fix line is a complaint. Name the two states that
    # actually cause this and the command that clears each, so the next step is
    # on screen rather than in a search engine.
    if [ "$PM" = apt-get ]; then
      if $SUDO dpkg --audit 2>/dev/null | grep -q . \
         || [ -f /var/lib/dpkg/updates/0000 ]; then
        add "dpkg was interrupted. Clear it, then run this again:"
        add "    sudo dpkg --configure -a"
      fi
      if $SUDO fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
        add "another package manager holds the dpkg lock. Wait for it, then run this again."
      fi
      add "the scanners below are still updated; only the OS packages were skipped"
    fi
  fi
else
  WANT=()
  for logical in gitleaks pipx docker; do
    case "$logical" in
      gitleaks) have gitleaks && continue ;;
      pipx)     have pipx     && continue ;;
      docker)   have docker   && continue ;;
    esac
    pkg="$(pkg_name "$logical")"
    if [ -n "$pkg" ]; then
      WANT+=("$pkg")
    else
      # Named rather than skipped in silence. gitleaks has no package on some
      # managers, and "we did not try" is a different statement from "it failed".
      add "$logical: no $PM package known — install it by hand if you need it"
    fi
  done
  if [ "${#WANT[@]}" -gt 0 ]; then
    add "$PM: ${WANT[*]}"
    pm_refresh >/dev/null 2>&1 || bad "$PM refresh failed"
    pm_install "${WANT[@]}" || bad "$PM install failed for: ${WANT[*]}"
  fi
fi
have pipx && pipx ensurepath >/dev/null 2>&1 || true

# gh only powers GitHub-issue baselines; no scan service needs it, so a failure
# here is a gap rather than a problem. Most managers ship it; apt does not, and
# needs GitHub's own repository added first.
if have gh; then
  okv gh
elif [ "$PRIV" = none ] && [ "$PM" != brew ]; then
  add "gh: skipped, needs privilege (optional; only used for baselines)"
elif [ "$PM" = apt-get ]; then
  add "gh: adding the GitHub CLI apt repo"
  $SUDO mkdir -p -m 755 /etc/apt/keyrings
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | $SUDO tee /etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null 2>&1
  $SUDO chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg 2>/dev/null
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | $SUDO tee /etc/apt/sources.list.d/github-cli.list >/dev/null
  pm_refresh >/dev/null 2>&1 && pm_install gh >/dev/null 2>&1 \
    && okv gh || bad "gh — repo add or install failed (optional; only used for baselines)"
else
  ghpkg="$(pkg_name gh)"
  if [ -n "$ghpkg" ]; then
    add "$PM: $ghpkg"
    pm_install "$ghpkg" >/dev/null 2>&1 && okv gh \
      || bad "gh — install failed (optional; only used for baselines)"
  else
    add "gh: no $PM package known (optional; only used for baselines)"
  fi
fi

# --- Python scanners via pipx ----------------------------------------------
if [ "$MODE" = update ]; then
  if have pipx; then
    add "pipx: upgrading semgrep, bandit, checkov"
    # Output kept. "ok pipx tools" was true whether three tools upgraded or
    # none did, which makes it not worth printing.
    if PIPX_OUT="$(pipx upgrade-all 2>&1)"; then
      printf '%s\n' "$PIPX_OUT" | sed 's/^/       /'
      ok "pipx tools"
    else
      printf '%s\n' "$PIPX_OUT" | sed 's/^/       /'
      bad "pipx upgrade-all reported a problem"
    fi
    for t in semgrep bandit checkov; do have "$t" && okv "$t"; done
  fi
else
  for tool in semgrep bandit checkov; do
    if have "$tool"; then okv "$tool"; else
      add "pipx: $tool"
      if pipx install "$tool" >/dev/null 2>&1; then okv "$tool"; else
        bad "$tool — pipx install failed (on Python 3.13+ try: pipx install --python python3.12 $tool)"
      fi
    fi
  done
fi

# --- Go scanners via official installers (they always fetch latest) ---------
# Downloads the vendor installer, records its sha256, and only then runs it as
# root. It used to be `curl ... | sudo sh`, which runs unseen code as root and
# leaves nothing behind saying which code that was — the exact practice the
# header of this file warns the reader about. Hashing does not make a hostile
# installer safe. It makes the thing that ran identifiable afterwards, so a
# change between two runs is visible instead of invisible.
run_vendor_installer() { # name  url
  local tmp sum bytes
  tmp="$(mktemp)" || { bad "$1 — could not create a temp file"; return 1; }
  if ! curl -sSfL "$2" -o "$tmp"; then
    bad "$1 — download failed from $2"
    fact "{\"kind\":\"download\",\"tool\":\"$1\",\"url\":\"$2\",\"ok\":false}"
    rm -f "$tmp"; return 1
  fi
  sum="$(sha256sum "$tmp" 2>/dev/null | awk '{print $1}')"
  bytes="$(wc -c < "$tmp" | tr -d ' ')"
  fact "{\"kind\":\"download\",\"tool\":\"$1\",\"url\":\"$2\",\"sha256\":\"${sum:-unknown}\",\"bytes\":${bytes:-0},\"ok\":true}"
  add "$1: fetched $bytes bytes, sha256 ${sum:0:16}..."
  if $SUDO sh "$tmp" -b /usr/local/bin >/dev/null 2>&1; then
    rm -f "$tmp"; return 0
  fi
  bad "$1 — vendor installer exited non-zero"
  rm -f "$tmp"; return 1
}

install_bin() { # name  url
  if [ "$MODE" = install ] && have "$1"; then okv "$1" "${3:---version}"; return; fi
  [ "$MODE" = update ] && ! have "$1" && return   # update does not add new tools
  add "installer: $1"
  run_vendor_installer "$1" "$2" && okv "$1" "${3:---version}"
}
install_bin syft  https://raw.githubusercontent.com/anchore/syft/main/install.sh version
install_bin grype https://raw.githubusercontent.com/anchore/grype/main/install.sh version
if [ "$MODE" = update ] && ! have trivy; then :; else
  if [ "$MODE" = install ] && have trivy; then okv trivy; else
    add "installer: trivy"
    run_vendor_installer trivy \
      https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      && okv trivy
  fi
fi

# --- Vulnerability databases (update mode only) -----------------------------
# The part that actually matters for accuracy. A tool at the right version with
# a month-old database quietly reports fewer CVEs than exist.
if [ "$MODE" = update ]; then
  echo
  if have trivy; then
    add "trivy: refreshing the vulnerability database"
    if trivy image --download-db-only >/dev/null 2>&1; then
      ok "trivy vuln DB"; fact '{"kind":"vulndb","tool":"trivy","ok":true}'
    else
      bad "trivy DB refresh failed (rate limit or network) — findings may be stale"
      fact '{"kind":"vulndb","tool":"trivy","ok":false}'
    fi
  fi
  if have grype; then
    add "grype: refreshing the vulnerability database"
    if grype db update >/dev/null 2>&1; then
      ok "grype vuln DB"; fact '{"kind":"vulndb","tool":"grype","ok":true}'
    else
      bad "grype DB refresh failed — findings may be stale"
      fact '{"kind":"vulndb","tool":"grype","ok":false}'
    fi
  fi

  # --- Container images Squawk runs -----------------------------------------
  if have docker; then
    add "docker: pulling the ZAP image used for DAST"
    if docker pull ghcr.io/zaproxy/zaproxy:stable >/dev/null 2>&1; then
      ZAPDIG="$(docker image inspect --format '{{index .RepoDigests 0}}' \
                ghcr.io/zaproxy/zaproxy:stable 2>/dev/null || echo unknown)"
      ok "ZAP image  $ZAPDIG"
      fact "{\"kind\":\"image\",\"ref\":\"ghcr.io/zaproxy/zaproxy:stable\",\"digest\":\"$ZAPDIG\"}"
    else
      bad "ZAP image pull failed — liveprobe will report it rather than scan"
      fact '{"kind":"image","ref":"ghcr.io/zaproxy/zaproxy:stable","ok":false}'
    fi
  fi
fi

echo
if have docker && ! groups | grep -qw docker; then
  echo "Docker installed — add yourself to the group so you can run it without sudo:"
  echo "    sudo usermod -aG docker \"\$USER\" && newgrp docker"
fi
if [ "$MODE" = install ]; then
  echo "ZAP (DAST) needs no install — Squawk runs it from the ZAP Docker image."
  echo "If pipx tools show as gaps, open a new shell so ~/.local/bin is on PATH."
else
  echo "Squawk itself is not updated here — that would change the code mid-run."
  echo "Update it deliberately:  git -C <checkout> pull"
fi
echo
if [ "$FAILURES" -gt 0 ]; then
  echo "$FAILURES step(s) failed. This script now exits non-zero so the caller"
  echo "records the failure rather than treating a partial update as a clean one."
  echo
  echo "Next: python3 squawk.py --doctor"
  exit 1
fi
echo "Next: python3 squawk.py --doctor"
