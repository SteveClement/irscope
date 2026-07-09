#!/usr/bin/env bash
# Module 12 — Package inventory: installed packages, recently installed, outdated

run_module() {
  section "Packages & Software"

  subsection "Package Manager"
  if have_cmd dpkg; then
    info "Package manager: dpkg/apt (Debian/Ubuntu)"

    subsection "Total Installed Packages"
    local pkg_count
    pkg_count=$(dpkg -l 2>/dev/null | grep -c '^ii' || echo "unknown")
    info "Installed packages: ${pkg_count}"

    subsection "Recently Installed / Upgraded (last ${SCAN_DAYS_RECENT} days)"
    local recent_pkgs
    if [[ -f /var/log/dpkg.log ]]; then
      recent_pkgs=$(grep -E ' (installed|upgraded) ' /var/log/dpkg.log 2>/dev/null | tail -100 || true)
    fi
    for f in /var/log/dpkg.log.{1..5} /var/log/dpkg.log.*.gz; do
      [[ -f "$f" ]] || continue
      if [[ "$f" == *.gz ]]; then
        recent_pkgs+=$(zgrep -E ' (installed|upgraded) ' "$f" 2>/dev/null | tail -50 || true)
      else
        recent_pkgs+=$(grep -E ' (installed|upgraded) ' "$f" 2>/dev/null | tail -50 || true)
      fi
    done
    if [[ -n "$recent_pkgs" ]]; then
      info "Recent package changes:"
      printf '%s\n' "$recent_pkgs" | sort | tail -50 | raw_block
    else
      info "No recent package changes found in dpkg.log"
    fi

    subsection "Security-Relevant Packages"
    local sec_pkgs=(openssh-server openssh-client ufw fail2ban auditd apparmor
                    libpam-google-authenticator libssl openssl php php-fpm
                    apache2 nginx mysql-server mariadb-server postfix)
    for p in "${sec_pkgs[@]}"; do
      local ver
      ver=$(dpkg -l "$p" 2>/dev/null | grep "^ii" | awk '{print $3}' || echo "not installed")
      info "  ${p}: ${ver}"
    done

    subsection "Upgradable Packages"
    if have_cmd apt; then
      local upgradable
      upgradable=$(apt list --upgradable 2>/dev/null | grep -v '^Listing' | head -50 || true)
      if [[ -n "$upgradable" ]]; then
        warn "Packages with pending upgrades:"
        printf '%s\n' "$upgradable" | raw_block
        local upgrade_count
        upgrade_count=$(printf '%s\n' "$upgradable" | wc -l | tr -d ' ')
        (( upgrade_count > 20 )) && high "${upgrade_count} packages have pending upgrades — security patches may be missing"
      else
        info "All packages up-to-date"
      fi
    fi

    subsection "Packages Installed from Non-Official Sources"
    local foreign_pkgs
    foreign_pkgs=$(dpkg -l 2>/dev/null | awk '/^ii/{print $2}' \
      | xargs apt-cache show 2>/dev/null \
      | grep -E '(Filename|APT-Sources)' \
      | grep -v 'deb.debian.org\|security.debian.org\|archive.ubuntu.com\|security.ubuntu.com' \
      | head -20 || true)
    if [[ -n "$foreign_pkgs" ]]; then
      warn "Packages possibly from non-official repos:"
      printf '%s\n' "$foreign_pkgs" | raw_block
    fi

  elif have_cmd rpm; then
    info "Package manager: rpm/yum/dnf (RHEL/CentOS/Fedora)"
    subsection "Recently Installed"
    rpm -qa --queryformat '%{installtime:date} %{name}-%{version}\n' 2>/dev/null \
      | sort -r | head -50 | raw_block || true
    subsection "Upgradable"
    if have_cmd dnf; then
      dnf check-update 2>/dev/null | head -30 | raw_block || true
    elif have_cmd yum; then
      yum check-update 2>/dev/null | head -30 | raw_block || true
    fi
  else
    info "Unknown package manager — skipping package analysis"
  fi

  subsection "Unexpected Interpreters / Tools"
  local pentest_tools=(nmap masscan nikto sqlmap metasploit msfconsole
                       hydra medusa john hashcat aircrack-ng netcat ncat
                       socat chisel ligolo pwncat)
  for t in "${pentest_tools[@]}"; do
    if have_cmd "$t"; then
      warn "Offensive/pentest tool found: ${t} ($(command -v "$t"))"
    fi
  done
}
