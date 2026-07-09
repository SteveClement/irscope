#!/usr/bin/env bash
# Module 13 — Security hardening: AppArmor/SELinux, auditd, fail2ban, CVE checks

run_module() {
  section "Security Configuration"

  subsection "AppArmor"
  if have_cmd aa-status; then
    aa-status 2>/dev/null | raw_block
    local enforced
    enforced=$(aa-status 2>/dev/null | grep 'profiles are in enforce mode' | grep -oP '^\d+' || echo 0)
    local complain
    complain=$(aa-status 2>/dev/null | grep 'profiles are in complain mode' | grep -oP '^\d+' || echo 0)
    info "AppArmor: ${enforced} profiles enforced, ${complain} in complain mode"
    (( complain > 0 )) && warn "${complain} AppArmor profiles in complain mode — not enforcing"
  else
    warn "AppArmor not available or not running"
  fi

  subsection "SELinux"
  if have_cmd getenforce; then
    local selinux_status
    selinux_status=$(getenforce 2>/dev/null || echo "unknown")
    info "SELinux: ${selinux_status}"
    [[ "$selinux_status" == "Disabled" || "$selinux_status" == "Permissive" ]] \
      && warn "SELinux is ${selinux_status}"
  else
    info "SELinux not installed"
  fi

  subsection "Fail2ban"
  if have_cmd fail2ban-client; then
    fail2ban-client status 2>/dev/null | raw_block || true
    # List active jails
    local jails
    jails=$(fail2ban-client status 2>/dev/null | grep 'Jail list' | cut -d: -f2 | tr ',' '\n' | xargs || true)
    for jail in $jails; do
      [[ -z "$jail" ]] && continue
      fail2ban-client status "$jail" 2>/dev/null | raw_block || true
    done
  else
    warn "fail2ban not installed — no brute-force protection"
  fi

  subsection "Auditd"
  if have_cmd auditctl; then
    auditctl -l 2>/dev/null | raw_block || true
    if have_cmd aureport; then
      aureport --summary 2>/dev/null | head -30 | raw_block || true
      # Recent authentication failures
      aureport --auth --failed 2>/dev/null | head -20 | raw_block || true
    fi
  else
    warn "auditd not active — security event logging limited to syslog"
  fi

  subsection "AIDE / File Integrity"
  if have_cmd aide; then
    info "AIDE installed: $(aide --version 2>/dev/null | head -1 || echo 'version unknown')"
    if [[ -f /var/lib/aide/aide.db ]]; then
      info "AIDE database present: /var/lib/aide/aide.db"
    else
      warn "AIDE installed but no database found — integrity checking not initialised"
    fi
  else
    warn "AIDE not installed — no file integrity monitoring"
  fi

  subsection "USBGuard"
  have_cmd usbguard && usbguard list-devices 2>/dev/null | raw_block \
    || info "USBGuard not installed"

  subsection "SSH Key Audit"
  # Check for weak key types (DSA, RSA < 2048)
  while IFS= read -r homedir; do
    for kf in "${homedir}/.ssh/authorized_keys" "${homedir}/.ssh/authorized_keys2"; do
      [[ -f "$kf" ]] || continue
      while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        local ktype
        ktype=$(awk '{print $1}' <<< "$line")
        case "$ktype" in
          ssh-dss)
            warn "DSA key (deprecated, weak) in ${kf}: ${line:0:80}..."
            ;;
          ssh-rsa)
            local bits
            bits=$(ssh-keygen -lf <(echo "$line") 2>/dev/null | awk '{print $1}' || echo 0)
            (( bits > 0 && bits < 2048 )) && warn "Weak RSA key (${bits} bits) in ${kf}"
            ;;
        esac
      done < "$kf"
    done
  done < <(awk -F: '{print $6}' /etc/passwd | sort -u)

  subsection "Exposed Credentials in Environment"
  # Scan /proc/*/environ for potential credential patterns (passwords, tokens)
  local cred_procs=0
  for env_file in /proc/*/environ; do
    [[ -f "$env_file" ]] || continue
    if tr '\0' '\n' < "$env_file" 2>/dev/null | grep -qiE '(password|passwd|secret|token|api.?key|db.?pass)=.{3,}'; then
      local pid="${env_file#/proc/}"
      pid="${pid%/environ}"
      local cmd
      cmd=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null | head -c 80 || echo "unknown")
      warn "Credentials in environment of PID ${pid} (${cmd})"
      (( ++cred_procs ))
    fi
  done
  (( cred_procs == 0 )) && info "No credential patterns found in process environments"

  subsection "Vulnerability Checks (version-based)"
  # OpenSSH CVE-2024-6387
  if have_cmd sshd; then
    local sshd_ver
    sshd_ver=$(sshd -V 2>&1 | head -1)
    if echo "$sshd_ver" | grep -qE 'OpenSSH_(8\.[5-9]|9\.[0-7])p1'; then
      critical "CVE-2024-6387 (regreSSHion): sshd version in vulnerable range: ${sshd_ver}"
      raw "  Remediation: upgrade OpenSSH to >= 9.8p1"
    else
      info "OpenSSH not in CVE-2024-6387 vulnerable range: ${sshd_ver}"
    fi
  fi

  # Sudo CVE-2021-3156 (Baron Samedit)
  if have_cmd sudo; then
    local sudo_ver
    sudo_ver=$(sudo --version 2>/dev/null | head -1 | grep -oP '[0-9]+\.[0-9]+\.[0-9p]+')
    info "Sudo version: ${sudo_ver}"
    # Vulnerable: 1.8.2 - 1.9.5p2
    if echo "$sudo_ver" | grep -qE '^1\.(8\.[2-9]|8\.[1-9][0-9]|9\.[0-4]|9\.5p[01]?)$'; then
      high "CVE-2021-3156 (Baron Samedit): sudo version ${sudo_ver} may be vulnerable"
    fi
  fi

  # PHP version
  if have_cmd php; then
    local php_ver
    php_ver=$(php -v 2>/dev/null | head -1)
    info "PHP: ${php_ver}"
    # PHP 8.0.x EOL Jan 2023, 8.1.x EOL Nov 2024
    echo "$php_ver" | grep -qE 'PHP (5\.|7\.[0-3]|8\.0\.)' \
      && high "PHP version is EOL / no longer receiving security updates: ${php_ver}"
  fi
}
