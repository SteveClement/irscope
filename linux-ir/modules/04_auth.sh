#!/usr/bin/env bash
# Module 04 — Authentication: users, SSH, sudo, login history, PAM

run_module() {
  section "Authentication & Access"

  subsection "Local Users (UID >= 1000 or login shell)"
  awk -F: '($3>=1000 && $3!=65534) || $7 ~ /(bash|sh|zsh|fish|ksh)$/ {
    printf "%-20s uid=%-6s gid=%-6s home=%-30s shell=%s\n", $1,$3,$4,$6,$7
  }' /etc/passwd 2>/dev/null | raw_block

  subsection "Users with UID 0 (root equivalent)"
  local root_users
  root_users=$(awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null)
  for u in $root_users; do
    if [[ "$u" != "root" ]]; then
      critical "Non-root account with UID 0: ${u}"
    else
      info "Root account: ${u}"
    fi
  done

  subsection "Accounts with Empty Passwords"
  # $2==""  → truly empty password (critical — anyone can login)
  # $2=="!" or $2=="!!" → locked account (no password login possible; normal for service accounts)
  local empty_pw locked_pw
  empty_pw=$(awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null || true)
  locked_pw=$(awk -F: '$2=="!" || $2=="!!"{print $1}' /etc/shadow 2>/dev/null || true)
  if [[ -n "$empty_pw" ]]; then
    critical "Accounts with EMPTY passwords (login without password possible): ${empty_pw}"
  else
    info "No accounts with empty passwords"
  fi
  if [[ -n "$locked_pw" ]]; then
    info "Accounts with locked passwords (expected for service accounts): $(printf '%s' "$locked_pw" | tr '\n' ' ')"
  fi

  subsection "Locked / Disabled Accounts"
  awk -F: '$2~/^[!*]/{print $1}' /etc/shadow 2>/dev/null | while read -r u; do
    info "Locked account: ${u}"
  done

  subsection "Groups with Elevated Privilege"
  for g in sudo wheel adm docker lxd disk; do
    local members
    members=$(getent group "$g" 2>/dev/null | cut -d: -f4)
    if [[ -n "$members" ]]; then
      info "Group '${g}' members: ${members}"
      # Docker group = effective root
      if [[ "$g" == "docker" || "$g" == "lxd" || "$g" == "disk" ]]; then
        warn "Group '${g}' grants near-root access; members: ${members}"
      fi
    fi
  done

  subsection "SSH Authorised Keys"
  local key_files=()
  while IFS= read -r homedir; do
    [[ -f "${homedir}/.ssh/authorized_keys" ]] && key_files+=("${homedir}/.ssh/authorized_keys")
    [[ -f "${homedir}/.ssh/authorized_keys2" ]] && key_files+=("${homedir}/.ssh/authorized_keys2")
  done < <(awk -F: '($3>=0){print $6}' /etc/passwd | sort -u)
  key_files+=("/root/.ssh/authorized_keys")

  for kf in "${key_files[@]}"; do
    [[ -f "$kf" ]] || continue
    local count
    count=$(grep -c 'ssh-' "$kf" 2>/dev/null || echo 0)
    info "${kf}: ${count} key(s)"
    # Show full content for root's keys
    if [[ "$kf" == /root/* ]]; then
      cat "$kf" 2>/dev/null | raw_block
    fi
  done

  subsection "SSH Daemon Configuration"
  local sshd_conf=/etc/ssh/sshd_config
  if [[ -f "$sshd_conf" ]]; then
    local params=(PermitRootLogin PasswordAuthentication PubkeyAuthentication
                  AllowUsers DenyUsers AllowGroups DenyGroups
                  AuthorizedKeysFile PermitEmptyPasswords
                  X11Forwarding AllowAgentForwarding AllowTcpForwarding
                  Port ListenAddress MaxAuthTries)
    for p in "${params[@]}"; do
      local val
      val=$(grep -iE "^\s*${p}\s" "$sshd_conf" /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
            | grep -v '^#' | tail -1 | awk '{$1=""; print $0}' | xargs || echo "default")
      info "  ${p}: ${val}"
    done
    # Flag risky settings
    grep -iE '^\s*PermitRootLogin\s+(yes|prohibit-password)' "$sshd_conf" &>/dev/null \
      && warn "PermitRootLogin is not 'no' — direct root SSH may be possible"
    grep -iE '^\s*PasswordAuthentication\s+yes' "$sshd_conf" &>/dev/null \
      && warn "PasswordAuthentication enabled — brute-force risk"
    grep -iE '^\s*AllowAgentForwarding\s+yes' "$sshd_conf" &>/dev/null \
      && low "SSH agent forwarding enabled (CVE-2023-38408 risk if agents forwarded)"
    grep -iE '^\s*PermitEmptyPasswords\s+yes' "$sshd_conf" &>/dev/null \
      && critical "PermitEmptyPasswords yes — allows login with blank password"
  else
    warn "sshd_config not found at ${sshd_conf}"
  fi

  subsection "OpenSSH Version"
  if have_cmd sshd; then
    local sshd_ver
    sshd_ver=$(sshd -V 2>&1 | head -1 || ssh -V 2>&1 | head -1 || echo "unknown")
    info "sshd version: ${sshd_ver}"
    # CVE-2024-6387 (regreSSHion): OpenSSH 8.5p1–9.7p1 on glibc Linux
    if echo "$sshd_ver" | grep -qE 'OpenSSH_(8\.[5-9]|9\.[0-7])p1'; then
      critical "sshd may be vulnerable to CVE-2024-6387 (regreSSHion — unauthenticated RCE)"
    fi
  fi

  subsection "Login History (last)"
  last -F -n 50 2>/dev/null | raw_block || last -n 50 2>/dev/null | raw_block

  subsection "Failed Login Attempts (lastb)"
  lastb -n 30 2>/dev/null | raw_block || true

  subsection "Currently Logged-in Users"
  who 2>/dev/null | raw_block
  w 2>/dev/null | raw_block

  subsection "Sudo Configuration"
  cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' | raw_block || true
  for f in /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    info "sudoers.d: ${f}"
    grep -v '^#' "$f" | grep -v '^$' | raw_block
  done

  subsection "Recent sudo Usage"
  if [[ -f /var/log/auth.log ]]; then
    grep -aE 'sudo:.*COMMAND' /var/log/auth.log 2>/dev/null | tail -50 | raw_block || true
  fi
  for f in /var/log/auth.log.{1..5} /var/log/auth.log.*.gz; do
    [[ -f "$f" ]] || continue
    if [[ "$f" == *.gz ]]; then
      zgrep -aE 'sudo:.*COMMAND' "$f" 2>/dev/null | tail -20 | raw_block || true
    else
      grep -aE 'sudo:.*COMMAND' "$f" 2>/dev/null | tail -20 | raw_block || true
    fi
  done

  subsection "PAM Configuration"
  if [[ -d /etc/pam.d ]]; then
    for svc in sshd login su sudo common-auth; do
      [[ -f "/etc/pam.d/${svc}" ]] || continue
      info "PAM ${svc}:"
      grep -v '^#' "/etc/pam.d/${svc}" | grep -v '^$' | raw_block
    done
  fi
}
