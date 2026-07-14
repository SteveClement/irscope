#!/usr/bin/env bash
# Module 10 — MySQL/MariaDB: config, access controls, users, exposure

run_module() {
  section "MySQL / MariaDB"

  # ── Detect MySQL ───────────────────────────────────────────────────────────
  local mysql_bin=""
  for b in mysql mariadb; do
    have_cmd "$b" && mysql_bin="$b" && break
  done

  if ! have_cmd mysqld && ! have_cmd mariadbd && [[ -z "$mysql_bin" ]]; then
    info "MySQL/MariaDB not found — skipping module"
    return
  fi

  subsection "Server Version"
  if have_cmd mysqld; then
    mysqld --version 2>&1 | raw_block || true
  elif have_cmd mariadbd; then
    mariadbd --version 2>&1 | raw_block || true
  fi

  subsection "Listening Interfaces"
  local mysql_listen
  mysql_listen=$(ss -tlnp 2>/dev/null | grep ':3306' || netstat -tlnp 2>/dev/null | grep ':3306' || true)
  if [[ -n "$mysql_listen" ]]; then
    info "MySQL listening:"
    printf '%s\n' "$mysql_listen" | raw_block
    if echo "$mysql_listen" | grep -qE '0\.0\.0\.0:3306|:::3306|\*:3306'; then
      critical "MySQL listening on all interfaces — externally accessible if firewall not blocking"
    else
      info "MySQL bound to loopback/specific interface only (good)"
    fi
  else
    info "MySQL not listening on port 3306 (socket-only or stopped)"
  fi

  subsection "My.cnf Configuration"
  for conf in /etc/mysql/my.cnf /etc/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf \
               /etc/mysql/mariadb.conf.d/50-server.cnf; do
    [[ -f "$conf" ]] || continue
    info "Config: ${conf}"
    grep -v '^#' "$conf" | grep -v '^$' | raw_block
    # Flag bind-address
    local bind
    bind=$(grep -iE '^\s*bind.address\s*=' "$conf" 2>/dev/null | tail -1 | cut -d= -f2 | xargs || echo "")
    if [[ -n "$bind" ]]; then
      info "  bind-address: ${bind}"
      if [[ "$bind" == "0.0.0.0" || "$bind" == "::" || "$bind" == "*" ]]; then
        critical "bind-address=${bind} — MySQL accepts connections from all interfaces"
      fi
    fi
    # Flag skip-grant-tables — disables all authentication
    if grep -qiE '^\s*skip.grant.tables' "$conf" 2>/dev/null; then
      critical "skip-grant-tables set in ${conf} — all authentication bypassed"
    fi
  done

  subsection "MySQL Users and Privileges"
  # Try to connect as root without password (misconfiguration check)
  local can_connect=0
  if [[ -n "$mysql_bin" ]]; then
    if "$mysql_bin" -u root --connect-timeout=3 -e '' &>/dev/null; then
      can_connect=1
      # Distinguish socket authentication from a true empty password
      local root_plugin
      root_plugin=$("$mysql_bin" -u root --connect-timeout=3 --skip-column-names -e \
        "SELECT plugin FROM mysql.user WHERE user='root' LIMIT 1;" 2>/dev/null || echo "")
      if [[ "$root_plugin" == *socket* ]]; then
        warn "MySQL root uses socket authentication (unix_socket/auth_socket) — passwordless login works only as OS root"
        raw "  This is controlled access but means any process running as root can read the database."
        raw "  Consider adding a password as defence-in-depth: ALTER USER 'root'@'localhost' IDENTIFIED BY '...';"
      else
        critical "MySQL root login without password succeeds (plugin: ${root_plugin:-unknown}) — immediate remediation required"
      fi
    elif "$mysql_bin" -u root -p'' --connect-timeout=3 -e '' &>/dev/null; then
      critical "MySQL root login with empty string password succeeds"
      can_connect=1
    fi

    if (( can_connect )); then
      # List users
      subsection "User List"
      "$mysql_bin" -u root --connect-timeout=3 -e \
        "SELECT user, host, authentication_string!='' AS has_pw, \
         Super_priv, Grant_priv, File_priv FROM mysql.user;" 2>/dev/null | raw_block || true

      # Flag any user with host '%' (any host)
      local wildcard_users
      wildcard_users=$("$mysql_bin" -u root --connect-timeout=3 -e \
        "SELECT user, host FROM mysql.user WHERE host='%';" 2>/dev/null || true)
      if [[ -n "$wildcard_users" ]]; then
        high "MySQL users with wildcard host '%' (accessible from any host):"
        printf '%s\n' "$wildcard_users" | raw_block
      fi

      # Show grants for application users
      subsection "Application User Grants"
      "$mysql_bin" -u root --connect-timeout=3 -e \
        "SELECT CONCAT('SHOW GRANTS FOR ''', user, '''@''', host, ''';')
         FROM mysql.user WHERE user NOT IN ('root','mysql.sys','mysql.session','mariadb.sys');" \
        --skip-column-names 2>/dev/null \
        | while read -r stmt; do
            "$mysql_bin" -u root --connect-timeout=3 -e "$stmt" 2>/dev/null | raw_block || true
          done
    fi
  fi

  subsection "MySQL Error Log (last 50 lines)"
  for log in /var/log/mysql/error.log /var/log/mariadb/mariadb.log /var/log/mysqld.log; do
    [[ -f "$log" ]] || continue
    info "Error log: ${log}"
    tail -50 "$log" | raw_block
  done

  subsection "MySQL Data Directory"
  if [[ -d "${SCAN_MYSQL_DATADIR}" ]]; then
    ls -la "${SCAN_MYSQL_DATADIR}" 2>/dev/null | raw_block
    local dd_perms
    dd_perms=$(stat -c '%a' "${SCAN_MYSQL_DATADIR}" 2>/dev/null || echo "unknown")
    info "Data dir permissions: ${dd_perms}"
    if is_world_readable "${SCAN_MYSQL_DATADIR}"; then
      warn "MySQL data directory is world-readable"
    else
      info "MySQL data directory is not world-readable (good)"
    fi
  fi
}
