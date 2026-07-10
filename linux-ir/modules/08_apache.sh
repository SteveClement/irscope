#!/usr/bin/env bash
# Module 08 — Apache: config review, vhost enumeration, log analysis

run_module() {
  section "Apache Web Server"

  # ── Detect Apache ──────────────────────────────────────────────────────────
  local apache_bin=""
  for b in apache2 httpd apache; do
    have_cmd "$b" && apache_bin="$b" && break
  done
  if [[ -z "$apache_bin" ]]; then
    info "Apache not found in PATH — skipping module"
    return
  fi

  subsection "Version"
  "${apache_bin}" -v 2>&1 | raw_block

  subsection "Loaded Modules"
  "${apache_bin}" -M 2>/dev/null | raw_block || true
  # Flag mod_status if publicly accessible (information disclosure)
  "${apache_bin}" -M 2>/dev/null | grep -q 'status_module' \
    && warn "mod_status loaded — verify it is restricted to localhost"

  subsection "Active Configuration (vhosts)"
  "${apache_bin}" -S 2>/dev/null | raw_block || true

  subsection "Main Config Files"
  for conf in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf; do
    [[ -f "$conf" ]] || continue
    info "Config: ${conf}"
    grep -v '^#' "$conf" | grep -v '^$' | raw_block
  done

  subsection "Virtual Host Configs"
  local vhost_dirs=(/etc/apache2/sites-enabled /etc/httpd/conf.d)
  for vdir in "${vhost_dirs[@]}"; do
    [[ -d "$vdir" ]] || continue
    for f in "${vdir}"/*; do
      [[ -f "$f" ]] || continue
      info "VHost: ${f}"
      grep -v '^#' "$f" | grep -v '^$' | raw_block

      # Flag missing security headers
      grep -qiE 'Header.*X-Content-Type-Options' "$f" \
        || low "Missing X-Content-Type-Options in ${f}"
      grep -qiE 'Header.*X-Frame-Options' "$f" \
        || low "Missing X-Frame-Options in ${f}"
      grep -qiE 'Header.*Content-Security-Policy' "$f" \
        || low "Missing Content-Security-Policy in ${f}"

      # Check FilesMatch / Files backup restrictions
      grep -qiE 'FilesMatch|<Files' "$f" \
        && info "File access restrictions present in ${f}" \
        || warn "No FilesMatch/Files access restrictions in ${f}"
    done
  done

  subsection "Log Rotation Config"
  if [[ -f /etc/logrotate.d/apache2 ]]; then
    cat /etc/logrotate.d/apache2 2>/dev/null | raw_block
    local rotate_val
    rotate_val=$(grep -E '^\s*rotate\s+' /etc/logrotate.d/apache2 2>/dev/null | awk '{print $2}')
    if [[ -n "$rotate_val" ]]; then
      info "Log rotation: keep ${rotate_val} files"
      if (( rotate_val < 30 )); then
        warn "Log retention is ${rotate_val} files — forensic gap possible (recommend >= 30)"
      fi
    fi
  fi

  subsection "Access Log Analysis"
  local log_prefix="${SCAN_APACHE_LOG_DIR}/access.log"
  local vhost_logs
  # Match only base log files (*.log); search_logs handles rotations (.1, .2.gz, etc.)
  vhost_logs=$(find "${SCAN_APACHE_LOG_DIR}" -maxdepth 1 -name '*access*.log' 2>/dev/null | sort)

  for log_base in "${log_prefix}" ${vhost_logs}; do
    [[ "${log_base}" == "${log_prefix}" ]] || info "Analysing vhost log: ${log_base}"

    # Top 20 IPs
    subsection "Top Requestors (${log_base##*/})"
    search_logs '.' "$log_base" 2>/dev/null \
      | awk '{print $1}' | sort | uniq -c | sort -rn | head -20 | raw_block || true

    # HTTP 4xx/5xx errors
    subsection "4xx/5xx Errors"
    search_logs '" [45][0-9][0-9] ' "$log_base" 2>/dev/null | tail -50 | raw_block || true

    # Scanner fingerprints (from signatures file)
    if [[ -f "${SIGNATURES_DIR}/scanners.txt" ]]; then
      local scan_pattern
      scan_pattern=$(grep -v '^#' "${SIGNATURES_DIR}/scanners.txt" | grep -v '^$' | paste -sd'|' || true)
      if [[ -n "$scan_pattern" ]]; then
        subsection "Scanner/Tool Fingerprints"
        local scanner_hits
        scanner_hits=$(search_logs "$scan_pattern" "$log_base" 2>/dev/null | head -50 || true)
        if [[ -n "$scanner_hits" ]]; then
          warn "Scanner/automated tool activity detected:"
          printf '%s\n' "$scanner_hits" | raw_block
        else
          info "No known scanner fingerprints found"
        fi
      fi
    fi

    # Config/backup file downloads
    subsection "Backup/Config File Requests"
    local backup_hits
    backup_hits=$(search_logs '\.(bak|backup|old|orig|save|swp|sql|dump|env)\b' "$log_base" 2>/dev/null | head -50 || true)
    if [[ -n "$backup_hits" ]]; then
      high "Requests for backup/config files:"
      printf '%s\n' "$backup_hits" | raw_block
    else
      info "No backup/config file requests found in logs"
    fi

    # PHP/shell upload attempts
    subsection "Upload / WebShell Attempts"
    local upload_hits
    upload_hits=$(search_logs '(POST.*\.(php|phtml|phar|shtml)|cmd=|c99|r57|shell\.php|upload\.php)' \
      "$log_base" 2>/dev/null | head -30 || true)
    if [[ -n "$upload_hits" ]]; then
      high "Possible webshell upload/execution attempts:"
      printf '%s\n' "$upload_hits" | raw_block
    else
      info "No obvious webshell upload patterns found"
    fi

    # CVE / exploit attempt patterns
    subsection "Exploit Attempt Patterns"
    local exploit_patterns='(\/\.\.\/|%2e%2e|%252e|etc\/passwd|proc\/self|\/shell\?|cmd\.exe|\bexec\s*\(|\beval\s*\(|UNION.*SELECT|<script|onerror=|onload=|javascript:|vbscript:|OGNL\.|\.wsdl\?wsdl|\/jndi:|T\(java\.)'
    local exploit_hits
    exploit_hits=$(search_logs "$exploit_patterns" "$log_base" 2>/dev/null | head -30 || true)
    if [[ -n "$exploit_hits" ]]; then
      high "Exploit/injection attempt patterns in logs:"
      printf '%s\n' "$exploit_hits" | raw_block
    else
      info "No exploit attempt patterns found"
    fi
  done

  subsection "Error Log Summary (last 100 lines)"
  local error_log="${SCAN_APACHE_LOG_DIR}/error.log"
  [[ -f "$error_log" ]] && tail -100 "$error_log" | raw_block || true
}
