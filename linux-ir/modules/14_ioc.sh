#!/usr/bin/env bash
# Module 14 — IOC matching: IPs, domains, hashes, file patterns from signatures

run_module() {
  section "IOC / Threat Intelligence Matching"

  local ioc_file="${SIGNATURES_DIR}/iocs.txt"
  if [[ ! -f "$ioc_file" ]]; then
    info "No IOC file found at ${ioc_file} — skipping IOC matching"
    return
  fi

  # Parse IOC file into typed lists
  local -a ioc_ips ioc_domains ioc_hashes ioc_strings
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    case "$line" in
      ip:*)     ioc_ips+=("${line#ip:}") ;;
      domain:*) ioc_domains+=("${line#domain:}") ;;
      hash:*)   ioc_hashes+=("${line#hash:}") ;;
      str:*)    ioc_strings+=("${line#str:}") ;;
      *)        ioc_strings+=("$line") ;;
    esac
  done < "$ioc_file"

  info "Loaded IOCs: ${#ioc_ips[@]} IPs, ${#ioc_domains[@]} domains, ${#ioc_hashes[@]} hashes, ${#ioc_strings[@]} strings"

  # ── IP IOCs in logs ────────────────────────────────────────────────────────
  if (( ${#ioc_ips[@]} > 0 )); then
    subsection "IOC IPs in Apache Logs"
    local ip_pattern
    ip_pattern=$(printf '%s\n' "${ioc_ips[@]}" | paste -sd'|')
    local log_prefix="${SCAN_APACHE_LOG_DIR}/access.log"
    local ip_hits
    ip_hits=$(search_logs "$ip_pattern" "$log_prefix" 2>/dev/null | head -50 || true)
    # Also search vhost logs
    while IFS= read -r vlog; do
      ip_hits+=$(search_logs "$ip_pattern" "$vlog" 2>/dev/null | head -20 || true)
    done < <(find "${SCAN_APACHE_LOG_DIR}" -maxdepth 1 -name '*access*' 2>/dev/null)

    if [[ -n "$ip_hits" ]]; then
      critical "IOC IP addresses found in Apache access logs:"
      printf '%s\n' "$ip_hits" | raw_block
    else
      info "No IOC IPs found in Apache access logs"
    fi

    subsection "IOC IPs in Active Connections"
    if have_cmd ss; then
      local active_hits
      active_hits=$(ss -antp 2>/dev/null | grep -E "$ip_pattern" || true)
      if [[ -n "$active_hits" ]]; then
        critical "Active network connections to IOC IPs:"
        printf '%s\n' "$active_hits" | raw_block
      else
        info "No active connections to IOC IPs"
      fi
    fi

    subsection "IOC IPs in Auth Logs"
    for log in /var/log/auth.log /var/log/secure; do
      [[ -f "$log" ]] || continue
      local auth_hits
      auth_hits=$(grep -aE "$ip_pattern" "$log" 2>/dev/null | tail -20 || true)
      [[ -n "$auth_hits" ]] && critical "IOC IPs in ${log}:" && printf '%s\n' "$auth_hits" | raw_block
    done
  fi

  # ── Domain IOCs ────────────────────────────────────────────────────────────
  if (( ${#ioc_domains[@]} > 0 )); then
    subsection "IOC Domains in /etc/hosts and resolv.conf"
    local domain_pattern
    domain_pattern=$(printf '%s\n' "${ioc_domains[@]}" | paste -sd'|')
    local dns_hits
    dns_hits=$(cat /etc/hosts /etc/resolv.conf 2>/dev/null | grep -iE "$domain_pattern" || true)
    if [[ -n "$dns_hits" ]]; then
      critical "IOC domains in DNS configuration:"
      printf '%s\n' "$dns_hits" | raw_block
    fi

    subsection "IOC Domains in Apache Logs"
    local dom_log_hits
    dom_log_hits=$(search_logs "$domain_pattern" "${SCAN_APACHE_LOG_DIR}/access.log" 2>/dev/null | head -20 || true)
    if [[ -n "$dom_log_hits" ]]; then
      critical "IOC domains in Apache access logs:"
      printf '%s\n' "$dom_log_hits" | raw_block
    else
      info "No IOC domains in Apache access logs"
    fi
  fi

  # ── Hash IOCs ─────────────────────────────────────────────────────────────
  if (( ${#ioc_hashes[@]} > 0 )); then
    subsection "IOC File Hashes"
    if have_cmd md5sum || have_cmd sha256sum; then
      for hash in "${ioc_hashes[@]}"; do
        local hashlen="${#hash}"
        local hash_hits
        if (( hashlen == 32 )); then
          # MD5
          hash_hits=$(find "${SCAN_WEBROOT}" /tmp /var/tmp -type f 2>/dev/null \
            | xargs md5sum 2>/dev/null | grep -i "$hash" | head -5 || true)
        elif (( hashlen == 64 )); then
          # SHA256
          hash_hits=$(find "${SCAN_WEBROOT}" /tmp /var/tmp -type f 2>/dev/null \
            | xargs sha256sum 2>/dev/null | grep -i "$hash" | head -5 || true)
        fi
        if [[ -n "$hash_hits" ]]; then
          critical "IOC hash match: ${hash}"
          printf '%s\n' "$hash_hits" | raw_block
        fi
      done
      info "IOC hash scan complete (${#ioc_hashes[@]} hashes checked)"
    else
      warn "md5sum/sha256sum not available — skipping hash IOC scan"
    fi
  fi

  # ── String IOCs in running processes ──────────────────────────────────────
  if (( ${#ioc_strings[@]} > 0 )); then
    subsection "IOC Strings in Process Command Lines"
    local str_pattern
    str_pattern=$(printf '%s\n' "${ioc_strings[@]}" | paste -sd'|')
    local proc_hits
    proc_hits=$(ps aux 2>/dev/null | grep -iE "$str_pattern" | grep -v grep || true)
    if [[ -n "$proc_hits" ]]; then
      critical "IOC strings in running processes:"
      printf '%s\n' "$proc_hits" | raw_block
    else
      info "No IOC strings in running process names"
    fi

    subsection "IOC Strings in Web Files"
    local file_hits
    file_hits=$(grep -rlE "$str_pattern" "${SCAN_WEBROOT}" 2>/dev/null | head -20 || true)
    if [[ -n "$file_hits" ]]; then
      critical "IOC strings found in web files:"
      printf '%s\n' "$file_hits" | raw_block
    else
      info "No IOC strings found in web root files"
    fi
  fi
}
