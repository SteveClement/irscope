#!/usr/bin/env bash
# Module 07 — Filesystem: recently modified files, backup exposure, sensitive files

run_module() {
  section "Filesystem"

  subsection "Recently Modified Files in Web Root (last ${SCAN_DAYS_RECENT} days)"
  local recent_web
  recent_web=$(find "${SCAN_WEBROOT}" -maxdepth 6 -type f \
    -mtime "-${SCAN_DAYS_RECENT}" \
    ! -path '*/\.*' \
    2>/dev/null | head -100 || true)
  if [[ -n "$recent_web" ]]; then
    info "Recently modified web files:"
    printf '%s\n' "$recent_web" | while read -r f; do
      printf '  %s  %s\n' "$(stat_mtime "$f")" "$f"
    done | raw_block
  else
    info "No web files modified in last ${SCAN_DAYS_RECENT} days"
  fi

  subsection "Config/Backup Files Exposed in Web Root"
  # Files that should never be web-accessible
  local exposed_patterns=(
    '*.bak' '*.backup' '*.old' '*.orig' '*.save' '*.swp' '*.tmp'
    '*.sql' '*.dump' '*.tar' '*.tar.gz' '*.tar.bz2' '*.zip' '*.7z'
    '*.env' '*.conf' 'config.php.bak' '.env' '*.pem' '*.key' '*.p12'
    '*.pfx' 'id_rsa' 'id_dsa' 'id_ecdsa' 'id_ed25519'
    'wp-config.php.bak' 'settings.php.bak'
  )
  local found_exposed=0
  for pat in "${exposed_patterns[@]}"; do
    local found_pat=0
    while IFS= read -r -d '' f; do
      if [[ $found_pat -eq 0 ]]; then
        high "Potentially exposed file (${pat}) in web root:"
        found_pat=1
        found_exposed=1
      fi
      local perms
      perms=$(stat -c '%a' "$f" 2>/dev/null || echo "?")
      raw "  [perms:${perms}] ${f}"
      is_world_readable "$f" && critical "  ^ World-readable: ${f}"
    done < <(find "${SCAN_WEBROOT}" -maxdepth 8 -name "$pat" -type f -print0 2>/dev/null)
  done
  [[ $found_exposed -eq 0 ]] && info "No backup/config files found exposed in web root"

  subsection "PHP Files with Obfuscated/Encoded Content"
  local php_sus
  # --include='*.php' avoids grepping GBs of user-uploaded data; timeout caps worst-case
  # Exclude Nextcloud core/app/vendor dirs — only custom and user-upload paths are suspicious
  php_sus=$(timeout 120 grep -rlE --include='*.php' \
    --exclude-dir='data' --exclude-dir='.git' \
    --exclude-dir='apps' --exclude-dir='core' \
    --exclude-dir='lib' --exclude-dir='3rdparty' --exclude-dir='vendor' \
    '(base64_decode\s*\(|eval\s*\(|assert\s*\(|gzinflate|str_rot13|preg_replace.*\/e|exec\s*\(|system\s*\(|passthru)' \
    "${SCAN_WEBROOT}" 2>/dev/null | head -30 || true)
  if [[ -n "$php_sus" ]]; then
    high "PHP files with suspicious function calls (possible webshell):"
    printf '%s\n' "$php_sus" | raw_block
  else
    info "No obviously obfuscated PHP detected"
  fi

  subsection "Webshell Signature Scan"
  if [[ -f "${SIGNATURES_DIR}/webshells.txt" ]]; then
    local ws_pattern
    ws_pattern=$(grep -v '^#' "${SIGNATURES_DIR}/webshells.txt" | grep -v '^$' | paste -sd'|' || true)
    if [[ -n "$ws_pattern" ]]; then
      local ws_hits
      ws_hits=$(timeout 120 grep -rlE --include='*.php' \
        --exclude-dir='data' --exclude-dir='.git' \
        --exclude-dir='apps' --exclude-dir='core' \
        --exclude-dir='lib' --exclude-dir='3rdparty' --exclude-dir='vendor' \
        "$ws_pattern" "${SCAN_WEBROOT}" 2>/dev/null | head -20 || true)
      if [[ -n "$ws_hits" ]]; then
        critical "Webshell signatures matched:"
        printf '%s\n' "$ws_hits" | raw_block
      else
        info "No webshell signatures matched"
      fi
    fi
  fi

  subsection "World-Writable Files in Web Root"
  local ww_files
  ww_files=$(find "${SCAN_WEBROOT}" -maxdepth 6 -type f -perm -o+w 2>/dev/null | head -30 || true)
  if [[ -n "$ww_files" ]]; then
    warn "World-writable files in web root:"
    printf '%s\n' "$ww_files" | raw_block
  else
    info "No world-writable files in web root"
  fi

  subsection "World-Writable Directories in Web Root"
  local ww_dirs
  ww_dirs=$(find "${SCAN_WEBROOT}" -maxdepth 6 -type d -perm -o+w 2>/dev/null | head -20 || true)
  if [[ -n "$ww_dirs" ]]; then
    warn "World-writable directories in web root:"
    printf '%s\n' "$ww_dirs" | raw_block
  else
    info "No world-writable directories in web root"
  fi

  subsection "Sensitive File Search (system-wide)"
  if [[ -f "${SIGNATURES_DIR}/sensitive-files.txt" ]]; then
    while IFS= read -r pat; do
      [[ -z "$pat" || "$pat" == \#* ]] && continue
      local hits
      hits=$(find / -maxdepth 8 -name "$pat" -not -path '/proc/*' \
        -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null | head -10 || true)
      if [[ -n "$hits" ]]; then
        warn "Sensitive file pattern '${pat}' found:"
        printf '%s\n' "$hits" | raw_block
      fi
    done < "${SIGNATURES_DIR}/sensitive-files.txt"
  fi

  subsection "Immutable Files"
  if have_cmd lsattr; then
    local immutable
    immutable=$(lsattr -R /etc /var/www /tmp 2>/dev/null | grep '^----i' | head -20 || true)
    if [[ -n "$immutable" ]]; then
      warn "Immutable files (chattr +i — may prevent remediation):"
      printf '%s\n' "$immutable" | raw_block
    else
      info "No immutable files detected in /etc, /var/www, /tmp"
    fi
  fi
}
