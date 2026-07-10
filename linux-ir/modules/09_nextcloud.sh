#!/usr/bin/env bash
# Module 09 — Nextcloud: installation review, config audit, exposed files, activity

run_module() {
  section "Nextcloud"

  # ── Auto-detect Nextcloud root ─────────────────────────────────────────────
  local nc_root="${SCAN_NEXTCLOUD_ROOT}"
  if [[ -z "$nc_root" ]]; then
    for candidate in \
        /var/www/html/nextcloud \
        /var/www/nextcloud \
        /var/www/html/cloud \
        /opt/nextcloud; do
      if [[ -f "${candidate}/config/config.php" ]]; then
        nc_root="$candidate"
        break
      fi
    done
    # Broader search if not found in candidates
    if [[ -z "$nc_root" ]]; then
      nc_root=$(find "${SCAN_WEBROOT}" -maxdepth 4 -name 'config.php' \
        -path '*/config/config.php' 2>/dev/null | head -1 | xargs -r dirname | xargs -r dirname || true)
    fi
  fi

  if [[ -z "$nc_root" ]]; then
    info "Nextcloud installation not found under ${SCAN_WEBROOT}"
    return
  fi

  info "Nextcloud root: ${nc_root}"
  export SCAN_NEXTCLOUD_ROOT="$nc_root"

  # ── Version ───────────────────────────────────────────────────────────────
  subsection "Version"
  local nc_version="unknown"
  if [[ -f "${nc_root}/version.php" ]]; then
    nc_version=$(grep 'OC_VersionString' "${nc_root}/version.php" 2>/dev/null \
      | grep -oP "'\K[^']+'" || echo "unknown")
    info "Nextcloud version: ${nc_version}"
  fi
  if [[ -f "${nc_root}/config/config.php" ]]; then
    local ver_in_cfg
    ver_in_cfg=$(grep "'version'" "${nc_root}/config/config.php" 2>/dev/null \
      | grep -oP "'\K[0-9][^']+" || echo "")
    [[ -n "$ver_in_cfg" ]] && info "Version in config: ${ver_in_cfg}"
  fi

  # ── config.php audit ──────────────────────────────────────────────────────
  subsection "config.php Audit"
  local cfg="${nc_root}/config/config.php"
  if [[ -f "$cfg" ]]; then
    # Permissions
    local cfg_perms
    cfg_perms=$(stat -c '%a %U:%G' "$cfg" 2>/dev/null || echo "unknown")
    info "config.php permissions: ${cfg_perms}"
    is_world_readable "$cfg" && critical "config.php is world-readable!" \
      || info "config.php not world-readable (good)"

    # Key settings (redacted display)
    local settings=(
      datadirectory dbtype dbhost dbname dbuser dbpassword
      mail_smtphost mail_smtpport mail_smtpname mail_smtppassword
      mail_domain trusted_domains version
      passwordsalt secret maintenance
    )
    for key in "${settings[@]}"; do
      local val
      val=$(php -r "
        \$c = include '${cfg}';
        echo isset(\$c['${key}']) ? \$c['${key}'] : '__unset__';
      " 2>/dev/null || grep -oP "(?<='${key}'\s=>\s')[^']+" "$cfg" 2>/dev/null | head -1 || echo "")

      if [[ -z "$val" || "$val" == "__unset__" ]]; then
        info "  ${key}: (not set)"
        continue
      fi

      # Redact secrets from output
      case "$key" in
        dbpassword|mail_smtppassword|passwordsalt|secret)
          local masked="${val:0:4}****${val: -2}"
          info "  ${key}: ${masked} [REDACTED in report]"
          _json_finding "INFO" "09_nextcloud" "${key} present" "${key}=${masked}"
          ;;
        *)
          info "  ${key}: ${val}" ;;
      esac
    done

    # Check for debug mode
    grep -qiE "'debug'\s*=>\s*true" "$cfg" && warn "Debug mode enabled in config.php"
    # Check maintenance mode
    grep -qiE "'maintenance'\s*=>\s*true" "$cfg" && info "Maintenance mode: ON"
    # Trusted domains
    info "Trusted domains:"
    grep -A 20 "'trusted_domains'" "$cfg" | head -20 | raw_block
  else
    warn "config.php not found at ${cfg}"
  fi

  # ── Backup files in Nextcloud dirs ────────────────────────────────────────
  subsection "Backup / Config Files in Nextcloud Tree"
  local bak_files bak_dirs
  bak_files=$(find "${nc_root}" -maxdepth 6 -type f \
    \( -name '*.bak' -o -name '*.backup' -o -name '*.old' -o -name '*.orig' -o -name '*.save' \) \
    2>/dev/null || true)
  # Also check parent dir for backup copies of the entire installation (directories)
  bak_dirs=$(find "$(dirname "${nc_root}")" -maxdepth 3 -type d \
    \( -name '*backup*' -o -name '*bak*' -o -name '*old*' \) 2>/dev/null | head -10 || true)
  [[ -n "$bak_dirs" ]] && bak_files+=$'\n'"$bak_dirs"

  if [[ -n "$bak_files" ]]; then
    high "Backup/config files found in Nextcloud tree:"
    printf '%s\n' "$bak_files" | while read -r f; do
      [[ -n "$f" ]] || continue
      local perms
      perms=$(stat -c '%a' "$f" 2>/dev/null || echo "?")
      raw "  [perms:${perms}] ${f}"
      # Only flag world-readable on regular files — 755 directories are expected
      [[ -f "$f" ]] && is_world_readable "$f" 2>/dev/null && critical "  ^ World-readable: ${f}"
    done
  else
    info "No backup config files found in Nextcloud tree"
  fi

  # ── Web-accessible backup ─────────────────────────────────────────────────
  subsection "config.php.bak World-Readable Check"
  local cfg_bak="${nc_root}/config/config.php.bak"
  if [[ -f "$cfg_bak" ]]; then
    critical "config.php.bak exists: ${cfg_bak}"
    local bak_perms
    bak_perms=$(stat -c '%a %U:%G' "$cfg_bak" 2>/dev/null)
    info "  Permissions: ${bak_perms}"
    info "  mtime: $(stat_mtime "${cfg_bak}")"
    is_world_readable "$cfg_bak" \
      && critical "config.php.bak is world-readable — remediate immediately" \
      || warn "config.php.bak exists but is not world-readable"
  else
    info "config.php.bak not found (good)"
  fi

  # ── Data directory ────────────────────────────────────────────────────────
  subsection "Data Directory"
  local data_dir
  data_dir=$(grep -oP "(?<='datadirectory'\s=>\s')[^']+" "$cfg" 2>/dev/null || echo "")
  if [[ -n "$data_dir" ]]; then
    info "Data dir: ${data_dir}"
    if [[ "${data_dir}" == "${SCAN_WEBROOT}"* ]]; then
      critical "Data directory is inside web root — files directly accessible via HTTP"
    else
      info "Data directory is outside web root (good)"
    fi
    if [[ -f "${data_dir}/.htaccess" ]]; then
      info ".htaccess present in data dir"
    else
      warn "No .htaccess in data dir — Apache may serve raw user files if DirectoryIndex misconfigured"
    fi
  fi

  # ── File ownership ────────────────────────────────────────────────────────
  subsection "File Ownership"
  local nc_owner
  nc_owner=$(stat -c '%U' "${nc_root}/index.php" 2>/dev/null || echo "unknown")
  info "Nextcloud files owned by: ${nc_owner}"
  local root_owned
  root_owned=$(find "${nc_root}" -maxdepth 3 -not -user "$nc_owner" \
    -not -user root -type f 2>/dev/null | head -10 || true)
  [[ -n "$root_owned" ]] && warn "Files not owned by ${nc_owner} or root:" && printf '%s\n' "$root_owned" | raw_block

  # ── Apps ──────────────────────────────────────────────────────────────────
  subsection "Installed Apps"
  if [[ -d "${nc_root}/apps" ]]; then
    find "${nc_root}/apps" -maxdepth 1 -type d ! -name 'apps' 2>/dev/null \
      | sort | xargs -I{} basename {} | raw_block
  fi
  if [[ -d "${nc_root}/custom_apps" ]]; then
    info "Custom apps:"
    find "${nc_root}/custom_apps" -maxdepth 1 -type d ! -name 'custom_apps' 2>/dev/null \
      | sort | xargs -I{} basename {} | raw_block
  fi

  # ── OCC utility (read-only commands only) ────────────────────────────────
  # NOTE: occ bootstraps Nextcloud's PHP stack — may write PHP session/tmp files
  # to the data directory. All commands below are read-only OCC operations.
  # Do NOT run: maintenance:repair, upgrade, db:*, files:scan (all write to DB/disk).
  subsection "OCC Status"
  if [[ -f "${nc_root}/occ" ]]; then
    sudo -u "${nc_owner}" php "${nc_root}/occ" status 2>/dev/null | raw_block \
      || info "occ status unavailable (permission or PHP issue)"

    subsection "OCC App List"
    sudo -u "${nc_owner}" php "${nc_root}/occ" app:list 2>/dev/null | raw_block || true

    subsection "OCC Config (non-sensitive keys)"
    sudo -u "${nc_owner}" php "${nc_root}/occ" config:list --private=false 2>/dev/null \
      | raw_block || true
  fi
}
