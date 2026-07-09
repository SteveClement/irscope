#!/usr/bin/env bash
# Module 15 — Baseline comparison: diff current state against saved baseline

run_module() {
  section "Baseline Comparison"

  local baseline_dir="${SCRIPT_DIR}/baselines"

  if [[ ! -d "$baseline_dir" ]] || [[ -z "$(ls -A "$baseline_dir" 2>/dev/null)" ]]; then
    info "No baselines found in ${baseline_dir}"
    info "To create a baseline, run: sudo ./ir.sh --baseline (saves current state)"
    info "Subsequent runs will diff against the saved baseline"
    return
  fi

  subsection "Available Baselines"
  ls -la "$baseline_dir" | raw_block

  # ── Compare: listening ports ───────────────────────────────────────────────
  if [[ -f "${baseline_dir}/listening_ports.txt" ]]; then
    subsection "Listening Ports Delta"
    local current_ports
    current_ports=$(ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | sort -u)
    local baseline_ports
    baseline_ports=$(cat "${baseline_dir}/listening_ports.txt")
    local port_diff
    port_diff=$(diff <(echo "$baseline_ports") <(echo "$current_ports") || true)
    if [[ -n "$port_diff" ]]; then
      warn "Port changes since baseline:"
      printf '%s\n' "$port_diff" | raw_block
      echo "$port_diff" | grep '^>' | while read -r line; do
        high "New listening port since baseline: ${line#> }"
      done
    else
      info "No changes in listening ports since baseline"
    fi
  fi

  # ── Compare: SUID files ───────────────────────────────────────────────────
  if [[ -f "${baseline_dir}/suid_files.txt" ]]; then
    subsection "SUID Files Delta"
    local current_suid
    current_suid=$(find /usr /bin /sbin -type f -perm -4000 2>/dev/null | sort)
    local suid_diff
    suid_diff=$(diff "${baseline_dir}/suid_files.txt" <(echo "$current_suid") || true)
    if [[ -n "$suid_diff" ]]; then
      warn "SUID file changes since baseline:"
      printf '%s\n' "$suid_diff" | raw_block
      echo "$suid_diff" | grep '^>' | while read -r line; do
        high "New SUID binary since baseline: ${line#> }"
      done
    else
      info "No SUID file changes since baseline"
    fi
  fi

  # ── Compare: installed packages ───────────────────────────────────────────
  if [[ -f "${baseline_dir}/packages.txt" ]] && have_cmd dpkg; then
    subsection "Package Delta"
    local current_pkgs
    current_pkgs=$(dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2"="$3}' | sort)
    local pkg_diff
    pkg_diff=$(diff "${baseline_dir}/packages.txt" <(echo "$current_pkgs") || true)
    if [[ -n "$pkg_diff" ]]; then
      info "Package changes since baseline:"
      printf '%s\n' "$pkg_diff" | raw_block
      local added_count
      added_count=$(echo "$pkg_diff" | grep -c '^>' || echo 0)
      local removed_count
      removed_count=$(echo "$pkg_diff" | grep -c '^<' || echo 0)
      info "Added: ${added_count} packages, Removed/changed: ${removed_count} packages"
    else
      info "No package changes since baseline"
    fi
  fi

  # ── Compare: local users ──────────────────────────────────────────────────
  if [[ -f "${baseline_dir}/users.txt" ]]; then
    subsection "User Account Delta"
    local current_users
    current_users=$(awk -F: '{print $1":"$3":"$7}' /etc/passwd 2>/dev/null | sort)
    local user_diff
    user_diff=$(diff "${baseline_dir}/users.txt" <(echo "$current_users") || true)
    if [[ -n "$user_diff" ]]; then
      warn "User account changes since baseline:"
      printf '%s\n' "$user_diff" | raw_block
      echo "$user_diff" | grep '^>' | while read -r line; do
        high "New/changed user account: ${line#> }"
      done
    else
      info "No user account changes since baseline"
    fi
  fi

  # ── Compare: cron jobs ────────────────────────────────────────────────────
  if [[ -f "${baseline_dir}/crontabs.txt" ]]; then
    subsection "Crontab Delta"
    local current_cron
    current_cron=$(cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -v '^#' | grep -v '^$' | sort || true)
    local cron_diff
    cron_diff=$(diff "${baseline_dir}/crontabs.txt" <(echo "$current_cron") || true)
    if [[ -n "$cron_diff" ]]; then
      warn "Crontab changes since baseline:"
      printf '%s\n' "$cron_diff" | raw_block
      echo "$cron_diff" | grep '^>' | while read -r line; do
        high "New cron entry: ${line#> }"
      done
    else
      info "No crontab changes since baseline"
    fi
  fi

  subsection "Saving Current State as Comparison Snapshot"
  local snap_dir="${OUTPUT_DIR}/snapshot"
  mkdir -p "$snap_dir"
  ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | sort -u > "${snap_dir}/listening_ports.txt"
  find /usr /bin /sbin -type f -perm -4000 2>/dev/null | sort > "${snap_dir}/suid_files.txt"
  awk -F: '{print $1":"$3":"$7}' /etc/passwd 2>/dev/null | sort > "${snap_dir}/users.txt"
  cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -v '^#' | grep -v '^$' | sort > "${snap_dir}/crontabs.txt" || true
  have_cmd dpkg && dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2"="$3}' | sort > "${snap_dir}/packages.txt" || true
  info "Snapshot saved to ${snap_dir} — copy to baselines/ to use in future runs"
}
