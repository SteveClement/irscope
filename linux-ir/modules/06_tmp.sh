#!/usr/bin/env bash
# Module 06 — Temp directories: hidden files, executables, recent drops

run_module() {
  section "Temporary Directories"

  local tmp_dirs=(/tmp /var/tmp /dev/shm /run/shm)
  # Also check world-writable dirs in /var (common drop spots)
  while IFS= read -r d; do
    tmp_dirs+=("$d")
  done < <(find /var -maxdepth 2 -type d -perm -o+w 2>/dev/null | grep -v '/var/tmp' | head -10)

  for dir in "${tmp_dirs[@]}"; do
    [[ -d "$dir" ]] || continue
    section "Directory: ${dir}"

    subsection "Listing (all files including hidden)"
    ls -lahR "$dir" 2>/dev/null | head -100 | raw_block

    subsection "Executable Files"
    local execs
    execs=$(find "$dir" -maxdepth 3 -type f -executable 2>/dev/null || true)
    if [[ -n "$execs" ]]; then
      high "Executable files in ${dir}:"
      printf '%s\n' "$execs" | raw_block
      # File type check
      while IFS= read -r f; do
        local ftype
        ftype=$(file "$f" 2>/dev/null || echo "unknown")
        raw "  ${ftype}"
      done <<< "$execs"
    else
      info "No executable files in ${dir}"
    fi

    subsection "Hidden Files / Directories"
    local hidden
    hidden=$(find "$dir" -maxdepth 3 -name '.*' ! -name '.' ! -name '..' 2>/dev/null || true)
    if [[ -n "$hidden" ]]; then
      warn "Hidden entries in ${dir}:"
      printf '%s\n' "$hidden" | raw_block
    else
      info "No hidden files in ${dir}"
    fi

    subsection "Recently Created (last ${SCAN_DAYS_RECENT} days)"
    local recent
    recent=$(find "$dir" -maxdepth 3 -type f -mtime "-${SCAN_DAYS_RECENT}" 2>/dev/null | head -50 || true)
    if [[ -n "$recent" ]]; then
      info "Recently created files in ${dir}:"
      printf '%s\n' "$recent" | while read -r f; do
        printf '  %s  %s\n' "$(stat_mtime "$f")" "$f"
      done | raw_block
    else
      info "No files created in last ${SCAN_DAYS_RECENT} days in ${dir}"
    fi

    subsection "Script Files"
    local scripts
    scripts=$(find "$dir" -maxdepth 3 -type f \
      \( -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.rb' \
         -o -name '*.php' -o -name '*.js' \) 2>/dev/null || true)
    if [[ -n "$scripts" ]]; then
      warn "Script files in ${dir}:"
      printf '%s\n' "$scripts" | raw_block
    fi
  done

  subsection "Open Deleted Files in /tmp"
  # Files unlinked but still held open (in-memory payloads)
  local open_deleted
  open_deleted=$(lsof +L1 2>/dev/null | grep -E '/tmp|/var/tmp|/dev/shm' || true)
  if [[ -n "$open_deleted" ]]; then
    high "Deleted files still held open (possible in-memory payload):"
    printf '%s\n' "$open_deleted" | raw_block
  else
    info "No deleted temp files held open"
  fi
}
