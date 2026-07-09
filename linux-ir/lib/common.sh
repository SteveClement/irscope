#!/usr/bin/env bash
# Common helpers: privilege checks, command detection, safe runners, log search.

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    printf '[ERROR] %s requires root. Re-run with sudo.\n' "${0##*/}" >&2
    exit 1
  fi
}

have_cmd() { command -v "$1" &>/dev/null; }

# Run a command, capture output, never exit on failure.
# Usage: safe_run <var_name> <cmd...>
safe_run() {
  local _var="$1"; shift
  local _out
  _out=$("$@" 2>&1) || true
  printf -v "$_var" '%s' "$_out"
}

# search_logs <pattern> <log_path_prefix>
# Searches .log, .log.1, and .log.*.gz transparently.
# Returns matching lines on stdout.
search_logs() {
  local pattern="$1"
  local prefix="$2"
  local found=0

  # Plain / rotated uncompressed
  for f in "${prefix}" "${prefix}.1" "${prefix}".{2..14}; do
    [[ -f "$f" ]] || continue
    grep -aE "$pattern" "$f" 2>/dev/null && found=1
  done

  # Compressed rotations
  if have_cmd zgrep; then
    for f in "${prefix}".*.gz "${prefix}-"*.gz; do
      [[ -f "$f" ]] || continue
      zgrep -aE "$pattern" "$f" 2>/dev/null && found=1
    done
  fi

  return $(( found == 0 ? 1 : 0 ))
}

# find_files_newer_than <days> <path>
find_files_newer_than() {
  local days="$1" path="$2"
  find "$path" -maxdepth 5 -type f -newer /proc/1 -mtime "-${days}" 2>/dev/null
}

# stat_file <path> — portable mtime
stat_mtime() {
  if have_cmd stat; then
    stat -c '%y' "$1" 2>/dev/null || stat -f '%Sm' "$1" 2>/dev/null || echo "unknown"
  else
    ls -la "$1" 2>/dev/null | awk '{print $6,$7,$8}' || echo "unknown"
  fi
}

# is_world_readable <path>
is_world_readable() {
  local perms
  perms=$(stat -c '%a' "$1" 2>/dev/null) || return 1
  (( (8#${perms} & 8#004) != 0 ))
}

# Trim leading/trailing whitespace
trim() {
  local s="$*"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}
