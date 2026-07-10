#!/usr/bin/env bash
# linux-ir — Modular Linux DFIR triage toolkit
# Designed for Debian 12 (works on most systemd Linux).
# Read-only: no package installs, no service restarts, no file modifications.
#
# Usage:
#   sudo ./ir.sh [OPTIONS]
#
# Options:
#   -o DIR     Output directory (default: /tmp/ir-<host>-<timestamp>)
#   -w PATH    Web root to scan (default: /var/www)
#   -l PATH    Apache log directory (default: /var/log/apache2)
#   -n PATH    Nextcloud root (auto-detected if omitted)
#   -d DAYS    "Recent" file threshold in days (default: 14)
#   -s MODS    Space-separated module numbers to skip (e.g. "10 11")
#   -q         Quiet — findings only, suppress [INFO] lines
#   -v         Verbose — include debug output
#   -h         Show this help

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SIGNATURES_DIR="${SCRIPT_DIR}/signatures"

# ── lib ──────────────────────────────────────────────────────────────────────
# shellcheck source=lib/config.sh
source "${SCRIPT_DIR}/lib/config.sh"
# shellcheck source=lib/output.sh
source "${SCRIPT_DIR}/lib/output.sh"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=lib/utils.sh
source "${SCRIPT_DIR}/lib/utils.sh"

# ── argument parsing ──────────────────────────────────────────────────────────
usage() {
  grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,1\}//'
  exit 0
}

while getopts ':o:w:l:n:d:s:qvh' opt; do
  case "$opt" in
    o) OUTPUT_DIR="$OPTARG" ;;
    w) SCAN_WEBROOT="$OPTARG" ;;
    l) SCAN_APACHE_LOG_DIR="$OPTARG" ;;
    n) SCAN_NEXTCLOUD_ROOT="$OPTARG" ;;
    d) SCAN_DAYS_RECENT="$OPTARG" ;;
    s) SKIP_MODULES="$OPTARG" ;;
    q) IR_VERBOSE=0 ;;
    v) IR_VERBOSE=2 ;;
    h) usage ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 1 ;;
    ?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; exit 1 ;;
  esac
done

# Recalculate derived paths after option parsing
REPORT_FILE="${OUTPUT_DIR}/report.md"
JSON_FILE="${OUTPUT_DIR}/findings.json"
BASELINE_FILE="${OUTPUT_DIR}/baseline.json"
export OUTPUT_DIR REPORT_FILE JSON_FILE BASELINE_FILE

# ── privilege check ───────────────────────────────────────────────────────────
require_root

# ── initialise ────────────────────────────────────────────────────────────────
timer_start
init_output

progress "linux-ir starting — output: ${OUTPUT_DIR}"
progress "Host: $(hostname -f 2>/dev/null || hostname)  |  Kernel: $(uname -r)"

# ── load and run modules ──────────────────────────────────────────────────────
MODULES=(
  "00_metadata"
  "01_system"
  "02_processes"
  "03_network"
  "04_auth"
  "05_persistence"
  "06_tmp"
  "07_filesystem"
  "08_apache"
  "09_nextcloud"
  "10_mysql"
  "11_mail"
  "12_packages"
  "13_security"
  "14_ioc"
  "15_compare"
  "99_summary"
)

FINDING_COUNTS=()
export CURRENT_MODULE=""

for mod in "${MODULES[@]}"; do
  num="${mod%%_*}"
  if module_skip "$num"; then
    progress "Skipping module ${mod}"
    continue
  fi

  mod_file="${SCRIPT_DIR}/modules/${mod}.sh"
  if [[ ! -f "$mod_file" ]]; then
    progress "Module ${mod} not found — skipping"
    continue
  fi

  CURRENT_MODULE="$mod"
  export CURRENT_MODULE

  progress "Running module: ${mod}"
  # shellcheck source=/dev/null
  source "$mod_file"
  ( run_module ) || progress "Module ${mod} exited non-zero — continuing"
done

# ── finalise ──────────────────────────────────────────────────────────────────
finalise_json
report_footer

progress "Done — $(timer_elapsed)s elapsed"
progress "Report:   ${REPORT_FILE}"
progress "Findings: ${JSON_FILE}"
