#!/usr/bin/env bash
# Output helpers — all user-visible output goes through these functions.
# Writes to stdout (tty) and appends to REPORT_FILE / JSON_FILE when set.

# Colour codes (disabled when not a tty or NO_COLOR is set)
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  _CLR_RESET='\033[0m'
  _CLR_CYAN='\033[0;36m'
  _CLR_GREEN='\033[0;32m'
  _CLR_YELLOW='\033[0;33m'
  _CLR_RED='\033[0;31m'
  _CLR_MAGENTA='\033[0;35m'
  _CLR_BOLD='\033[1m'
else
  _CLR_RESET='' _CLR_CYAN='' _CLR_GREEN='' _CLR_YELLOW=''
  _CLR_RED='' _CLR_MAGENTA='' _CLR_BOLD=''
fi

# Internal: append line to markdown report
_md() { printf '%s\n' "$1" >> "${REPORT_FILE}"; }

# Internal: append a finding to JSON array (requires jq)
_json_finding() {
  local severity="$1" module="$2" msg="$3" detail="${4:-}"
  if command -v jq &>/dev/null && [[ -n "${JSON_FILE:-}" ]]; then
    local entry
    entry=$(jq -cn \
      --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg sev "$severity" \
      --arg mod "$module" \
      --arg msg "$msg" \
      --arg det "$detail" \
      '{timestamp:$ts, severity:$sev, module:$mod, message:$msg, detail:$det}')
    printf '%s\n' "$entry" >> "${JSON_FILE}.lines"
  fi
}

section() {
  local title="$1"
  printf '\n%b=== %s ===%b\n' "${_CLR_BOLD}${_CLR_CYAN}" "$title" "${_CLR_RESET}"
  _md ""
  _md "## ${title}"
  _md ""
}

subsection() {
  local title="$1"
  printf '%b--- %s ---%b\n' "${_CLR_BOLD}" "$title" "${_CLR_RESET}"
  _md "### ${title}"
}

info() {
  printf '%b[INFO]%b  %s\n' "${_CLR_GREEN}" "${_CLR_RESET}" "$*"
  _md "- **[INFO]** $*"
  _json_finding "INFO" "${CURRENT_MODULE:-unknown}" "$*"
}

low() {
  printf '%b[LOW]%b   %s\n' "${_CLR_CYAN}" "${_CLR_RESET}" "$*"
  _md "- **[LOW]** $*"
  _json_finding "LOW" "${CURRENT_MODULE:-unknown}" "$*"
}

warn() {
  printf '%b[MEDIUM]%b %s\n' "${_CLR_YELLOW}" "${_CLR_RESET}" "$*"
  _md "- **[MEDIUM]** $*"
  _json_finding "MEDIUM" "${CURRENT_MODULE:-unknown}" "$*"
}

high() {
  printf '%b[HIGH]%b  %s\n' "${_CLR_RED}" "${_CLR_RESET}" "$*"
  _md "- **[HIGH]** $*"
  _json_finding "HIGH" "${CURRENT_MODULE:-unknown}" "$*"
}

critical() {
  printf '%b[CRITICAL]%b %s\n' "${_CLR_BOLD}${_CLR_MAGENTA}" "${_CLR_RESET}" "$*"
  _md "- **[CRITICAL]** $*"
  _json_finding "CRITICAL" "${CURRENT_MODULE:-unknown}" "$*"
}

finding() {
  # finding <SEVERITY> <message> [detail]
  local sev="${1:-INFO}"
  shift
  case "${sev^^}" in
    INFO)     info "$@" ;;
    LOW)      low "$@" ;;
    MEDIUM)   warn "$@" ;;
    HIGH)     high "$@" ;;
    CRITICAL) critical "$@" ;;
    *)        info "[${sev}] $*" ;;
  esac
}

raw() {
  printf '%s\n' "$*"
  _md "\`\`\`"
  _md "$*"
  _md "\`\`\`"
}

raw_block() {
  # raw_block <lang> — read stdin, emit fenced code block
  local lang="${1:-}"
  printf '%s\n' "---"
  _md "\`\`\`${lang}"
  while IFS= read -r line; do
    printf '%s\n' "  $line"
    _md "$line"
  done
  _md "\`\`\`"
  printf '%s\n' "---"
}

cmd_output() {
  # cmd_output <label> <command...>
  local label="$1"; shift
  subsection "$label"
  local out
  out=$("$@" 2>&1 || true)
  printf '%s\n' "$out" | raw_block
}
