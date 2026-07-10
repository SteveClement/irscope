#!/usr/bin/env bash
# Utility functions: JSON finalisation, report header/footer, timing.

_IR_START_TS=0

timer_start() { _IR_START_TS=$(date +%s); }

timer_elapsed() {
  local end
  end=$(date +%s)
  echo $(( end - _IR_START_TS ))
}

init_output() {
  mkdir -p "${OUTPUT_DIR}"

  # Markdown report header
  {
    printf '# Linux IR Triage Report\n\n'
    printf '| Field | Value |\n'
    printf '|-------|-------|\n'
    printf '| Host | %s |\n' "$(hostname -f 2>/dev/null || hostname)"
    printf '| Date | %s |\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    printf '| Operator | %s |\n' "$(whoami)@$(hostname -s)"
    printf '| Kernel | %s |\n' "$(uname -r)"
    printf '| OS | %s |\n' "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -s)"
    printf '| Uptime | %s |\n' "$(uptime -p 2>/dev/null || uptime)"
    printf '\n---\n'
  } > "${REPORT_FILE}"

  # Seed JSON lines file
  : > "${JSON_FILE}.lines"
}

finalise_json() {
  # Wrap individual JSON objects into an array
  local lines="${JSON_FILE}.lines"
  {
    printf '[\n'
    local first=1
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      [[ $first -eq 0 ]] && printf ',\n'
      printf '%s' "$line"
      first=0
    done < "$lines"
    printf '\n]\n'
  } > "${JSON_FILE}"
  rm -f "$lines"
}

report_footer() {
  local elapsed
  elapsed=$(timer_elapsed)
  {
    printf '\n---\n'
    printf '\n## Scan Complete\n\n'
    printf -- '- Duration: %ds\n' "$elapsed"
    printf -- '- Output: `%s`\n' "${OUTPUT_DIR}"
    printf -- '- Report: `%s`\n' "${REPORT_FILE}"
    printf -- '- Findings JSON: `%s`\n' "${JSON_FILE}"
  } >> "${REPORT_FILE}"
}

# module_skip <number> — returns 0 if module should be skipped
module_skip() {
  local num="$1"
  for s in ${SKIP_MODULES}; do
    [[ "$s" == "$num" ]] && return 0
  done
  return 1
}

# Print a progress banner to stderr (never captured into report)
progress() {
  printf '\033[0;36m[*]\033[0m %s\n' "$*" >&2
}
