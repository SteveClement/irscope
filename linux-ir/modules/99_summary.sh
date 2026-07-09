#!/usr/bin/env bash
# Module 99 — Executive summary: counts by severity, key findings, next steps

run_module() {
  section "Executive Summary"

  if [[ ! -f "${JSON_FILE}.lines" ]]; then
    info "No findings data available yet"
    return
  fi

  # Count findings by severity from the .lines buffer
  local crit high med low_ info_
  crit=$(grep -c '"severity":"CRITICAL"' "${JSON_FILE}.lines" 2>/dev/null || echo 0)
  high=$(grep -c '"severity":"HIGH"' "${JSON_FILE}.lines" 2>/dev/null || echo 0)
  med=$(grep -c '"severity":"MEDIUM"' "${JSON_FILE}.lines" 2>/dev/null || echo 0)
  low_=$(grep -c '"severity":"LOW"' "${JSON_FILE}.lines" 2>/dev/null || echo 0)
  info_=$(grep -c '"severity":"INFO"' "${JSON_FILE}.lines" 2>/dev/null || echo 0)
  local total=$(( crit + high + med + low_ + info_ ))

  subsection "Findings by Severity"
  {
    printf '\n| Severity | Count |\n'
    printf '|----------|-------|\n'
    printf '| CRITICAL | %d |\n' "$crit"
    printf '| HIGH     | %d |\n' "$high"
    printf '| MEDIUM   | %d |\n' "$med"
    printf '| LOW      | %d |\n' "$low_"
    printf '| INFO     | %d |\n' "$info_"
    printf '| **Total**| **%d** |\n' "$total"
  } | tee -a "${REPORT_FILE}"

  # Terminal output
  (( crit > 0 ))  && critical "${crit} CRITICAL finding(s) require immediate action"
  (( high > 0 ))  && high "${high} HIGH finding(s) require prompt remediation"
  (( med > 0 ))   && warn "${med} MEDIUM finding(s) should be addressed"
  (( low_ > 0 ))  && low "${low_} LOW finding(s) noted for review"

  subsection "Critical Findings"
  if (( crit > 0 )); then
    grep '"severity":"CRITICAL"' "${JSON_FILE}.lines" 2>/dev/null \
      | grep -oP '"message":"\K[^"]+' \
      | while read -r msg; do
          critical "  >> ${msg}"
        done
  else
    info "No CRITICAL findings"
  fi

  subsection "High Findings"
  if (( high > 0 )); then
    grep '"severity":"HIGH"' "${JSON_FILE}.lines" 2>/dev/null \
      | grep -oP '"message":"\K[^"]+' \
      | while read -r msg; do
          high "  >> ${msg}"
        done
  else
    info "No HIGH findings"
  fi

  subsection "Recommended Actions"
  {
    printf '\n'
    (( crit > 0 ))  && printf '1. **[IMMEDIATE]** Address all CRITICAL findings before resuming normal operations\n'
    (( high > 0 ))  && printf '2. **[URGENT]** Remediate HIGH findings within 24h\n'
    (( med > 0 ))   && printf '3. **[PLANNED]** Schedule remediation for MEDIUM findings\n'
    printf '4. Archive this report: `%s`\n' "${OUTPUT_DIR}"
    printf '5. Preserve findings JSON for ticketing: `%s`\n' "${JSON_FILE}"
    printf '\n'
  } | tee -a "${REPORT_FILE}"

  subsection "Output Files"
  info "Report (Markdown): ${REPORT_FILE}"
  info "Findings (JSON):   ${JSON_FILE}"
  info "Snapshot:          ${OUTPUT_DIR}/snapshot/"

  # Risk rating
  local risk="LOW"
  (( crit > 0 )) && risk="CRITICAL"
  (( crit == 0 && high > 0 )) && risk="HIGH"
  (( crit == 0 && high == 0 && med > 0 )) && risk="MEDIUM"

  printf '\n%b╔══════════════════════════════════════════╗%b\n' "${_CLR_BOLD}" "${_CLR_RESET}"
  printf '%b║  Overall Risk Rating: %-20s║%b\n' "${_CLR_BOLD}" "${risk}" "${_CLR_RESET}"
  printf '%b╚══════════════════════════════════════════╝%b\n\n' "${_CLR_BOLD}" "${_CLR_RESET}"
  _md ""
  _md "**Overall Risk Rating: ${risk}**"
  _md ""
}
