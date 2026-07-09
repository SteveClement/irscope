#!/usr/bin/env bash
# Module 02 — Running processes: anomalies, deleted binaries, suspicious cmdlines

run_module() {
  section "Running Processes"

  subsection "Full Process List"
  ps auxf 2>/dev/null | raw_block || ps aux 2>/dev/null | raw_block

  subsection "Processes Running Deleted Binaries"
  local deleted_procs
  deleted_procs=$(find /proc -maxdepth 2 -name exe -type l 2>/dev/null \
    | xargs -r ls -la 2>/dev/null \
    | grep -i deleted || true)
  if [[ -n "$deleted_procs" ]]; then
    high "Processes running from deleted/replaced binaries:"
    printf '%s\n' "$deleted_procs" | raw_block
  else
    info "No processes running deleted binaries"
  fi

  subsection "Processes with Anonymous/Memfd Mappings"
  # memfd / anonymous executable maps can indicate in-memory malware
  local memfd_procs=()
  while IFS= read -r pid; do
    [[ -d "/proc/${pid}" ]] || continue
    if grep -qE '(memfd|/proc/[0-9]+/fd).*rwxp' "/proc/${pid}/maps" 2>/dev/null; then
      local cmdline
      cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || echo "unknown")
      memfd_procs+=("PID ${pid}: ${cmdline}")
    fi
  done < <(ls /proc/ | grep -E '^[0-9]+$')
  if (( ${#memfd_procs[@]} > 0 )); then
    high "Processes with anonymous executable memory mappings:"
    for p in "${memfd_procs[@]}"; do raw "$p"; done
  else
    info "No processes with suspicious anonymous executable mappings"
  fi

  subsection "Listening Processes (ss)"
  if have_cmd ss; then
    ss -tlnpu 2>/dev/null | raw_block
  elif have_cmd netstat; then
    netstat -tlnpu 2>/dev/null | raw_block
  fi

  subsection "Processes Owned by Web/App Users"
  for web_user in www-data apache nginx nobody http; do
    id "$web_user" &>/dev/null || continue
    local procs
    procs=$(ps -u "$web_user" --no-headers -o pid,cmd 2>/dev/null || true)
    if [[ -n "$procs" ]]; then
      info "Processes running as ${web_user}:"
      printf '%s\n' "$procs" | raw_block
    fi
  done

  subsection "High CPU / Memory Processes"
  ps aux --sort=-%cpu 2>/dev/null | head -15 | raw_block || true

  subsection "Cron Daemons"
  for cron_svc in cron crond fcron anacron; do
    if pgrep -x "$cron_svc" &>/dev/null; then
      info "Cron daemon running: ${cron_svc}"
    fi
  done

  subsection "Suspicious Process Names"
  local suspicious_patterns='(nc |ncat |netcat |socat |msfconsole|meterpreter|reverse.?shell|bash -i|python.*pty|perl.*socket|ruby.*socket|php.*exec|/dev/tcp|/dev/udp)'
  local sus_procs
  sus_procs=$(ps aux 2>/dev/null | grep -iE "$suspicious_patterns" | grep -v grep || true)
  if [[ -n "$sus_procs" ]]; then
    critical "Potentially suspicious processes:"
    printf '%s\n' "$sus_procs" | raw_block
  else
    info "No obviously suspicious process names detected"
  fi
}
