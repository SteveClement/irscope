#!/usr/bin/env bash
# Module 05 — Persistence mechanisms: cron, systemd, rc.local, profile, at jobs

run_module() {
  section "Persistence Mechanisms"

  subsection "System Crontabs"
  for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* \
            /etc/cron.weekly/* /etc/cron.monthly/*; do
    [[ -f "$f" ]] || continue
    info "Cron file: ${f}"
    grep -v '^#' "$f" | grep -v '^$' | raw_block
  done

  subsection "User Crontabs"
  for user in $(cut -d: -f1 /etc/passwd); do
    local ctab
    ctab=$(crontab -l -u "$user" 2>/dev/null | grep -v '^#' | grep -v '^$' || true)
    if [[ -n "$ctab" ]]; then
      info "Crontab for ${user}:"
      printf '%s\n' "$ctab" | raw_block
      # Flag network callbacks in crontabs
      if echo "$ctab" | grep -qiE '(curl|wget|nc |ncat|/dev/tcp|bash.*http)'; then
        high "Crontab for ${user} contains network download/callback command"
      fi
    fi
  done

  subsection "At Jobs"
  if have_cmd atq; then
    local atjobs
    atjobs=$(atq 2>/dev/null || true)
    if [[ -n "$atjobs" ]]; then
      warn "Pending at jobs:"
      printf '%s\n' "$atjobs" | raw_block
    else
      info "No pending at jobs"
    fi
  fi

  subsection "Systemd Unit Files (custom / non-package)"
  for dir in /etc/systemd/system /usr/local/lib/systemd/system; do
    [[ -d "$dir" ]] || continue
    local custom_units
    custom_units=$(find "$dir" -maxdepth 2 -name '*.service' -o -name '*.timer' \
      | grep -v '@' | head -40 || true)
    if [[ -n "$custom_units" ]]; then
      info "Custom units in ${dir}:"
      printf '%s\n' "$custom_units" | raw_block
      # Inspect each for suspicious ExecStart
      while IFS= read -r unit; do
        local exec_line
        exec_line=$(grep -iE '^\s*ExecStart\s*=' "$unit" 2>/dev/null | head -3 || true)
        if echo "$exec_line" | grep -qiE '(curl|wget|nc |ncat|/dev/tcp|base64|python.*http|bash -i)'; then
          high "Suspicious ExecStart in ${unit}: ${exec_line}"
        fi
      done <<< "$custom_units"
    fi
  done

  subsection "Systemd Timers"
  if have_cmd systemctl; then
    systemctl list-timers --all 2>/dev/null | raw_block || true
  fi

  subsection "rc.local / init.d"
  if [[ -f /etc/rc.local ]]; then
    info "/etc/rc.local:"
    grep -v '^#' /etc/rc.local | grep -v '^$' | raw_block
  fi
  if [[ -d /etc/init.d ]]; then
    local custom_init
    custom_init=$(find /etc/init.d -type f ! -name '*.dpkg-*' 2>/dev/null | head -20)
    [[ -n "$custom_init" ]] && printf '%s\n' "$custom_init" | raw_block
  fi

  subsection "Shell Profile Backdoors"
  local profile_files=(
    /etc/profile /etc/bash.bashrc /etc/environment
    /root/.bashrc /root/.bash_profile /root/.profile /root/.zshrc
  )
  while IFS= read -r homedir; do
    for f in .bashrc .bash_profile .profile .zshrc .zprofile; do
      profile_files+=("${homedir}/${f}")
    done
  done < <(awk -F: '$3>=1000 && $3!=65534{print $6}' /etc/passwd)

  for f in "${profile_files[@]}"; do
    [[ -f "$f" ]] || continue
    if grep -qiE '(curl|wget|nc |ncat|/dev/tcp|base64.*decode|python.*http|bash -i)' "$f" 2>/dev/null; then
      high "Suspicious content in shell profile ${f}:"
      grep -iE '(curl|wget|nc |ncat|/dev/tcp|base64.*decode|python.*http|bash -i)' "$f" | raw_block
    fi
  done

  subsection "SUID / SGID Binaries (non-standard)"
  # Compare against expected set — flag anything not owned by root
  local suid_bins
  suid_bins=$(find /usr /bin /sbin /opt -type f \( -perm -4000 -o -perm -2000 \) \
    ! -user root 2>/dev/null | head -20 || true)
  if [[ -n "$suid_bins" ]]; then
    high "SUID/SGID binaries not owned by root:"
    printf '%s\n' "$suid_bins" | raw_block
  fi

  # Recently modified SUID binaries
  local recent_suid
  recent_suid=$(find /usr /bin /sbin -type f -perm -4000 \
    -mtime "-${SCAN_DAYS_RECENT}" 2>/dev/null | head -20 || true)
  if [[ -n "$recent_suid" ]]; then
    warn "SUID binaries modified in last ${SCAN_DAYS_RECENT} days:"
    printf '%s\n' "$recent_suid" | raw_block
  else
    info "No SUID binaries modified in last ${SCAN_DAYS_RECENT} days"
  fi

  subsection "LD_PRELOAD / Dynamic Linker Backdoors"
  if [[ -f /etc/ld.so.preload ]]; then
    high "/etc/ld.so.preload exists — possible LD_PRELOAD rootkit:"
    cat /etc/ld.so.preload 2>/dev/null | raw_block
  else
    info "/etc/ld.so.preload not present"
  fi

  # Check environment for LD_PRELOAD in running processes
  local preload_procs
  preload_procs=$(grep -lr 'LD_PRELOAD' /proc/*/environ 2>/dev/null | head -10 || true)
  if [[ -n "$preload_procs" ]]; then
    high "Processes with LD_PRELOAD set:"
    printf '%s\n' "$preload_procs" | while read -r env_file; do
      local pid="${env_file#/proc/}"
      pid="${pid%/environ}"
      local cmd
      cmd=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || echo "unknown")
      raw "  PID ${pid}: ${cmd}"
    done
  fi
}
