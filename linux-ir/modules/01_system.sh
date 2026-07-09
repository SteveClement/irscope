#!/usr/bin/env bash
# Module 01 — System state: mounts, disk, kernel modules, dmesg anomalies

run_module() {
  section "System State"

  subsection "Disk Usage"
  df -h 2>/dev/null | raw_block

  subsection "Mount Points"
  mount 2>/dev/null | grep -v 'proc\|sysfs\|cgroup\|devtmpfs\|tmpfs\|devpts\|securityfs\|pstore\|debugfs\|tracefs\|bpf\|hugetlbfs\|mqueue\|fusectl\|configfs' | raw_block || true

  # Flag noexec-less /tmp
  if mount | grep -qE ' /tmp .*\brw\b' && ! mount | grep -qE ' /tmp .*\bnoexec\b'; then
    warn "/tmp mounted without noexec — executable payloads can run from /tmp"
  fi

  subsection "Loaded Kernel Modules"
  local suspicious_mods=()
  if have_cmd lsmod; then
    lsmod 2>/dev/null | raw_block
    # Flag known rootkit module names
    while IFS= read -r line; do
      local modname
      modname=$(awk '{print $1}' <<< "$line")
      case "$modname" in
        # Well-known rootkit/hiding module patterns
        diamorphine|azazel|adore|knark|rkit|suterusu|reptile|modhide|syscall_hooker)
          critical "Suspected rootkit kernel module loaded: ${modname}"
          ;;
      esac
    done < <(lsmod 2>/dev/null | tail -n +2)
  fi

  subsection "dmesg — recent errors/warnings"
  if have_cmd dmesg; then
    local dmesg_out
    dmesg_out=$(dmesg --level=err,warn --time-format=iso 2>/dev/null | tail -50 || dmesg 2>/dev/null | grep -iE 'err|warn|fail|oops|panic' | tail -50 || true)
    if [[ -n "$dmesg_out" ]]; then
      printf '%s\n' "$dmesg_out" | raw_block
    else
      info "No kernel errors/warnings in dmesg"
    fi
  fi

  subsection "Kernel Parameters (security-relevant)"
  local params=(
    "kernel.dmesg_restrict"
    "kernel.kptr_restrict"
    "net.ipv4.ip_forward"
    "net.ipv4.conf.all.rp_filter"
    "kernel.randomize_va_space"
    "fs.suid_dumpable"
  )
  for p in "${params[@]}"; do
    local val
    val=$(sysctl -n "$p" 2>/dev/null || echo "N/A")
    info "  ${p} = ${val}"
    case "$p" in
      net.ipv4.ip_forward) [[ "$val" == "1" ]] && warn "IP forwarding enabled — host may be acting as router" ;;
      kernel.randomize_va_space) [[ "$val" == "0" ]] && warn "ASLR disabled (randomize_va_space=0)" ;;
      fs.suid_dumpable) [[ "$val" == "2" ]] && warn "fs.suid_dumpable=2 — core dumps from setuid programs readable by root" ;;
    esac
  done

  subsection "Systemd Service Status (failed)"
  if have_cmd systemctl; then
    local failed
    failed=$(systemctl --failed --no-legend 2>/dev/null || true)
    if [[ -n "$failed" ]]; then
      warn "Failed systemd units detected:"
      printf '%s\n' "$failed" | raw_block
    else
      info "No failed systemd units"
    fi
  fi

  subsection "Recently Modified System Binaries"
  local recent_bins
  recent_bins=$(find /usr/bin /usr/sbin /bin /sbin -type f -newer /proc/1 \
    -mtime "-${SCAN_DAYS_RECENT}" 2>/dev/null | head -30 || true)
  if [[ -n "$recent_bins" ]]; then
    warn "System binaries modified in last ${SCAN_DAYS_RECENT} days:"
    printf '%s\n' "$recent_bins" | raw_block
  else
    info "No system binaries modified in last ${SCAN_DAYS_RECENT} days"
  fi
}
