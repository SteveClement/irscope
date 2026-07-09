#!/usr/bin/env bash
# Module 00 — Host metadata and environment baseline

run_module() {
  section "Host Metadata"

  subsection "Identity"
  info "Hostname: $(hostname -f 2>/dev/null || hostname)"
  info "Short name: $(hostname -s 2>/dev/null || hostname)"
  safe_run _ip_addrs ip -4 addr show 2>/dev/null || true
  info "IPv4 addresses: $(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet )\S+' | paste -sd', ' || echo 'unknown')"

  subsection "OS / Kernel"
  if [[ -f /etc/os-release ]]; then
    while IFS='=' read -r k v; do
      v="${v//\"/}"
      case "$k" in
        PRETTY_NAME) info "OS: ${v}" ;;
        VERSION_ID)  info "Version ID: ${v}" ;;
        ID)          info "Distro ID: ${v}" ;;
      esac
    done < /etc/os-release
  fi
  info "Kernel: $(uname -r)"
  info "Architecture: $(uname -m)"
  info "Build: $(uname -v)"

  subsection "Hardware"
  if have_cmd dmidecode; then
    local mfr model serial
    mfr=$(dmidecode -s system-manufacturer 2>/dev/null || echo "unknown")
    model=$(dmidecode -s system-product-name 2>/dev/null || echo "unknown")
    serial=$(dmidecode -s system-serial-number 2>/dev/null || echo "unknown")
    info "Manufacturer: ${mfr}"
    info "Model: ${model}"
    info "Serial: ${serial}"
  fi
  info "CPU: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo 'unknown')"
  info "RAM: $(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || echo 'unknown')"

  subsection "Boot / Uptime"
  info "Uptime: $(uptime -p 2>/dev/null || uptime)"
  info "Boot time: $(who -b 2>/dev/null | awk '{print $3,$4}' || echo 'unknown')"
  info "Timezone: $(timedatectl show --property=Timezone --value 2>/dev/null || date +%Z)"

  if have_cmd timedatectl; then
    local ntp_status
    ntp_status=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || echo "unknown")
    if [[ "$ntp_status" != "yes" ]]; then
      warn "NTP not synchronised — timestamps may be unreliable"
    else
      info "NTP synchronised: yes"
    fi
  fi

  subsection "Scan Parameters"
  info "Output dir: ${OUTPUT_DIR}"
  info "Web root: ${SCAN_WEBROOT}"
  info "Apache log dir: ${SCAN_APACHE_LOG_DIR}"
  info "Nextcloud root: ${SCAN_NEXTCLOUD_ROOT:-auto-detect}"
  info "Recent file threshold: ${SCAN_DAYS_RECENT} days"
  info "IR tool: linux-ir ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
}
