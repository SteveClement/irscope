#!/usr/bin/env bash
# Module 03 — Network: interfaces, connections, routing, firewall, ARP

run_module() {
  section "Network"

  subsection "Interfaces"
  ip addr show 2>/dev/null | raw_block || ifconfig -a 2>/dev/null | raw_block

  subsection "Routing Table"
  ip route show 2>/dev/null | raw_block || route -n 2>/dev/null | raw_block

  subsection "Active Connections"
  if have_cmd ss; then
    ss -anptu 2>/dev/null | raw_block
  elif have_cmd netstat; then
    netstat -anptu 2>/dev/null | raw_block
  fi

  # Flag established connections to unusual ports
  local unusual_conns
  unusual_conns=$(ss -antp 2>/dev/null \
    | grep ESTAB \
    | grep -vE ':(22|80|443|3306|25|587|465|143|993|8080|8443)\s' \
    || true)
  if [[ -n "$unusual_conns" ]]; then
    warn "Established connections on non-standard ports:"
    printf '%s\n' "$unusual_conns" | raw_block
  fi

  subsection "Listening Services"
  ss -tlnp 2>/dev/null | raw_block || netstat -tlnp 2>/dev/null | raw_block

  # Warn if MySQL/Postgres listening on 0.0.0.0
  if ss -tlnp 2>/dev/null | grep -qE '0\.0\.0\.0:(3306|5432)'; then
    critical "MySQL/PostgreSQL listening on all interfaces (0.0.0.0) — check firewall"
  fi

  subsection "DNS Configuration"
  cat /etc/resolv.conf 2>/dev/null | grep -v '^#' | raw_block || true
  if [[ -f /etc/hosts ]]; then
    info "/etc/hosts (non-comment entries):"
    grep -v '^#' /etc/hosts | grep -v '^$' | raw_block
  fi

  # Flag suspicious /etc/hosts entries
  local sus_hosts
  sus_hosts=$(grep -v '^#' /etc/hosts 2>/dev/null \
    | grep -v '^$' \
    | grep -v -E '^(127\.|::1|fe80|0\.0\.0\.0|255\.)' \
    | grep -vE '^\s*(localhost|ip6-\S+)' \
    || true)
  if [[ -n "$sus_hosts" ]]; then
    warn "Non-standard /etc/hosts entries:"
    printf '%s\n' "$sus_hosts" | raw_block
  fi

  subsection "ARP Cache"
  arp -n 2>/dev/null | raw_block || ip neigh 2>/dev/null | raw_block

  subsection "Firewall Rules"
  if have_cmd iptables; then
    iptables -L -n -v --line-numbers 2>/dev/null | raw_block
    iptables -t nat -L -n -v 2>/dev/null | raw_block
  fi
  if have_cmd nft; then
    nft list ruleset 2>/dev/null | raw_block
  fi
  if have_cmd ufw; then
    ufw status verbose 2>/dev/null | raw_block
  fi

  subsection "Open Ports (ss summary)"
  ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | sort -u | while read -r addr_port; do
    info "Listening: ${addr_port}"
  done

  subsection "Network Namespaces"
  if have_cmd ip; then
    local ns_list
    ns_list=$(ip netns list 2>/dev/null || true)
    if [[ -n "$ns_list" ]]; then
      info "Network namespaces:"
      printf '%s\n' "$ns_list" | raw_block
    else
      info "No additional network namespaces"
    fi
  fi
}
