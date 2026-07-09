#!/usr/bin/env bash
# Module 11 — Mail: Postfix/Sendmail config, relay settings, mail queue

run_module() {
  section "Mail Server"

  # ── Detect MTA ────────────────────────────────────────────────────────────
  local mta=""
  for b in postfix sendmail exim4 exim; do
    have_cmd "$b" && mta="$b" && break
  done

  if [[ -z "$mta" ]]; then
    info "No MTA detected — skipping module"
    return
  fi
  info "MTA: ${mta}"

  # ── Listening ports ────────────────────────────────────────────────────────
  subsection "Listening Ports"
  ss -tlnp 2>/dev/null | grep -E ':25|:465|:587|:110|:143|:993|:995' | raw_block || true

  case "$mta" in
    postfix)
      subsection "Postfix Main Configuration"
      postconf 2>/dev/null | grep -vE '^(#|$)' | raw_block || \
        cat /etc/postfix/main.cf 2>/dev/null | grep -v '^#' | grep -v '^$' | raw_block

      # Flag open relay
      local mynetworks
      mynetworks=$(postconf -h mynetworks 2>/dev/null || grep 'mynetworks' /etc/postfix/main.cf 2>/dev/null | tail -1)
      info "mynetworks: ${mynetworks}"
      if echo "$mynetworks" | grep -qE '0\.0\.0\.0/0|::/0'; then
        critical "Postfix configured as open relay (mynetworks includes 0.0.0.0/0)"
      fi

      # Flag plaintext relay credentials
      if [[ -f /etc/postfix/sasl_passwd ]]; then
        warn "SASL password file exists: /etc/postfix/sasl_passwd"
        local passwd_perms
        passwd_perms=$(stat -c '%a' /etc/postfix/sasl_passwd 2>/dev/null || echo "unknown")
        info "  Permissions: ${passwd_perms}"
        is_world_readable /etc/postfix/sasl_passwd \
          && critical "sasl_passwd is world-readable — relay credentials exposed"
      fi

      subsection "Postfix Master.cf"
      cat /etc/postfix/master.cf 2>/dev/null | grep -v '^#' | grep -v '^$' | raw_block

      subsection "Mail Queue"
      mailq 2>/dev/null | head -30 | raw_block || postqueue -p 2>/dev/null | head -30 | raw_block || true
      local queue_count
      queue_count=$(mailq 2>/dev/null | grep -c '^[A-F0-9]' || postqueue -p 2>/dev/null | grep -c '^[A-F0-9]' || echo 0)
      if (( queue_count > 100 )); then
        warn "Large mail queue: ${queue_count} messages — possible spam relay"
      else
        info "Mail queue size: ${queue_count} messages"
      fi
      ;;

    exim4|exim)
      subsection "Exim Configuration"
      exim -bP 2>/dev/null | head -50 | raw_block || true
      subsection "Mail Queue"
      exim -bp 2>/dev/null | head -30 | raw_block || true
      ;;

    sendmail)
      subsection "Sendmail Configuration"
      cat /etc/mail/sendmail.cf 2>/dev/null | grep -v '^#' | head -50 | raw_block || true
      ;;
  esac

  subsection "Mail Logs (recent authentication events)"
  for log in /var/log/mail.log /var/log/maillog; do
    [[ -f "$log" ]] || continue
    info "Log: ${log}"
    grep -aE '(SASL|authentication|reject|warning|error)' "$log" 2>/dev/null | tail -30 | raw_block || true
    # Flag AUTH failures
    local auth_fails
    auth_fails=$(grep -c 'SASL.*authentication failed\|NOQUEUE: reject' "$log" 2>/dev/null || echo 0)
    (( auth_fails > 50 )) && warn "High SASL/AUTH failure count in ${log}: ${auth_fails} events"
  done
}
