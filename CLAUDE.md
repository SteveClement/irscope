# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`linux-ir/` is a read-only Bash DFIR triage toolkit for Debian 12 / systemd Linux. It collects evidence without modifying the target: no package installs, no service restarts, no file writes outside the output directory.

## Commands

```bash
# Syntax check all shell files
bash -n linux-ir/ir.sh linux-ir/modules/*.sh linux-ir/lib/*.sh

# Lint (quoting, subshell, portability)
shellcheck linux-ir/ir.sh linux-ir/modules/*.sh linux-ir/lib/*.sh

# Run locally (requires root)
sudo bash linux-ir/ir.sh -o /tmp/ir-test

# Run on remote host, fetch results
ssh <host> 'nohup sudo linux-ir/ir.sh > /tmp/ir-nohup.log 2>&1 & echo $!'
rsync -azv '<host>:/tmp/ir-messeu-*' tmp/

# Skip specific modules (e.g. MySQL and mail)
sudo bash linux-ir/ir.sh -s "10 11"

# Override web root / log dir
sudo bash linux-ir/ir.sh -w /srv/www -l /var/log/nginx
```

## Architecture

### Execution flow

`ir.sh` sets `set -Eeuo pipefail`, sources all four libs, parses args, then loops over `MODULES`. Each module file is `source`d (so it shares the lib functions) and then its `run_module()` is called inside a subshell: `( run_module ) || progress "..."`. The subshell isolation means a module failure doesn't abort subsequent modules.

### Dual output

Every finding goes through `lib/output.sh` helpers (`info`, `warn`, `high`, `critical`, etc.). Each helper simultaneously:
- Prints colored text to stdout
- Appends Markdown to `$REPORT_FILE` (`report.md`)
- Appends an NDJSON object to `$JSON_FILE.lines` (assembled into `findings.json` at the end)

Never use `echo` for findings — always use the output helpers so both sinks stay in sync.

### Lib files

| File | Purpose |
|------|---------|
| `lib/config.sh` | All tunables via `${VAR:=default}` — override with env vars or CLI flags |
| `lib/output.sh` | `section`, `subsection`, `info`…`critical`, `raw_block`, `cmd_output` |
| `lib/common.sh` | `have_cmd`, `safe_run`, `search_logs`, `is_world_readable`, `stat_mtime` |
| `lib/utils.sh` | `init_output`, `finalise_json`, `timer_*`, `module_skip`, `progress` |

### Adding a module

1. Create `linux-ir/modules/NN_name.sh` with a single `run_module()` function.
2. Add `"NN_name"` to the `MODULES` array in `ir.sh`.
3. Use `have_cmd foo || return` to degrade gracefully when tools are absent.
4. Use `search_logs <pattern> <prefix>` from `lib/common.sh` — it transparently handles `.log`, `.log.1`, and `.log.*.gz` rotations.
5. Cap unbounded searches: `timeout 120 grep ... | head -N`.

### Signatures / IOC files

`linux-ir/signatures/` contains plain-text lists loaded at runtime:

- `iocs.txt` — per-incident IOCs. Format: `ip:`, `domain:`, `hash:`, `str:` prefixes (or bare strings treated as `str:`). **Populate before each engagement.**
- `webshells.txt` — regex patterns piped into `grep -rlE --include='*.php'`
- `scanners.txt` — scanner UA/tool strings for Apache log matching
- `sensitive-files.txt` — filename globs for system-wide sensitive file search

### Baselines

`linux-ir/baselines/` holds pre-incident snapshots (listening ports, SUID files, users, packages, crontabs). Module 15 diffs the current state against these files. Module 15 also writes a fresh snapshot to `$OUTPUT_DIR/snapshot/` each run — copy that to `baselines/` to establish a clean reference. The `--baseline` flag is referenced in module 15 but not yet wired into `ir.sh`'s getopts.

## Recurring pitfalls

### `|| true` is load-bearing

The parent script runs `set -Eeuo pipefail`. Any command in a module that exits non-zero (including `getent` for absent groups on Debian, `sshd -V`, `grep` with no match, `paste` on empty input) will kill the entire scan unless guarded with `|| true`. Add `|| true` to any assignment that could legitimately produce a non-zero exit.

### `printf` with format strings starting with `-`

Some `printf` implementations treat a leading `-` as an option flag. Always use `printf --` when the format string starts with `-`:
```bash
printf -- '- item: %s\n' "$value"   # correct
printf '- item: %s\n' "$value"      # may error on some systems
```

### `nc` substring matching

The string `nc ` (netcat) appears as a substring in `rsync `, `sync `, etc. Always use `\bnc\b` in grep patterns when matching netcat specifically:
```bash
grep -qiE '\bnc\b'   # correct — won't match rsync
grep -qiE 'nc '      # wrong — matches "rsync --daemon"
```

### `search_logs` takes a base prefix, not a file path

`search_logs <pattern> <prefix>` in `lib/common.sh` expands the prefix to find `.log`, `.log.1`, `.log.{2..14}`, and `.log.*.gz` / `.log-*.gz` automatically. **Pass the base log name, never an individual rotated file.** Passing `/var/log/apache2/access.log.8.gz` as the prefix causes the uncompressed branch to `grep` raw binary.

```bash
search_logs '.' /var/log/apache2/access.log        # correct
search_logs '.' /var/log/apache2/access.log.8.gz   # wrong — reads binary
```

When discovering vhost logs with `find`, filter to base names only:
```bash
find /var/log/apache2 -maxdepth 1 -name '*access*.log'   # correct
find /var/log/apache2 -maxdepth 1 -name '*access*'       # wrong — finds .gz rotations too
```

### PHP/webshell grep on large web roots

Never run `grep -rE` across `/var/www` without `--include='*.php'`. A Nextcloud data directory can be 1+ TB and will hang for hours scanning non-PHP files. Also exclude framework directories that legitimately use encoding functions:

```bash
timeout 120 grep -rlE --include='*.php' \
  --exclude-dir='data' --exclude-dir='.git' \
  --exclude-dir='apps' --exclude-dir='core' \
  --exclude-dir='lib' --exclude-dir='3rdparty' --exclude-dir='vendor' \
  "$pattern" "${SCAN_WEBROOT}"
```

### `ss -p` output width

`ss` with the `-p` flag lists every PID for each socket. Multi-process listeners (Apache with 16 workers) produce 600+ character lines. Truncate at 130 chars for readability:

```bash
ss -tlnp 2>/dev/null | awk '{ if (length > 130) print substr($0,1,127) "..."; else print }'
```

For sections where process attribution isn't needed (active connection dumps), drop `-p` entirely.

### Known-good deleted-file patterns

`lsof +L1` reports all files unlinked while still open. On a typical Nextcloud/PHP-FPM/MariaDB/Collabora stack, these are always present and are not payloads:
- `.ZendSem.*` — PHP-FPM semaphore files
- `#NNN` (numeric only) — MariaDB anonymous tmpfiles
- `coolwsd`, `AppRun`, `forkit` — Collabora Online

Filter these before alerting:
```bash
lsof +L1 | grep -E '/tmp|/var/tmp|/dev/shm' \
  | grep -vE '(\.ZendSem\.|/#[0-9]+|coolwsd|AppRun|forkit|systemd-journal)'
```

### `is_world_readable` returns true for 755 directories

`is_world_readable` in `lib/common.sh` checks bit `004`. A directory at `755` passes this check because `o+r` is set — but 755 is normal and required for Apache to traverse into application directories. Only flag world-readable on regular files (`-type f`), not directories.

## Known implementation gaps

- `IR_VERBOSE` is exported but `lib/output.sh` never checks it — `-q`/`-v` flags are currently no-ops.
- `--baseline` flag mentioned in module 15 help text has no getopts entry in `ir.sh`.
- Module 09 (`09_nextcloud.sh`) runs `occ` which may write PHP session files — conflicts with the "read-only" guarantee in the header.
- Module 07 (`07_filesystem.sh`) exposed-file check uses `-type f` but the world-readable test is also called on results from `sensitive-files.txt` which may return directories; 755 directories produce false-positive CRITICAL alerts.
