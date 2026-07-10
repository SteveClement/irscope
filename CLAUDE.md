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

### `|| true` is load-bearing

The parent script runs `set -Eeuo pipefail`. Any command in a module that exits non-zero (including `getent` for absent groups, `sshd -V`, `grep` with no match, `paste` on empty input) will kill the entire scan unless guarded with `|| true`. Add `|| true` to any assignment that could legitimately produce a non-zero exit.

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

## Known implementation gaps (not yet fixed)

- `IR_VERBOSE` is exported but `lib/output.sh` never checks it — `-q`/`-v` flags are currently no-ops.
- `--baseline` flag mentioned in module 15 help text has no getopts entry in `ir.sh`.
- Module 09 (`09_nextcloud.sh`) runs `occ` which may write PHP session files — conflicts with the "read-only" guarantee in the header.
