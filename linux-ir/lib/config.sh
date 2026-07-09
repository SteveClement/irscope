#!/usr/bin/env bash
# Runtime configuration — all tunables in one place.

# Output paths (set by ir.sh before sourcing modules)
: "${OUTPUT_DIR:=/tmp/ir-$(hostname -s)-$(date +%Y%m%d-%H%M%S)}"
: "${REPORT_FILE:=${OUTPUT_DIR}/report.md}"
: "${JSON_FILE:=${OUTPUT_DIR}/findings.json}"
: "${BASELINE_FILE:=${OUTPUT_DIR}/baseline.json}"

# Scope controls
: "${SCAN_WEBROOT:=/var/www}"
: "${SCAN_APACHE_LOG_DIR:=/var/log/apache2}"
: "${SCAN_NEXTCLOUD_ROOT:=}"          # auto-detected if empty
: "${SCAN_MYSQL_DATADIR:=/var/lib/mysql}"
: "${SCAN_DAYS_RECENT:=14}"           # "recent" file threshold in days
: "${SCAN_MAX_LOG_LINES:=50000}"      # cap per-log grep to avoid memory issues

# IOC / signature dirs (relative to ir.sh location)
: "${SIGNATURES_DIR:=}"               # set by ir.sh

# Modules to skip (space-separated module numbers, e.g. "10 11")
: "${SKIP_MODULES:=}"

# Verbosity: 0=findings only, 1=info+findings, 2=debug
: "${IR_VERBOSE:=1}"

export OUTPUT_DIR REPORT_FILE JSON_FILE BASELINE_FILE
export SCAN_WEBROOT SCAN_APACHE_LOG_DIR SCAN_NEXTCLOUD_ROOT
export SCAN_MYSQL_DATADIR SCAN_DAYS_RECENT SCAN_MAX_LOG_LINES
export SIGNATURES_DIR SKIP_MODULES IR_VERBOSE
