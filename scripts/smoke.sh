#!/usr/bin/env bash
# VulnCanon smoke test.
#
# Verifies three load-bearing properties:
#   1. `vulnc check-all` reports every entry ACCEPTED.
#   2. For every entry, `vulnc scan --only <id>` against the entry's own
#      vulnerable_fixture/ produces ≥ 1 match (the rule fires on the bug).
#   3. For every entry, `vulnc scan --only <id>` against the entry's own
#      patched_fixture/ produces 0 matches (the rule is suppressed by the fix).
#
# Exits non-zero on any regression. Drop into CI as the canon's gate.

set -u  # don't use -e: we want to collect all failures and report

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANON_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VULNC=(node "$CANON_ROOT/compiler/vulnc/bin/vulnc.js")

red()    { printf '\033[31m%s\033[0m' "$1"; }
green()  { printf '\033[32m%s\033[0m' "$1"; }
yellow() { printf '\033[33m%s\033[0m' "$1"; }
bold()   { printf '\033[1m%s\033[0m'  "$1"; }

errors=0

# -- (1) check-all -----------------------------------------------------------
printf '\n%s\n' "$(bold "1. vulnc check-all")"
if "${VULNC[@]}" check-all >/dev/null 2>&1; then
  printf '   %s every entry ACCEPTED\n' "$(green '✓')"
else
  printf '   %s vulnc check-all reported a REJECTED entry\n' "$(red '✗')"
  "${VULNC[@]}" check-all 2>&1 | tail -20
  errors=$((errors + 1))
fi

# -- (2) and (3) per-entry differential --------------------------------------
printf '\n%s\n' "$(bold "2/3. per-entry scan differential")"
for entry_dir in "$CANON_ROOT"/entries/VC-*/; do
  entry_id="$(basename "$entry_dir")"
  v_dir="$entry_dir/vulnerable_fixture"
  p_dir="$entry_dir/patched_fixture"

  v_findings=$("${VULNC[@]}" scan "$v_dir" --only "$entry_id" --json 2>/dev/null \
    | grep -oE '"finding_count":\s*[0-9]+' \
    | grep -oE '[0-9]+' || echo 0)
  p_findings=$("${VULNC[@]}" scan "$p_dir" --only "$entry_id" --json 2>/dev/null \
    | grep -oE '"finding_count":\s*[0-9]+' \
    | grep -oE '[0-9]+' || echo 0)

  v_findings=${v_findings:-0}
  p_findings=${p_findings:-0}

  if [ "$v_findings" -gt 0 ] && [ "$p_findings" -eq 0 ]; then
    printf '   %s %-22s vulnerable=%s match  patched=0\n' \
      "$(green '✓')" "$entry_id" "$v_findings"
  else
    printf '   %s %-22s vulnerable=%s  patched=%s  (expected v>0, p=0)\n' \
      "$(red '✗')" "$entry_id" "$v_findings" "$p_findings"
    errors=$((errors + 1))
  fi
done

# -- summary -----------------------------------------------------------------
printf '\n'
if [ "$errors" -eq 0 ]; then
  printf '%s\n\n' "$(green "$(bold "smoke test PASSED")")"
  exit 0
else
  printf '%s — %s\n\n' "$(red "$(bold "smoke test FAILED")")" "$errors error(s)"
  exit 1
fi
