#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/Build/QTest.bin"
KAT="$SRC/Build/kat"
[ -x "$BIN" ] || { echo "missing $BIN (mayhem/build.sh builds it)" >&2; emit_ctrf "qentem-qtest" 0 1 0; exit 1; }
[ -x "$KAT" ] || { echo "missing $KAT (mayhem/build.sh builds it)" >&2; emit_ctrf "qentem-qtest" 0 1 0; exit 1; }

passed=0
failed=0

check() { # check <label> <actual> <expected>
  if [ "$2" == "$3" ]; then passed=$((passed + 1)); else
    failed=$((failed + 1)); echo "KAT FAIL: $1" >&2; echo "  want: $3" >&2; echo "  got:  $2" >&2
  fi
}

# 1) Upstream's own suite (all unit tests in one binary). Parse its per-test and summary lines: a neutered
#    binary prints nothing, which fails both the per-suite summary and the minimum-count assertions.
out="$("$BIN" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
n_pass=$(printf '%s\n' "$out" | grep -c '^Pass: ' || true)
n_fail=$(printf '%s\n' "$out" | grep -c '^Fail' || true)
n_suites=$(printf '%s\n' "$out" | grep -c 'Passed all tests$' || true)
all_good=$(printf '%s\n' "$out" | sed -n 's/^All good\. (\([0-9]*\)) tests$/\1/p')
echo "QTest: $n_pass passing cases, $n_fail failing, $n_suites suites passed, summary='$all_good'"
if [ "$n_pass" -ge 200 ] && [ "$n_fail" -eq 0 ] && [ "${all_good:-0}" -ge 20 ] && [ "$n_suites" -ge 20 ]; then
  passed=$((passed + n_pass))
else
  failed=$((failed + 1)); echo "upstream QTest suite did not report a clean pass" >&2
fi

# 2) Known-answer probe: fixed inputs -> exact outputs, computed by a dynamically linked binary.
kat_out="$("$KAT")"
get() { printf '%s\n' "$kat_out" | grep "^$1=" | head -1 | cut -d= -f2-; }
check json  "$(get json)"  '{"a":[1,2.5,"x\ty",null,true],"b":{"k":-7},"s":"q"}'
check tpl   "$(get tpl)"   $'q|-7|2.5|14|yes|1,2.5,x\ty,null,true,|neg'
check num   "$(get num)"   '18446744073709551615|-1234567890123|3.142'
check parse "$(get parse)" '2:-42'
check esc   "$(get esc)"   'a\"b\n'

emit_ctrf "qentem-qtest" "$passed" "$failed" 0
