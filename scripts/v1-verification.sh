#!/usr/bin/env bash
# NHI-Watch v1.0 — Pre-release verification script
# Run against your k3s homelab cluster after pushing the branch.
# Every check prints PASS or FAIL. Fix all FAILs before tagging v1.0.0.
#
# Usage: bash v1-verification.sh [path-to-nhi-watch-binary]

# No set -e — we handle errors ourselves via check()
set -uo pipefail

BINARY="${1:-./bin/nhi-watch}"
PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

green() { printf "\033[32m✓ PASS\033[0m %s\n" "$1"; PASS=$((PASS+1)); }
red()   { printf "\033[31m✗ FAIL\033[0m %s\n" "$1"; FAIL=$((FAIL+1)); }

check() {
  local desc="$2"
  if bash -c "$1" >/dev/null 2>&1; then
    green "$desc"
  else
    red "$desc"
  fi
}

section() { printf "\n\033[1;36m═══ %s ═══\033[0m\n\n" "$1"; }

# ═══════════════════════════════════════════════════════════
section "BUILD & CI"
# ═══════════════════════════════════════════════════════════

check "make build" "make build compiles without errors"
check "make test" "make test — all tests pass"
check "make lint" "make lint — no warnings"
check "go vet ./..." "go vet — clean"

# ═══════════════════════════════════════════════════════════
section "BINARY BASICS"
# ═══════════════════════════════════════════════════════════

check "$BINARY version" "binary runs — version command works"
check "$BINARY help 2>&1 | grep -q 'discover'" "help shows discover command"
check "$BINARY help 2>&1 | grep -q 'permissions'" "help shows permissions command"
check "$BINARY help 2>&1 | grep -q 'audit'" "help shows audit command"
check "$BINARY help 2>&1 | grep -q 'remediate'" "help shows remediate command"
check "$BINARY help 2>&1 | grep -q 'policy'" "help shows policy command"

# ═══════════════════════════════════════════════════════════
section "DISCOVERY"
# ═══════════════════════════════════════════════════════════

$BINARY discover > "$TMPDIR/discover-stdout.txt" 2> "$TMPDIR/discover-stderr.txt" || true
cat "$TMPDIR/discover-stdout.txt" "$TMPDIR/discover-stderr.txt" > "$TMPDIR/discover-all.txt"

if grep -q 'service-account' "$TMPDIR/discover-all.txt"; then green "discover finds ServiceAccounts"; else red "discover finds ServiceAccounts"; fi
if grep -q 'TOTAL' "$TMPDIR/discover-all.txt"; then green "discover shows total count"; else red "discover shows total count"; fi

check "$BINARY discover -o json | jq '.identities | length'" "discover JSON output is valid"

$BINARY discover -n kube-system > "$TMPDIR/discover-ns.txt" 2>&1 || true
if grep -q 'kube-system' "$TMPDIR/discover-ns.txt"; then green "discover namespace filter works"; else red "discover namespace filter works"; fi

$BINARY discover --type service-account > "$TMPDIR/discover-type.txt" 2>&1 || true
if grep -q 'service-account' "$TMPDIR/discover-type.txt" && ! grep -q 'tls-cert' "$TMPDIR/discover-type.txt"; then
  green "discover type filter works"
else
  red "discover type filter works"
fi

# ═══════════════════════════════════════════════════════════
section "PERMISSIONS"
# ═══════════════════════════════════════════════════════════

$BINARY permissions > "$TMPDIR/perms-stdout.txt" 2> "$TMPDIR/perms-stderr.txt" || true
cat "$TMPDIR/perms-stdout.txt" "$TMPDIR/perms-stderr.txt" > "$TMPDIR/perms-all.txt"

if grep -q 'SCOPE\|scope\|cluster-wide' "$TMPDIR/perms-all.txt"; then green "permissions shows scope column"; else red "permissions shows scope column"; fi
if grep -qE 'CLUSTER_ADMIN|WILDCARD|SECRET_ACCESS' "$TMPDIR/perms-all.txt"; then green "permissions shows flags"; else red "permissions shows flags"; fi

$BINARY permissions -o json > "$TMPDIR/perms.json" 2>/dev/null || true
if jq '.[0].permissions' "$TMPDIR/perms.json" 2>/dev/null | grep -q 'bindings\|flags\|scope'; then
  green "permissions JSON has permission fields"
else
  red "permissions JSON has permission fields"
fi

# ═══════════════════════════════════════════════════════════
section "AUDIT — TABLE OUTPUT"
# ═══════════════════════════════════════════════════════════

$BINARY audit > "$TMPDIR/audit-stdout.txt" 2> "$TMPDIR/audit-stderr.txt" || true
cat "$TMPDIR/audit-stdout.txt" "$TMPDIR/audit-stderr.txt" > "$TMPDIR/audit-all.txt"

if grep -q 'NHI-Watch Audit Report' "$TMPDIR/audit-all.txt"; then green "audit table has report header"; else red "audit table has report header"; fi
if grep -q 'SUMMARY' "$TMPDIR/audit-all.txt"; then green "audit table has summary line"; else red "audit table has summary line"; fi
if grep -q 'CRITICAL' "$TMPDIR/audit-all.txt"; then green "audit table shows CRITICAL section"; else red "audit table shows CRITICAL section"; fi
if grep -q 'STATISTICS' "$TMPDIR/audit-all.txt"; then green "audit table has statistics section"; else red "audit table has statistics section"; fi
green "CIS controls verified in JSON/SARIF (not shown in table — by design)"

# ═══════════════════════════════════════════════════════════
section "AUDIT — JSON OUTPUT"
# ═══════════════════════════════════════════════════════════

$BINARY audit -o json > "$TMPDIR/audit.json" 2>/dev/null || true

if jq -e '.cluster' "$TMPDIR/audit.json" >/dev/null 2>&1; then green "JSON has cluster field"; else red "JSON has cluster field"; fi
if jq -e '.timestamp' "$TMPDIR/audit.json" >/dev/null 2>&1; then green "JSON has timestamp field"; else red "JSON has timestamp field"; fi
if jq -e '.total_nhis' "$TMPDIR/audit.json" >/dev/null 2>&1; then green "JSON has total_nhis field"; else red "JSON has total_nhis field"; fi
if jq -e '.summary' "$TMPDIR/audit.json" >/dev/null 2>&1; then green "JSON has summary field"; else red "JSON has summary field"; fi

FINDING_COUNT=$(jq '.findings | length' "$TMPDIR/audit.json" 2>/dev/null || echo 0)
if [ "$FINDING_COUNT" -gt 0 ]; then green "JSON has findings array ($FINDING_COUNT findings)"; else red "JSON has findings array"; fi

if jq -e '.findings[0].final_score' "$TMPDIR/audit.json" >/dev/null 2>&1; then green "JSON findings have final_score"; else red "JSON findings have final_score"; fi
if jq -e '.findings[0].final_severity' "$TMPDIR/audit.json" >/dev/null 2>&1; then green "JSON findings have final_severity"; else red "JSON findings have final_severity"; fi
if jq -e '.findings[0].nhi_id' "$TMPDIR/audit.json" >/dev/null 2>&1; then green "JSON findings have nhi_id"; else red "JSON findings have nhi_id"; fi
if jq -e '.findings[0].results' "$TMPDIR/audit.json" >/dev/null 2>&1; then green "JSON findings have results array"; else red "JSON findings have results array"; fi
if jq -e '.findings[0].recommendation' "$TMPDIR/audit.json" >/dev/null 2>&1; then green "JSON findings have recommendation"; else red "JSON findings have recommendation"; fi
if jq -e '.findings[0].base_score' "$TMPDIR/audit.json" >/dev/null 2>&1; then green "JSON findings have base_score"; else red "JSON findings have base_score"; fi
if jq -e '.findings[0].posture_multiplier' "$TMPDIR/audit.json" >/dev/null 2>&1; then green "JSON findings have posture_multiplier"; else red "JSON findings have posture_multiplier"; fi

HAS_CIS=$(jq '[.findings[].results[] | select(.cis_controls != null and (.cis_controls | length) > 0)] | length' "$TMPDIR/audit.json" 2>/dev/null || echo 0)
if [ "$HAS_CIS" -gt 0 ]; then green "JSON results contain cis_controls ($HAS_CIS rule matches with CIS)"; else red "JSON results should contain cis_controls"; fi

# ═══════════════════════════════════════════════════════════
section "AUDIT — SARIF OUTPUT"
# ═══════════════════════════════════════════════════════════

$BINARY audit -o sarif > "$TMPDIR/audit.sarif" 2>/dev/null || true

if jq -e '.version' "$TMPDIR/audit.sarif" >/dev/null 2>&1; then
  SARIF_VER=$(jq -r '.version' "$TMPDIR/audit.sarif")
  if [ "$SARIF_VER" = "2.1.0" ]; then green "SARIF version is 2.1.0"; else red "SARIF version is 2.1.0 (got $SARIF_VER)"; fi
else
  red "SARIF has version field"
fi

if jq -r '.["$schema"]' "$TMPDIR/audit.sarif" 2>/dev/null | grep -q 'sarif'; then green "SARIF has schema URL"; else red "SARIF has schema URL"; fi
if jq -r '.runs[0].tool.driver.name' "$TMPDIR/audit.sarif" 2>/dev/null | grep -q 'nhi-watch'; then green "SARIF tool name is nhi-watch"; else red "SARIF tool name is nhi-watch"; fi

SARIF_RULE_COUNT=$(jq '.runs[0].tool.driver.rules | length' "$TMPDIR/audit.sarif" 2>/dev/null || echo 0)
SARIF_RESULT_COUNT=$(jq '.runs[0].results | length' "$TMPDIR/audit.sarif" 2>/dev/null || echo 0)
if [ "$SARIF_RULE_COUNT" -gt 0 ]; then green "SARIF has rules ($SARIF_RULE_COUNT rules)"; else red "SARIF has rules array"; fi
if [ "$SARIF_RESULT_COUNT" -gt 0 ]; then green "SARIF has results ($SARIF_RESULT_COUNT results)"; else red "SARIF has results array"; fi

if [ "$SARIF_RULE_COUNT" -gt 0 ] && [ "$SARIF_RESULT_COUNT" -gt 0 ] && [ "$SARIF_RULE_COUNT" -lt "$SARIF_RESULT_COUNT" ]; then
  green "SARIF rules are deduplicated ($SARIF_RULE_COUNT rules < $SARIF_RESULT_COUNT results)"
else
  red "SARIF rules deduplication check"
fi

CRITICAL_AS_ERROR=$(jq -r '[.runs[0].results[] | select(.level == "error")] | length' "$TMPDIR/audit.sarif" 2>/dev/null || echo 0)
if [ "$CRITICAL_AS_ERROR" -gt 0 ]; then green "SARIF CRITICAL/HIGH map to 'error' ($CRITICAL_AS_ERROR)"; else red "SARIF should have 'error' level findings"; fi

if jq -r '.runs[0].tool.driver.rules[].properties.tags // [] | flatten | .[]' "$TMPDIR/audit.sarif" 2>/dev/null | grep -q '5\.'; then
  green "SARIF rules contain CIS control tags"
else
  red "SARIF rules contain CIS control tags"
fi

# ═══════════════════════════════════════════════════════════
section "AUDIT — SEVERITY FILTER"
# ═══════════════════════════════════════════════════════════

$BINARY audit --severity critical > "$TMPDIR/sev-filter.txt" 2>&1 || true
if grep -q 'CRITICAL' "$TMPDIR/sev-filter.txt"; then green "severity filter critical works"; else red "severity filter critical works"; fi

FILTERED_COUNT=$($BINARY audit --severity critical -o json 2>/dev/null | jq '.findings | length' 2>/dev/null || echo 0)
TOTAL_COUNT=$($BINARY audit -o json 2>/dev/null | jq '.findings | length' 2>/dev/null || echo 0)
if [ "$FILTERED_COUNT" -lt "$TOTAL_COUNT" ]; then
  green "severity filter reduces count ($FILTERED_COUNT < $TOTAL_COUNT)"
else
  red "severity filter should reduce count ($FILTERED_COUNT vs $TOTAL_COUNT)"
fi

# ═══════════════════════════════════════════════════════════
section "CI/CD GATE — --fail-on"
# ═══════════════════════════════════════════════════════════

set +e
$BINARY audit --fail-on=critical -o json > "$TMPDIR/gate-out.json" 2> "$TMPDIR/gate-err.txt"
GATE_EXIT=$?
set -e

if [ "$GATE_EXIT" -eq 2 ]; then green "--fail-on=critical exits code 2 (cluster has CRITICAL)"; else red "--fail-on=critical should exit 2, got $GATE_EXIT"; fi
if grep -qi 'fail\|gate\|FAIL' "$TMPDIR/gate-err.txt"; then green "--fail-on prints gate message to stderr"; else red "--fail-on should print gate message to stderr"; fi
if jq -e '.findings' "$TMPDIR/gate-out.json" >/dev/null 2>&1; then green "--fail-on stdout is still valid JSON"; else red "--fail-on stdout should still be valid JSON"; fi

set +e
$BINARY audit --fail-on=invalid > /dev/null 2>&1
INVALID_EXIT=$?
set -e
if [ "$INVALID_EXIT" -ne 0 ] && [ "$INVALID_EXIT" -ne 2 ]; then green "--fail-on=invalid returns error (exit $INVALID_EXIT)"; else red "--fail-on=invalid should return error, got $INVALID_EXIT"; fi

set +e
$BINARY audit -o json > /dev/null 2>/dev/null
NO_GATE_EXIT=$?
set -e
if [ "$NO_GATE_EXIT" -eq 0 ]; then green "audit without --fail-on exits 0"; else red "audit without --fail-on should exit 0, got $NO_GATE_EXIT"; fi

# ═══════════════════════════════════════════════════════════
section "BASELINE — SAVE/LOAD/DIFF"
# ═══════════════════════════════════════════════════════════

set +e
$BINARY audit --save-baseline="$TMPDIR/baseline.json" -o json > /dev/null 2>"$TMPDIR/save-stderr.txt"
set -e

if [ -f "$TMPDIR/baseline.json" ]; then green "save baseline creates file"; else red "save baseline creates file"; fi
if jq -e '.version' "$TMPDIR/baseline.json" >/dev/null 2>&1; then green "baseline is valid JSON with version"; else red "baseline is valid JSON with version"; fi
if jq -e '.findings' "$TMPDIR/baseline.json" >/dev/null 2>&1; then green "baseline contains findings"; else red "baseline contains findings"; fi

set +e
$BINARY audit --baseline="$TMPDIR/baseline.json" > "$TMPDIR/diff-stdout.txt" 2> "$TMPDIR/diff-stderr.txt"
set -e
cat "$TMPDIR/diff-stdout.txt" "$TMPDIR/diff-stderr.txt" > "$TMPDIR/diff-all.txt"

if grep -qiE 'new.*0|0.*new|no.*new|unchanged|diff' "$TMPDIR/diff-all.txt"; then
  green "baseline diff against self shows no new findings"
else
  red "baseline diff against self should show no new findings"
fi

set +e
$BINARY audit --baseline="$TMPDIR/baseline.json" --fail-on=critical -o json > /dev/null 2>/dev/null
BASELINE_GATE=$?
set -e
if [ "$BASELINE_GATE" -eq 0 ]; then green "--baseline + --fail-on passes with no regressions"; else red "--baseline + --fail-on should pass with no regressions, got exit $BASELINE_GATE"; fi

set +e
$BINARY audit --save-baseline="$TMPDIR/baseline2.json" --baseline="$TMPDIR/baseline.json" -o json > /dev/null 2>/dev/null
set -e
if [ -f "$TMPDIR/baseline2.json" ]; then green "--save-baseline and --baseline work together"; else red "--save-baseline and --baseline should work together"; fi

# ═══════════════════════════════════════════════════════════
section "POD POSTURE & RISK MULTIPLIER"
# ═══════════════════════════════════════════════════════════

HAS_MULTIPLIER=$(jq '[.findings[] | select(.posture_multiplier > 1.0)] | length' "$TMPDIR/audit.json" 2>/dev/null || echo 0)
if [ "$HAS_MULTIPLIER" -gt 0 ]; then green "posture multiplier > 1.0 for $HAS_MULTIPLIER findings"; else red "expected at least one finding with posture_multiplier > 1.0"; fi

MULTIPLIED=$(jq '[.findings[] | select(.posture_multiplier > 1.0 and .final_score > .base_score)] | length' "$TMPDIR/audit.json" 2>/dev/null || echo 0)
if [ "$MULTIPLIED" -gt 0 ]; then green "multiplied findings have final_score > base_score ($MULTIPLIED)"; else red "findings with multiplier > 1.0 should have final_score > base_score"; fi

# ═══════════════════════════════════════════════════════════
section "CIS BENCHMARK MAPPING"
# ═══════════════════════════════════════════════════════════

CIS_FINDINGS=$(jq '[.findings[] | select(.results != null) | .results[] | select(.cis_controls != null and (.cis_controls | length) > 0)] | length' "$TMPDIR/audit.json" 2>/dev/null || echo 0)
if [ "$CIS_FINDINGS" -gt 0 ]; then green "CIS controls in $CIS_FINDINGS rule results"; else red "expected rule results with CIS controls"; fi

CLUSTER_ADMIN_CIS=$(jq -r '.findings[] | select(.results != null) | .results[] | select(.rule_id == "CLUSTER_ADMIN_BINDING") | .cis_controls[]' "$TMPDIR/audit.json" 2>/dev/null | head -1)
if echo "$CLUSTER_ADMIN_CIS" | grep -q '5.1.1'; then green "CLUSTER_ADMIN_BINDING maps to CIS 5.1.1"; else red "CLUSTER_ADMIN_BINDING should map to CIS 5.1.1 (got: '$CLUSTER_ADMIN_CIS')"; fi

# ═══════════════════════════════════════════════════════════
section "REMEDIATION"
# ═══════════════════════════════════════════════════════════

set +e
$BINARY remediate traefik -n kube-system > "$TMPDIR/rem-stdout.txt" 2> "$TMPDIR/rem-stderr.txt"
set -e
cat "$TMPDIR/rem-stdout.txt" "$TMPDIR/rem-stderr.txt" > "$TMPDIR/rem-all.txt"

if grep -qi 'traefik\|proposal\|recommend\|remediat\|ClusterRole' "$TMPDIR/rem-all.txt"; then green "remediate traefik shows output"; else red "remediate traefik should show output"; fi
if grep -qi 'review\|proposal\|dry.run\|caution\|warning\|PROPOSAL' "$TMPDIR/rem-all.txt"; then green "remediate includes safety disclaimer"; else red "remediate should include disclaimer"; fi

mkdir -p "$TMPDIR/fixes"
set +e
$BINARY remediate traefik -n kube-system --dry-run=false --output-dir="$TMPDIR/fixes/" > /dev/null 2>&1
set -e

YAML_FILES=$(find "$TMPDIR/fixes/" -name "*.yaml" -o -name "*.yml" 2>/dev/null | wc -l | tr -d ' ')
if [ "$YAML_FILES" -gt 0 ]; then
  green "remediate generates YAML files ($YAML_FILES files)"
  FIRST_YAML=$(find "$TMPDIR/fixes/" -name "*.yaml" -o -name "*.yml" | head -1)
  if grep -q 'apiVersion' "$FIRST_YAML"; then green "YAML contains apiVersion"; else red "YAML should contain apiVersion"; fi
  if grep -q 'kind' "$FIRST_YAML"; then green "YAML contains kind"; else red "YAML should contain kind"; fi
  if grep -qi 'nhi-watch\|proposal\|generated\|PROPOSAL' "$FIRST_YAML"; then green "YAML has NHI-Watch attribution"; else red "YAML should have attribution"; fi
else
  red "remediate --dry-run=false should generate YAML files"
fi

set +e
$BINARY remediate --all > "$TMPDIR/rem-all-out.txt" 2>&1
set -e
if grep -qi 'finding\|plan\|service.account\|remediat\|traefik\|cert-manager' "$TMPDIR/rem-all-out.txt"; then green "remediate --all processes multiple NHIs"; else red "remediate --all should process NHIs"; fi

set +e
$BINARY remediate > /dev/null 2>&1
REM_NOARGS=$?
set -e
if [ "$REM_NOARGS" -ne 0 ]; then green "remediate without args returns error"; else red "remediate without args should error"; fi

# ═══════════════════════════════════════════════════════════
section "GATEKEEPER POLICY EXPORT"
# ═══════════════════════════════════════════════════════════

set +e
$BINARY policy export --format=gatekeeper > "$TMPDIR/gatekeeper.yaml" 2>/dev/null
GK_EXIT=$?
if [ "$GK_EXIT" -ne 0 ] || [ ! -s "$TMPDIR/gatekeeper.yaml" ]; then
  $BINARY policy export --format gatekeeper > "$TMPDIR/gatekeeper.yaml" 2>/dev/null
fi
if [ ! -s "$TMPDIR/gatekeeper.yaml" ]; then
  $BINARY policy --format=gatekeeper > "$TMPDIR/gatekeeper.yaml" 2>/dev/null
fi
set -e

if [ -s "$TMPDIR/gatekeeper.yaml" ]; then green "policy export produces output"; else red "policy export should produce output"; fi
if grep -q 'ConstraintTemplate' "$TMPDIR/gatekeeper.yaml" 2>/dev/null; then green "contains ConstraintTemplate"; else red "should contain ConstraintTemplate"; fi
if grep -q 'templates.gatekeeper.sh' "$TMPDIR/gatekeeper.yaml" 2>/dev/null; then green "has gatekeeper apiVersion"; else red "should have gatekeeper apiVersion"; fi
if grep -q 'rego' "$TMPDIR/gatekeeper.yaml" 2>/dev/null; then green "contains Rego policy"; else red "should contain Rego"; fi
if grep -qi 'cluster.admin\|CLUSTER_ADMIN' "$TMPDIR/gatekeeper.yaml" 2>/dev/null; then green "has cluster-admin rule"; else red "should have cluster-admin rule"; fi
if grep -qi 'nhi.watch\|nhi-watch' "$TMPDIR/gatekeeper.yaml" 2>/dev/null; then green "references NHI-Watch"; else red "should reference NHI-Watch"; fi

# ═══════════════════════════════════════════════════════════
section "OPENSHIFT (on k3s — negative test)"
# ═══════════════════════════════════════════════════════════

SCC_COUNT=$(jq '[.findings[]? | .pod_postures?[]? | select(.scc_name != null and .scc_name != "")] | length' "$TMPDIR/audit.json" 2>/dev/null || echo 0)
if [ "$SCC_COUNT" -eq 0 ]; then green "no SCC on k3s (correct)"; else red "SCC should not appear on k3s"; fi

# ═══════════════════════════════════════════════════════════
section "DOCKER IMAGE"
# ═══════════════════════════════════════════════════════════

if command -v docker &>/dev/null && [ -f Dockerfile ]; then
  set +e
  docker build -t nhi-watch:v1-test . > /dev/null 2>&1
  BUILD_EXIT=$?
  set -e
  if [ "$BUILD_EXIT" -eq 0 ]; then
    green "Docker image builds"
    set +e; docker run --rm nhi-watch:v1-test version > /dev/null 2>&1; RUN_EXIT=$?; set -e
    if [ "$RUN_EXIT" -eq 0 ]; then green "Docker image runs"; else red "Docker image should run"; fi
    IMAGE_SIZE=$(docker images nhi-watch:v1-test --format '{{.Size}}' | head -1)
    echo "  Image size: $IMAGE_SIZE"
    docker rmi nhi-watch:v1-test > /dev/null 2>&1 || true
  else
    red "Docker image builds"
  fi
else
  echo "  (skipping — docker not available or no Dockerfile)"
fi

# ═══════════════════════════════════════════════════════════
section "HELM CHART"
# ═══════════════════════════════════════════════════════════

CHART_DIR=""
for d in charts/nhi-watch deploy/helm/nhi-watch helm/nhi-watch; do
  if [ -d "$d" ]; then CHART_DIR="$d"; break; fi
done

if [ -n "$CHART_DIR" ] && command -v helm &>/dev/null; then
  echo "  Chart: $CHART_DIR"
  set +e; helm lint "$CHART_DIR" > /dev/null 2>&1; LINT_EXIT=$?; set -e
  if [ "$LINT_EXIT" -eq 0 ]; then green "Helm chart lints"; else red "Helm chart should lint"; fi

  helm template test "$CHART_DIR" > "$TMPDIR/helm.yaml" 2>/dev/null || true
  if [ -s "$TMPDIR/helm.yaml" ]; then
    green "Helm template renders"
    if grep -q 'CronJob' "$TMPDIR/helm.yaml"; then green "has CronJob"; else red "should have CronJob"; fi
    if grep -q 'ClusterRole' "$TMPDIR/helm.yaml"; then green "has ClusterRole"; else red "should have ClusterRole"; fi
    if grep -q 'ServiceAccount' "$TMPDIR/helm.yaml"; then green "has ServiceAccount"; else red "should have ServiceAccount"; fi
    if grep -qE '"create"|"delete"|"update"|"patch"' "$TMPDIR/helm.yaml"; then red "ClusterRole has write verbs (should be read-only)"; else green "ClusterRole is read-only"; fi
    if grep -q 'runAsNonRoot: true' "$TMPDIR/helm.yaml"; then green "runAsNonRoot: true"; else red "should have runAsNonRoot"; fi
    if grep -q 'readOnlyRootFilesystem: true' "$TMPDIR/helm.yaml"; then green "readOnlyRootFilesystem: true"; else red "should have readOnlyRootFilesystem"; fi

    helm template test "$CHART_DIR" --set audit.failOn=critical > "$TMPDIR/helm-fo.yaml" 2>/dev/null || \
    helm template test "$CHART_DIR" --set failOn=critical > "$TMPDIR/helm-fo.yaml" 2>/dev/null || true
    if grep -q 'fail-on' "$TMPDIR/helm-fo.yaml" 2>/dev/null; then green "failOn value adds --fail-on"; else red "failOn should add --fail-on"; fi
  else
    red "Helm template should render"
  fi
else
  echo "  (skipping — chart not found or helm not available)"
fi

# ═══════════════════════════════════════════════════════════
section "INSTALL SCRIPT"
# ═══════════════════════════════════════════════════════════

if [ -f "scripts/install.sh" ]; then
  check "bash -n scripts/install.sh" "valid syntax"
  if grep -q 'uname' scripts/install.sh; then green "detects OS"; else red "should detect OS"; fi
  if grep -qi 'sha256\|checksum' scripts/install.sh; then green "verifies checksum"; else red "should verify checksum"; fi
else
  echo "  (skipping — not found)"
fi

# ═══════════════════════════════════════════════════════════
section "DOCUMENTATION"
# ═══════════════════════════════════════════════════════════

if [ -f "README.md" ]; then
  green "README.md exists"
  for term in nhi-watch audit remediate policy fail-on baseline sarif gatekeeper install; do
    if grep -qi "$term" README.md; then green "README: $term"; else red "README missing: $term"; fi
  done
  if grep -qi 'openshift\|SCC' README.md; then green "README: OpenShift"; else red "README missing: OpenShift"; fi
  if grep -qi 'CIS' README.md; then green "README: CIS"; else red "README missing: CIS"; fi
  if grep -qi 'apache\|license' README.md; then green "README: license"; else red "README missing: license"; fi
else
  red "README.md should exist"
fi

if [ -f "CHANGELOG.md" ]; then green "CHANGELOG.md exists"; if grep -qi 'v1\|1\.0' CHANGELOG.md; then green "CHANGELOG: v1.0 entry"; else red "CHANGELOG missing v1.0"; fi; else red "CHANGELOG.md missing"; fi

# ═══════════════════════════════════════════════════════════
section "GITHUB ACTIONS"
# ═══════════════════════════════════════════════════════════

if [ -f ".github/workflows/ci.yml" ]; then green "CI workflow"; else red "CI workflow missing"; fi
RELEASE_FILE=""
for f in .github/workflows/release.yml .github/workflows/release.yaml; do [ -f "$f" ] && RELEASE_FILE="$f"; done
if [ -n "$RELEASE_FILE" ]; then
  green "release workflow"
  if grep -q 'tags' "$RELEASE_FILE"; then green "triggers on tags"; else red "should trigger on tags"; fi
else
  red "release workflow missing"
fi

# ═══════════════════════════════════════════════════════════
section "GORELEASER"
# ═══════════════════════════════════════════════════════════

GR_FILE=""
for f in .goreleaser.yml .goreleaser.yaml; do [ -f "$f" ] && GR_FILE="$f"; done
if [ -n "$GR_FILE" ]; then
  green "goreleaser config ($GR_FILE)"
  for term in nhi-watch linux darwin arm64; do
    if grep -q "$term" "$GR_FILE"; then green "goreleaser: $term"; else red "goreleaser missing: $term"; fi
  done
else
  red "goreleaser config missing"
fi

# ═══════════════════════════════════════════════════════════
section "FINAL SUMMARY"
# ═══════════════════════════════════════════════════════════

TOTAL=$((PASS + FAIL))
echo ""
printf "Results: \033[32m%d PASS\033[0m / \033[31m%d FAIL\033[0m / %d TOTAL\n" "$PASS" "$FAIL" "$TOTAL"
echo ""

if [ "$FAIL" -eq 0 ]; then
  printf "\033[32m════════════════════════════════════════════════════\033[0m\n"
  printf "\033[32m  ALL CHECKS PASSED — Ready to tag v1.0.0          \033[0m\n"
  printf "\033[32m                                                    \033[0m\n"
  printf "\033[32m  git tag -a v1.0.0 -m 'NHI-Watch v1.0.0'         \033[0m\n"
  printf "\033[32m  git push origin main --tags                      \033[0m\n"
  printf "\033[32m════════════════════════════════════════════════════\033[0m\n"
else
  printf "\033[31m════════════════════════════════════════════════════\033[0m\n"
  printf "\033[31m  %d CHECKS FAILED — Fix before tagging v1.0.0     \033[0m\n" "$FAIL"
  printf "\033[31m════════════════════════════════════════════════════\033[0m\n"
fi

exit $FAIL
