#!/usr/bin/env bash
# audit_token_usage.sh – check for overly broad or insecure GITHUB_TOKEN usage
# patterns across all workflow files.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
WORKFLOW_DIR="$REPO_ROOT/.github/workflows"
ISSUES=0
WARNINGS=0

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; WARNINGS=$((WARNINGS + 1)); }
log_issue()   { echo -e "${RED}[ISSUE]${NC}   $*"; ISSUES=$((ISSUES + 1)); }
log_section() { echo -e "\n${CYAN}══ $* ══${NC}"; }

if [[ ! -d "$WORKFLOW_DIR" ]]; then
  log_info "No .github/workflows directory found – skipping."
  exit 0
fi

mapfile -t WORKFLOW_FILES < <(find "$WORKFLOW_DIR" -name "*.yml" -o -name "*.yaml")

if [[ ${#WORKFLOW_FILES[@]} -eq 0 ]]; then
  log_info "No workflow files found."
  exit 0
fi

log_info "Auditing GITHUB_TOKEN / PAT usage in ${#WORKFLOW_FILES[@]} workflow file(s)"

for f in "${WORKFLOW_FILES[@]}"; do
  fname="$(basename "$f")"
  log_section "$fname"

  # 1. Raw GITHUB_TOKEN passed to curl/wget (direct REST API calls)
  if grep -qE 'curl.*\$\{\{\s*secrets\.GITHUB_TOKEN\s*\}\}|curl.*\$GITHUB_TOKEN' "$f"; then
    log_issue "$fname: GITHUB_TOKEN passed directly to curl – prefer official GitHub Actions SDKs or octokit to reduce risk."
  fi

  # 2. Token used in environment variable named GH_TOKEN or GITHUB_TOKEN
  #    AND the same step runs something untrusted
  if grep -qE 'GITHUB_TOKEN.*\$\{\{' "$f" && grep -q "pull_request_target" "$f"; then
    log_issue "$fname: GITHUB_TOKEN exposed in environment of a 'pull_request_target' triggered workflow – untrusted code may steal it."
  fi

  # 3. Secrets exposed in run: blocks via echo (handles inline and block-scalar run: values)
  if python3 - "$f" <<'PYEOF' 2>/dev/null; then
import sys, re
with open(sys.argv[1]) as fh:
    content = fh.read()
# Match multi-line run blocks (|, >, or inline) and look for echo + secrets
run_blocks = re.findall(r'run:\s*[|>]?\s*\n?((?:[ \t]+.*\n?)+)', content)
for block in run_blocks:
    if re.search(r'echo.*secrets\.', block):
        sys.exit(0)  # found – exit 0 so the shell 'if' branch triggers
sys.exit(1)
PYEOF
    log_issue "$fname: secret value may be echoed in a 'run:' step – this will appear in logs."
  fi

  # 4. Token passed to external (non-GitHub) services
  if grep -E 'Authorization.*GITHUB_TOKEN|Authorization.*secrets\.' "$f" | \
     grep -qvE 'api\.github\.com|github\.com' 2>/dev/null; then
    log_warn "$fname: GITHUB_TOKEN/secret may be sent to a non-GitHub host."
  fi

  # 5. Long-lived PATs stored as secrets (heuristic: secret names ending in _PAT or _TOKEN)
  if grep -qE 'secrets\.[A-Z_]*(PAT|TOKEN)[A-Z_]*\s*\}\}' "$f"; then
    log_warn "$fname: possible Personal Access Token used – prefer GITHUB_TOKEN where possible and rotate PATs regularly."
  fi

  # 6. Token passed to matrix jobs without constraints
  if grep -q "matrix" "$f" && grep -q "GITHUB_TOKEN" "$f"; then
    log_warn "$fname: GITHUB_TOKEN used inside a matrix job – ensure only the minimum required jobs receive the token."
  fi
done

# ──────────────────────────────────────────────────────────────────────────────
# Check for PAT / secrets stored as plain env vars at repository level
# (We can only inspect workflow files here – secrets themselves are opaque)
# ──────────────────────────────────────────────────────────────────────────────
log_section "Repository-level env: variables"
for f in "${WORKFLOW_FILES[@]}"; do
  fname="$(basename "$f")"
  # Top-level 'env:' block that references secrets
  if grep -A20 "^env:" "$f" | grep -q "secrets\."; then
    log_warn "$fname: secrets referenced in top-level 'env:' block – they are available to ALL jobs."
  fi
done

echo
echo "──────────────────────────────────────────────────────"
log_info "Token usage audit complete. Issues=$ISSUES  Warnings=$WARNINGS"

if [[ $ISSUES -gt 0 ]]; then
  exit 1
fi
