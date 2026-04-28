#!/usr/bin/env bash
# audit_workflows.sh – audit GitHub Actions workflow files for dangerous patterns.
# Exits with code 1 if critical issues are found.

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

log_info "Auditing ${#WORKFLOW_FILES[@]} workflow file(s) in $WORKFLOW_DIR"

# ──────────────────────────────────────────────────────────────────────────────
# CHECK 1 – pull_request_target without checkout guard (pwn-request)
# ──────────────────────────────────────────────────────────────────────────────
log_section "CHECK 1: pull_request_target (pwn-request) detection"

for f in "${WORKFLOW_FILES[@]}"; do
  if grep -q "pull_request_target" "$f"; then
    # Check whether the workflow checks out the PR head without a safe ref
    if grep -q "ref.*pull_request" "$f" || grep -q "github\.head_ref" "$f"; then
      log_issue "$(basename "$f"): uses pull_request_target AND checks out the PR head ref – high risk of pwn-request attack."
    else
      log_warn "$(basename "$f"): uses pull_request_target. Verify it does not expose secrets to untrusted code."
    fi
  fi
done

# ──────────────────────────────────────────────────────────────────────────────
# CHECK 2 – Script injection via untrusted context variables
# ──────────────────────────────────────────────────────────────────────────────
log_section "CHECK 2: Script injection via untrusted GitHub context"

INJECTION_PATTERNS=(
  '\$\{\{.*github\.event\.pull_request\.title'
  '\$\{\{.*github\.event\.pull_request\.body'
  '\$\{\{.*github\.event\.issue\.title'
  '\$\{\{.*github\.event\.issue\.body'
  '\$\{\{.*github\.event\.comment\.body'
  '\$\{\{.*github\.event\.head_commit\.message'
  '\$\{\{.*github\.head_ref'
  '\$\{\{.*github\.event\.pages\.'
)

for f in "${WORKFLOW_FILES[@]}"; do
  for pattern in "${INJECTION_PATTERNS[@]}"; do
    if grep -qE "$pattern" "$f"; then
      log_issue "$(basename "$f"): possible script injection – untrusted input used directly in run: step via $pattern"
    fi
  done
done

# ──────────────────────────────────────────────────────────────────────────────
# CHECK 3 – Overly broad permissions
# ──────────────────────────────────────────────────────────────────────────────
log_section "CHECK 3: Overly broad permissions"

for f in "${WORKFLOW_FILES[@]}"; do
  if grep -qE "^\s+write-all" "$f"; then
    log_issue "$(basename "$f"): uses 'permissions: write-all' – overly broad."
  fi
  if ! grep -q "permissions:" "$f"; then
    log_warn "$(basename "$f"): no 'permissions:' block found – defaults may be overly broad."
  fi
done

# ──────────────────────────────────────────────────────────────────────────────
# CHECK 4 – Secrets passed to third-party (non-github) actions
# ──────────────────────────────────────────────────────────────────────────────
log_section "CHECK 4: Secrets passed to third-party actions"

for f in "${WORKFLOW_FILES[@]}"; do
  fname="$(basename "$f")"
  # Identify third-party actions (not actions/ or github/) that appear in the
  # same job context as a 'secrets.' reference.  We extract all 'uses:' orgs
  # and warn if any non-first-party org also has secrets in the same file.
  third_party_actions=$(grep -oE '^\s+uses:\s+[A-Za-z0-9_.-]+/' "$f" 2>/dev/null | \
    grep -vE '(actions|github)/' | grep -c '.' || true)

  if [[ "$third_party_actions" -gt 0 ]] && grep -q "secrets\." "$f"; then
    log_warn "$fname: secrets are present and the file uses third-party action(s). Verify secrets are not inadvertently passed to untrusted actions."
  fi
done

# ──────────────────────────────────────────────────────────────────────────────
# CHECK 5 – Unpinned actions (not pinned to a full commit SHA)
# ──────────────────────────────────────────────────────────────────────────────
log_section "CHECK 5: Unpinned actions"

for f in "${WORKFLOW_FILES[@]}"; do
  # Match 'uses: owner/repo@tag-or-branch' but not '@<40-char SHA>'
  while IFS= read -r line; do
    uses_val=$(echo "$line" | grep -oE '[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[A-Za-z0-9_./-]+' | head -1 || true)
    if [[ -n "$uses_val" ]]; then
      pin=$(echo "$uses_val" | cut -d'@' -f2)
      if ! echo "$pin" | grep -qE '^[0-9a-f]{40}$'; then
        log_warn "$(basename "$f"): action '$uses_val' is not pinned to a full commit SHA."
      fi
    fi
  done < <(grep -E '^\s+uses:' "$f")
done

# ──────────────────────────────────────────────────────────────────────────────
# CHECK 6 – GITHUB_TOKEN with write permissions used in dangerous contexts
# ──────────────────────────────────────────────────────────────────────────────
log_section "CHECK 6: GITHUB_TOKEN write in dangerous contexts"

for f in "${WORKFLOW_FILES[@]}"; do
  if grep -q "GITHUB_TOKEN" "$f" && \
     (grep -q "contents: write" "$f" || grep -q "pull-requests: write" "$f" || grep -q "packages: write" "$f"); then
    log_warn "$(basename "$f"): GITHUB_TOKEN is used with elevated write permissions. Confirm this is intentional."
  fi
done

# ──────────────────────────────────────────────────────────────────────────────
# CHECK 7 – Suspicious / explicitly malicious patterns
# ──────────────────────────────────────────────────────────────────────────────
log_section "CHECK 7: Suspicious commands"

SUSPICIOUS_PATTERNS=(
  # Data exfiltration
  "curl.*\.ngrok\."
  "wget.*\.ngrok\."
  "nc -e "
  "bash -i >&"
  "/dev/tcp/"
  "base64 -d.*\|.*sh"
  "python -c.*socket\.socket"
  # Cryptocurrency mining
  "xmrig"
  "stratum\+tcp"
  "monero"
  # Persistence / backdoors
  "crontab -[el]"
  "authorized_keys"
  # Self-modifying workflows
  "git push.*--force"
  "git commit.*--amend"
  # Auto-merge without review (REST API endpoint pattern)
  "pulls/[0-9]+/merge"
)

for f in "${WORKFLOW_FILES[@]}"; do
  for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
    if grep -qiE "$pattern" "$f"; then
      log_issue "$(basename "$f"): suspicious pattern detected – '$pattern'"
    fi
  done
done

# ──────────────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────────────
echo
echo "──────────────────────────────────────────────────────"
log_info "Workflow audit complete."
log_info "Issues  : $ISSUES"
log_info "Warnings: $WARNINGS"

if [[ $ISSUES -gt 0 ]]; then
  echo -e "${RED}Critical issues found. Please remediate before merging.${NC}"
  exit 1
elif [[ $WARNINGS -gt 0 ]]; then
  echo -e "${YELLOW}Warnings found. Manual review recommended.${NC}"
  exit 0
else
  echo -e "${GREEN}All workflow checks passed. ✓${NC}"
fi
