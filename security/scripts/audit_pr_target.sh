#!/usr/bin/env bash
# audit_pr_target.sh – detect dangerous uses of pull_request_target that can
# lead to "pwn-request" attacks (privilege escalation via untrusted PR code).
#
# Background:
#   pull_request_target runs in the context of the BASE branch with write
#   permissions even when triggered by a fork PR.  If the workflow also checks
#   out and executes code from the PR head, an attacker can steal secrets.
#
# References:
#   https://securitylab.github.com/research/github-actions-preventing-pwn-requests/

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

log_info "Checking for pull_request_target misuse in ${#WORKFLOW_FILES[@]} workflow file(s)"

for f in "${WORKFLOW_FILES[@]}"; do
  fname="$(basename "$f")"

  # Only flag files where pull_request_target appears as a YAML event trigger key,
  # i.e., at the top-level "on:" block (indented with 2 spaces or as direct key).
  # This avoids false positives from comments or step names that mention the string.
  if ! grep -qE '^  pull_request_target:|^pull_request_target:' "$f"; then
    continue
  fi

  log_section "$fname"
  log_warn "$fname: uses pull_request_target trigger."

  # ── Risk 1: checkout of untrusted ref ──────────────────────────────────────
  # The danger is using github.event.pull_request.head.sha or github.head_ref
  # in the 'ref' parameter of actions/checkout.
  if grep -qE "ref:.*github\.(event\.pull_request\.head|head_ref)" "$f"; then
    log_issue "$fname: CRITICAL – checks out untrusted PR head ref inside pull_request_target. " \
              "This is the classic pwn-request vulnerability."
  fi

  if grep -qE "github\.event\.pull_request\.head\.sha" "$f"; then
    log_issue "$fname: CRITICAL – references github.event.pull_request.head.sha inside pull_request_target."
  fi

  # ── Risk 2: uses GITHUB_TOKEN write operations ─────────────────────────────
  if grep -q "GITHUB_TOKEN" "$f"; then
    if grep -E "contents: write|pull-requests: write|packages: write" "$f" | grep -q .; then
      log_issue "$fname: CRITICAL – GITHUB_TOKEN with write permissions inside pull_request_target."
    else
      log_warn "$fname: GITHUB_TOKEN present – confirm it is scoped to read-only operations."
    fi
  fi

  # ── Risk 3: auto-merge or admin API calls ─────────────────────────────────
  if grep -qiE "pulls/.*/merge|auto.?merge|merge_method" "$f"; then
    log_issue "$fname: CRITICAL – auto-merge API call detected inside pull_request_target."
  fi

  # ── Risk 4: user-controlled data in run: steps ────────────────────────────
  UNTRUSTED_PATTERNS=(
    "github\.event\.pull_request\.title"
    "github\.event\.pull_request\.body"
    "github\.event\.pull_request\.head\.label"
    "github\.event\.pull_request\.head\.ref"
    "github\.event\.comment\.body"
    "github\.event\.issue\.title"
    "github\.event\.issue\.body"
  )

  for pattern in "${UNTRUSTED_PATTERNS[@]}"; do
    if grep -qE "$pattern" "$f"; then
      log_issue "$fname: CRITICAL – untrusted user-controlled data ($pattern) used in pull_request_target context."
    fi
  done

  # ── Risk 5: external run scripts that may be overwritten ─────────────────
  if grep -E "^\s+run:" "$f" | grep -qE '\./|bash\s+\S+\.sh'; then
    log_warn "$fname: executes local scripts inside pull_request_target – if PR code modified these scripts, they run with elevated permissions."
  fi

  # ── Safer patterns ────────────────────────────────────────────────────────
  # The workflow is less risky if it only operates on the BASE repo context
  if grep -q "environment:" "$f"; then
    log_info "$fname: uses deployment environments (provides additional approval gate) ✓"
  fi
done

echo
echo "──────────────────────────────────────────────────────"
log_info "pwn-request audit complete. Issues=$ISSUES  Warnings=$WARNINGS"

if [[ $ISSUES -gt 0 ]]; then
  echo -e "${RED}CRITICAL: pull_request_target misuse found.${NC}"
  echo "See https://securitylab.github.com/research/github-actions-preventing-pwn-requests/ for remediation."
  exit 1
elif [[ $WARNINGS -gt 0 ]]; then
  echo -e "${YELLOW}Warnings found – manual review recommended.${NC}"
else
  echo -e "${GREEN}No pull_request_target misuse detected. ✓${NC}"
fi
