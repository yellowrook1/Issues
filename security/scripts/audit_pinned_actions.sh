#!/usr/bin/env bash
# audit_pinned_actions.sh – verify that every 'uses:' reference in workflow
# files is pinned to a full 40-character commit SHA, not a mutable tag/branch.
# Supply-chain attacks (e.g. "tj-actions/changed-files") exploit unpinned refs.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
WORKFLOW_DIR="$REPO_ROOT/.github/workflows"
ISSUES=0

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
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

log_info "Checking action pinning in ${#WORKFLOW_FILES[@]} workflow file(s)"

# Allowlist: local actions and Docker images are exempt from SHA pinning
EXEMPT_PREFIXES=("\./" "docker://")

is_exempt() {
  local ref="$1"
  for prefix in "${EXEMPT_PREFIXES[@]}"; do
    if echo "$ref" | grep -qE "^$prefix"; then
      return 0
    fi
  done
  return 1
}

for f in "${WORKFLOW_FILES[@]}"; do
  fname="$(basename "$f")"
  log_section "$fname"
  file_issues=0

  while IFS= read -r line; do
    # Strip leading whitespace and extract the value after 'uses:'
    uses_val=$(echo "$line" | sed -E 's/^\s*uses:\s*//' | tr -d '"'"'" | xargs)

    if [[ -z "$uses_val" ]]; then
      continue
    fi

    if is_exempt "$uses_val"; then
      continue
    fi

    # Extract the ref part (after '@')
    if ! echo "$uses_val" | grep -q '@'; then
      log_issue "$fname: action '$uses_val' has no '@ref' at all – always pin to a SHA."
      file_issues=$((file_issues + 1))
      continue
    fi

    pin=$(echo "$uses_val" | cut -d'@' -f2)

    # A full SHA is exactly 40 lowercase hex characters
    if echo "$pin" | grep -qE '^[0-9a-f]{40}$'; then
      log_info "OK: $uses_val"
    else
      log_issue "$fname: '$uses_val' is pinned to '$pin' (not a full commit SHA)."
      # Provide remediation hint
      owner_repo=$(echo "$uses_val" | cut -d'@' -f1)
      log_warn "    Remediation: look up the SHA for '$pin' at:"
      log_warn "    https://github.com/$owner_repo/commits/$pin"
      file_issues=$((file_issues + 1))
    fi
  done < <(grep -E '^\s+uses:' "$f")

  if [[ $file_issues -eq 0 ]]; then
    log_info "All actions in $fname are properly pinned ✓"
  fi
done

echo
echo "──────────────────────────────────────────────────────"
log_info "Pinned-actions audit complete. Unpinned actions found: $ISSUES"

if [[ $ISSUES -gt 0 ]]; then
  echo -e "${RED}Please pin all third-party actions to a full commit SHA.${NC}"
  echo "See: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"
  exit 1
else
  echo -e "${GREEN}All actions are pinned. ✓${NC}"
fi
