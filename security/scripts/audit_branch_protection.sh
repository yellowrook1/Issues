#!/usr/bin/env bash
# audit_branch_protection.sh – verify that branch protection rules are configured
# for the default and important branches via the GitHub REST API.
# Requires: GITHUB_TOKEN and REPO environment variables.

set -euo pipefail

: "${GITHUB_TOKEN:?GITHUB_TOKEN must be set}"
: "${REPO:?REPO must be set (format: owner/repo)}"

API="https://api.github.com"
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

gh_api() {
  curl -fsSL \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$@"
}

# ──────────────────────────────────────────────────────────────────────────────
# Fetch repository metadata
# ──────────────────────────────────────────────────────────────────────────────
log_info "Fetching repository metadata for $REPO …"
repo_json=$(gh_api "$API/repos/$REPO")
default_branch=$(echo "$repo_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['default_branch'])")
log_info "Default branch: $default_branch"

# ──────────────────────────────────────────────────────────────────────────────
# Branches to audit
# ──────────────────────────────────────────────────────────────────────────────
BRANCHES_TO_AUDIT=("$default_branch" "main" "master" "develop" "release")
# Deduplicate
mapfile -t BRANCHES_TO_AUDIT < <(printf '%s\n' "${BRANCHES_TO_AUDIT[@]}" | sort -u)

# ──────────────────────────────────────────────────────────────────────────────
# Helper: check a single branch
# ──────────────────────────────────────────────────────────────────────────────
audit_branch() {
  local branch="$1"
  log_section "Branch: $branch"

  # Check if branch exists
  branch_exists=$(gh_api "$API/repos/$REPO/branches/$branch" 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'name' in d else 'no')" 2>/dev/null || echo "no")

  if [[ "$branch_exists" != "yes" ]]; then
    log_info "Branch '$branch' does not exist – skipping."
    return
  fi

  # Fetch branch protection
  protection_json=$(gh_api "$API/repos/$REPO/branches/$branch/protection" 2>/dev/null || echo "{}")

  if echo "$protection_json" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if 'required_status_checks' in d or 'required_pull_request_reviews' in d else 1)" 2>/dev/null; then
    log_info "Branch protection is configured."
  else
    log_issue "Branch '$branch' has NO branch protection rules configured."
    return
  fi

  # Required pull request reviews
  reviews=$(echo "$protection_json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
r = d.get('required_pull_request_reviews', {})
if not r:
    print('NONE')
else:
    count = r.get('required_approving_review_count', 0)
    dismiss = r.get('dismiss_stale_reviews', False)
    code_owners = r.get('require_code_owner_reviews', False)
    print(f'approvals={count} dismiss_stale={dismiss} codeowners={code_owners}')
" 2>/dev/null || echo "NONE")

  if [[ "$reviews" == "NONE" ]]; then
    log_issue "Branch '$branch': required pull request reviews are NOT enforced."
  else
    log_info "PR reviews: $reviews"
    if echo "$reviews" | grep -q "approvals=0"; then
      log_warn "Branch '$branch': required approving review count is 0."
    fi
    if echo "$reviews" | grep -q "dismiss_stale=False"; then
      log_warn "Branch '$branch': stale reviews are NOT dismissed on new commits."
    fi
  fi

  # Required status checks
  status_checks=$(echo "$protection_json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
sc = d.get('required_status_checks', {})
if not sc:
    print('NONE')
else:
    strict = sc.get('strict', False)
    contexts = sc.get('contexts', [])
    checks = sc.get('checks', [])
    all_checks = contexts + [c['context'] for c in checks]
    print(f'strict={strict} checks={all_checks}')
" 2>/dev/null || echo "NONE")

  if [[ "$status_checks" == "NONE" ]]; then
    log_warn "Branch '$branch': no required status checks configured."
  else
    log_info "Status checks: $status_checks"
    if echo "$status_checks" | grep -q "strict=False"; then
      log_warn "Branch '$branch': branch is not required to be up to date before merging."
    fi
  fi

  # Enforce admins
  enforce_admins=$(echo "$protection_json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
ea = d.get('enforce_admins', {})
print(ea.get('enabled', False) if isinstance(ea, dict) else ea)
" 2>/dev/null || echo "False")

  if [[ "$enforce_admins" == "False" ]]; then
    log_warn "Branch '$branch': branch protection rules are NOT enforced for administrators."
  else
    log_info "Admin enforcement: enabled ✓"
  fi

  # Require linear history
  linear=$(echo "$protection_json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('required_linear_history', {}).get('enabled', False))
" 2>/dev/null || echo "False")

  if [[ "$linear" == "False" ]]; then
    log_warn "Branch '$branch': linear history (no merge commits) is NOT required."
  else
    log_info "Linear history: required ✓"
  fi

  # Require signed commits
  signed=$(echo "$protection_json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('required_signatures', {}).get('enabled', False))
" 2>/dev/null || echo "False")

  if [[ "$signed" == "False" ]]; then
    log_warn "Branch '$branch': signed commits are NOT required."
  else
    log_info "Signed commits: required ✓"
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Audit all target branches
# ──────────────────────────────────────────────────────────────────────────────
for branch in "${BRANCHES_TO_AUDIT[@]}"; do
  audit_branch "$branch"
done

# ──────────────────────────────────────────────────────────────────────────────
# Repository-level settings
# ──────────────────────────────────────────────────────────────────────────────
log_section "Repository-level security settings"

delete_head=$(echo "$repo_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('delete_branch_on_merge', False))" 2>/dev/null || echo "False")
if [[ "$delete_head" == "False" ]]; then
  log_warn "Auto-delete of head branches after merge is disabled."
else
  log_info "Auto-delete head branches: enabled ✓"
fi

private=$(echo "$repo_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('private', False))" 2>/dev/null || echo "False")
log_info "Repository visibility: $( [[ "$private" == "True" ]] && echo 'private' || echo 'public')"

allow_fork=$(echo "$repo_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('allow_forking', True))" 2>/dev/null || echo "True")
if [[ "$allow_fork" == "True" ]] && [[ "$private" == "True" ]]; then
  log_warn "Private repository allows forking."
fi

# ──────────────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────────────
echo
echo "──────────────────────────────────────────────────────"
log_info "Branch protection audit complete."
log_info "Issues  : $ISSUES"
log_info "Warnings: $WARNINGS"

if [[ $ISSUES -gt 0 ]]; then
  echo -e "${RED}Critical issues found.${NC}"
  exit 1
fi
