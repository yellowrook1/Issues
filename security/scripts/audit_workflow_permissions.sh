#!/usr/bin/env bash
# audit_workflow_permissions.sh – verify that all workflow files declare
# minimal, explicit permissions rather than relying on broad defaults.

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

log_info "Auditing permissions in ${#WORKFLOW_FILES[@]} workflow file(s)"

# Dangerous write scopes that should rarely be granted
DANGEROUS_WRITE_SCOPES=(
  "contents: write"
  "packages: write"
  "deployments: write"
  "environments: write"
  "id-token: write"
  "actions: write"
  "administration: write"
  "members: write"
  "organization-administration: write"
)

for f in "${WORKFLOW_FILES[@]}"; do
  fname="$(basename "$f")"
  log_section "$fname"

  # 1. Top-level permissions block
  if ! grep -q "^permissions:" "$f"; then
    log_issue "$fname: no top-level 'permissions:' block – GITHUB_TOKEN may have overly broad defaults."
  fi

  # 2. write-all
  if grep -qE "^\s*permissions:\s*write-all" "$f" || grep -qE "^\s+write-all" "$f"; then
    log_issue "$fname: 'permissions: write-all' grants ALL write permissions – use principle of least privilege."
  fi

  # 3. read-all at top level is generally acceptable, but warn
  if grep -qE "^\s*permissions:\s*read-all" "$f"; then
    log_warn "$fname: 'permissions: read-all' – confirm all read permissions are necessary."
  fi

  # 4. Dangerous write scopes
  for scope in "${DANGEROUS_WRITE_SCOPES[@]}"; do
    if grep -q "$scope" "$f"; then
      log_warn "$fname: uses '$scope' – verify this elevated permission is required."
    fi
  done

  # 5. Jobs without explicit permissions (inheriting from workflow level)
  jobs_without_perms=$(python3 - "$f" <<'PYEOF'
import sys, re

with open(sys.argv[1]) as fh:
    content = fh.read()

# Very simple YAML job-block detection
job_sections = re.findall(r'^  (\w[\w-]*):\n((?:    .*\n)*)', content, re.MULTILINE)
for name, body in job_sections:
    if 'permissions:' not in body and name not in ('strategy', 'env', 'defaults', 'outputs', 'needs', 'if', 'runs-on', 'steps'):
        print(name)
PYEOF
  )

  if [[ -n "$jobs_without_perms" ]]; then
    while IFS= read -r job; do
      log_warn "$fname: job '$job' has no explicit 'permissions:' block – inherits from workflow level."
    done <<< "$jobs_without_perms"
  fi

  if [[ $ISSUES -eq 0 ]] && [[ $WARNINGS -eq 0 ]]; then
    log_info "$fname: permissions look reasonable ✓"
  fi
done

echo
echo "──────────────────────────────────────────────────────"
log_info "Permissions audit complete. Issues=$ISSUES  Warnings=$WARNINGS"

if [[ $ISSUES -gt 0 ]]; then
  exit 1
fi
