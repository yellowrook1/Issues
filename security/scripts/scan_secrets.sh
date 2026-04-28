#!/usr/bin/env bash
# scan_secrets.sh – detect hard-coded credentials / secrets in the repository.
# Exits with code 1 if suspicious patterns are found.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
FINDINGS=0

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_finding() { echo -e "${RED}[FINDING]${NC} $*"; FINDINGS=$((FINDINGS + 1)); }

# ──────────────────────────────────────────────────────────────────────────────
# Directories / files to exclude from scanning
# ──────────────────────────────────────────────────────────────────────────────
EXCLUDE_DIRS=(
  ".git"
  "node_modules"
  "vendor"
  ".venv"
  "__pycache__"
  "dist"
  "build"
)

build_exclude_args() {
  local args=()
  for d in "${EXCLUDE_DIRS[@]}"; do
    args+=(--exclude-dir="$d")
  done
  echo "${args[@]}"
}

# ──────────────────────────────────────────────────────────────────────────────
# Pattern catalogue
# Each entry: "DESCRIPTION|REGEX"
# ──────────────────────────────────────────────────────────────────────────────
declare -a PATTERNS=(
  # Generic high-entropy assignments
  "Possible password assignment|password\s*=\s*['\"][^'\"]{8,}['\"]"
  "Possible secret assignment|secret\s*=\s*['\"][^'\"]{8,}['\"]"
  "Possible API key assignment|api[_-]?key\s*=\s*['\"][^'\"]{8,}['\"]"
  "Possible token assignment|token\s*=\s*['\"][^'\"]{16,}['\"]"
  "Possible private key material|-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY"
  "Possible AWS access key|AKIA[0-9A-Z]{16}"
  "Possible AWS secret key|aws[_-]?secret[_-]?access[_-]?key\s*=\s*['\"][^'\"]{20,}['\"]"
  "Possible GCP service account key|\"type\": \"service_account\""
  "Possible GitHub PAT (classic)|ghp_[0-9A-Za-z]{36}"
  "Possible GitHub PAT (fine-grained)|github_pat_[0-9A-Za-z_]{82}"
  "Possible GitHub OAuth token|gho_[0-9A-Za-z]{36}"
  "Possible GitHub Actions token|ghs_[0-9A-Za-z]{36}"
  "Possible Slack token|xox[baprs]-[0-9A-Za-z\-]{10,48}"
  "Possible Slack webhook|hooks\.slack\.com/services/[A-Z0-9]{9,11}/[A-Z0-9]{9,11}/[A-Za-z0-9]{24}"
  "Possible Stripe live key|sk_live_[0-9A-Za-z]{24}"
  "Possible Stripe test key|sk_test_[0-9A-Za-z]{24}"
  "Possible Twilio SID|AC[a-z0-9]{32}"
  "Possible SendGrid key|SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"
  "Possible Heroku API key|[hH]eroku.{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
  "Possible JWT token|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
  "Possible database URL with password|[a-zA-Z]+://[^:@\s]+:[^@\s]{4,}@[^/\s]+"
  "Possible connection string with password|[Pp]assword=[^;\"' ]{4,}"
)

log_info "Scanning repository at: $REPO_ROOT"
log_info "Looking for ${#PATTERNS[@]} secret patterns …"
echo

# ──────────────────────────────────────────────────────────────────────────────
# Main scan loop
# ──────────────────────────────────────────────────────────────────────────────
IFS_BACKUP="$IFS"
for entry in "${PATTERNS[@]}"; do
  IFS='|' read -r description pattern <<< "$entry"
  IFS="$IFS_BACKUP"

  # shellcheck disable=SC2046
  results=$(grep -rniI \
    $(build_exclude_args) \
    --include="*" \
    -E "$pattern" \
    "$REPO_ROOT" 2>/dev/null || true)

  if [[ -n "$results" ]]; then
    log_finding "$description"
    while IFS= read -r line; do
      echo "    $line"
    done <<< "$results"
    echo
  fi
done

# ──────────────────────────────────────────────────────────────────────────────
# High-entropy string heuristic (base64-ish strings ≥ 40 chars)
# ──────────────────────────────────────────────────────────────────────────────
log_info "Checking for high-entropy strings …"
# shellcheck disable=SC2046
entropy_hits=$(grep -rniI \
  $(build_exclude_args) \
  -E "['\"][A-Za-z0-9+/=_-]{40,}['\"]" \
  "$REPO_ROOT" 2>/dev/null || true)

if [[ -n "$entropy_hits" ]]; then
  log_warn "Potential high-entropy strings found (manual review recommended):"
  echo "$entropy_hits" | head -20
  echo
fi

# ──────────────────────────────────────────────────────────────────────────────
# Result summary
# ──────────────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────"
if [[ $FINDINGS -gt 0 ]]; then
  log_finding "Total confirmed pattern matches: $FINDINGS"
  echo "Review the findings above and rotate any exposed credentials immediately."
  exit 1
else
  log_info "No hard-coded secret patterns detected. ✓"
fi
