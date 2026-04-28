#!/usr/bin/env bash
# check_licenses.sh – verify that all dependency licenses are compatible with
# the project's license policy.  Supports npm (package.json) and Python (pip).

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
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

# ──────────────────────────────────────────────────────────────────────────────
# Policy: licenses that are DENIED (strong copyleft – incompatible with most
# proprietary or permissive projects).  Adjust to your organisation's policy.
# ──────────────────────────────────────────────────────────────────────────────
DENIED_LICENSES=(
  "GPL-2.0"
  "GPL-3.0"
  "AGPL-1.0"
  "AGPL-3.0"
  "EUPL-1.1"
  "EUPL-1.2"
  "CDDL-1.0"
  "CDDL-1.1"
  "SSPL-1.0"
  "BUSL-1.1"
)

# Licenses that require review before use
WARN_LICENSES=(
  "LGPL-2.0"
  "LGPL-2.1"
  "LGPL-3.0"
  "MPL-2.0"
  "EPL-1.0"
  "EPL-2.0"
  "CC-BY-SA-4.0"
)

is_denied() {
  local lic="$1"
  for denied in "${DENIED_LICENSES[@]}"; do
    if echo "$lic" | grep -qi "$denied"; then
      return 0
    fi
  done
  return 1
}

is_warned() {
  local lic="$1"
  for warn in "${WARN_LICENSES[@]}"; do
    if echo "$lic" | grep -qi "$warn"; then
      return 0
    fi
  done
  return 1
}

# ──────────────────────────────────────────────────────────────────────────────
# npm / Node.js
# ──────────────────────────────────────────────────────────────────────────────
check_npm_licenses() {
  local pkg_json="$1"
  log_section "npm license check: $pkg_json"

  if ! command -v npm &>/dev/null; then
    log_warn "npm not found – skipping Node.js license check."
    return
  fi

  if ! npm install --prefix "$(dirname "$pkg_json")" --ignore-scripts --silent 2>/dev/null; then
    log_warn "npm install failed – skipping Node.js license check."
    return
  fi

  # license-checker outputs CSV: module@version,license,repository,...
  if ! command -v npx &>/dev/null; then
    log_warn "npx not found – skipping Node.js license check."
    return
  fi

  local csv
  csv=$(npx --yes license-checker --csv --production --start "$(dirname "$pkg_json")" 2>/dev/null || true)

  if [[ -z "$csv" ]]; then
    log_warn "license-checker returned no output."
    return
  fi

  while IFS=',' read -r module license _rest; do
    module=$(echo "$module" | tr -d '"')
    license=$(echo "$license" | tr -d '"')

    if is_denied "$license"; then
      log_issue "npm: $module uses denied license: $license"
    elif is_warned "$license"; then
      log_warn "npm: $module uses license requiring review: $license"
    fi
  done <<< "$csv"
}

# ──────────────────────────────────────────────────────────────────────────────
# Python / pip
# ──────────────────────────────────────────────────────────────────────────────
check_python_licenses() {
  log_section "Python license check"

  if ! command -v pip &>/dev/null && ! command -v pip3 &>/dev/null; then
    log_warn "pip not found – skipping Python license check."
    return
  fi

  local pip_cmd
  pip_cmd=$(command -v pip3 || command -v pip)

  if ! "$pip_cmd" install pip-licenses --quiet 2>/dev/null; then
    log_warn "Could not install pip-licenses – skipping Python license check."
    return
  fi

  local output
  output=$(pip-licenses --format=csv --with-urls 2>/dev/null || true)

  if [[ -z "$output" ]]; then
    log_warn "pip-licenses returned no output."
    return
  fi

  # Skip header line
  while IFS=',' read -r package version license url; do
    package=$(echo "$package" | tr -d '"')
    version=$(echo "$version" | tr -d '"')
    license=$(echo "$license" | tr -d '"')

    if is_denied "$license"; then
      log_issue "pip: $package==$version uses denied license: $license"
    elif is_warned "$license"; then
      log_warn "pip: $package==$version uses license requiring review: $license"
    fi
  done < <(tail -n +2 <<< "$output")
}

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
log_info "Starting license compliance check from $REPO_ROOT"
log_info "Denied licenses: ${DENIED_LICENSES[*]}"
log_info "Review required: ${WARN_LICENSES[*]}"

# Find all package.json files (excluding node_modules)
mapfile -t PKG_JSONS < <(find "$REPO_ROOT" -name "package.json" \
  -not -path "*/node_modules/*" \
  -not -path "*/.git/*" 2>/dev/null || true)

for pkg in "${PKG_JSONS[@]}"; do
  check_npm_licenses "$pkg"
done

# Check for requirements files
REQ_FILES=("requirements.txt" "requirements-*.txt" "setup.py" "setup.cfg" "pyproject.toml" "Pipfile")
for req in "${REQ_FILES[@]}"; do
  if find "$REPO_ROOT" -name "$req" -not -path "*/.git/*" | grep -q .; then
    check_python_licenses
    break
  fi
done

echo
echo "──────────────────────────────────────────────────────"
log_info "License compliance check complete. Issues=$ISSUES  Warnings=$WARNINGS"

if [[ $ISSUES -gt 0 ]]; then
  echo -e "${RED}Denied licenses found. Review and replace the affected packages.${NC}"
  exit 1
fi
