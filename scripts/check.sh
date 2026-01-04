#!/bin/bash
# Pre-push check script for Hackles
# Run this before pushing to catch CI issues locally

set -e  # Exit on first error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Hackles Pre-Push Checks${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Track if we're in fix mode
FIX_MODE=false
if [[ "$1" == "--fix" || "$1" == "-f" ]]; then
    FIX_MODE=true
    echo -e "${YELLOW}Running in FIX mode - will auto-fix issues${NC}"
    echo
fi

# Function to run a check
run_check() {
    local name="$1"
    local cmd="$2"
    echo -e "${BLUE}[*] $name${NC}"
    if eval "$cmd"; then
        echo -e "${GREEN}    ✓ Passed${NC}"
        return 0
    else
        echo -e "${RED}    ✗ Failed${NC}"
        return 1
    fi
}

FAILED=0

# 1. Black formatting
echo -e "${BLUE}[1/5] Code Formatting (black)${NC}"
if $FIX_MODE; then
    black hackles/ tests/ 2>&1 | grep -E "^(reformatted|All done)" || true
    echo -e "${GREEN}    ✓ Formatted${NC}"
else
    if black --check --diff hackles/ tests/ 2>&1 | head -20; then
        echo -e "${GREEN}    ✓ Passed${NC}"
    else
        echo -e "${RED}    ✗ Failed - run with --fix to auto-format${NC}"
        ((FAILED++))
    fi
fi
echo

# 2. Import sorting
echo -e "${BLUE}[2/5] Import Sorting (isort)${NC}"
if $FIX_MODE; then
    isort hackles/ tests/ 2>&1 | grep -E "^(Fixing|Skipping)" || echo "    No changes needed"
    echo -e "${GREEN}    ✓ Sorted${NC}"
else
    if isort --check-only --diff hackles/ tests/ 2>&1 | head -20; then
        echo -e "${GREEN}    ✓ Passed${NC}"
    else
        echo -e "${RED}    ✗ Failed - run with --fix to auto-sort${NC}"
        ((FAILED++))
    fi
fi
echo

# 3. Flake8 linting (critical errors only - matches CI)
echo -e "${BLUE}[3/5] Linting (flake8 - critical errors)${NC}"
if flake8 hackles/ tests/ --count --select=E9,F63,F7,F82,F824 --show-source --statistics 2>&1; then
    echo -e "${GREEN}    ✓ Passed${NC}"
else
    echo -e "${RED}    ✗ Failed - fix errors above${NC}"
    ((FAILED++))
fi
echo

# 4. Ruff linting (optional but helpful)
echo -e "${BLUE}[4/5] Linting (ruff)${NC}"
if command -v ruff &> /dev/null; then
    if $FIX_MODE; then
        ruff check --fix hackles/ tests/ 2>&1 | tail -5 || true
        echo -e "${GREEN}    ✓ Fixed${NC}"
    else
        if ruff check hackles/ tests/ 2>&1 | tail -10; then
            echo -e "${GREEN}    ✓ Passed${NC}"
        else
            echo -e "${YELLOW}    ! Warnings (non-blocking)${NC}"
        fi
    fi
else
    echo -e "${YELLOW}    ! Skipped (ruff not installed)${NC}"
fi
echo

# 5. Tests
echo -e "${BLUE}[5/5] Tests (pytest)${NC}"
if pytest tests/ -q --tb=short 2>&1 | tail -15; then
    echo -e "${GREEN}    ✓ Passed${NC}"
else
    echo -e "${RED}    ✗ Failed${NC}"
    ((FAILED++))
fi
echo

# Summary
echo -e "${BLUE}========================================${NC}"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}  All checks passed! Safe to push.${NC}"
    echo -e "${BLUE}========================================${NC}"
    exit 0
else
    echo -e "${RED}  $FAILED check(s) failed${NC}"
    echo -e "${YELLOW}  Run: ./scripts/check.sh --fix${NC}"
    echo -e "${BLUE}========================================${NC}"
    exit 1
fi
