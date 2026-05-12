#!/usr/bin/env sh
# Sample git pre-commit hook: scan staged content for credential-shaped literals.
# Install (from repo root): cp node_modules/@critiq/cli/scripts/hooks/pre-commit.sample.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
set -eu
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
exec npx --no-install @critiq/cli audit secrets . --staged
