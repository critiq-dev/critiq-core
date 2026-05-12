#!/usr/bin/env sh
# Sample git pre-push hook: scan commits being pushed against the remote default branch.
# Adjust BASE to your protected branch (e.g. origin/develop). Install like pre-commit.sample.sh.
set -eu
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
BASE="${CRITIQ_PRE_PUSH_BASE:-origin/main}"
if ! git rev-parse --verify "$BASE" >/dev/null 2>&1; then
  echo "critiq pre-push: skip (no $BASE)" >&2
  exit 0
fi
exec npx --no-install @critiq/cli audit secrets . --base "$BASE" --head HEAD
