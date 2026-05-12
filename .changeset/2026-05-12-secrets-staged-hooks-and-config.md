---
"@critiq/cli": minor
"@critiq/core-config": minor
"@critiq/check-runner": minor
---

Add `--staged` for `critiq check` and `critiq audit secrets` to scan `git diff --cached` index blobs. Extend `.critiq/config.yaml` with optional `secretsScan` (`ignorePaths`, `disabledDetectors`, `suppressFingerprints`). Ship sample `pre-commit` and `pre-push` hook scripts under `scripts/hooks/`.
