---
'@critiq/adapter-typescript': patch
---

Add React maintenance pattern facts for JavaScript batch 05 (JS-0424, JS-0435)

- `ui.react.unnecessary-fragment` (JS-0424) — flags unnecessary fragment and Fragment wrappers with a single child
- `ui.react.this-state-in-set-state` (JS-0435) — flags this.state read inside setState() calls
