---
"@critiq/adapter-typescript": patch
---

Emit additional React UI facts for DeepSource-aligned parity: invalid anchor href targets, `aria-activedescendant` owners that are not keyboard focusable, widget roles without a non-negative tabIndex, semantic text elements with interactive roles, combined click and keyboard handlers without a widget role, pointer or key handlers without click or widget roles, and deprecated `react-dom` root APIs plus `createFactory`. Extend JSX element and event helper utilities accordingly.
