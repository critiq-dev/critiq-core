---
"@critiq/adapter-typescript": minor
---

Add 6 new React class-component adapter facts for JavaScript batch 06 parity:

- `ui.react.set-state-in-component-will-update` — setState in componentWillUpdate
- `ui.react.deprecated-is-mounted` — this.isMounted / ReactDOM.isMounted
- `ui.react.should-component-update` — shouldComponentUpdate method override
- `ui.react.lifecycle-method-typo` — misspelled lifecycle method names (Levenshtein ≤ 2)
- `ui.react.invalid-markup-characters` — control and zero-width characters in JSX text
- `ui.react.render-return-value` — render() returning non-JSX values
