---
'@critiq/cli': patch
'@critiq/adapter-java': patch
---

feat: add Java documentation fact collectors (java-doc.ts) for batch 05

Adds four Javadoc fact collectors:
- `java.doc.unmatched-parameter-tag` — detects @param tags that don't match method parameters
- `java.doc.parameter-tag-no-description` — detects @param tags with no description
- `java.doc.empty-javadoc-tag` — detects bare Javadoc block tags with no content
- `java.doc.malformed-javadoc-comment` — detects doubled @@ symbols in Javadoc

New domain file: `java-doc.ts` following the `go-doc.ts` pattern.
