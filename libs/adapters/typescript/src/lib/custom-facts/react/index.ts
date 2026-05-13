import type { ObservedFact } from '@critiq/core-rules-engine';

import type { TypeScriptFactDetectorContext } from '../shared';
import { collectAccessibilityParityFacts } from './accessibility-parity';
import { collectDerivedStateFacts } from './derived-state';
import { collectIndexKeyFacts } from './index-key';
import { collectLegacyReactPatternFacts } from './legacy-react-patterns';
import { collectMissingAccessibleNameFacts } from './accessible-name';
import { collectUncontrolledControlledInputFacts } from './uncontrolled-controlled-input';

/** Collects React UI and accessibility facts for JS and TS sources. */
export function detectReactAccessibilityFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  return [
    ...collectIndexKeyFacts(context),
    ...collectDerivedStateFacts(context),
    ...collectMissingAccessibleNameFacts(context),
    ...collectUncontrolledControlledInputFacts(context),
    ...collectLegacyReactPatternFacts(context),
    ...collectAccessibilityParityFacts(context),
  ];
}

/** Compatibility alias for callers that want the full React fact collector. */
export const collectReactFacts = detectReactAccessibilityFacts;

export { collectAccessibilityParityFacts } from './accessibility-parity';
export { collectDerivedStateFacts } from './derived-state';
export { collectIndexKeyFacts } from './index-key';
export { collectLegacyReactPatternFacts } from './legacy-react-patterns';
export { collectMissingAccessibleNameFacts } from './accessible-name';
export { collectUncontrolledControlledInputFacts } from './uncontrolled-controlled-input';
export {
  flatJsxElementsInFragment,
  getJsxTagName,
} from './jsx-elements';
export {
  getJsxStringAttr,
} from './jsx-attributes';

export * from './dedupe-facts';
export * from './jsx-attributes';
export * from './jsx-elements';
export * from './legacy-react-patterns';
export * from './react-class-components';
