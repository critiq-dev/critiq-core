import { type CheckCommandEnvelope } from '@critiq/check-runner';

import { renderJson } from '../json.rendering';

export function renderCheckJson(envelope: CheckCommandEnvelope): string {
  return renderJson(envelope);
}
