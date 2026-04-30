import { normalizeText as normalizeSharedText } from '../shared';

export function normalizeText(text: string | undefined): string {
  return normalizeSharedText(text);
}
