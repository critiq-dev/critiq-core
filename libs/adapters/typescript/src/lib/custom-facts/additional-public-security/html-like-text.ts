export function isHtmlLikeText(text: string | undefined): boolean {
  return typeof text === 'string' && /<\w+(\s[^>]*)?>/u.test(text);
}
