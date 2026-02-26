export function lineForIndex(content: string, index: number): number {
  if (index <= 0) return 1;
  let line = 1;
  for (let i = 0; i < content.length && i < index; i += 1) {
    if (content[i] === '\n') line += 1;
  }
  return line;
}
