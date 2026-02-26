import crypto from 'node:crypto';

export function stableFingerprint(input: string): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}
