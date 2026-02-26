import { Finding } from '../types.js';
import { Rule } from './types.js';
import { lineForIndex } from '../engine/line.js';
import { redactExcerpt } from '../output/redact.js';
import { stableFingerprint } from '../engine/fingerprint.js';

const PRIVATE_KEY_BLOCK = /-----BEGIN (RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----/g;
const GITHUB_TOKEN = /(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})/g;
const AWS_ACCESS_KEY = /\b(AKIA[0-9A-Z]{16})\b/g;
const AWS_SECRET_KEY = /(?:aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi;
const STRIPE_LIVE_KEY = /\b(sk_live_[0-9a-zA-Z]{24,})\b/g;
const SLACK_TOKEN = /\b(xox[aboprs]-[0-9A-Za-z\-]{10,})\b/g;
const HIGH_ENTROPY_STRING = /["']([A-Za-z0-9+/=_\-]{20,})["']/g;

const SECRETS_FILE_BASENAMES = new Set([
  '.env',
  'credentials.json',
  'id_rsa',
  'id_ed25519',
  'id_ecdsa',
  'id_dsa',
]);

function isSecretsFilePath(filePath: string): boolean {
  const base = filePath.split('/').pop() ?? filePath;
  if (SECRETS_FILE_BASENAMES.has(base)) return true;
  if (base.startsWith('.env.')) return true;
  if (base.endsWith('.pem')) return true;
  if (base.startsWith('secrets.')) return true;
  return false;
}

function shannonEntropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  const len = s.length;
  return Object.values(freq).reduce((h, count) => {
    const p = count / len;
    return h - p * Math.log2(p);
  }, 0);
}

function looksLikeUrl(s: string): boolean {
  return s.startsWith('http') || s.startsWith('ftp');
}

export const secretsV1Rules: Rule[] = [
  {
    id: 'SEC001',
    title: 'Private key block detected',
    defaultSeverity: 'critical',
    appliesTo: () => true,
    run: (ctx) => {
      const findings: Finding[] = [];
      for (const match of ctx.content.matchAll(PRIVATE_KEY_BLOCK)) {
        const index = match.index ?? 0;
        const line = lineForIndex(ctx.content, index);
        const matched = match[0];
        const redactedExcerpt = redactExcerpt(matched, ctx.config.output.redact);
        findings.push({
          ruleId: 'SEC001',
          severity: 'critical',
          path: ctx.path,
          line,
          message: 'Private key block detected',
          why: 'Private keys should not be committed to source control.',
          fix: 'Remove the key from the repo and rotate it immediately.',
          redactedExcerpt,
          fingerprint: stableFingerprint(`SEC001:${ctx.path}:${line}:${matched.slice(0, 16)}`),
        });
      }
      return findings;
    },
  },
  {
    id: 'SEC002',
    title: 'AWS credentials detected',
    defaultSeverity: 'critical',
    appliesTo: () => true,
    run: (ctx) => {
      const findings: Finding[] = [];
      for (const match of ctx.content.matchAll(AWS_ACCESS_KEY)) {
        const index = match.index ?? 0;
        const line = lineForIndex(ctx.content, index);
        const matched = match[1];
        if (!matched) continue;
        findings.push({
          ruleId: 'SEC002',
          severity: 'critical',
          path: ctx.path,
          line,
          message: 'AWS access key ID detected',
          why: 'AWS access keys grant account access and must not be committed.',
          fix: 'Remove the key and rotate it in the AWS console immediately.',
          redactedExcerpt: redactExcerpt(matched, ctx.config.output.redact),
          fingerprint: stableFingerprint(`SEC002:${ctx.path}:${line}:${matched.slice(0, 8)}`),
        });
      }
      for (const match of ctx.content.matchAll(AWS_SECRET_KEY)) {
        const index = match.index ?? 0;
        const line = lineForIndex(ctx.content, index);
        const matched = match[1];
        if (!matched) continue;
        findings.push({
          ruleId: 'SEC002',
          severity: 'critical',
          path: ctx.path,
          line,
          message: 'AWS secret access key detected',
          why: 'AWS secret keys grant full account access and must not be committed.',
          fix: 'Remove the key and rotate it in the AWS console immediately.',
          redactedExcerpt: redactExcerpt(matched, ctx.config.output.redact),
          fingerprint: stableFingerprint(`SEC002:${ctx.path}:${line}:${matched.slice(0, 8)}`),
        });
      }
      return findings;
    },
  },
  {
    id: 'SEC003',
    title: 'GitHub token detected',
    defaultSeverity: 'critical',
    appliesTo: () => true,
    run: (ctx) => {
      const findings: Finding[] = [];
      for (const match of ctx.content.matchAll(GITHUB_TOKEN)) {
        const index = match.index ?? 0;
        const line = lineForIndex(ctx.content, index);
        const matched = match[0];
        const redactedExcerpt = redactExcerpt(matched, ctx.config.output.redact);
        findings.push({
          ruleId: 'SEC003',
          severity: 'critical',
          path: ctx.path,
          line,
          message: 'GitHub token detected',
          why: 'Tokens provide API access and should be stored in a secret manager.',
          fix: 'Remove the token and rotate it in GitHub immediately.',
          redactedExcerpt,
          fingerprint: stableFingerprint(`SEC003:${ctx.path}:${line}:${matched.slice(0, 16)}`),
        });
      }
      return findings;
    },
  },
  {
    id: 'SEC004',
    title: 'Stripe live secret key detected',
    defaultSeverity: 'critical',
    appliesTo: () => true,
    run: (ctx) => {
      const findings: Finding[] = [];
      for (const match of ctx.content.matchAll(STRIPE_LIVE_KEY)) {
        const index = match.index ?? 0;
        const line = lineForIndex(ctx.content, index);
        const matched = match[1];
        if (!matched) continue;
        findings.push({
          ruleId: 'SEC004',
          severity: 'critical',
          path: ctx.path,
          line,
          message: 'Stripe live secret key detected',
          why: 'Live Stripe keys can charge real cards and must not be committed.',
          fix: 'Remove the key and rotate it in the Stripe dashboard immediately.',
          redactedExcerpt: redactExcerpt(matched, ctx.config.output.redact),
          fingerprint: stableFingerprint(`SEC004:${ctx.path}:${line}:${matched.slice(0, 12)}`),
        });
      }
      return findings;
    },
  },
  {
    id: 'SEC005',
    title: 'Slack token detected',
    defaultSeverity: 'critical',
    appliesTo: () => true,
    run: (ctx) => {
      const findings: Finding[] = [];
      for (const match of ctx.content.matchAll(SLACK_TOKEN)) {
        const index = match.index ?? 0;
        const line = lineForIndex(ctx.content, index);
        const matched = match[1];
        if (!matched) continue;
        findings.push({
          ruleId: 'SEC005',
          severity: 'critical',
          path: ctx.path,
          line,
          message: 'Slack token detected',
          why: 'Slack tokens grant API access and must not be committed.',
          fix: 'Remove the token and rotate it in the Slack app dashboard.',
          redactedExcerpt: redactExcerpt(matched, ctx.config.output.redact),
          fingerprint: stableFingerprint(`SEC005:${ctx.path}:${line}:${matched.slice(0, 12)}`),
        });
      }
      return findings;
    },
  },
  {
    id: 'SEC006',
    title: 'GCP service account key detected',
    defaultSeverity: 'critical',
    appliesTo: (path) => path.endsWith('.json'),
    run: (ctx) => {
      try {
        const parsed = JSON.parse(ctx.content) as Record<string, unknown>;
        if (
          parsed['type'] === 'service_account' &&
          typeof parsed['private_key'] === 'string' &&
          parsed['private_key'].length > 0
        ) {
          return [
            {
              ruleId: 'SEC006',
              severity: 'critical',
              path: ctx.path,
              message: 'GCP service account key file detected',
              why: 'Service account keys grant cloud access and must not be committed.',
              fix: 'Remove the file, revoke the key in GCP IAM, and use Workload Identity instead.',
              fingerprint: stableFingerprint(`SEC006:${ctx.path}`),
            },
          ];
        }
      } catch {
        // Not valid JSON
      }
      return [];
    },
  },
  {
    id: 'SEC007',
    title: 'Secrets file tracked',
    defaultSeverity: 'warning',
    appliesTo: (path) => isSecretsFilePath(path),
    run: (ctx) => [
      {
        ruleId: 'SEC007',
        severity: 'warning',
        path: ctx.path,
        message: `Secrets file tracked in repository: ${ctx.path.split('/').pop()}`,
        why: 'Files like .env and private key files should never be committed.',
        fix: 'Remove the file from the repository and add it to .gitignore.',
        fingerprint: stableFingerprint(`SEC007:${ctx.path}`),
      },
    ],
  },
  {
    id: 'SEC050',
    title: 'High-entropy token heuristic',
    defaultSeverity: 'warning',
    appliesTo: () => true,
    run: (ctx) => {
      const findings: Finding[] = [];
      for (const match of ctx.content.matchAll(HIGH_ENTROPY_STRING)) {
        const candidate = match[1];
        if (!candidate) continue;
        if (looksLikeUrl(candidate)) continue;
        if (shannonEntropy(candidate) >= 4.5) {
          const index = match.index ?? 0;
          const line = lineForIndex(ctx.content, index);
          findings.push({
            ruleId: 'SEC050',
            severity: 'warning',
            path: ctx.path,
            line,
            message: 'High-entropy string detected (possible secret)',
            why: 'Randomly-generated tokens often indicate embedded secrets.',
            fix: 'Move to a secret manager or environment variable.',
            redactedExcerpt: redactExcerpt(candidate, ctx.config.output.redact),
            fingerprint: stableFingerprint(`SEC050:${ctx.path}:${line}:${candidate.slice(0, 8)}`),
          });
        }
      }
      return findings;
    },
  },
];

// Export patterns for reuse in AI artifacts rule
export { PRIVATE_KEY_BLOCK, GITHUB_TOKEN, AWS_ACCESS_KEY, STRIPE_LIVE_KEY, SLACK_TOKEN };
