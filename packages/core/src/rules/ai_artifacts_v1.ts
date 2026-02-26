import { Finding } from '../types.js';
import { Rule } from './types.js';
import { lineForIndex } from '../engine/line.js';
import { redactExcerpt } from '../output/redact.js';
import { stableFingerprint } from '../engine/fingerprint.js';
import {
  PRIVATE_KEY_BLOCK,
  GITHUB_TOKEN,
  AWS_ACCESS_KEY,
  STRIPE_LIVE_KEY,
  SLACK_TOKEN,
} from './secrets_v1.js';

const AI_ARTIFACT_PATTERNS = [
  /\bchat\b/i,
  /\bprompt\b/i,
  /\btranscript\b/i,
  /\.prompt_history$/,
  /\bgpt\b/i,
  /\bclaude\b/i,
  /\bllm[-_]?output\b/i,
];

function isAiArtifact(filePath: string): boolean {
  const base = filePath.split('/').pop() ?? filePath;
  return AI_ARTIFACT_PATTERNS.some((p) => p.test(base));
}

type SecretPattern = {
  regex: RegExp;
  label: string;
};

const SECRET_PATTERNS: SecretPattern[] = [
  { regex: PRIVATE_KEY_BLOCK, label: 'Private key block' },
  { regex: GITHUB_TOKEN, label: 'GitHub token' },
  { regex: AWS_ACCESS_KEY, label: 'AWS access key' },
  { regex: STRIPE_LIVE_KEY, label: 'Stripe live key' },
  { regex: SLACK_TOKEN, label: 'Slack token' },
];

export const aiArtifactsV1Rules: Rule[] = [
  // AI001 — AI transcript/prompt artifacts tracked
  {
    id: 'AI001',
    title: 'AI artifact file tracked',
    defaultSeverity: 'info',
    appliesTo: (path) => isAiArtifact(path),
    run: (ctx) => [
      {
        ruleId: 'AI001',
        severity: 'info',
        path: ctx.path,
        message: `AI artifact file tracked in repository: ${ctx.path.split('/').pop()}`,
        why: 'AI transcripts and prompt logs may contain sensitive context or secrets.',
        fix: 'Remove the file or add it to .gitignore.',
        fingerprint: stableFingerprint(`AI001:${ctx.path}`),
      },
    ],
  },

  // AI002 — Secrets in AI artifacts
  {
    id: 'AI002',
    title: 'Secret detected in AI artifact',
    defaultSeverity: 'critical',
    appliesTo: (path) => isAiArtifact(path),
    run: (ctx) => {
      const findings: Finding[] = [];

      for (const { regex, label } of SECRET_PATTERNS) {
        // Reset lastIndex since these are exported compiled regexes
        const re = new RegExp(regex.source, regex.flags);
        for (const match of ctx.content.matchAll(re)) {
          const index = match.index ?? 0;
          const line = lineForIndex(ctx.content, index);
          const matched = match[0];
          findings.push({
            ruleId: 'AI002',
            severity: 'critical',
            path: ctx.path,
            line,
            message: `${label} found in AI artifact`,
            why: 'Secrets in AI artifacts should be removed and rotated immediately.',
            fix: 'Remove the file, rotate the secret, and add the file to .gitignore.',
            redactedExcerpt: redactExcerpt(matched, ctx.config.output.redact),
            fingerprint: stableFingerprint(`AI002:${ctx.path}:${line}:${matched.slice(0, 8)}`),
          });
        }
      }

      return findings;
    },
  },
];
