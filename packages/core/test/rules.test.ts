import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { scanRepo, scanEntries, formatText } from '../src/index.js';
import type { OopsConfig } from '../src/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(__dirname, 'fixtures');

function makeConfig(rulesets: string[] = ['secrets_v1', 'containers_v1', 'ai_artifacts_v1']): OopsConfig {
  return {
    version: 1,
    include: ['**/*'],
    exclude: [],
    rulesets,
    rules: { disable: [], severity_overrides: {} },
    output: { format: 'text', failOn: 'critical', redact: { showPrefix: 4, showSuffix: 4 } },
    baseline: { mode: 'off', file: '.oops-baseline.json' },
    allowlist: { paths: [], rules: {} },
  };
}

function ruleIds(findings: Awaited<ReturnType<typeof scanRepo>>['findings']): string[] {
  return findings.map((f) => f.ruleId).sort();
}

// ── Secrets ───────────────────────────────────────────────────────────────────

describe('SEC002 — AWS credentials', () => {
  it('detects AWS access key ID', async () => {
    const config = makeConfig(['secrets_v1']);
    const result = await scanRepo(fixturesDir, config);
    expect(ruleIds(result.findings)).toContain('SEC002');
  });
});

describe('SEC004 — Stripe live key', () => {
  // Inline content: avoid committing a real-looking key to git history.
  // The string is split across parts so secret scanners don't flag the source.
  it('detects sk_live_ keys', () => {
    const prefix = 'sk' + '_live_';
    const suffix = '51ABCDEFghijklmnopqrstuvwxyz1234567890AB';
    const content = `STRIPE_SECRET_KEY=${prefix}${suffix}\n`;
    const config = makeConfig(['secrets_v1']);
    const result = scanEntries('/', config, [{ path: 'config.env', content }]);
    expect(result.findings.filter((f) => f.ruleId === 'SEC004').length).toBeGreaterThan(0);
  });
});

describe('SEC005 — Slack token', () => {
  it('detects xoxb- tokens', () => {
    const prefix = 'xoxb' + '-';
    const content = `SLACK_TOKEN=${prefix}1234567890-1234567890123-abcdefghijklmnopqrstuvwx\n`;
    const config = makeConfig(['secrets_v1']);
    const result = scanEntries('/', config, [{ path: 'config.env', content }]);
    expect(result.findings.filter((f) => f.ruleId === 'SEC005').length).toBeGreaterThan(0);
  });
});

describe('SEC006 — GCP service account', () => {
  it('detects service_account JSON files', async () => {
    const config = makeConfig(['secrets_v1']);
    const result = await scanRepo(fixturesDir, config);
    const gcpFindings = result.findings.filter(
      (f) => f.ruleId === 'SEC006' && f.path.includes('gcp-service-account'),
    );
    expect(gcpFindings.length).toBe(1);
  });
});

describe('SEC007 — Secrets files tracked', () => {
  it('flags .env files', async () => {
    const config = makeConfig(['secrets_v1']);
    const result = await scanRepo(fixturesDir, config);
    const envFindings = result.findings.filter(
      (f) => f.ruleId === 'SEC007' && f.path.endsWith('.env'),
    );
    expect(envFindings.length).toBe(1);
    expect(envFindings[0]!.severity).toBe('warning');
  });
});

describe('SEC050 — High-entropy heuristic', () => {
  it('flags high-entropy quoted strings', async () => {
    const config = makeConfig(['secrets_v1']);
    const result = await scanRepo(fixturesDir, config);
    const entropyFindings = result.findings.filter(
      (f) => f.ruleId === 'SEC050' && f.path.includes('high-entropy'),
    );
    expect(entropyFindings.length).toBeGreaterThan(0);
  });
});

// ── Containers ────────────────────────────────────────────────────────────────

describe('CON002 — Privileged container', () => {
  it('detects privileged: true in compose', async () => {
    const config = makeConfig(['containers_v1']);
    const result = await scanRepo(fixturesDir, config);
    const privFindings = result.findings.filter(
      (f) => f.ruleId === 'CON002' && f.path.includes('privileged-compose'),
    );
    expect(privFindings.length).toBe(1);
  });
});

describe('CON003 — Host networking', () => {
  it('detects network_mode: host in compose', async () => {
    const config = makeConfig(['containers_v1']);
    const result = await scanRepo(fixturesDir, config);
    const netFindings = result.findings.filter(
      (f) => f.ruleId === 'CON003' && f.path.includes('privileged-compose'),
    );
    expect(netFindings.length).toBe(1);
  });
});

describe('CON004 — Container runs as root', () => {
  it('flags Dockerfile with no USER instruction', async () => {
    const config = makeConfig(['containers_v1']);
    const result = await scanRepo(fixturesDir, config);
    const rootFindings = result.findings.filter(
      (f) => f.ruleId === 'CON004' && f.path.includes('Dockerfile'),
    );
    expect(rootFindings.length).toBe(1);
    expect(rootFindings[0]!.severity).toBe('warning');
  });
});

describe('CON101 — Credential directory mounted', () => {
  it('detects ~/.aws mount in compose', async () => {
    const config = makeConfig(['containers_v1']);
    const result = await scanRepo(fixturesDir, config);
    const credFindings = result.findings.filter(
      (f) => f.ruleId === 'CON101' && f.path.includes('privileged-compose'),
    );
    expect(credFindings.length).toBe(1);
  });
});

// ── AI artifacts ──────────────────────────────────────────────────────────────

describe('AI001 — AI artifact file tracked', () => {
  it('flags chat-transcript.txt', async () => {
    const config = makeConfig(['ai_artifacts_v1']);
    const result = await scanRepo(fixturesDir, config);
    const aiFindings = result.findings.filter(
      (f) => f.ruleId === 'AI001' && f.path.includes('chat-transcript'),
    );
    expect(aiFindings.length).toBe(1);
    expect(aiFindings[0]!.severity).toBe('info');
  });
});

describe('AI002 — Secrets in AI artifact', () => {
  it('detects GitHub token inside chat-transcript.txt', async () => {
    const config = makeConfig(['ai_artifacts_v1']);
    const result = await scanRepo(fixturesDir, config);
    const ai2Findings = result.findings.filter(
      (f) => f.ruleId === 'AI002' && f.path.includes('chat-transcript'),
    );
    expect(ai2Findings.length).toBeGreaterThan(0);
    expect(ai2Findings[0]!.severity).toBe('critical');
  });
});

// ── Output safety ─────────────────────────────────────────────────────────────

describe('output safety — no raw secrets in text output', () => {
  it('redacts AWS and GitHub secrets found in fixtures', async () => {
    const config = makeConfig();
    const result = await scanRepo(fixturesDir, config);
    const text = formatText(result.findings);
    expect(text).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(text).not.toContain('wJalrXUtnFEMI');
    expect(text).not.toContain('ghp_1234567890abcdef1234567890abcdef1234');
  });

  it('redacts Stripe and Slack secrets from inline scan', () => {
    const stripePrefix = 'sk' + '_live_';
    const stripeKey = stripePrefix + '51ABCDEFghijklmnopqrstuvwxyz1234567890AB';
    const slackPrefix = 'xoxb' + '-';
    const slackToken = slackPrefix + '1234567890-1234567890123-abcdefghijklmnopqrstuvwx';
    const content = `KEY=${stripeKey}\nTOKEN=${slackToken}\n`;
    const config = makeConfig(['secrets_v1']);
    const result = scanEntries('/', config, [{ path: 'secrets.env', content }]);
    const text = formatText(result.findings);
    expect(text).not.toContain(stripeKey);
    expect(text).not.toContain(slackToken);
    expect(result.findings.some((f) => f.ruleId === 'SEC004')).toBe(true);
    expect(result.findings.some((f) => f.ruleId === 'SEC005')).toBe(true);
  });
});
