import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { scanRepo, formatText, formatJson } from '../src/index.js';
import type { OopsConfig } from '../src/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(__dirname, 'fixtures');

function makeConfig(): OopsConfig {
  return {
    version: 1,
    include: ['**/*'],
    exclude: [],
    rulesets: ['secrets_v1', 'containers_v1'],
    rules: { disable: [], severity_overrides: {} },
    output: { format: 'text', failOn: 'critical', redact: { showPrefix: 4, showSuffix: 4 } },
    baseline: { mode: 'off', file: '.oops-baseline.json' },
    allowlist: { paths: [], rules: {} },
  };
}

describe('scanRepo', () => {
  it('detects private key, GitHub token, and docker.sock mounts', async () => {
    const config = makeConfig();
    const result = await scanRepo(fixturesDir, config);
    const ruleIds = new Set(result.findings.map((f) => f.ruleId));
    expect(ruleIds.has('SEC001')).toBe(true);
    expect(ruleIds.has('SEC003')).toBe(true);
    expect(ruleIds.has('CON001')).toBe(true);
  });

  it('never echoes raw secrets in text or json output', async () => {
    const config = makeConfig();
    const result = await scanRepo(fixturesDir, config);
    const text = formatText(result.findings);
    const json = formatJson(result.findings);

    const rawPrivateKey = 'MIIEpAIBAAKCAQEAxZ4eQ5c1s7oVx0r0oEm3Y9Jq9sY2VfD0G0jVb6lqfV1s3HkY';
    const rawToken = 'ghp_1234567890abcdef1234567890abcdef1234';

    expect(text).not.toContain(rawPrivateKey);
    expect(text).not.toContain(rawToken);
    expect(json).not.toContain(rawPrivateKey);
    expect(json).not.toContain(rawToken);
  });
});
