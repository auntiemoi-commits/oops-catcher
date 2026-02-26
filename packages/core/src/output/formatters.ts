import { Finding, Severity } from '../types.js';

const ORDER: Severity[] = ['critical', 'warning', 'info'];

function groupBySeverity(findings: Finding[]): Record<Severity, Finding[]> {
  return {
    critical: findings.filter((f) => f.severity === 'critical'),
    warning: findings.filter((f) => f.severity === 'warning'),
    info: findings.filter((f) => f.severity === 'info'),
  };
}

export function formatText(findings: Finding[]): string {
  if (findings.length === 0) return 'No findings.\n';
  const grouped = groupBySeverity(findings);
  const lines: string[] = [];

  for (const severity of ORDER) {
    const bucket = grouped[severity];
    if (bucket.length === 0) continue;
    lines.push(`${severity.toUpperCase()} (${bucket.length})`);
    for (const f of bucket) {
      const location = f.line ? `${f.path}:${f.line}` : f.path;
      lines.push(`- ${f.ruleId} ${location}: ${f.message}`);
      lines.push(`  Why: ${f.why}`);
      lines.push(`  Fix: ${f.fix}`);
      if (f.redactedExcerpt) {
        lines.push(`  Excerpt: ${f.redactedExcerpt}`);
      }
    }
    lines.push('');
  }

  return lines.join('\n');
}

export function formatJson(findings: Finding[]): string {
  return JSON.stringify({ findings }, null, 2) + '\n';
}
