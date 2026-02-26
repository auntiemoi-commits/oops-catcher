import { OopsConfig, Finding, Severity } from '../types.js';
import { listFiles, readFileSafely } from './walker.js';
import { getRulesets } from '../rules/registry.js';
import { Rule } from '../rules/types.js';

const SEVERITY_ORDER: Severity[] = ['info', 'warning', 'critical'];

function applySeverityOverride(ruleId: string, severity: Severity, config: OopsConfig): Severity {
  return config.rules.severity_overrides[ruleId] ?? severity;
}

function isAllowed(pathValue: string, ruleId: string, config: OopsConfig): boolean {
  if (config.allowlist.paths.some((p) => pathValue.includes(p))) return true;
  const ruleAllows = config.allowlist.rules[ruleId] ?? [];
  return ruleAllows.some((p) => pathValue.includes(p));
}

function shouldIncludeFinding(finding: Finding, config: OopsConfig): boolean {
  if (config.rules.disable.includes(finding.ruleId)) return false;
  if (isAllowed(finding.path, finding.ruleId, config)) return false;
  return true;
}

export function applyRules(
  rules: Rule[],
  config: OopsConfig,
  cwd: string,
  pathValue: string,
  content: string
): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    if (!rule.appliesTo(pathValue)) continue;
    const ruleFindings = rule.run({ cwd, path: pathValue, content, config });
    for (const f of ruleFindings) {
      findings.push({
        ...f,
        severity: applySeverityOverride(rule.id, f.severity, config),
      });
    }
  }
  return findings;
}

export type ScanResult = {
  findings: Finding[];
};

export async function scanRepo(cwd: string, config: OopsConfig): Promise<ScanResult> {
  const files = await listFiles(cwd, config.include, config.exclude);
  const entries = files
    .map((filePath) => readFileSafely(cwd, filePath))
    .filter((entry): entry is NonNullable<typeof entry> => Boolean(entry));
  return scanEntries(cwd, config, entries);
}

export function scanEntries(
  cwd: string,
  config: OopsConfig,
  entries: { path: string; content: string }[]
): ScanResult {
  const rulesets = getRulesets(config.rulesets);
  const rules = rulesets.flatMap((set) => set.rules);
  const findings: Finding[] = [];

  for (const entry of entries) {
    const fileFindings = applyRules(rules, config, cwd, entry.path, entry.content)
      .filter((f) => shouldIncludeFinding(f, config));
    findings.push(...fileFindings);
  }

  return { findings };
}

export function hasFindingsAtOrAbove(findings: Finding[], failOn: Severity): boolean {
  const failIndex = SEVERITY_ORDER.indexOf(failOn);
  return findings.some((f) => SEVERITY_ORDER.indexOf(f.severity) >= failIndex);
}
