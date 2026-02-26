import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import { ConfigSchema, ParsedConfig } from './schema.js';

export const DEFAULT_CONFIG_PATH = 'oops.yml';

export function loadConfig(cwd: string, explicitPath?: string): ParsedConfig {
  const configPath = explicitPath
    ? path.resolve(cwd, explicitPath)
    : path.resolve(cwd, DEFAULT_CONFIG_PATH);

  if (!fs.existsSync(configPath)) {
    return ConfigSchema.parse({});
  }

  const raw = fs.readFileSync(configPath, 'utf8');
  const data = yaml.load(raw) ?? {};
  return ConfigSchema.parse(data);
}

export function getDefaultConfigYaml(): string {
  return `version: 1
include: ["**/*"]
exclude: [".git/**","node_modules/**","dist/**","build/**",".next/**","coverage/**"]
rulesets: ["secrets_v1","containers_v1","ai_artifacts_v1"]
rules:
  disable: []
  severity_overrides: {}
output:
  format: text
  failOn: critical
  redact: { showPrefix: 4, showSuffix: 4 }
baseline:
  mode: off
  file: ".oops-baseline.json"
allowlist:
  paths: []
  rules: {}
`;
}
