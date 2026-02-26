export type Severity = 'critical' | 'warning' | 'info';

export type Finding = {
  ruleId: string;
  severity: Severity;
  path: string;
  line?: number;
  message: string;
  why: string;
  fix: string;
  redactedExcerpt?: string;
  fingerprint: string;
};

export type RedactConfig = {
  showPrefix: number;
  showSuffix: number;
};

export type OutputFormat = 'text' | 'json';

export type OopsConfig = {
  version: 1;
  include: string[];
  exclude: string[];
  rulesets: string[];
  rules: {
    disable: string[];
    severity_overrides: Record<string, Severity>;
  };
  output: {
    format: OutputFormat;
    failOn: Severity;
    redact: RedactConfig;
  };
  baseline: {
    mode: 'off' | 'use' | 'update';
    file: string;
  };
  allowlist: {
    paths: string[];
    rules: Record<string, string[]>;
  };
};
