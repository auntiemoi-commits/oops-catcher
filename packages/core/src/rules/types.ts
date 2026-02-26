import { Finding, OopsConfig } from '../types.js';

export type RuleContext = {
  cwd: string;
  path: string;
  content: string;
  config: OopsConfig;
};

export type Rule = {
  id: string;
  title: string;
  defaultSeverity: 'critical' | 'warning' | 'info';
  appliesTo: (path: string) => boolean;
  run: (ctx: RuleContext) => Finding[];
};

export type Ruleset = {
  id: string;
  rules: Rule[];
};
