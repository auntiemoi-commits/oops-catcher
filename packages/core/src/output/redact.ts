import { RedactConfig } from '../types.js';

export function redact(value: string, config: RedactConfig): string {
  const { showPrefix, showSuffix } = config;
  if (value.length <= showPrefix + showSuffix) {
    return `${value.slice(0, showPrefix)}…${value.slice(-showSuffix)}`;
  }
  const prefix = value.slice(0, showPrefix);
  const suffix = value.slice(-showSuffix);
  return `${prefix}…${suffix}`;
}

export function redactExcerpt(value: string, config: RedactConfig, maxLen = 120): string {
  const clipped = value.length > maxLen ? value.slice(0, maxLen) : value;
  return redact(clipped, config);
}
