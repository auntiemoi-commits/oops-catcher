import { z } from 'zod';

const SeveritySchema = z.enum(['critical', 'warning', 'info']);

export const ConfigSchema = z.object({
  version: z.literal(1).default(1),
  include: z.array(z.string()).default(['**/*']),
  exclude: z
    .array(z.string())
    .default([
      '.git/**',
      'node_modules/**',
      'dist/**',
      'build/**',
      '.next/**',
      'coverage/**',
    ]),
  rulesets: z
    .array(z.string())
    .default(['secrets_v1', 'containers_v1', 'ai_artifacts_v1']),
  rules: z
    .object({
      disable: z.array(z.string()).default([]),
      severity_overrides: z.record(SeveritySchema).default({}),
    })
    .default({ disable: [], severity_overrides: {} }),
  output: z
    .object({
      format: z.enum(['text', 'json']).default('text'),
      failOn: SeveritySchema.default('critical'),
      redact: z
        .object({
          showPrefix: z.number().int().min(0).default(4),
          showSuffix: z.number().int().min(0).default(4),
        })
        .default({ showPrefix: 4, showSuffix: 4 }),
    })
    .default({
      format: 'text',
      failOn: 'critical',
      redact: { showPrefix: 4, showSuffix: 4 },
    }),
  baseline: z
    .object({
      mode: z.enum(['off', 'use', 'update']).default('off'),
      file: z.string().default('.oops-baseline.json'),
    })
    .default({ mode: 'off', file: '.oops-baseline.json' }),
  allowlist: z
    .object({
      paths: z.array(z.string()).default([]),
      rules: z.record(z.array(z.string())).default({}),
    })
    .default({ paths: [], rules: {} }),
});

export type ParsedConfig = z.infer<typeof ConfigSchema>;
