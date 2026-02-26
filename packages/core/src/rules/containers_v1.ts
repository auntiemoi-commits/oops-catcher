import yaml from 'js-yaml';
import { Finding } from '../types.js';
import { Rule } from './types.js';
import { lineForIndex } from '../engine/line.js';
import { redactExcerpt } from '../output/redact.js';
import { stableFingerprint } from '../engine/fingerprint.js';

// ── helpers ──────────────────────────────────────────────────────────────────

const DOCKER_SOCK = '/var/run/docker.sock';

const CRED_DIRS = ['/.ssh', '/.aws', '/.config/gcloud'];

const REMOTE_SCRIPT = /\b(curl|wget)\b[^|#\n]*\|\s*(ba)?sh/g;

function isComposeFile(path: string): boolean {
  return (
    path.endsWith('docker-compose.yml') ||
    path.endsWith('docker-compose.yaml') ||
    path.endsWith('compose.yml') ||
    path.endsWith('compose.yaml')
  );
}

function isDevcontainer(path: string): boolean {
  return path.endsWith('devcontainer.json');
}

function isDockerfile(path: string): boolean {
  const base = path.split('/').pop() ?? path;
  return base === 'Dockerfile' || base.startsWith('Dockerfile.');
}

function lineForText(content: string, text: string): number | undefined {
  const index = content.indexOf(text);
  if (index === -1) return undefined;
  return lineForIndex(content, index);
}

function hasDockerSockMount(value: unknown): boolean {
  if (typeof value === 'string') return value.includes(DOCKER_SOCK);
  if (Array.isArray(value)) return value.some(hasDockerSockMount);
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return Object.values(obj).some(hasDockerSockMount);
  }
  return false;
}

function hasCredDirMount(value: unknown): string | null {
  if (typeof value === 'string') {
    const hit = CRED_DIRS.find((d) => value.includes(d));
    return hit ?? null;
  }
  if (Array.isArray(value)) {
    for (const v of value) {
      const hit = hasCredDirMount(v);
      if (hit) return hit;
    }
  }
  if (value && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) {
      const hit = hasCredDirMount(v);
      if (hit) return hit;
    }
  }
  return null;
}

function deepSearch(value: unknown, predicate: (s: string) => boolean): boolean {
  if (typeof value === 'string') return predicate(value);
  if (Array.isArray(value)) return value.some((v) => deepSearch(v, predicate));
  if (value && typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).some((v) => deepSearch(v, predicate));
  }
  return false;
}

function parseYaml(content: string): Record<string, unknown> | null {
  try {
    return yaml.load(content) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function parseJson(content: string): Record<string, unknown> | null {
  try {
    return JSON.parse(content) as Record<string, unknown>;
  } catch {
    return null;
  }
}

// ── rules ─────────────────────────────────────────────────────────────────────

export const containersV1Rules: Rule[] = [
  // CON001 — Docker socket mounted
  {
    id: 'CON001',
    title: 'Docker socket mounted',
    defaultSeverity: 'critical',
    appliesTo: (path) => isDevcontainer(path) || isComposeFile(path),
    run: (ctx) => {
      const findings: Finding[] = [];
      const line = lineForText(ctx.content, DOCKER_SOCK);
      const redactedExcerpt = line !== undefined
        ? redactExcerpt(DOCKER_SOCK, ctx.config.output.redact)
        : undefined;

      if (isDevcontainer(ctx.path)) {
        const parsed = parseJson(ctx.content);
        if (!parsed) return [];
        if (hasDockerSockMount(parsed?.['mounts'])) {
          findings.push({
            ruleId: 'CON001',
            severity: 'critical',
            path: ctx.path,
            line,
            message: 'Docker socket mounted in devcontainer',
            why: 'Mounting the Docker socket grants host-level control inside the container.',
            fix: 'Remove the socket mount or switch to a safer build workflow.',
            redactedExcerpt,
            fingerprint: stableFingerprint(`CON001:${ctx.path}:${line ?? 0}:devcontainer`),
          });
        }
      } else {
        const parsed = parseYaml(ctx.content);
        if (!parsed) return [];
        const services = (parsed['services'] ?? {}) as Record<string, unknown>;
        const hasSock = Object.values(services).some((service) => {
          if (!service || typeof service !== 'object') return false;
          return hasDockerSockMount((service as Record<string, unknown>)['volumes']);
        });
        if (hasSock) {
          findings.push({
            ruleId: 'CON001',
            severity: 'critical',
            path: ctx.path,
            line,
            message: 'Docker socket mounted in compose',
            why: 'Mounting the Docker socket grants host-level control inside the container.',
            fix: 'Remove the socket mount or use a safer build service.',
            redactedExcerpt,
            fingerprint: stableFingerprint(`CON001:${ctx.path}:${line ?? 0}:compose`),
          });
        }
      }

      return findings;
    },
  },

  // CON002 — Privileged container
  {
    id: 'CON002',
    title: 'Privileged container',
    defaultSeverity: 'critical',
    appliesTo: (path) => isComposeFile(path) || isDevcontainer(path) || isDockerfile(path),
    run: (ctx) => {
      const findings: Finding[] = [];

      if (isDockerfile(ctx.path)) {
        if (/\bRUN\b[^\n]*--privileged/.test(ctx.content)) {
          const line = lineForText(ctx.content, '--privileged');
          findings.push({
            ruleId: 'CON002',
            severity: 'critical',
            path: ctx.path,
            line,
            message: 'Privileged flag used in Dockerfile RUN',
            why: 'Privileged containers bypass isolation and can escape to the host.',
            fix: 'Remove the --privileged flag.',
            fingerprint: stableFingerprint(`CON002:${ctx.path}:${line ?? 0}`),
          });
        }
        return findings;
      }

      if (isDevcontainer(ctx.path)) {
        const parsed = parseJson(ctx.content);
        if (!parsed) return [];
        if (deepSearch(parsed, (s) => s.includes('--privileged'))) {
          const line = lineForText(ctx.content, '--privileged');
          findings.push({
            ruleId: 'CON002',
            severity: 'critical',
            path: ctx.path,
            line,
            message: 'Privileged flag in devcontainer',
            why: 'Privileged containers bypass isolation.',
            fix: 'Remove the --privileged flag.',
            fingerprint: stableFingerprint(`CON002:${ctx.path}:${line ?? 0}:devcontainer`),
          });
        }
        return findings;
      }

      // Compose
      const parsed = parseYaml(ctx.content);
      if (!parsed) return [];
      const services = (parsed['services'] ?? {}) as Record<string, unknown>;
      for (const [name, service] of Object.entries(services)) {
        if (!service || typeof service !== 'object') continue;
        const svc = service as Record<string, unknown>;
        if (svc['privileged'] === true) {
          const line = lineForText(ctx.content, 'privileged: true');
          findings.push({
            ruleId: 'CON002',
            severity: 'critical',
            path: ctx.path,
            line,
            message: `Privileged container in service '${name}'`,
            why: 'Privileged containers bypass isolation and can escape to the host.',
            fix: 'Remove privileged: true from the service definition.',
            fingerprint: stableFingerprint(`CON002:${ctx.path}:${name}`),
          });
        }
      }
      return findings;
    },
  },

  // CON003 — Host networking
  {
    id: 'CON003',
    title: 'Host networking enabled',
    defaultSeverity: 'critical',
    appliesTo: (path) => isComposeFile(path) || isDevcontainer(path),
    run: (ctx) => {
      const findings: Finding[] = [];

      if (isDevcontainer(ctx.path)) {
        const parsed = parseJson(ctx.content);
        if (!parsed) return [];
        if (deepSearch(parsed, (s) => s === 'host')) {
          const line = lineForText(ctx.content, 'host');
          findings.push({
            ruleId: 'CON003',
            severity: 'critical',
            path: ctx.path,
            line,
            message: 'Host networking in devcontainer',
            why: 'Host networking reduces container isolation.',
            fix: 'Use a bridge network instead.',
            fingerprint: stableFingerprint(`CON003:${ctx.path}:devcontainer`),
          });
        }
        return findings;
      }

      const parsed = parseYaml(ctx.content);
      if (!parsed) return [];
      const services = (parsed['services'] ?? {}) as Record<string, unknown>;
      for (const [name, service] of Object.entries(services)) {
        if (!service || typeof service !== 'object') continue;
        const svc = service as Record<string, unknown>;
        if (svc['network_mode'] === 'host') {
          const line = lineForText(ctx.content, 'network_mode: host');
          findings.push({
            ruleId: 'CON003',
            severity: 'critical',
            path: ctx.path,
            line,
            message: `Host networking in service '${name}'`,
            why: 'Host networking reduces container isolation.',
            fix: "Remove network_mode: host and use a bridge network.",
            fingerprint: stableFingerprint(`CON003:${ctx.path}:${name}`),
          });
        }
      }
      return findings;
    },
  },

  // CON004 — Container runs as root
  {
    id: 'CON004',
    title: 'Container runs as root',
    defaultSeverity: 'warning',
    appliesTo: (path) => isDevcontainer(path) || isDockerfile(path),
    run: (ctx) => {
      if (isDockerfile(ctx.path)) {
        // Heuristic: no USER instruction = runs as root
        if (!/^\s*USER\s+/m.test(ctx.content)) {
          return [
            {
              ruleId: 'CON004',
              severity: 'warning',
              path: ctx.path,
              message: 'No USER instruction in Dockerfile (runs as root)',
              why: 'Containers that run as root increase blast radius if compromised.',
              fix: 'Add a USER instruction to run as a non-root user.',
              fingerprint: stableFingerprint(`CON004:${ctx.path}:no-user`),
            },
          ];
        }
        return [];
      }

      // devcontainer: remoteUser = root
      const parsed = parseJson(ctx.content);
      if (!parsed) return [];
      if (parsed['remoteUser'] === 'root') {
        return [
          {
            ruleId: 'CON004',
            severity: 'warning',
            path: ctx.path,
            message: 'remoteUser set to root in devcontainer',
            why: 'Running as root in a container increases blast radius.',
            fix: 'Set remoteUser to a non-root user.',
            fingerprint: stableFingerprint(`CON004:${ctx.path}:remoteUser`),
          },
        ];
      }
      return [];
    },
  },

  // CON101 — Credential directories mounted
  {
    id: 'CON101',
    title: 'Credential directory mounted',
    defaultSeverity: 'warning',
    appliesTo: (path) => isComposeFile(path) || isDevcontainer(path),
    run: (ctx) => {
      const findings: Finding[] = [];

      if (isDevcontainer(ctx.path)) {
        const parsed = parseJson(ctx.content);
        if (!parsed) return [];
        const hit = hasCredDirMount(parsed);
        if (hit) {
          const line = lineForText(ctx.content, hit);
          findings.push({
            ruleId: 'CON101',
            severity: 'warning',
            path: ctx.path,
            line,
            message: `Credential directory mounted in devcontainer (${hit})`,
            why: 'Mounting credential directories exposes host secrets inside containers.',
            fix: 'Remove the mount or use short-lived credentials instead.',
            fingerprint: stableFingerprint(`CON101:${ctx.path}:devcontainer:${hit}`),
          });
        }
        return findings;
      }

      const parsed = parseYaml(ctx.content);
      if (!parsed) return [];
      const services = (parsed['services'] ?? {}) as Record<string, unknown>;
      for (const [name, service] of Object.entries(services)) {
        if (!service || typeof service !== 'object') continue;
        const svc = service as Record<string, unknown>;
        const hit = hasCredDirMount(svc['volumes']);
        if (hit) {
          const line = lineForText(ctx.content, hit);
          findings.push({
            ruleId: 'CON101',
            severity: 'warning',
            path: ctx.path,
            line,
            message: `Credential directory mounted in service '${name}' (${hit})`,
            why: 'Mounting credential directories exposes host secrets inside containers.',
            fix: 'Remove the mount or use short-lived credentials instead.',
            fingerprint: stableFingerprint(`CON101:${ctx.path}:${name}:${hit}`),
          });
        }
      }
      return findings;
    },
  },

  // CON102 — Remote script execution
  {
    id: 'CON102',
    title: 'Remote script execution in dev setup',
    defaultSeverity: 'warning',
    appliesTo: (path) => isDockerfile(path) || isDevcontainer(path),
    run: (ctx) => {
      const findings: Finding[] = [];

      for (const match of ctx.content.matchAll(REMOTE_SCRIPT)) {
        const index = match.index ?? 0;
        const line = lineForIndex(ctx.content, index);
        const matched = match[0];
        findings.push({
          ruleId: 'CON102',
          severity: 'warning',
          path: ctx.path,
          line,
          message: `Remote script piped to shell: ${matched.slice(0, 60)}`,
          why: 'Piping remote scripts to a shell is risky; the script could change without notice.',
          fix: 'Pin the script URL to a specific commit hash and validate its checksum.',
          redactedExcerpt: matched.slice(0, 80),
          fingerprint: stableFingerprint(`CON102:${ctx.path}:${line}`),
        });
      }
      return findings;
    },
  },
];
