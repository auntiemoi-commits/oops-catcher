#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import fg from 'fast-glob';
import micromatch from 'micromatch';
import {
  loadConfig,
  getDefaultConfigYaml,
  scanRepo,
  scanEntries,
  hasFindingsAtOrAbove,
  formatText,
  formatJson,
} from '@oops-catcher/core';

const argv = process.argv.slice(2);
const command = argv[0];

function printUsage(): void {
  console.log('Usage: oops <command>');
  console.log('Commands:');
  console.log('  scan            Scan repository');
  console.log('  scan --staged   Scan staged git changes only');
  console.log('  init            Write starter oops.yml');
  console.log('  install-hook    Install pre-commit hook');
}

function matchesConfig(pathValue: string, include: string[], exclude: string[]): boolean {
  const included = include.some((pattern) => micromatch.isMatch(pathValue, pattern));
  const excluded = exclude.some((pattern) => micromatch.isMatch(pathValue, pattern));
  return included && !excluded;
}

function getStagedFiles(cwd: string): string[] {
  const output = execFileSync('git', ['diff', '--cached', '--name-only', '-z'], { cwd });
  return output
    .toString('utf8')
    .split('\u0000')
    .filter((p) => p.length > 0);
}

function getStagedContent(cwd: string, filePath: string): string | null {
  try {
    return execFileSync('git', ['show', `:${filePath}`], { cwd, encoding: 'utf8' });
  } catch {
    return null;
  }
}

async function runScan(isStaged = false): Promise<number> {
  const cwd = process.cwd();
  const config = loadConfig(cwd);
  const result = isStaged
    ? scanEntries(
        cwd,
        config,
        getStagedFiles(cwd)
          .filter((filePath) => matchesConfig(filePath, config.include, config.exclude))
          .map((filePath) => ({ path: filePath, content: getStagedContent(cwd, filePath) }))
          .filter((entry): entry is { path: string; content: string } => typeof entry.content === 'string')
      )
    : await scanRepo(cwd, config);
  const output = config.output.format === 'json'
    ? formatJson(result.findings)
    : formatText(result.findings);
  process.stdout.write(output);
  return hasFindingsAtOrAbove(result.findings, config.output.failOn) ? 1 : 0;
}

function runInit(): number {
  const cwd = process.cwd();
  const target = path.resolve(cwd, 'oops.yml');
  if (fs.existsSync(target)) {
    console.error('oops.yml already exists.');
    return 2;
  }
  fs.writeFileSync(target, getDefaultConfigYaml(), 'utf8');
  console.log('Wrote oops.yml');
  return 0;
}

function runInstallHook(): number {
  const cwd = process.cwd();
  const gitDir = path.resolve(cwd, '.git');
  const hooksDir = path.resolve(gitDir, 'hooks');
  const hookPath = path.resolve(hooksDir, 'pre-commit');

  if (!fs.existsSync(gitDir)) {
    console.error('No .git directory found. Run this inside a git repository.');
    return 2;
  }

  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  const script = `#!/bin/sh\nexec npx oops scan --staged\n`;
  fs.writeFileSync(hookPath, script, { encoding: 'utf8', mode: 0o755 });
  console.log('Installed pre-commit hook.');
  return 0;
}

(async () => {
  if (!command) {
    printUsage();
    process.exit(2);
  }

  if (command === 'scan') {
    const isStaged = argv.includes('--staged');
    const code = await runScan(isStaged);
    process.exit(code);
  }

  if (command === 'init') {
    const code = runInit();
    process.exit(code);
  }

  if (command === 'install-hook') {
    const code = runInstallHook();
    process.exit(code);
  }

  printUsage();
  process.exit(2);
})();
