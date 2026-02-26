import fs from 'node:fs';
import path from 'node:path';
import fg from 'fast-glob';

const MAX_FILE_SIZE_BYTES = 1024 * 1024; // 1MB
const BINARY_SAMPLE_BYTES = 8192;

export type FileEntry = {
  path: string;
  content: string;
};

export async function listFiles(cwd: string, include: string[], exclude: string[]): Promise<string[]> {
  return fg(include, {
    cwd,
    ignore: exclude,
    dot: true,
    onlyFiles: true,
    followSymbolicLinks: false,
  });
}

export function isBinary(buffer: Buffer): boolean {
  for (let i = 0; i < buffer.length; i += 1) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

export function readFileSafely(cwd: string, relativePath: string): FileEntry | null {
  const fullPath = path.resolve(cwd, relativePath);
  const stat = fs.statSync(fullPath, { throwIfNoEntry: false });
  if (!stat || !stat.isFile()) return null;
  if (stat.size > MAX_FILE_SIZE_BYTES) return null;

  const fd = fs.openSync(fullPath, 'r');
  try {
    const sample = Buffer.alloc(Math.min(BINARY_SAMPLE_BYTES, stat.size));
    fs.readSync(fd, sample, 0, sample.length, 0);
    if (isBinary(sample)) return null;
  } finally {
    fs.closeSync(fd);
  }

  const content = fs.readFileSync(fullPath, 'utf8');
  return { path: relativePath, content };
}
