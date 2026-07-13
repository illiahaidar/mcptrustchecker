/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Rug-pull / Trust-On-First-Use (TOFU) integrity lockfile.
 *
 * On first scan we pin the canonical fingerprint of each server's tool surface.
 * On every rescan we diff against the pin: any silent change to a tool's
 * description or schema (the MCPoison rug-pull) shows up as drift and must be
 * re-approved. Users are encouraged to commit `mcptrustchecker.lock` to git.
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import type { IntegrityResult, ServerSurface, SurfaceChange } from './types.js';
import { canonicalTool, surfaceDigest, toolDigest } from './util/hash.js';
import { METHODOLOGY_VERSION } from './version.js';

export interface LockEntry {
  digest: string;
  tools: Record<string, string>;
  instructionsDigest: string;
  pinnedAt?: string;
}

export interface Lockfile {
  lockfileVersion: 1;
  methodologyVersion: string;
  servers: Record<string, LockEntry>;
}

function hashString(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

export function emptyLockfile(): Lockfile {
  return { lockfileVersion: 1, methodologyVersion: METHODOLOGY_VERSION, servers: {} };
}

export function readLockfile(path: string): Lockfile | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as Lockfile;
  } catch (err) {
    throw new Error(`Failed to parse lockfile ${path}: ${(err as Error).message}`);
  }
}

export function writeLockfile(path: string, lock: Lockfile): void {
  writeFileSync(path, JSON.stringify(lock, null, 2) + '\n', 'utf8');
}

/** Build a lock entry from the current surface. */
export function entryFor(surface: ServerSurface, pinnedAt?: string): LockEntry {
  const tools: Record<string, string> = {};
  for (const t of surface.tools) tools[t.name] = toolDigest(t);
  return {
    digest: surfaceDigest(surface),
    tools,
    instructionsDigest: hashString(surface.server.instructions ?? ''),
    ...(pinnedAt ? { pinnedAt } : {}),
  };
}

/** Add/update this surface's pin in the lockfile (returns a new object). */
export function pinSurface(lock: Lockfile, surface: ServerSurface, pinnedAt?: string): Lockfile {
  return {
    ...lock,
    methodologyVersion: METHODOLOGY_VERSION,
    servers: { ...lock.servers, [surface.id]: entryFor(surface, pinnedAt) },
  };
}

/** Compare the current surface against its pinned entry. */
export function checkIntegrity(surface: ServerSurface, lock: Lockfile | null): IntegrityResult {
  const currentDigest = surfaceDigest(surface);
  const entry = lock?.servers[surface.id];
  if (!entry) return { status: 'first-seen', currentDigest };
  if (entry.digest === currentDigest) return { status: 'unchanged', currentDigest, previousDigest: entry.digest };

  const changes: SurfaceChange[] = [];
  const currentTools: Record<string, string> = {};
  for (const t of surface.tools) currentTools[t.name] = toolDigest(t);

  for (const name of Object.keys(currentTools)) {
    if (!(name in entry.tools)) {
      changes.push({ kind: 'tool-added', name, detail: `Tool "${name}" is new since the pin.` });
    } else if (entry.tools[name] !== currentTools[name]) {
      const tool = surface.tools.find((t) => t.name === name);
      changes.push({
        kind: 'tool-changed',
        name,
        detail: `Tool "${name}" changed after approval (description/schema drift): ${JSON.stringify(canonicalTool(tool!)).slice(0, 200)}…`,
      });
    }
  }
  for (const name of Object.keys(entry.tools)) {
    if (!(name in currentTools)) {
      changes.push({ kind: 'tool-removed', name, detail: `Tool "${name}" was removed since the pin.` });
    }
  }
  if (entry.instructionsDigest !== hashString(surface.server.instructions ?? '')) {
    changes.push({ kind: 'instructions-changed', detail: 'Server instructions changed since the pin.' });
  }

  return { status: 'drift', currentDigest, previousDigest: entry.digest, changes };
}
