/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Best-effort package-metadata resolution for the supply-chain stage. Network
 * access is opt-in (`--online`); everything degrades gracefully offline.
 */

import type { PackageMeta } from '../types.js';

async function getJson(url: string, timeoutMs = 8000): Promise<unknown> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': 'mcptrustchecker' } });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Fetch npm registry metadata for a package (latest dist-tag). */
export async function fetchNpmMeta(name: string): Promise<PackageMeta> {
  const meta: PackageMeta = { registry: 'npm', name };
  const packument = (await getJson(`https://registry.npmjs.org/${encodeURIComponent(name).replace('%40', '@')}`)) as
    | Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
    | null;
  if (packument && typeof packument === 'object') {
    const latest = packument['dist-tags']?.latest as string | undefined;
    const version = latest ?? Object.keys(packument.versions ?? {}).pop();
    meta.version = version;
    const v = version ? packument.versions?.[version] : undefined;
    if (v) {
      meta.scripts = v.scripts ?? {};
      meta.dependencies = Object.keys(v.dependencies ?? {});
      meta.license = typeof v.license === 'string' ? v.license : v.license == null ? null : String(v.license);
      const repo = v.repository;
      meta.repositoryUrl = typeof repo === 'string' ? repo : repo?.url ?? null;
    }
    meta.publishedAt = version ? packument.time?.[version] ?? null : null;
  }

  const encoded = encodeURIComponent(name).replace('%40', '@');
  const downloads = (await getJson(`https://api.npmjs.org/downloads/point/last-week/${encoded}`)) as
    | { downloads?: number }
    | null;
  meta.weeklyDownloads = downloads?.downloads ?? null;

  return meta;
}

/** Fetch PyPI metadata for a package. */
export async function fetchPypiMeta(name: string): Promise<PackageMeta> {
  const meta: PackageMeta = { registry: 'pypi', name };
  const data = (await getJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`)) as
    | Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
    | null;
  if (data?.info) {
    meta.version = data.info.version;
    meta.license = data.info.license || null;
    meta.repositoryUrl = data.info.project_urls?.Source ?? data.info.home_page ?? null;
  }
  return meta;
}
