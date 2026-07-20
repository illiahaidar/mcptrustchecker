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

/** Is `v` an exact version (not a range/tag) we can resolve to one artifact? */
function isExactVersion(v?: string): v is string {
  return typeof v === 'string' && /^\d+\.\d+\.\d+/.test(v);
}

/**
 * Fetch npm registry metadata for a package. Resolves `requested` when it names
 * an exact published version (so a pinned `pkg@1.0.0` is analyzed, not `latest`);
 * otherwise falls back to the `latest` dist-tag.
 */
export async function fetchNpmMeta(name: string, requested?: string): Promise<PackageMeta> {
  const meta: PackageMeta = { registry: 'npm', name };
  const packument = (await getJson(`https://registry.npmjs.org/${encodeURIComponent(name).replace('%40', '@')}`)) as
    | Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
    | null;
  if (packument && typeof packument === 'object') {
    // `dist-tags.latest` is attacker-controlled: accept it ONLY as a string, so a
    // non-primitive (array/object) can't become `meta.version`. A non-string
    // version survives to the lockfile as `["1.0.0"]`, and after the JSON
    // round-trip the `meta.version === entry.packageVersion` check can never be
    // true — silently suppressing the MTC-TOFU-002 byte-level rug-pull finding.
    const latest = typeof packument['dist-tags']?.latest === 'string' ? (packument['dist-tags'].latest as string) : undefined;
    // `versions` is attacker-controlled; guard the `in` check so a non-object
    // (string/number) can't throw a raw TypeError. On the client-config path an
    // unguarded throw would unwind resolveTargets and make the CLI skip the whole
    // config — hiding every sibling server. Fail closed instead.
    const versions =
      packument.versions && typeof packument.versions === 'object' && !Array.isArray(packument.versions)
        ? (packument.versions as Record<string, any>) // eslint-disable-line @typescript-eslint/no-explicit-any
        : {};
    // A pinned exact version that the registry does NOT list must NEVER silently
    // fall back to `latest` — an attacker who controls the registry response
    // could drop the pinned version and serve a malicious `latest`, defeating the
    // byte pin (the requested version's artifact simply isn't resolved, and the
    // substitution is flagged so it can't pass as a clean scan of the pin).
    const wantExact = isExactVersion(requested);
    const requestedMissing = wantExact && !Object.prototype.hasOwnProperty.call(versions, requested);
    const version = wantExact ? requested : (latest ?? Object.keys(versions).pop());
    meta.version = version;
    if (requestedMissing) {
      meta.requestedVersionMissing = true;
      // Leave scripts/deps/artifact unresolved: there is no such published
      // version to read. tarballUrl stays undefined → no source fetch / byte pin.
      return meta;
    }
    const v = version ? packument.versions?.[version] : undefined;
    if (v) {
      meta.scripts = v.scripts ?? {};
      meta.dependencies = Object.keys(v.dependencies ?? {});
      meta.license = typeof v.license === 'string' ? v.license : v.license == null ? null : String(v.license);
      const repo = v.repository;
      meta.repositoryUrl = typeof repo === 'string' ? repo : repo?.url ?? null;
      // The published artifact: URL + registry-declared hash (SRI, or legacy sha1 hex).
      meta.tarballUrl = typeof v.dist?.tarball === 'string' ? v.dist.tarball : null;
      meta.tarballIntegrity =
        typeof v.dist?.integrity === 'string'
          ? v.dist.integrity
          : typeof v.dist?.shasum === 'string'
            ? `sha1:${v.dist.shasum}`
            : null;
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

/**
 * Fetch PyPI metadata for a package. When `requested` is an exact version, the
 * versioned JSON endpoint (`/pypi/<name>/<version>/json`) is used so a pinned
 * spec is analyzed rather than the newest release.
 */
export async function fetchPypiMeta(name: string, requested?: string): Promise<PackageMeta> {
  const meta: PackageMeta = { registry: 'pypi', name };
  const url = isExactVersion(requested)
    ? `https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(requested)}/json`
    : `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;
  const data = (await getJson(url)) as
    | Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
    | null;
  if (data?.info) {
    // For an exact pin the version-specific endpoint is authoritative for the
    // version, so force the label to the REQUESTED version — never let an
    // attacker-controlled `info.version` relabel the pin to a different release
    // (the same silent-substitution hole the npm path refuses).
    meta.version = isExactVersion(requested)
      ? requested
      : typeof data.info.version === 'string'
        ? data.info.version
        : undefined;
    meta.license = data.info.license || null;
    meta.repositoryUrl = data.info.project_urls?.Source ?? data.info.home_page ?? null;
    // The published artifact: prefer the sdist (real source layout) over a wheel.
    const files = Array.isArray(data.urls) ? data.urls : [];
    const artifact =
      files.find((f: any) => f?.packagetype === 'sdist' && typeof f.url === 'string') ??
      files.find((f: any) => f?.packagetype === 'bdist_wheel' && typeof f.url === 'string');
    if (artifact) {
      meta.tarballUrl = artifact.url;
      meta.tarballIntegrity =
        typeof artifact.digests?.sha256 === 'string' ? `sha256:${artifact.digests.sha256}` : null;
      meta.publishedAt = typeof artifact.upload_time_iso_8601 === 'string' ? artifact.upload_time_iso_8601 : null;
    }
  } else if (isExactVersion(requested)) {
    // The exact version endpoint returned nothing: the pinned version is not
    // resolvable (unpublished/yanked/hidden). Flag it rather than falling back.
    meta.version = requested;
    meta.requestedVersionMissing = true;
  }
  return meta;
}
