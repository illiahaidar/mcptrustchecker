/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Target resolution — turn a CLI target (path / URL / package / config) plus
 * options into one or more normalized surfaces, choosing the safest acquisition
 * path. Live process spawning from a client config is opt-in (`--run`).
 */

import { existsSync, readFileSync, statSync } from 'node:fs';
import type { PackageMeta, ServerSurface } from '../types.js';
import { surfaceFromManifest } from './manifest.js';
import { surfaceFromPackageDir } from './source.js';
import { acquireHttp, acquireStdio, ALLOWED_COMMANDS, type LiveOptions } from './live.js';
import {
  expandVars,
  isClientConfig,
  packageSpecFromStdio,
  parseClientConfig,
  redactSensitiveArgs,
  type ConfigServerSpec,
} from './clientConfig.js';
import { fetchNpmMeta, fetchPypiMeta } from './npm.js';

export interface ResolveOptions extends LiveOptions {
  command?: string;
  args?: string[];
  url?: string;
  online?: boolean;
  run?: boolean;
  registry?: 'npm' | 'pypi';
  /** Environment variables to pass to a `--command` stdio server. */
  envVars?: Record<string, string>;
}

export interface ResolvedTarget {
  label: string;
  surface: ServerSurface;
}

const NPM_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;
const HTTP_RE = /^https?:\/\//i;

function commandBase(command: string): string {
  const cleaned = command.replace(/\\/g, '/');
  return cleaned.slice(cleaned.lastIndexOf('/') + 1);
}

async function metaFor(name: string, opts: ResolveOptions): Promise<PackageMeta> {
  if (!opts.online) return { registry: opts.registry ?? 'npm', name };
  return opts.registry === 'pypi' ? fetchPypiMeta(name) : fetchNpmMeta(name);
}

function packageSurface(name: string, meta: PackageMeta, origin: string): ServerSurface {
  return {
    id: name,
    source: { kind: 'package', origin },
    server: { name },
    tools: [],
    prompts: [],
    resources: [],
    packageMeta: meta,
  };
}

/** Strip the query string from a stored URL so config-embedded tokens don't leak. */
function redactUrl(url?: string): string | undefined {
  if (!url) return url;
  try {
    const u = new URL(url);
    if (u.search) u.search = ''; // query-string tokens
    u.username = ''; // userinfo credentials (user:pass@host)
    u.password = '';
    return u.href;
  } catch {
    return url;
  }
}

/** Build the static (no-spawn) surface for one client-config server entry. */
function staticConfigSurface(spec: ConfigServerSpec, origin: string): ServerSurface {
  const transport: ServerSurface['transport'] =
    spec.transport === 'http'
      ? { kind: 'http', url: redactUrl(spec.url) }
      : {
          kind: 'stdio',
          command: spec.command,
          args: redactSensitiveArgs(spec.args ?? []),
          // A path-qualified command OR one outside the allowlist is untrusted.
          userControlledCommand: spec.command
            ? /[\\/]/.test(spec.command) || !ALLOWED_COMMANDS.has(commandBase(spec.command))
            : false,
        };
  return {
    id: spec.id,
    source: { kind: 'client-config', origin },
    server: { name: spec.id },
    tools: [],
    prompts: [],
    resources: [],
    transport,
  };
}

/** Resolve a target into scannable surfaces. */
export async function resolveTargets(target: string | undefined, opts: ResolveOptions = {}): Promise<ResolvedTarget[]> {
  // 1) Explicit live specs win.
  if (opts.command) {
    const surface = await acquireStdio({ command: opts.command, args: opts.args, env: opts.envVars }, opts);
    return [{ label: surface.id, surface }];
  }
  if (opts.url || (target && HTTP_RE.test(target))) {
    const url = opts.url ?? target!;
    const surface = await acquireHttp(url, opts);
    return [{ label: url, surface }];
  }

  if (!target) throw new Error('No scan target provided.');

  // A scoped npm/PyPI package (@scope/name) contains '/' but is NOT a path.
  const isScopedPkg = /^@[a-z0-9-~][a-z0-9-._~]*\/[a-z0-9-~][a-z0-9-._~]*$/i.test(target);
  const looksLikePath =
    !isScopedPkg && (target.includes('/') || target.includes('\\') || target.toLowerCase().endsWith('.json'));

  // A path/manifest target that doesn't exist: say so plainly.
  if (looksLikePath && !existsSync(target)) {
    throw new Error(`No such file: ${target}`);
  }

  // A local package DIRECTORY → analyze its implementation source + metadata.
  if (existsSync(target) && statSync(target).isDirectory()) {
    return [{ label: target, surface: surfaceFromPackageDir(target) }];
  }

  // 2) A file on disk: manifest or client config.
  if (existsSync(target) && target.toLowerCase().endsWith('.json')) {
    let json: unknown;
    try {
      json = JSON.parse(readFileSync(target, 'utf8'));
    } catch (err) {
      throw new Error(`Invalid JSON in ${target}: ${(err as Error).message}`);
    }
    if (isClientConfig(json)) {
      const specs = parseClientConfig(json);
      const results: ResolvedTarget[] = [];
      for (const spec of specs) {
        if (opts.run) {
          // URLs/commands come from an UNTRUSTED config. Expand ${VAR} ONLY from
          // the entry's own env block — NEVER from the scanner's process.env,
          // which would leak operator secrets into an outbound request.
          const varEnv = { ...(spec.env ?? {}) };
          try {
            const surface =
              spec.transport === 'http'
                ? await acquireHttp(expandVars(spec.url!, varEnv), { ...opts, blockPrivateHosts: opts.blockPrivateHosts ?? true })
                : await acquireStdio(
                    {
                      command: expandVars(spec.command!, varEnv),
                      args: (spec.args ?? []).map((a) => expandVars(a, varEnv)),
                      env: spec.env,
                    },
                    opts,
                  );
            // Use the config's server key as the stable id (not the raw command,
            // which may embed a token), and scrub any secrets from stored args.
            surface.id = spec.id;
            surface.source = { kind: 'client-config', origin: target };
            if (surface.transport?.args) surface.transport.args = redactSensitiveArgs(surface.transport.args);
            // The expanded URL can carry a ${TOKEN} in its query/userinfo — redact
            // it before it is stored in the report (matches the static path).
            if (surface.transport?.url) surface.transport.url = redactUrl(surface.transport.url) ?? surface.transport.url;
            results.push({ label: spec.id, surface });
          } catch {
            // One dead/unreachable server must not abort the whole config scan.
            results.push({ label: spec.id, surface: staticConfigSurface(spec, target) });
          }
          continue;
        }
        // Static: posture + supply-chain only, no process spawned.
        const surface = staticConfigSurface(spec, target);
        if (spec.transport === 'stdio' && spec.command) {
          const pkgSpec = packageSpecFromStdio(spec.command, spec.args ?? []);
          // Only fetch metadata for a well-formed package name (config values are untrusted).
          if (pkgSpec && NPM_NAME.test(pkgSpec.name)) {
            const meta = await metaFor(pkgSpec.name, opts);
            meta.requestedSpec = pkgSpec.version;
            meta.pinned = Boolean(pkgSpec.version && pkgSpec.version !== 'latest' && /^[0-9]/.test(pkgSpec.version));
            surface.packageMeta = meta;
          }
        }
        results.push({ label: spec.id, surface });
      }
      if (results.length === 0) throw new Error(`No MCP servers found in config: ${target}`);
      return results;
    }
    // Plain tools manifest — must be a JSON object, not an array/null/scalar.
    if (!json || typeof json !== 'object' || Array.isArray(json)) {
      throw new Error(
        `${target} is not a recognizable MCP manifest (expected a JSON object with a "tools" array or an "mcpServers" map).`,
      );
    }
    const surface = surfaceFromManifest(json, target);
    return [{ label: surface.id, surface }];
  }

  // 3) A bare package name → supply-chain / provenance scan.
  if (NPM_NAME.test(target)) {
    const meta = await metaFor(target, opts);
    return [{ label: target, surface: packageSurface(target, meta, target) }];
  }

  throw new Error(
    `Could not resolve target "${target}". Provide a tools.json manifest, an http(s) URL, ` +
      `a client config, a package name, or use --command for stdio.`,
  );
}
