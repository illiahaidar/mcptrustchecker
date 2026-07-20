/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Coverage — a third, honest axis alongside Trust (grade) and Capability (blast
 * radius). It states how much of the target the scan could actually inspect, so
 * a clean grade from a shallow scan is never mistaken for a thorough one.
 *
 * Purely descriptive and deterministic: derived only from what the acquired
 * surface contains. It never changes the score — it explains the score's reach.
 */

import type { Coverage, CoverageLevel, ServerSurface } from '../types.js';

/** Derive the coverage descriptor from an acquired surface. */
export function computeCoverage(surface: ServerSurface): Coverage {
  const toolSurface =
    (Array.isArray(surface.tools) && surface.tools.length > 0) ||
    (Array.isArray(surface.prompts) && surface.prompts.length > 0) ||
    (Array.isArray(surface.resources) && surface.resources.length > 0);
  const implementationSource = Array.isArray(surface.sourceFiles) && surface.sourceFiles.length > 0;
  const m = surface.packageMeta;
  const packageMetadata = Boolean(
    m && (m.name || m.version || (Array.isArray(m.dependencies) && m.dependencies.length > 0) || m.tarballSha256),
  );
  const liveTransport = surface.source?.kind === 'stdio' || surface.source?.kind === 'http';

  // Richest signal wins for the headline label; `inputs` keeps the full detail.
  let level: CoverageLevel;
  if (liveTransport) level = 'live';
  else if (implementationSource) level = 'source';
  else if (toolSurface) level = 'manifest';
  else if (packageMetadata) level = 'metadata';
  else level = 'empty';

  const caveats: string[] = [];
  if (level === 'empty') {
    caveats.push('Nothing scannable was found on this target — an empty surface is not a clean bill of health.');
  } else {
    if (!toolSurface) {
      caveats.push(
        'No tools were enumerated, so prompt-injection, capability and toxic-flow analysis had no tool surface to inspect. ' +
          'To grade a package’s real runtime tools, scan the running server: --command "npx -y <package>".',
      );
    }
    if (!implementationSource && !liveTransport) {
      caveats.push(
        packageMetadata
          ? 'The implementation source was not read — this reflects registry metadata only. Add --online to fetch and analyze the published package source.'
          : 'The implementation source was not read — this reflects the declared tool metadata only.',
      );
    }
  }

  return { level, inputs: { toolSurface, implementationSource, packageMetadata, liveTransport }, caveats };
}

/** A short human label for a coverage level (terminal/markdown headline). */
export function coverageLabel(level: CoverageLevel): string {
  switch (level) {
    case 'live':
      return 'running server — real runtime tools';
    case 'source':
      return 'published/local source read';
    case 'manifest':
      return 'static tool list only — no source';
    case 'metadata':
      return 'registry metadata only — no tools, no source';
    case 'empty':
      return 'nothing inspected';
  }
}
