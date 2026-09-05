import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Extracts the authoritative technique -> detection-telemetry mapping from the ATT&CK STIX
// bundle. Everything emitted here is derived from MITRE objects; nothing is inferred:
//   technique metadata     <- attack-pattern
//   detection strategy     <- x-mitre-detection-strategy (detects -> attack-pattern)
//   log source + event ids <- x-mitre-analytic.x_mitre_log_source_references
//   tuning parameters      <- x-mitre-analytic.x_mitre_mutable_elements
//   pivots                 <- subtechnique-of relationships + shared intrusion-set usage
// Per-event FIELD lists are deliberately absent: ATT&CK does not publish them, so they live
// in the separately curated data/event-catalog.json instead of being synthesised here.

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
// A single channel may declare several codes: "EventCode=4103, 4104, 4105, 4106".
const EVENT_CODE_DECL = /Event(?:Code|ID)\s*=\s*([\d,\s]+)/gi;
const WINDOWS_SOURCE = /^(?:wineventlog|etw:|windows:)/i;
const ATTACK_VERSION_PATTERN = /^\d+(?:\.\d+){0,2}$/;

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? resolve(process.argv[index + 1]) : fallback;
}

function valueArg(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? String(process.argv[index + 1]).trim() : "";
}

function extId(object) {
  return (object.external_references || []).find(ref => ref.source_name === "mitre-attack")?.external_id || null;
}

export function parseEventCodes(channel) {
  if (!channel) return [];
  const codes = [];
  for (const match of String(channel).matchAll(EVENT_CODE_DECL)) {
    for (const code of match[1].match(/\d{1,5}/g) || []) codes.push(code);
  }
  return [...new Set(codes)];
}

function index(objects, type, liveOnly = true) {
  return new Map(objects
    .filter(o => o.type === type && (!liveOnly || (!o.revoked && !o.x_mitre_deprecated)))
    .map(o => [o.id, o]));
}

export function buildAttackAnalytics(stix, attackVersion) {
  if (!ATTACK_VERSION_PATTERN.test(String(attackVersion || "").trim())) {
    throw new Error("A valid ATT&CK release version is required (for example, 19.1).");
  }
  const objects = stix.objects || [];
  const patterns = index(objects, "attack-pattern");
  const strategies = index(objects, "x-mitre-detection-strategy");
  const analytics = index(objects, "x-mitre-analytic");
  const groups = index(objects, "intrusion-set");

  const techToStrategies = new Map();
  const parentOf = new Map();
  const groupTechniques = new Map();
  objects.forEach(o => {
    if (o.type !== "relationship" || o.revoked || o.x_mitre_deprecated) return;
    const { relationship_type: rt, source_ref: src, target_ref: tgt } = o;
    if (rt === "detects" && strategies.has(src) && patterns.has(tgt)) {
      if (!techToStrategies.has(tgt)) techToStrategies.set(tgt, []);
      techToStrategies.get(tgt).push(src);
    } else if (rt === "subtechnique-of" && patterns.has(src) && patterns.has(tgt)) {
      parentOf.set(src, tgt);
    } else if (rt === "uses" && groups.has(src) && patterns.has(tgt)) {
      if (!groupTechniques.has(src)) groupTechniques.set(src, new Set());
      groupTechniques.get(src).add(tgt);
    }
  });

  // Techniques used by the same intrusion sets are realistic investigation pivots. Ranking by
  // shared-group count surfaces a few strong pivots instead of every loosely related technique.
  const pairCounts = new Map();
  groupTechniques.forEach(used => {
    const list = [...used];
    list.forEach(a => {
      if (!pairCounts.has(a)) pairCounts.set(a, new Map());
      const row = pairCounts.get(a);
      list.forEach(b => { if (a !== b) row.set(b, (row.get(b) || 0) + 1); });
    });
  });

  const techniques = {};
  const stats = { withTelemetry: 0, logSources: 0, eventIds: 0, platformMismatch: 0 };

  patterns.forEach((pattern, stixId) => {
    const tid = extId(pattern);
    if (!tid) return;
    const techPlatforms = new Set(pattern.x_mitre_platforms || []);
    const telemetry = [];
    const tuning = [];
    const seen = new Set();

    (techToStrategies.get(stixId) || []).forEach(sid => {
      const strategy = strategies.get(sid);
      const strategyId = extId(strategy);
      (strategy.x_mitre_analytic_refs || []).forEach(ref => {
        const analytic = analytics.get(ref);
        if (!analytic) return;
        const analyticId = extId(analytic);
        (analytic.x_mitre_mutable_elements || []).forEach(element => {
          if (element.field) tuning.push({ field: element.field, description: element.description || "", analytic: analyticId });
        });
        (analytic.x_mitre_log_source_references || []).forEach(source => {
          const name = (source.name || "").trim();
          const channel = (source.channel || "").trim();
          const referenceKey = [analyticId, strategyId, name, channel].join("\u0000");
          if (!name || seen.has(referenceKey)) return;
          seen.add(referenceKey);
          const eventIds = parseEventCodes(channel);
          // ATT&CK sometimes cites a Windows log source on a technique with no Windows
          // platform. Flag rather than drop: the citation is MITRE's, but the analyst must
          // not be shown Windows event IDs as if they applied to an IaaS/SaaS investigation.
          const mismatch = WINDOWS_SOURCE.test(name) && techPlatforms.size > 0 && !techPlatforms.has("Windows");
          stats.logSources += 1;
          stats.eventIds += eventIds.length;
          if (mismatch) stats.platformMismatch += 1;
          telemetry.push({
            log_source: name, channel, event_ids: eventIds, platform_mismatch: mismatch,
            platforms: analytic.x_mitre_platforms || [], analytic: analyticId, strategy: strategyId,
            strategy_name: strategy.name || "",
            strategy_url: `https://attack.mitre.org/detectionstrategies/${strategyId}`
          });
        });
      });
    });

    const parent = parentOf.get(stixId);
    const pivots = [...(pairCounts.get(stixId) || new Map())]
      .sort((a, b) => b[1] - a[1]).slice(0, 6)
      .map(([other, count]) => ({ id: extId(patterns.get(other)), name: patterns.get(other)?.name, shared_groups: count }))
      .filter(pivot => pivot.id);

    techniques[tid] = {
      id: tid, name: pattern.name,
      is_subtechnique: Boolean(pattern.x_mitre_is_subtechnique),
      parent: parent ? extId(patterns.get(parent)) : null,
      tactics: (pattern.kill_chain_phases || []).filter(p => p.kill_chain_name === "mitre-attack").map(p => p.phase_name),
      platforms: pattern.x_mitre_platforms || [],
      url: `https://attack.mitre.org/techniques/${tid.replace(".", "/")}/`,
      detection: (pattern.x_mitre_detection || "").trim(),
      telemetry, tuning: tuning.slice(0, 8), pivots
    };
    if (telemetry.length) stats.withTelemetry += 1;
  });

  return {
    schema_version: "1.0.0",
    attack_version: String(attackVersion).trim(),
    generated_from: "MITRE ATT&CK Enterprise STIX (attack-stix-data)",
    source_url: "https://github.com/mitre-attack/attack-stix-data",
    counts: {
      techniques: Object.keys(techniques).length,
      with_telemetry: stats.withTelemetry,
      log_source_refs: stats.logSources,
      event_id_refs: stats.eventIds,
      platform_mismatched_refs: stats.platformMismatch
    },
    techniques
  };
}

async function main() {
  const stixPath = arg("stix");
  const attackVersion = valueArg("attack-version");
  if (!stixPath || !attackVersion) throw new Error("Usage: node scripts/build-attack-analytics.mjs --stix <enterprise-attack.json> --attack-version X.Y [--output data/attack-analytics.json]");
  const output = arg("output", resolve(ROOT, "data/attack-analytics.json"));
  const payload = buildAttackAnalytics(JSON.parse(await readFile(stixPath, "utf8")), attackVersion);
  await writeFile(output, `${JSON.stringify(payload)}\n`, "utf8");
  console.log(JSON.stringify({ output, ...payload.counts }, null, 2));
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1; });
