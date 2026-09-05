import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const GROUP_ID_PATTERN = /^G\d{4,5}$/;
const ATTACK_VERSION_PATTERN = /^\d+(?:\.\d+){0,2}$/;

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? resolve(process.argv[index + 1]) : fallback;
}

function valueArg(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? String(process.argv[index + 1]).trim() : "";
}

function externalId(stixObject) {
  const reference = (stixObject.external_references || []).find(ref => ref.source_name === "mitre-attack");
  return reference?.external_id || null;
}

// Direct group-to-technique "uses" relationships only (not techniques reached transitively
// through a group's malware/tools) -- this matches "this group was directly observed using
// this technique" rather than "this group's toolkit happens to touch this technique".
export function extractGroupsAndMappings(stix) {
  const objects = stix.objects || [];

  const groupsByStixId = new Map();
  objects.forEach(object => {
    if (object.type !== "intrusion-set" || object.revoked || object.x_mitre_deprecated) return;
    const id = externalId(object);
    if (!id) return;
    const name = String(object.name || "").trim();
    const aliases = [...new Set((object.aliases || []).map(value => String(value).trim()).filter(alias => alias && alias !== name))].sort();
    groupsByStixId.set(object.id, { id, name, aliases, url: `https://attack.mitre.org/groups/${id}/` });
  });

  const techniqueIdByStixId = new Map();
  objects.forEach(object => {
    if (object.type !== "attack-pattern" || object.revoked || object.x_mitre_deprecated) return;
    const id = externalId(object);
    if (id) techniqueIdByStixId.set(object.id, id);
  });

  const techniqueToGroupIds = new Map();
  objects.forEach(object => {
    if (object.type !== "relationship" || object.relationship_type !== "uses" || object.revoked || object.x_mitre_deprecated) return;
    if (typeof object.source_ref !== "string" || typeof object.target_ref !== "string") return;
    if (!object.source_ref.startsWith("intrusion-set--") || !object.target_ref.startsWith("attack-pattern--")) return;
    const group = groupsByStixId.get(object.source_ref);
    const techniqueId = techniqueIdByStixId.get(object.target_ref);
    if (!group || !techniqueId) return;
    if (!techniqueToGroupIds.has(techniqueId)) techniqueToGroupIds.set(techniqueId, new Set());
    techniqueToGroupIds.get(techniqueId).add(group.id);
  });

  const usedGroupIds = new Set([...techniqueToGroupIds.values()].flatMap(set => [...set]));
  const groups = [...groupsByStixId.values()].filter(group => usedGroupIds.has(group.id)).sort((a, b) => a.id.localeCompare(b.id));

  return { groups, techniqueToGroupIds };
}

function playbookTechniqueIds(playbook) {
  const ids = new Set();
  if (playbook.kind === "technique" && playbook.id) ids.add(playbook.id);
  (playbook.techniques || []).forEach(item => { if (item?.id) ids.add(item.id); });
  (playbook.subtechniques || []).forEach(item => { if (item?.id) ids.add(item.id); });
  return ids;
}

export function applyThreatGroups(dataset, groups, techniqueToGroupIds, options = {}) {
  if (!dataset?.meta || !Array.isArray(dataset.playbooks)) throw new Error("Input is not a playbook dataset.");
  const totalIncomingMappings = [...(techniqueToGroupIds instanceof Map ? techniqueToGroupIds.values() : [])]
    .reduce((total, ids) => total + (ids instanceof Set ? ids.size : 0), 0);
  if (!Array.isArray(groups) || !groups.length || !(techniqueToGroupIds instanceof Map) || !totalIncomingMappings) {
    throw new Error("ATT&CK evidence contains no live direct group-to-technique mappings; refusing to remove existing group data.");
  }
  const currentMappings = dataset.playbooks.reduce((total, playbook) => total + (Array.isArray(playbook.threat_groups) ? playbook.threat_groups.length : 0), 0);
  let removedMappings = 0;
  const projectedMappings = dataset.playbooks.reduce((total, playbook) => {
    const matched = new Set();
    playbookTechniqueIds(playbook).forEach(techniqueId => {
      (techniqueToGroupIds.get(techniqueId) || new Set()).forEach(groupId => matched.add(groupId));
    });
    removedMappings += (playbook.threat_groups || []).filter(groupId => !matched.has(groupId)).length;
    return total + matched.size;
  }, 0);
  if (removedMappings && !options.allowRemovals) {
    throw new Error(`ATT&CK synchronization would remove ${removedMappings} existing group mapping(s) (${currentMappings} current, ${projectedMappings} projected); pass --allow-removals only after reviewing the source release.`);
  }
  const groupsById = new Map(groups.map(group => [group.id, group]));
  const previousGroupsById = new Map((dataset.groups || []).map(group => [group?.id, group]));
  let playbooksWithGroups = 0;
  let totalMappings = 0;

  dataset.playbooks.forEach(playbook => {
    // search_terms is denormalized output. Remove terms produced by the previous
    // group directory before adding the current authoritative mappings.
    const previousGroupTerms = new Set((playbook.threat_groups || []).flatMap(groupId => {
      const group = previousGroupsById.get(groupId);
      return [groupId, group?.name, ...(group?.aliases || [])];
    }).filter(Boolean));
    playbook.search_terms = (playbook.search_terms || []).filter(term => !previousGroupTerms.has(term));
    const matched = new Set();
    playbookTechniqueIds(playbook).forEach(techniqueId => {
      (techniqueToGroupIds.get(techniqueId) || new Set()).forEach(groupId => matched.add(groupId));
    });
    const threatGroups = [...matched].sort();
    playbook.threat_groups = threatGroups;
    if (!threatGroups.length) return;

    playbooksWithGroups += 1;
    totalMappings += threatGroups.length;
    const existingTerms = new Set(playbook.search_terms || []);
    threatGroups.forEach(groupId => {
      const group = groupsById.get(groupId);
      [group.id, group.name].forEach(term => {
        if (term && !existingTerms.has(term)) {
          playbook.search_terms = playbook.search_terms || [];
          playbook.search_terms.push(term);
          existingTerms.add(term);
        }
      });
    });
  });

  dataset.groups = groups;
  dataset.meta.threat_groups_summary = {
    total_groups: groups.length,
    playbooks_with_groups: playbooksWithGroups,
    total_playbook_group_mappings: totalMappings,
    source: "MITRE ATT&CK STIX data (attack-stix-data), direct group-to-technique 'uses' relationships only",
    source_url: "https://github.com/mitre-attack/attack-stix-data",
    attack_version: options.attackVersion || dataset.meta.attack?.version
  };
  return { playbooksWithGroups, totalMappings };
}

async function main() {
  const stixPath = arg("stix");
  const attackVersion = valueArg("attack-version");
  if (!stixPath || !ATTACK_VERSION_PATTERN.test(attackVersion)) throw new Error("Usage: node scripts/add-threat-groups.mjs --stix <path-to-enterprise-attack.json> --attack-version X.Y [--allow-removals] [--input data/playbooks.json] [--output data/playbooks.json]");
  const input = arg("input", resolve(ROOT, "data/playbooks.json"));
  const output = arg("output", input);

  const stix = JSON.parse(await readFile(stixPath, "utf8"));
  const dataset = JSON.parse(await readFile(input, "utf8"));
  if (String(dataset.meta?.attack?.version || "") !== attackVersion) {
    throw new Error(`--attack-version ${attackVersion} does not match dataset meta.attack.version ${dataset.meta?.attack?.version || "missing"}.`);
  }

  const { groups, techniqueToGroupIds } = extractGroupsAndMappings(stix);
  groups.forEach(group => {
    if (!GROUP_ID_PATTERN.test(group.id)) throw new Error(`Extracted group ID does not match the expected ATT&CK format: ${group.id}`);
  });
  const summary = applyThreatGroups(dataset, groups, techniqueToGroupIds, {
    attackVersion,
    allowRemovals: process.argv.includes("--allow-removals")
  });

  await writeFile(output, `${JSON.stringify(dataset)}\n`, "utf8");
  console.log(JSON.stringify({ output, groups: groups.length, ...summary }, null, 2));
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main().catch(error => {
  console.error(`Threat-group enrichment failed: ${error.stack || error.message}`);
  process.exitCode = 1;
});
