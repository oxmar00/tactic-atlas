import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const ROOT = new URL("../", import.meta.url);
const GROUP_ID_PATTERN = /^G\d{4,5}$/;

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? resolve(process.argv[index + 1]) : fallback;
}

function externalId(stixObject) {
  const reference = (stixObject.external_references || []).find(ref => ref.source_name === "mitre-attack");
  return reference?.external_id || null;
}

// Direct group-to-technique "uses" relationships only (not techniques reached transitively
// through a group's malware/tools) -- this matches "this group was directly observed using
// this technique" rather than "this group's toolkit happens to touch this technique".
function extractGroupsAndMappings(stix) {
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
    if (object.type !== "relationship" || object.relationship_type !== "uses") return;
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

function applyThreatGroups(dataset, groups, techniqueToGroupIds) {
  const groupsById = new Map(groups.map(group => [group.id, group]));
  let playbooksWithGroups = 0;
  let totalMappings = 0;

  dataset.playbooks.forEach(playbook => {
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
    source_url: "https://github.com/mitre-attack/attack-stix-data"
  };
  return { playbooksWithGroups, totalMappings };
}

async function main() {
  const stixPath = arg("stix");
  if (!stixPath) throw new Error("Usage: node scripts/add-threat-groups.mjs --stix <path-to-enterprise-attack.json> [--input data/playbooks.json] [--output data/playbooks.json]");
  const input = arg("input", resolve(new URL("data/playbooks.json", ROOT).pathname));
  const output = arg("output", input);

  const stix = JSON.parse(await readFile(stixPath, "utf8"));
  const dataset = JSON.parse(await readFile(input, "utf8"));

  const { groups, techniqueToGroupIds } = extractGroupsAndMappings(stix);
  groups.forEach(group => {
    if (!GROUP_ID_PATTERN.test(group.id)) throw new Error(`Extracted group ID does not match the expected ATT&CK format: ${group.id}`);
  });
  const summary = applyThreatGroups(dataset, groups, techniqueToGroupIds);

  await writeFile(output, `${JSON.stringify(dataset)}\n`, "utf8");
  console.log(JSON.stringify({ output, groups: groups.length, ...summary }, null, 2));
}

main().catch(error => {
  console.error(`Threat-group enrichment failed: ${error.stack || error.message}`);
  process.exitCode = 1;
});
