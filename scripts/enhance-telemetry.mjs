import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const ROOT = new URL("../", import.meta.url);
const ATTACK_VERSION = "19.1";

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? resolve(process.argv[index + 1]) : fallback;
}

// Per-tactic telemetry gap text, mirrored from TACTIC_PROFILE in migrate-v4.mjs so
// newly created telemetry entries describe blind spots consistently with hand-authored ones.
const TACTIC_PROFILE_GAP = {
  "Reconnaissance": "Much reconnaissance occurs outside enterprise-controlled telemetry; exposure-management and external intelligence are compensating sources.",
  "Resource Development": "Adversary preparation commonly occurs off-network and may only be visible through external intelligence or later campaign correlation.",
  "Initial Access": "Encrypted traffic, unmanaged devices, external SaaS, and applications without audit logging can hide the entry point.",
  "Execution": "In-memory execution, truncated command lines, disabled script logging, and unmanaged interpreters reduce confidence.",
  "Persistence": "Unlogged configuration stores and weak golden-state baselines can make persistence appear legitimate.",
  "Privilege Escalation": "Kernel activity, inherited cloud roles, and missing privilege-change auditing require dedicated sources beyond process telemetry.",
  "Stealth": "Successful concealment may remove the evidence used to detect it; retain off-host logs and independent control-health signals.",
  "Defense Impairment": "Telemetry may become unavailable precisely when impairment succeeds; independent monitoring and off-host retention are required.",
  "Credential Access": "Memory-only access, unmanaged vaults, and incomplete directory auditing can obscure exactly which credentials were exposed.",
  "Discovery": "Legitimate administration resembles discovery; ancestry, novelty, volume, and approved change context are essential.",
  "Lateral Movement": "East-west blind spots, shared administrative accounts, NAT, and missing destination logs can hide the true source.",
  "Collection": "Metadata-only logs may not identify content; classification, DLP, application audit, and file telemetry improve confidence.",
  "Command and Control": "Encrypted, domain-fronted, peer-to-peer, and dead-drop channels can evade reputation-only analytics.",
  "Exfiltration": "TLS, sanctioned cloud services, removable media, and low-and-slow transfer can bypass simple thresholds.",
  "Impact": "Telemetry may stop during disruption; independent service, network, and backup monitoring is essential."
};

// MITRE log source name (lowercased prefix match) -> canonical telemetry id used across this dataset.
const CROSSWALK = [
  ["wineventlog:sysmon", "sysmon"], ["wineventlog:security", "windows-security"],
  ["wineventlog:powershell", "powershell"], ["wineventlog:system", "windows-security"],
  ["wineventlog:application", "windows-security"], ["wineventlog:wmi", "windows-security"],
  ["wineventlog:microsoft-windows-codeintegrity", "windows-security"], ["wineventlog:", "windows-security"],
  ["windows:perfmon", "windows-security"], ["etw:", "sysmon"], ["auditd:", "linux-audit"],
  ["linux:sysmon", "sysmon"], ["linux:syslog", "linux-audit"], ["linux:osquery", "linux-audit"],
  ["linux:cli", "linux-audit"], ["linux:cron", "linux-audit"], ["linux:procfs", "linux-audit"],
  ["linux:auth", "linux-audit"], ["linus:syslog", "linux-audit"], ["journald:", "linux-audit"],
  ["ebpf:", "linux-audit"], ["macos:", "macos"], ["fs:", "macos"], ["gatekeeper", "macos"],
  ["nsm:", "ndr"], ["network traffic", "ndr"], ["dns:query", "dns"], ["domain name", "dns"],
  ["networkdevice:syslog", "firewall"], ["networkdevice:cli", "firewall"], ["networkdevice:config", "firewall"],
  ["networkdevice:firmware", "firewall"], ["networkdevice:flow", "ndr"], ["networkdevice:ids", "ids-ips"],
  ["networkconfig", "firewall"], ["iptables:", "firewall"], ["pf:logs", "firewall"], ["snmp:trap", "firewall"],
  ["firewall audit logs", "firewall"], ["aws:cloudtrail", "aws-cloudtrail"], ["aws:vpcflowlogs", "aws-cloudtrail"],
  ["aws:cloudwatch", "aws-cloudtrail"], ["aws:", "aws-cloudtrail"], ["azure:signinlogs", "identity"],
  ["azure:audit", "cloud-audit"], ["azure:activity", "cloud-audit"], ["azure:", "cloud-audit"],
  ["gcp:", "cloud-audit"], ["m365:signinlogs", "identity"], ["m365:unified", "cloud-audit"],
  ["m365:exchange", "email"], ["m365:", "cloud-audit"], ["microsoft entra id audit logs", "identity"],
  ["persona", "threat-intel"], ["saas:okta", "identity"], ["saas:googleworkspace", "cloud-audit"],
  ["saas:github", "cloud-audit"], ["saas:slack", "cloud-audit"], ["saas:zoom", "cloud-audit"],
  ["saas:", "cloud-audit"], ["kubernetes:", "kubernetes"], ["docker:", "container-runtime"],
  ["containerd:", "container-runtime"], ["esxcli:", "security-control"], ["esxis:", "security-control"],
  ["esxi:", "security-control"], ["vpxd.log", "security-control"], ["edr:", "edr"],
  ["internet scan", "threat-intel"], ["malware repository", "threat-intel"], ["application:mail", "email"],
  ["application log", "windows-security"]
];

const PROVIDER_LABELS = [
  ["wineventlog:sysmon", "Sysmon"], ["wineventlog:security", "Windows Security"],
  ["wineventlog:powershell", "Windows PowerShell"], ["wineventlog:system", "Windows System"],
  ["wineventlog:application", "Windows Application"], ["wineventlog:wmi", "Windows WMI-Activity"],
  ["wineventlog:microsoft-windows-codeintegrity", "Windows Code Integrity"], ["wineventlog:", "Windows Event Log"],
  ["etw:", "Windows ETW"], ["auditd:", "Linux auditd"]
];

const TEMPLATE_FIELDS = [
  "source_name", "source_heading", "category", "tier", "priority", "event_types",
  "raw_fields", "normalized_fields", "mappings", "correlation_fields", "retention",
  "latency", "prerequisites", "audit_policy", "data_quality", "time_sync",
  "normalization", "health", "example_products"
];

const EVENT_CODE_PATTERN = /Event(?:Code|ID)\s*=\s*(\d+)/i;

function providerLabel(name) {
  const lower = name.toLowerCase();
  const match = PROVIDER_LABELS.find(([prefix]) => lower.startsWith(prefix));
  return match ? match[1] : name;
}

function classify(name) {
  const lower = name.toLowerCase();
  const match = CROSSWALK.find(([prefix]) => lower.startsWith(prefix));
  return match ? match[1] : null;
}

function parseEventCode(channel) {
  const match = EVENT_CODE_PATTERN.exec(channel || "");
  return match ? match[1] : null;
}

function extId(stixObject) {
  const ref = (stixObject.external_references || []).find(r => r.source_name === "mitre-attack");
  return ref?.external_id || null;
}

function loadStix(stix) {
  const objects = stix.objects || [];
  const apByStix = new Map();
  objects.forEach(o => {
    if (o.type === "attack-pattern" && !o.revoked && !o.x_mitre_deprecated) {
      const id = extId(o);
      if (id) apByStix.set(o.id, id);
    }
  });
  const detByStix = new Map(objects.filter(o => o.type === "x-mitre-detection-strategy" && !o.revoked && !o.x_mitre_deprecated).map(o => [o.id, o]));
  const anByStix = new Map(objects.filter(o => o.type === "x-mitre-analytic").map(o => [o.id, o]));
  const techToStrategies = new Map();
  objects.forEach(o => {
    if (o.type === "relationship" && o.relationship_type === "detects" && detByStix.has(o.source_ref) && apByStix.has(o.target_ref)) {
      const techId = apByStix.get(o.target_ref);
      if (!techToStrategies.has(techId)) techToStrategies.set(techId, []);
      techToStrategies.get(techId).push(o.source_ref);
    }
  });
  return { detByStix, anByStix, techToStrategies };
}

function signalsForTechnique(techId, { detByStix, anByStix, techToStrategies }) {
  const out = [];
  for (const stratStix of techToStrategies.get(techId) || []) {
    const strat = detByStix.get(stratStix);
    const stratExt = extId(strat);
    const stratUrl = `https://attack.mitre.org/detectionstrategies/${stratExt}`;
    for (const anRef of strat.x_mitre_analytic_refs || []) {
      const an = anByStix.get(anRef);
      if (!an) continue;
      const anExt = extId(an);
      for (const ref of an.x_mitre_log_source_references || []) {
        const canon = classify(ref.name || "");
        if (!canon) continue;
        out.push({
          canon, logSource: ref.name, channel: ref.channel || "",
          eventCode: parseEventCode(ref.channel), analyticId: anExt,
          strategyId: stratExt, strategyName: strat.name, strategyUrl: stratUrl
        });
      }
    }
  }
  return out;
}

function mostCommonValue(values) {
  const counts = new Map();
  values.forEach(v => {
    const key = JSON.stringify(v);
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  let best = null, bestCount = -1;
  counts.forEach((count, key) => { if (count > bestCount) { best = key; bestCount = count; } });
  return JSON.parse(best);
}

function buildTemplates(dataset) {
  const byId = new Map();
  dataset.playbooks.forEach(pb => {
    (pb.telemetry_requirements || []).forEach(t => {
      if (!t.id) return;
      if (!byId.has(t.id)) byId.set(t.id, new Map());
      const fields = byId.get(t.id);
      TEMPLATE_FIELDS.forEach(field => {
        if (field in t) {
          if (!fields.has(field)) fields.set(field, []);
          fields.get(field).push(t[field]);
        }
      });
    });
  });
  const templates = new Map();
  byId.forEach((fields, id) => {
    const template = {};
    fields.forEach((values, field) => { template[field] = mostCommonValue(values); });
    templates.set(id, template);
  });
  return templates;
}

function playbookTechniqueIds(pb) {
  const ids = new Set();
  if (pb.kind === "technique" && pb.id) ids.add(pb.id);
  (pb.techniques || []).forEach(item => { if (item.id) ids.add(item.id); });
  (pb.subtechniques || []).forEach(item => { if (item.id) ids.add(item.id); });
  return ids;
}

function dedupSignalsByCanon(signals) {
  const byCanon = new Map();
  const seen = new Map();
  signals.forEach(s => {
    if (!seen.has(s.canon)) seen.set(s.canon, new Set());
    const key = `${s.logSource} ${s.channel}`;
    if (seen.get(s.canon).has(key)) return;
    seen.get(s.canon).add(key);
    if (!byCanon.has(s.canon)) byCanon.set(s.canon, []);
    byCanon.get(s.canon).push(s);
  });
  return byCanon;
}

function buildAttackAnalytics(signals, cap = 6) {
  const seen = new Map();
  signals.forEach(s => {
    if (!seen.has(s.analyticId)) {
      seen.set(s.analyticId, {
        id: s.analyticId, detection_strategy: s.strategyId, name: s.strategyName,
        url: s.strategyUrl, log_source: s.logSource, channel: s.channel
      });
    }
  });
  return [...seen.values()].slice(0, cap);
}

function mergeEventIds(eventIds, signals, techniqueId) {
  const existingById = new Map(eventIds.filter(e => e && typeof e === "object").map(e => [e.id, e]));
  const codes = new Map();
  signals.forEach(s => { if (s.eventCode && !codes.has(s.eventCode)) codes.set(s.eventCode, s); });
  let added = 0, upgraded = 0;
  codes.forEach((s, code) => {
    const provider = providerLabel(s.logSource);
    const sourceNote = `ATT&CK v${ATTACK_VERSION} detection strategy ${s.strategyId} (analytic ${s.analyticId})`;
    if (existingById.has(code)) {
      const entry = existingById.get(code);
      if (entry.provenance === "legacy-authored-unverified") {
        entry.provenance = `attack-v${ATTACK_VERSION}-verified`;
        entry.description = `Confirmed by ${sourceNote} for ${techniqueId}.`;
        upgraded += 1;
      }
    } else {
      const entry = { provider, id: code, description: `Confirmed by ${sourceNote} for ${techniqueId}.`, provenance: `attack-v${ATTACK_VERSION}-verified` };
      eventIds.push(entry);
      existingById.set(code, entry);
      added += 1;
    }
  });
  return { added, upgraded };
}

function evidenceValueForTier(tier) {
  return tier === "required"
    ? ["Primary evidence when raw records and collection health are preserved."]
    : ["Corroborating or compensating evidence; do not treat source absence as proof of benign activity."];
}

function makeNewEntry(canon, template, signals, techniqueId, primaryTactic) {
  const entry = { id: canon };
  TEMPLATE_FIELDS.forEach(field => {
    if (field in template) entry[field] = JSON.parse(JSON.stringify(template[field]));
  });
  entry.source_heading = entry.source_heading || entry.source_name || canon;
  entry.event_ids = [];
  mergeEventIds(entry.event_ids, signals, techniqueId);
  const gap = TACTIC_PROFILE_GAP[primaryTactic] || "Telemetry gaps depend on collection scope, retention, and independent corroboration.";
  entry.blind_spots = [
    gap,
    `This telemetry source was derived from MITRE ATT&CK's official detection-strategy analytics for ${techniqueId} and has not been validated against a production deployment.`
  ];
  const strategyNames = [...new Set(signals.map(s => s.strategyName).filter(Boolean))].sort();
  const strategyLabel = strategyNames[0] || "the applicable ATT&CK detection strategy";
  const sourceLabel = entry.source_heading || entry.source_name || canon;
  entry.detection_relevance = [`MITRE ATT&CK's detection strategy for ${techniqueId} (${strategyLabel}) identifies ${sourceLabel} as a relevant log source for this technique.`];
  entry.investigation_relevance = [`Use ${entry.source_name || sourceLabel} to pivot on the actor, asset, process or session, target, and chronology associated with ${techniqueId}.`];
  entry.evidence_value = evidenceValueForTier(entry.tier);
  entry.attack_analytics = buildAttackAnalytics(signals);
  return entry;
}

async function main() {
  const stixPath = arg("stix");
  if (!stixPath) throw new Error("Usage: node scripts/enhance-telemetry.mjs --stix <path-to-enterprise-attack.json> [--input data/playbooks.json] [--output data/playbooks.json]");
  const input = arg("input", resolve(new URL("data/playbooks.json", ROOT).pathname));
  const output = arg("output", input);

  const stix = JSON.parse(await readFile(stixPath, "utf8"));
  const dataset = JSON.parse(await readFile(input, "utf8"));
  const stixIndex = loadStix(stix);
  const templates = buildTemplates(dataset);

  const stats = { entriesMerged: 0, entriesCreated: 0, eventIdsAdded: 0, eventIdsUpgraded: 0 };
  let playbooksTouched = 0;

  dataset.playbooks.forEach(pb => {
    if (pb.kind !== "technique") return;
    const techIds = playbookTechniqueIds(pb);
    if (!techIds.size) return;

    const allSignals = [];
    techIds.forEach(techId => allSignals.push(...signalsForTechnique(techId, stixIndex)));
    if (!allSignals.length) return;

    const byCanon = dedupSignalsByCanon(allSignals);
    const existingById = new Map((pb.telemetry_requirements || []).map(t => [t.id, t]));
    const primaryTactic = (pb.tactics || [])[0];
    const repTech = pb.kind === "technique" ? pb.id : [...techIds].sort()[0];
    let touched = false;

    byCanon.forEach((signals, canon) => {
      if (existingById.has(canon)) {
        const entry = existingById.get(canon);
        entry.event_ids = entry.event_ids || [];
        const { added, upgraded } = mergeEventIds(entry.event_ids, signals, repTech);
        entry.attack_analytics = buildAttackAnalytics(signals);
        if (added || upgraded) { stats.eventIdsAdded += added; stats.eventIdsUpgraded += upgraded; touched = true; }
        if (signals.length) { stats.entriesMerged += 1; touched = true; }
      } else {
        const template = templates.get(canon);
        if (!template) return;
        const newEntry = makeNewEntry(canon, template, signals, repTech, primaryTactic);
        pb.telemetry_requirements = pb.telemetry_requirements || [];
        pb.telemetry_requirements.push(newEntry);
        existingById.set(canon, newEntry);
        stats.entriesCreated += 1;
        stats.eventIdsAdded += newEntry.event_ids.length;
        touched = true;
      }
    });

    if (touched) playbooksTouched += 1;
  });

  dataset.meta.telemetry_enrichment_summary = {
    playbooks_enhanced: playbooksTouched,
    telemetry_entries_merged: stats.entriesMerged,
    telemetry_entries_created: stats.entriesCreated,
    event_ids_added: stats.eventIdsAdded,
    event_ids_upgraded_to_verified: stats.eventIdsUpgraded,
    source: "MITRE ATT&CK STIX detection-strategy and analytic objects (official log source references)",
    source_url: "https://github.com/mitre-attack/attack-stix-data",
    attack_version: ATTACK_VERSION
  };

  await writeFile(output, `${JSON.stringify(dataset)}\n`, "utf8");
  console.log(JSON.stringify({ output, playbooksTouched, ...stats }, null, 2));
}

main().catch(error => {
  console.error(`Telemetry enrichment failed: ${error.stack || error.message}`);
  process.exitCode = 1;
});
