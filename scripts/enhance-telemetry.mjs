import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const ATTACK_VERSION_PATTERN = /^\d+(?:\.\d+){0,2}$/;
const ATTACK_PROVENANCE_PATTERN = /^attack-v.+-verified$/;
const GENERATED_ENTRY_TEXT = "derived from MITRE ATT&CK's official detection-strategy analytics";

function pathArg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? resolve(process.argv[index + 1]) : fallback;
}

function valueArg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? String(process.argv[index + 1]).trim() : fallback;
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

// A single channel may declare several codes, for example
// "EventCode=4103, 4104, 4105, 4106".
const EVENT_CODE_DECL = /Event(?:Code|ID)\s*=\s*([\d,\s]+)/gi;

function providerLabel(name) {
  const lower = String(name || "").toLowerCase();
  const match = PROVIDER_LABELS.find(([prefix]) => lower.startsWith(prefix));
  return match ? match[1] : name;
}

function classify(name) {
  const lower = String(name || "").toLowerCase();
  const match = CROSSWALK.find(([prefix]) => lower.startsWith(prefix));
  return match ? match[1] : null;
}

export function parseEventCodes(channel) {
  if (!channel) return [];
  const codes = [];
  for (const match of String(channel).matchAll(EVENT_CODE_DECL)) {
    for (const code of match[1].match(/\d{1,5}/g) || []) codes.push(code);
  }
  return [...new Set(codes)];
}

function extId(stixObject) {
  const ref = (stixObject?.external_references || []).find(item => item.source_name === "mitre-attack");
  return ref?.external_id || null;
}

export function loadStix(stix) {
  const objects = Array.isArray(stix?.objects) ? stix.objects : [];
  const apByStix = new Map();
  objects.forEach(object => {
    if (object.type === "attack-pattern" && !object.revoked && !object.x_mitre_deprecated) {
      const id = extId(object);
      if (id) apByStix.set(object.id, id);
    }
  });
  const detByStix = new Map(objects
    .filter(object => object.type === "x-mitre-detection-strategy" && !object.revoked && !object.x_mitre_deprecated)
    .map(object => [object.id, object]));
  const anByStix = new Map(objects
    .filter(object => object.type === "x-mitre-analytic" && !object.revoked && !object.x_mitre_deprecated)
    .map(object => [object.id, object]));
  const techToStrategies = new Map();
  objects.forEach(object => {
    if (object.type === "relationship" && object.relationship_type === "detects" && !object.revoked && !object.x_mitre_deprecated && detByStix.has(object.source_ref) && apByStix.has(object.target_ref)) {
      const techId = apByStix.get(object.target_ref);
      if (!techToStrategies.has(techId)) techToStrategies.set(techId, []);
      techToStrategies.get(techId).push(object.source_ref);
    }
  });
  return { detByStix, anByStix, techToStrategies, techniqueIds: new Set(apByStix.values()) };
}

export function signalsForTechnique(techId, { detByStix, anByStix, techToStrategies }) {
  const out = [];
  for (const stratStix of techToStrategies.get(techId) || []) {
    const strategy = detByStix.get(stratStix);
    const strategyId = extId(strategy);
    if (!strategyId) continue;
    const strategyUrl = `https://attack.mitre.org/detectionstrategies/${strategyId}`;
    for (const analyticRef of strategy.x_mitre_analytic_refs || []) {
      const analytic = anByStix.get(analyticRef);
      if (!analytic) continue;
      const analyticId = extId(analytic);
      if (!analyticId) continue;
      for (const ref of analytic.x_mitre_log_source_references || []) {
        const canon = classify(ref.name);
        if (!canon) continue;
        out.push({
          canon,
          logSource: ref.name,
          channel: ref.channel || "",
          eventCodes: parseEventCodes(ref.channel),
          analyticId,
          strategyId,
          strategyName: strategy.name,
          strategyUrl
        });
      }
    }
  }
  return out;
}

export function loadAttackAnalytics(artifact) {
  const signalsByTechnique = new Map();
  Object.entries(artifact?.techniques || {}).forEach(([techniqueId, technique]) => {
    const signals = [];
    (technique?.telemetry || []).forEach(reference => {
      const canon = classify(reference.log_source);
      if (!canon) return;
      const eventCodes = [...new Set([
        ...(Array.isArray(reference.event_ids) ? reference.event_ids.map(String) : []),
        ...parseEventCodes(reference.channel)
      ])];
      signals.push({
        canon,
        logSource: reference.log_source,
        channel: reference.channel || "",
        eventCodes,
        analyticId: reference.analytic,
        strategyId: reference.strategy,
        strategyName: reference.strategy_name,
        strategyUrl: reference.strategy_url || `https://attack.mitre.org/detectionstrategies/${reference.strategy}`
      });
    });
    signalsByTechnique.set(techniqueId, signals);
  });
  return signalsByTechnique;
}

function mostCommonValue(values) {
  const counts = new Map();
  values.forEach(value => {
    const key = JSON.stringify(value);
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  let best = null;
  let bestCount = -1;
  counts.forEach((count, key) => {
    if (count > bestCount) {
      best = key;
      bestCount = count;
    }
  });
  return JSON.parse(best);
}

function buildTemplates(dataset) {
  const byId = new Map();
  dataset.playbooks.forEach(playbook => {
    (playbook.telemetry_requirements || []).forEach(telemetry => {
      if (!telemetry.id) return;
      if (!byId.has(telemetry.id)) byId.set(telemetry.id, new Map());
      const fields = byId.get(telemetry.id);
      TEMPLATE_FIELDS.forEach(field => {
        if (field in telemetry) {
          if (!fields.has(field)) fields.set(field, []);
          fields.get(field).push(telemetry[field]);
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

function playbookTechniqueIds(playbook) {
  const ids = new Set();
  if (playbook.kind === "technique" && playbook.id) ids.add(playbook.id);
  (playbook.techniques || []).forEach(item => { if (item?.id) ids.add(item.id); });
  (playbook.subtechniques || []).forEach(item => { if (item?.id) ids.add(item.id); });
  return ids;
}

function dedupSignalsByCanon(signals) {
  const byCanon = new Map();
  const seen = new Map();
  signals.forEach(signal => {
    if (!seen.has(signal.canon)) seen.set(signal.canon, new Set());
    const key = [signal.analyticId, signal.strategyId, signal.logSource, signal.channel].join("\u0000");
    if (seen.get(signal.canon).has(key)) return;
    seen.get(signal.canon).add(key);
    if (!byCanon.has(signal.canon)) byCanon.set(signal.canon, []);
    byCanon.get(signal.canon).push(signal);
  });
  return byCanon;
}

export function buildAttackAnalytics(signals, cap = Number.POSITIVE_INFINITY) {
  const seen = new Map();
  signals.forEach(signal => {
    const key = [signal.analyticId, signal.strategyId, signal.logSource, signal.channel].join("\u0000");
    if (!seen.has(key)) {
      seen.set(key, {
        id: signal.analyticId,
        detection_strategy: signal.strategyId,
        name: signal.strategyName,
        url: signal.strategyUrl,
        log_source: signal.logSource,
        channel: signal.channel
      });
    }
  });
  return [...seen.values()].slice(0, cap);
}

function attackDescription(signal, techniqueId, attackVersion) {
  const sourceNote = `ATT&CK v${attackVersion} detection strategy ${signal.strategyId} (analytic ${signal.analyticId})`;
  return `Confirmed by ${sourceNote} for ${techniqueId}.`;
}

function signalByEventCode(signals) {
  const result = new Map();
  signals.forEach(signal => {
    signal.eventCodes.forEach(code => {
      if (!result.has(code)) result.set(code, signal);
    });
  });
  return result;
}

function syncEventIds(eventIds, signals, techniqueId, attackVersion) {
  const codes = signalByEventCode(signals);
  const retained = [];
  const seen = new Set();
  const stats = { added: 0, upgraded: 0, removed: 0, refreshed: 0 };

  (Array.isArray(eventIds) ? eventIds : []).forEach(entry => {
    if (!entry || typeof entry !== "object") {
      retained.push(entry);
      return;
    }
    const code = String(entry.id || "");
    const signal = codes.get(code);
    const attackDerived = ATTACK_PROVENANCE_PATTERN.test(String(entry.provenance || ""));
    if (attackDerived && !signal) {
      stats.removed += 1;
      return;
    }
    if (signal) {
      seen.add(code);
      const nextProvenance = `attack-v${attackVersion}-verified`;
      const nextDescription = attackDescription(signal, techniqueId, attackVersion);
      if (entry.provenance === "legacy-authored-unverified") stats.upgraded += 1;
      if (attackDerived && (entry.provenance !== nextProvenance || entry.description !== nextDescription)) stats.refreshed += 1;
      if (entry.provenance === "legacy-authored-unverified" || attackDerived) {
        entry.provider = providerLabel(signal.logSource);
        entry.provenance = nextProvenance;
        entry.description = nextDescription;
      }
    }
    retained.push(entry);
  });

  codes.forEach((signal, code) => {
    if (seen.has(code)) return;
    retained.push({
      provider: providerLabel(signal.logSource),
      id: code,
      description: attackDescription(signal, techniqueId, attackVersion),
      provenance: `attack-v${attackVersion}-verified`
    });
    stats.added += 1;
  });
  return { eventIds: retained, ...stats };
}

function evidenceValueForTier(tier) {
  return tier === "required"
    ? ["Primary evidence when raw records and collection health are preserved."]
    : ["Corroborating or compensating evidence; do not treat source absence as proof of benign activity."];
}

function makeNewEntry(canon, template, signals, techniqueId, primaryTactic, attackVersion) {
  const entry = { id: canon };
  TEMPLATE_FIELDS.forEach(field => {
    if (field in template) entry[field] = JSON.parse(JSON.stringify(template[field]));
  });
  entry.source_heading = entry.source_heading || entry.source_name || canon;
  entry.event_ids = syncEventIds([], signals, techniqueId, attackVersion).eventIds;
  const gap = TACTIC_PROFILE_GAP[primaryTactic] || "Telemetry gaps depend on collection scope, retention, and independent corroboration.";
  entry.blind_spots = [
    gap,
    `This telemetry source was derived from MITRE ATT&CK's official detection-strategy analytics for ${techniqueId} and has not been validated against a production deployment.`
  ];
  const strategyNames = [...new Set(signals.map(signal => signal.strategyName).filter(Boolean))].sort();
  const strategyLabel = strategyNames[0] || "the applicable ATT&CK detection strategy";
  const sourceLabel = entry.source_heading || entry.source_name || canon;
  entry.detection_relevance = [`MITRE ATT&CK's detection strategy for ${techniqueId} (${strategyLabel}) identifies ${sourceLabel} as a relevant log source for this technique.`];
  entry.investigation_relevance = [`Use ${entry.source_name || sourceLabel} to pivot on the actor, asset, process or session, target, and chronology associated with ${techniqueId}.`];
  entry.evidence_value = evidenceValueForTier(entry.tier);
  entry.attack_analytics = buildAttackAnalytics(signals);
  entry.attack_enrichment = { source: "mitre-attack-stix", generated: true, attack_version: attackVersion };
  return entry;
}

function isGeneratedTelemetry(entry) {
  return entry?.attack_enrichment?.generated === true
    || (entry?.blind_spots || []).some(value => String(value).includes(GENERATED_ENTRY_TEXT));
}

function analyticsKey(item) {
  return [item?.id, item?.detection_strategy, item?.log_source, item?.channel].join("\u0000");
}

function analyticsDelta(previous, next) {
  const oldKeys = new Set((Array.isArray(previous) ? previous : []).map(analyticsKey));
  const newKeys = new Set(next.map(analyticsKey));
  return {
    added: [...newKeys].filter(key => !oldKeys.has(key)).length,
    removed: [...oldKeys].filter(key => !newKeys.has(key)).length
  };
}

function destructiveTelemetryDelta(playbook, signals) {
  const byCanon = dedupSignalsByCanon(signals);
  let removals = 0;
  (playbook.telemetry_requirements || []).forEach(entry => {
    const currentSignals = byCanon.get(entry?.id) || [];
    if (isGeneratedTelemetry(entry) && !currentSignals.length) {
      removals++;
      return;
    }
    const expectedCodes = signalByEventCode(currentSignals);
    removals += (entry.event_ids || []).filter(item =>
      ATTACK_PROVENANCE_PATTERN.test(String(item?.provenance || "")) && !expectedCodes.has(String(item?.id || ""))
    ).length;
    removals += analyticsDelta(entry.attack_analytics, buildAttackAnalytics(currentSignals)).removed;
  });
  return removals;
}

export function synchronizeTelemetryDerivatives(playbook) {
  const telemetry = Array.isArray(playbook?.telemetry_requirements) ? playbook.telemetry_requirements : [];
  const before = JSON.stringify({
    data_sources: playbook.data_sources,
    data_source_summary: playbook.data_source_summary,
    counts: playbook.coverage && {
      required_telemetry: playbook.coverage.required_telemetry,
      recommended_telemetry: playbook.coverage.recommended_telemetry,
      optional_telemetry: playbook.coverage.optional_telemetry,
      compensating_telemetry: playbook.coverage.compensating_telemetry
    }
  });
  playbook.data_sources = telemetry.map(entry => String(entry?.id || "").trim()).filter(Boolean);
  playbook.data_source_summary = telemetry.map(entry => {
    const tier = String(entry?.tier || entry?.priority || "unspecified").trim().toLowerCase();
    const source = String(entry?.source_name || entry?.source_heading || entry?.category || entry?.id || "unspecified telemetry").trim();
    return `${tier}: ${source}`;
  }).join("; ");
  if (!playbook.coverage || typeof playbook.coverage !== "object" || Array.isArray(playbook.coverage)) playbook.coverage = {};
  for (const tier of ["required", "recommended", "optional", "compensating"]) {
    playbook.coverage[`${tier}_telemetry`] = telemetry.filter(entry => String(entry?.tier || "").toLowerCase() === tier).length;
  }
  const after = JSON.stringify({
    data_sources: playbook.data_sources,
    data_source_summary: playbook.data_source_summary,
    counts: {
      required_telemetry: playbook.coverage.required_telemetry,
      recommended_telemetry: playbook.coverage.recommended_telemetry,
      optional_telemetry: playbook.coverage.optional_telemetry,
      compensating_telemetry: playbook.coverage.compensating_telemetry
    }
  });
  return before !== after;
}

export function resolveAttackVersion(dataset, explicitVersion) {
  const metadataVersion = String(dataset?.meta?.attack?.version || "").trim();
  const requestedVersion = String(explicitVersion || "").trim();
  if (requestedVersion && metadataVersion && requestedVersion !== metadataVersion) {
    throw new Error(`--attack-version ${requestedVersion} does not match dataset meta.attack.version ${metadataVersion}; update the dataset ATT&CK metadata first or pass the matching version.`);
  }
  const attackVersion = requestedVersion || metadataVersion;
  if (!ATTACK_VERSION_PATTERN.test(attackVersion)) {
    throw new Error("An ATT&CK version is required in dataset meta.attack.version or --attack-version (for example, 19.1).");
  }
  return attackVersion;
}

export function applyTelemetryEnrichment(dataset, evidence, options = {}) {
  if (!dataset?.meta || !Array.isArray(dataset.playbooks)) throw new Error("Input is not a playbook dataset.");
  const attackVersion = resolveAttackVersion(dataset, options.attackVersion);
  const artifactMode = evidence && typeof evidence === "object" && !Array.isArray(evidence)
    && Object.hasOwn(evidence, "techniques") && !Array.isArray(evidence?.objects);
  if (!artifactMode && !Array.isArray(evidence?.objects)) {
    throw new Error("ATT&CK evidence must be a STIX bundle or a generated attack-analytics artifact.");
  }
  if (artifactMode && (evidence.schema_version !== "1.0.0" || !evidence.techniques || typeof evidence.techniques !== "object" || Array.isArray(evidence.techniques))) {
    throw new Error("Attack analytics evidence must be a v1.0.0 artifact with a techniques object.");
  }
  if (artifactMode) {
    const evidenceVersion = String(evidence.attack_version || "").trim();
    if (!ATTACK_VERSION_PATTERN.test(evidenceVersion)) {
      throw new Error("Attack analytics evidence must declare the ATT&CK release in attack_version.");
    }
    if (evidenceVersion !== attackVersion) {
      throw new Error(`Attack analytics version ${evidenceVersion} does not match dataset meta.attack.version ${attackVersion}.`);
    }
  } else if (!String(options.attackVersion || "").trim()) {
    throw new Error("Direct STIX enrichment requires --attack-version so the snapshot cannot be mislabeled.");
  }
  const stixIndex = artifactMode ? null : loadStix(evidence);
  const artifactIndex = artifactMode ? loadAttackAnalytics(evidence) : null;
  const evidenceTechniqueIds = artifactMode
    ? new Set(Object.keys(evidence.techniques))
    : stixIndex.techniqueIds;
  const techniqueSignalCache = new Map();
  const signalsForId = techniqueId => {
    if (!techniqueSignalCache.has(techniqueId)) {
      techniqueSignalCache.set(
        techniqueId,
        artifactMode ? (artifactIndex.get(techniqueId) || []) : signalsForTechnique(techniqueId, stixIndex)
      );
    }
    return techniqueSignalCache.get(techniqueId);
  };
  const signalsForPlaybook = playbook => {
    const signals = [];
    playbookTechniqueIds(playbook).forEach(techniqueId => signals.push(...signalsForId(techniqueId)));
    return signals;
  };
  const techniquePlaybooks = dataset.playbooks.filter(playbook => playbook.kind === "technique");
  const mutationTargets = options.allowPartial
    ? techniquePlaybooks.filter(playbook => {
      const ids = [...playbookTechniqueIds(playbook)];
      return ids.length && ids.every(id => evidenceTechniqueIds.has(id));
    })
    : techniquePlaybooks;
  if (options.allowPartial && !mutationTargets.length) {
    throw new Error("Partial ATT&CK evidence does not fully represent any playbook technique set; refusing to mutate data.");
  }
  const currentCoverage = mutationTargets.filter(playbook => (playbook.telemetry_requirements || []).some(entry =>
    isGeneratedTelemetry(entry)
      || (entry.attack_analytics || []).length
      || (entry.event_ids || []).some(item => ATTACK_PROVENANCE_PATTERN.test(String(item?.provenance || "")))
  )).length;
  const incomingCoverage = mutationTargets.filter(playbook => signalsForPlaybook(playbook).length).length;
  const usableSignalCount = [...techniqueSignalCache.values()].reduce((total, signals) => total + signals.length, 0);
  if (!usableSignalCount || !incomingCoverage) {
    throw new Error("ATT&CK evidence contains no usable detection-strategy log-source signals; refusing to remove existing enrichment.");
  }
  if (!options.allowRemovals && incomingCoverage < currentCoverage) {
    throw new Error(`ATT&CK evidence reduces enriched-playbook coverage from ${currentCoverage} to ${incomingCoverage}; pass --allow-removals only after reviewing the source release.`);
  }
  const destructiveRemovals = mutationTargets.reduce((total, playbook) => total + destructiveTelemetryDelta(playbook, signalsForPlaybook(playbook)), 0);
  if (destructiveRemovals && !options.allowRemovals) {
    throw new Error(`ATT&CK synchronization would remove ${destructiveRemovals} derived item(s); pass --allow-removals only after reviewing the source release.`);
  }
  const mutationTargetSet = new Set(mutationTargets);
  const templates = buildTemplates(dataset);
  const stats = {
    entriesMerged: 0,
    entriesCreated: 0,
    entriesRemoved: 0,
    eventIdsAdded: 0,
    eventIdsUpgraded: 0,
    eventIdsRemoved: 0,
    eventIdsRefreshed: 0,
    attackAnalyticsAdded: 0,
    attackAnalyticsRemoved: 0
  };
  let playbooksEnhanced = 0;
  let playbooksChanged = 0;

  dataset.playbooks.forEach(playbook => {
    if (playbook.kind !== "technique") return;
    if (!mutationTargetSet.has(playbook)) return;
    const techniqueIds = playbookTechniqueIds(playbook);
    if (!techniqueIds.size) return;
    const signals = signalsForPlaybook(playbook);
    const byCanon = dedupSignalsByCanon(signals);
    const representativeTechnique = playbook.id || [...techniqueIds].sort()[0];
    const primaryTactic = (playbook.tactics || [])[0];
    const previousTelemetry = Array.isArray(playbook.telemetry_requirements) ? playbook.telemetry_requirements : [];
    const nextTelemetry = [];
    const existingIds = new Set();
    let changed = false;

    previousTelemetry.forEach(entry => {
      const currentSignals = byCanon.get(entry?.id) || [];
      if (isGeneratedTelemetry(entry) && !currentSignals.length) {
        stats.entriesRemoved += 1;
        stats.eventIdsRemoved += (entry.event_ids || []).filter(item => ATTACK_PROVENANCE_PATTERN.test(String(item?.provenance || ""))).length;
        stats.attackAnalyticsRemoved += (entry.attack_analytics || []).length;
        changed = true;
        return;
      }

      existingIds.add(entry?.id);
      const oldEventIds = JSON.stringify(entry.event_ids || []);
      const eventSync = syncEventIds(entry.event_ids, currentSignals, representativeTechnique, attackVersion);
      entry.event_ids = eventSync.eventIds;
      stats.eventIdsAdded += eventSync.added;
      stats.eventIdsUpgraded += eventSync.upgraded;
      stats.eventIdsRemoved += eventSync.removed;
      stats.eventIdsRefreshed += eventSync.refreshed;
      if (oldEventIds !== JSON.stringify(entry.event_ids)) changed = true;

      const nextAnalytics = buildAttackAnalytics(currentSignals);
      const delta = analyticsDelta(entry.attack_analytics, nextAnalytics);
      stats.attackAnalyticsAdded += delta.added;
      stats.attackAnalyticsRemoved += delta.removed;
      if (delta.added || delta.removed) changed = true;
      if (nextAnalytics.length) entry.attack_analytics = nextAnalytics;
      else delete entry.attack_analytics;
      if (currentSignals.length) {
        stats.entriesMerged += 1;
        if (entry.attack_enrichment?.generated) entry.attack_enrichment.attack_version = attackVersion;
      }
      nextTelemetry.push(entry);
    });

    byCanon.forEach((currentSignals, canon) => {
      if (existingIds.has(canon)) return;
      const template = templates.get(canon);
      if (!template) return;
      const entry = makeNewEntry(canon, template, currentSignals, representativeTechnique, primaryTactic, attackVersion);
      nextTelemetry.push(entry);
      stats.entriesCreated += 1;
      stats.eventIdsAdded += entry.event_ids.length;
      stats.attackAnalyticsAdded += entry.attack_analytics.length;
      changed = true;
    });

    playbook.telemetry_requirements = nextTelemetry;
    if (synchronizeTelemetryDerivatives(playbook)) changed = true;
    if (signals.length) playbooksEnhanced += 1;
    if (changed) playbooksChanged += 1;
  });

  dataset.meta.telemetry_enrichment_summary = {
    playbooks_enhanced: playbooksEnhanced,
    playbooks_changed: playbooksChanged,
    telemetry_entries_merged: stats.entriesMerged,
    telemetry_entries_created: stats.entriesCreated,
    telemetry_entries_removed: stats.entriesRemoved,
    event_ids_added: stats.eventIdsAdded,
    event_ids_upgraded_to_verified: stats.eventIdsUpgraded,
    event_ids_removed_as_obsolete: stats.eventIdsRemoved,
    event_ids_refreshed: stats.eventIdsRefreshed,
    attack_analytics_added: stats.attackAnalyticsAdded,
    attack_analytics_removed_as_obsolete: stats.attackAnalyticsRemoved,
    source: artifactMode
      ? "Generated MITRE ATT&CK analytics artifact (official STIX detection-strategy and analytic log source references)"
      : "MITRE ATT&CK STIX detection-strategy and analytic objects (official log source references)",
    source_url: "https://github.com/mitre-attack/attack-stix-data",
    attack_version: attackVersion
  };
  const generatedDate = String(options.generatedDate || new Date().toISOString().slice(0, 10));
  if (!/^\d{4}-\d{2}-\d{2}$/.test(generatedDate) || Number.isNaN(Date.parse(`${generatedDate}T00:00:00Z`))) {
    throw new Error(`Invalid generated date: ${generatedDate}`);
  }
  dataset.meta.generated = generatedDate;

  return { attackVersion, playbooksEnhanced, playbooksChanged, ...stats };
}

async function main() {
  const stixPath = pathArg("stix");
  const analyticsPath = pathArg("analytics");
  if ((!stixPath && !analyticsPath) || (stixPath && analyticsPath)) {
    throw new Error("Usage: node scripts/enhance-telemetry.mjs (--stix <enterprise-attack.json> | --analytics <attack-analytics.json>) [--attack-version X.Y] [--allow-partial] [--allow-removals] [--input data/playbooks.json] [--output data/playbooks.json]");
  }
  const input = pathArg("input", resolve(ROOT, "data/playbooks.json"));
  const output = pathArg("output", input);
  const explicitVersion = valueArg("attack-version");
  const evidence = JSON.parse(await readFile(stixPath || analyticsPath, "utf8"));
  const dataset = JSON.parse(await readFile(input, "utf8"));
  const summary = applyTelemetryEnrichment(dataset, evidence, {
    attackVersion: explicitVersion,
    allowPartial: process.argv.includes("--allow-partial"),
    allowRemovals: process.argv.includes("--allow-removals")
  });
  await writeFile(output, `${JSON.stringify(dataset)}\n`, "utf8");
  console.log(JSON.stringify({ output, ...summary }, null, 2));
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main().catch(error => {
  console.error(`Telemetry enrichment failed: ${error.stack || error.message}`);
  process.exitCode = 1;
});
