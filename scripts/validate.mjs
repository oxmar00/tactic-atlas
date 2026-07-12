import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { renderStandalone } from "./build-standalone.mjs";

export const SCHEMA_VERSION = "4.0.0";
export const TACTICS = Object.freeze([
  "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
  "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact"
]);

const KINDS = new Set(["technique", "operational", "platform"]);
const SEVERITIES = new Set(["informational", "low", "medium", "high", "critical"]);
const CONFIDENCE = new Set(["low", "medium", "high"]);
const STATUSES = new Set(["draft", "testing", "pilot", "active", "production", "deprecated", "retired"]);
const TELEMETRY_TIERS = new Set(["required", "recommended", "optional", "compensating"]);
const RESPONSE_PHASES = [
  "triage", "investigation", "scoping", "containment", "eradication", "recovery",
  "post_incident", "escalation", "decision_tree", "closure_criteria"
];
const REQUIRED_PLAYBOOK_FIELDS = [
  "schema_version", "id", "name", "kind", "description", "tactics", "tactic_mappings",
  "techniques", "subtechniques", "platforms", "data_source_summary", "telemetry_requirements",
  "detection", "queries", "validation", "response", "lifecycle", "tags", "severity", "confidence",
  "maturity", "status", "quality_score", "quality_breakdown", "coverage", "content_sections", "search_terms"
];
const ARRAY_TELEMETRY_FIELDS = [
  "event_types", "event_ids", "raw_fields", "normalized_fields", "mappings", "correlation_fields",
  "prerequisites", "audit_policy", "blind_spots", "data_quality", "time_sync", "normalization",
  "health", "example_products", "detection_relevance", "investigation_relevance", "evidence_value"
];
const PLACEHOLDER = /\b(?:todo|tbd|fixme|lorem ipsum|add content here|placeholder text|coming soon)\b/i;
const DANGEROUS_MARKUP = /<(?:script|iframe|object|embed|base|form|meta)\b|<[^>]+\s(?:on[a-z]+|srcdoc|style)\s*=|(?:href|src)\s*=\s*["']?\s*(?:javascript|vbscript|data):/i;
const root = new URL("../", import.meta.url);

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function makeCollector(limit = 600) {
  const errors = [];
  let omitted = 0;
  return {
    add(path, message) {
      if (errors.length < limit) errors.push(`${path}: ${message}`);
      else omitted++;
    },
    finish() {
      if (omitted) errors.push(`validation: ${omitted} additional error(s) omitted`);
      return errors;
    }
  };
}

function stringValue(value, path, add, { min = 1, max = 100_000, pattern, allowed } = {}) {
  if (typeof value !== "string") {
    add(path, "must be a string");
    return "";
  }
  const trimmed = value.trim();
  if (trimmed.length < min) add(path, `must contain at least ${min} character(s)`);
  if (trimmed.length > max) add(path, `must not exceed ${max} characters`);
  if (pattern && !pattern.test(trimmed)) add(path, "has an invalid format");
  if (allowed && !allowed.has(trimmed.toLowerCase())) add(path, `must be one of: ${[...allowed].join(", ")}`);
  return trimmed;
}

function stringArray(value, path, add, { min = 0, max = 2_000, allowed } = {}) {
  if (!Array.isArray(value)) {
    add(path, "must be an array");
    return [];
  }
  if (value.length < min) add(path, `must contain at least ${min} item(s)`);
  if (value.length > max) add(path, `must not contain more than ${max} items`);
  const seen = new Set();
  value.forEach((item, index) => {
    const normalized = stringValue(item, `${path}[${index}]`, add, { max: 500 });
    const key = normalized.toLowerCase();
    if (normalized && seen.has(key)) add(`${path}[${index}]`, "duplicates an earlier value");
    seen.add(key);
    if (allowed && normalized && !allowed.has(normalized)) add(`${path}[${index}]`, `unknown value ${normalized}`);
  });
  return value;
}

function substantive(value) {
  if (typeof value === "string") return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0 && value.some(substantive);
  if (plainObject(value)) return Object.keys(value).length > 0 && Object.values(value).some(substantive);
  return typeof value === "number" || typeof value === "boolean";
}

function substantiveArray(value, path, add, { required = false, min = 0, max = 500 } = {}) {
  if (value == null && !required) return;
  if (!Array.isArray(value)) {
    add(path, "must be an array");
    return;
  }
  if (value.length < min) add(path, `must contain at least ${min} item(s)`);
  if (value.length > max) add(path, `must not contain more than ${max} items`);
  value.forEach((item, index) => {
    if (!substantive(item)) add(`${path}[${index}]`, "must contain a substantive JSON value");
  });
}

function inspectJsonSafety(value, path, add, depth = 0) {
  if (depth > 24) {
    add(path, "exceeds the maximum nesting depth of 24");
    return;
  }
  if (value === null || ["string", "number", "boolean"].includes(typeof value)) return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => inspectJsonSafety(item, `${path}[${index}]`, add, depth + 1));
    return;
  }
  if (!plainObject(value)) {
    add(path, "must contain only JSON-compatible values");
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    if (["__proto__", "prototype", "constructor"].includes(key)) add(`${path}.${key}`, "prototype-mutating keys are forbidden");
    inspectJsonSafety(item, `${path}.${key}`, add, depth + 1);
  }
}

function inspectText(value, path, add, depth = 0) {
  if (depth > 24 || value == null) return;
  if (typeof value === "string") {
    if (PLACEHOLDER.test(value)) add(path, "contains placeholder language");
    return;
  }
  if (Array.isArray(value)) value.forEach((item, index) => inspectText(item, `${path}[${index}]`, add, depth + 1));
  else if (plainObject(value)) Object.entries(value).forEach(([key, item]) => inspectText(item, `${path}.${key}`, add, depth + 1));
}

function namedItems(value, path, add, { min = 0 } = {}) {
  if (!Array.isArray(value)) {
    add(path, "must be an array");
    return;
  }
  if (value.length < min) add(path, `must contain at least ${min} item(s)`);
  const seen = new Set();
  value.forEach((item, index) => {
    if (typeof item === "string") {
      const id = stringValue(item, `${path}[${index}]`, add, { max: 160 });
      if (seen.has(id)) add(`${path}[${index}]`, "duplicates an earlier item");
      seen.add(id);
      return;
    }
    if (!plainObject(item)) {
      add(`${path}[${index}]`, "must be a string or object");
      return;
    }
    const id = stringValue(item.id, `${path}[${index}].id`, add, { max: 160 });
    stringValue(item.name, `${path}[${index}].name`, add, { max: 300 });
    if (seen.has(id)) add(`${path}[${index}].id`, "duplicates an earlier item");
    seen.add(id);
  });
}

function validateTacticMappings(value, playbook, path, add, knownTactics) {
  if (!Array.isArray(value)) {
    add(path, "must be an array");
    return;
  }
  if (playbook.kind === "technique" && value.length === 0) add(path, "must map a technique playbook to at least one tactic");
  value.forEach((mapping, index) => {
    const at = `${path}[${index}]`;
    if (!plainObject(mapping)) {
      add(at, "must be an object");
      return;
    }
    const tactic = stringValue(mapping.tactic ?? mapping.name, `${at}.tactic`, add, { max: 100 });
    if (tactic && !knownTactics.has(tactic) && !legacyMappingAllowed(playbook, mapping)) {
      add(`${at}.tactic`, `unknown tactic ${tactic}; legacy mappings require deprecated status and explicit legacy/unverified provenance`);
    }
    if (!substantive(mapping)) add(at, "must contain a substantive mapping");
  });
}

function legacyMappingAllowed(playbook, mapping) {
  const deprecated = [playbook.status, playbook.lifecycle?.status].some(value => /^(?:deprecated|retired)$/i.test(String(value || "")));
  const provenance = JSON.stringify({
    legacy: mapping?.legacy,
    status: mapping?.status ?? mapping?.mapping_status,
    provenance: mapping?.provenance
  });
  return deprecated && (mapping?.legacy === true || /legacy|unverified|deprecated/i.test(provenance));
}

function legacyTacticAllowed(playbook, tactic) {
  return Array.isArray(playbook.tactic_mappings)
    && playbook.tactic_mappings.some(mapping => plainObject(mapping)
      && (mapping.tactic ?? mapping.name) === tactic
      && legacyMappingAllowed(playbook, mapping));
}

function validateTelemetry(value, path, add) {
  if (!Array.isArray(value)) {
    add(path, "must be an array");
    return;
  }
  if (!value.length) add(path, "must contain at least one telemetry requirement");
  const ids = new Set();
  value.forEach((source, index) => {
    const at = `${path}[${index}]`;
    if (!plainObject(source)) {
      add(at, "must be an object");
      return;
    }
    const id = stringValue(source.id, `${at}.id`, add, { max: 160 });
    if (ids.has(id)) add(`${at}.id`, "duplicates an earlier telemetry ID");
    ids.add(id);
    stringValue(source.category, `${at}.category`, add, { max: 160 });
    const tier = stringValue(source.tier, `${at}.tier`, add, { allowed: TELEMETRY_TIERS, max: 20 });
    const priority = stringValue(source.priority, `${at}.priority`, add, { allowed: TELEMETRY_TIERS, max: 20 });
    if (tier && priority && tier !== priority) add(at, "tier and priority must use the same canonical value");
    substantiveArray(source.event_types, `${at}.event_types`, add, { required: true, min: 1, max: 100 });
    substantiveArray(source.raw_fields, `${at}.raw_fields`, add, { required: true, min: 1, max: 200 });
    substantiveArray(source.normalized_fields, `${at}.normalized_fields`, add, { required: true, min: 1, max: 200 });
    ARRAY_TELEMETRY_FIELDS.forEach(key => {
      if (key in source && !["event_types", "raw_fields", "normalized_fields"].includes(key)) {
        substantiveArray(source[key], `${at}.${key}`, add, { max: 200 });
      }
    });
    for (const key of ["retention", "latency"]) {
      if (key in source && !(typeof source[key] === "string" || plainObject(source[key])) || (key in source && !substantive(source[key]))) {
        add(`${at}.${key}`, "must be a substantive string or object");
      }
    }
  });
}

function validateDetection(value, path, add) {
  if (!plainObject(value)) {
    add(path, "must be an object");
    return;
  }
  stringValue(value.objective, `${path}.objective`, add, { min: 40 });
  stringValue(value.hypothesis, `${path}.hypothesis`, add, { min: 40 });
  if (!plainObject(value.strategy) || !substantive(value.strategy)) add(`${path}.strategy`, "must be a substantive summary strategy object");
  if (!Array.isArray(value.strategies) || !value.strategies.length || !value.strategies.every(substantive)) {
    add(`${path}.strategies`, "must contain one or more substantive strategies");
  }
  if (!Array.isArray(value.maturity_levels) || !value.maturity_levels.length || !value.maturity_levels.every(substantive)) {
    add(`${path}.maturity_levels`, "must contain one or more substantive maturity levels");
  }
}

function validateQueries(value, path, add) {
  if (!Array.isArray(value)) {
    add(path, "must be an array");
    return;
  }
  if (!value.length) add(path, "must contain at least one query or vendor-neutral pseudocode example");
  const ids = new Set();
  value.forEach((query, index) => {
    const at = `${path}[${index}]`;
    if (!plainObject(query)) {
      add(at, "must be an object");
      return;
    }
    const id = stringValue(query.id, `${at}.id`, add, { max: 160 });
    if (ids.has(id)) add(`${at}.id`, "duplicates an earlier query ID");
    ids.add(id);
    stringValue(query.name ?? query.title, `${at}.name`, add, { max: 300 });
    stringValue(query.platform ?? query.product, `${at}.platform`, add, { max: 160 });
    stringValue(query.language ?? query.type, `${at}.language`, add, { max: 100 });
    stringValue(query.query ?? query.code ?? query.text, `${at}.query`, add, { min: 20, max: 100_000 });
    if ("adaptation_required" in query && typeof query.adaptation_required !== "boolean") {
      add(`${at}.adaptation_required`, "must be a boolean");
    }
  });
}

function validateResponse(value, path, add) {
  if (!plainObject(value)) {
    add(path, "must be an object");
    return;
  }
  RESPONSE_PHASES.forEach(phase => {
    if (!substantive(value[phase])) add(`${path}.${phase}`, "must contain operational guidance");
  });
}

function validateLifecycle(value, path, add) {
  if (!plainObject(value)) {
    add(path, "must be an object");
    return;
  }
  if (!((typeof value.owner === "string" || plainObject(value.owner)) && substantive(value.owner))) {
    add(`${path}.owner`, "must be a substantive string or object");
  }
  stringValue(value.review_frequency, `${path}.review_frequency`, add, { min: 2, max: 300 });
  stringValue(value.version, `${path}.version`, add, { min: 1, max: 50 });
  const reviewed = stringValue(value.last_reviewed, `${path}.last_reviewed`, add, { pattern: /^\d{4}-\d{2}-\d{2}$/ });
  if (reviewed && Number.isNaN(Date.parse(`${reviewed}T00:00:00Z`))) add(`${path}.last_reviewed`, "must be a valid calendar date");
}

function validateScores(playbook, path, add) {
  if (typeof playbook.quality_score !== "number" || !Number.isFinite(playbook.quality_score)
      || playbook.quality_score < 0 || playbook.quality_score > 100) {
    add(`${path}.quality_score`, "must be a finite number from 0 through 100");
  }
  if (!plainObject(playbook.quality_breakdown) || !Object.keys(playbook.quality_breakdown).length) {
    add(`${path}.quality_breakdown`, "must be a non-empty object");
  } else {
    Object.entries(playbook.quality_breakdown).forEach(([key, value]) => {
      if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 100) {
        add(`${path}.quality_breakdown.${key}`, "must be a finite number from 0 through 100");
      }
    });
  }
  if (!plainObject(playbook.coverage) || !Object.keys(playbook.coverage).length) {
    add(`${path}.coverage`, "must be a non-empty object");
  }
}

function validateContentSections(value, path, add) {
  if (!Array.isArray(value) || !value.length) {
    add(path, "must contain at least one structured content section");
    return;
  }
  value.forEach((section, index) => {
    const at = `${path}[${index}]`;
    if (!plainObject(section)) {
      add(at, "must be an object");
      return;
    }
    stringValue(section.id, `${at}.id`, add, { max: 160 });
    stringValue(section.title, `${at}.title`, add, { max: 300 });
    if (!substantive(section)) add(at, "must contain substantive content");
  });
}

function validatePlaybook(playbook, index, add, knownTactics) {
  const path = `data.playbooks[${index}]`;
  if (!plainObject(playbook)) {
    add(path, "must be an object");
    return null;
  }
  REQUIRED_PLAYBOOK_FIELDS.forEach(field => {
    if (!Object.hasOwn(playbook, field)) add(`${path}.${field}`, "is required by schema v4.0.0");
  });
  inspectJsonSafety(playbook, path, add);
  inspectText(playbook, path, add);

  stringValue(playbook.schema_version, `${path}.schema_version`, add, { allowed: new Set([SCHEMA_VERSION]) });
  const id = stringValue(playbook.id, `${path}.id`, add, { pattern: /^[A-Z][A-Z0-9._:-]{1,127}$/ });
  stringValue(playbook.name, `${path}.name`, add, { min: 3, max: 300 });
  const kind = stringValue(playbook.kind, `${path}.kind`, add, { allowed: KINDS });
  const description = stringValue(playbook.description, `${path}.description`, add, { min: 40, max: 5_000 });
  const tactics = stringArray(playbook.tactics, `${path}.tactics`, add, { min: kind === "technique" ? 1 : 0, max: 20 });
  tactics.forEach((tactic, tacticIndex) => {
    if (kind === "technique" && !knownTactics.has(tactic) && !legacyTacticAllowed(playbook, tactic)) {
      add(`${path}.tactics[${tacticIndex}]`, `unknown tactic ${tactic}`);
    }
  });
  validateTacticMappings(playbook.tactic_mappings, playbook, `${path}.tactic_mappings`, add, knownTactics);
  namedItems(playbook.techniques, `${path}.techniques`, add, { min: kind === "technique" ? 1 : 0 });
  namedItems(playbook.subtechniques, `${path}.subtechniques`, add);
  stringArray(playbook.platforms, `${path}.platforms`, add, { max: 100 });
  stringValue(playbook.data_source_summary, `${path}.data_source_summary`, add, { min: 20, max: 5_000 });
  validateTelemetry(playbook.telemetry_requirements, `${path}.telemetry_requirements`, add);
  validateDetection(playbook.detection, `${path}.detection`, add);
  validateQueries(playbook.queries, `${path}.queries`, add);
  if (!plainObject(playbook.validation) || !substantive(playbook.validation)) add(`${path}.validation`, "must be a substantive object");
  validateResponse(playbook.response, `${path}.response`, add);
  validateLifecycle(playbook.lifecycle, `${path}.lifecycle`, add);
  stringArray(playbook.tags, `${path}.tags`, add, { min: 1, max: 100 });
  stringValue(playbook.severity, `${path}.severity`, add, { allowed: SEVERITIES, max: 20 });
  stringValue(playbook.confidence, `${path}.confidence`, add, { allowed: CONFIDENCE, max: 20 });
  if (!(Number.isInteger(playbook.maturity) && playbook.maturity >= 1 && playbook.maturity <= 4)
      && !(typeof playbook.maturity === "string" && /^(?:1|2|3|4|level [1-4]|basic|correlated|contextual|advanced)$/i.test(playbook.maturity.trim()))) {
    add(`${path}.maturity`, "must identify maturity level 1 through 4");
  }
  stringValue(playbook.status, `${path}.status`, add, { allowed: STATUSES, max: 20 });
  validateScores(playbook, path, add);
  validateContentSections(playbook.content_sections, `${path}.content_sections`, add);
  const searchTerms = stringArray(playbook.search_terms, `${path}.search_terms`, add, { min: 3, max: 2_000 });
  if (id && !searchTerms.some(term => term.toLowerCase() === id.toLowerCase())) {
    add(`${path}.search_terms`, "must include the playbook ID");
  }
  if (playbook.url != null && playbook.url !== "") {
    try {
      const url = new URL(playbook.url);
      if (url.protocol !== "https:") add(`${path}.url`, "must use HTTPS");
      if (kind === "technique" && url.hostname !== "attack.mitre.org") add(`${path}.url`, "technique references must use attack.mitre.org");
    } catch { add(`${path}.url`, "must be a valid URL"); }
  }
  if (typeof playbook.html === "string" && DANGEROUS_MARKUP.test(playbook.html)) {
    add(`${path}.html`, "contains markup forbidden by the runtime sanitizer contract");
  }
  return { id, kind, description };
}

export function validateDataset(data) {
  const collector = makeCollector();
  const add = collector.add.bind(collector);
  const stats = { total: 0, technique: 0, operational: 0, platform: 0 };

  if (!plainObject(data)) {
    add("data", "root must be an object");
    return { errors: collector.finish(), stats };
  }
  inspectJsonSafety(data, "data", add);
  if (!plainObject(data.meta)) add("data.meta", "must be an object");
  const meta = plainObject(data.meta) ? data.meta : {};
  stringValue(meta.schema_version, "data.meta.schema_version", add, { allowed: new Set([SCHEMA_VERSION]) });
  stringValue(meta.content_version, "data.meta.content_version", add, { allowed: new Set([SCHEMA_VERSION]) });
  const generated = stringValue(meta.generated ?? meta.last_updated, "data.meta.generated", add, { pattern: /^\d{4}-\d{2}-\d{2}$/ });
  if (generated && Number.isNaN(Date.parse(`${generated}T00:00:00Z`))) add("data.meta.generated", "must be a valid calendar date");
  const tacticOrder = stringArray(meta.tactic_order, "data.meta.tactic_order", add, { min: TACTICS.length, max: TACTICS.length });
  TACTICS.forEach(tactic => {
    if (!tacticOrder.includes(tactic)) add("data.meta.tactic_order", `missing Enterprise tactic ${tactic}`);
  });
  const knownTactics = new Set(tacticOrder);

  if (!Array.isArray(data.playbooks)) {
    add("data.playbooks", "must be an array");
    return { errors: collector.finish(), stats };
  }
  if (!data.playbooks.length) add("data.playbooks", "must contain at least one playbook");
  stats.total = data.playbooks.length;
  const ids = new Set();
  const descriptions = new Map();
  data.playbooks.forEach((playbook, index) => {
    const summary = validatePlaybook(playbook, index, add, knownTactics);
    if (!summary) return;
    if (ids.has(summary.id)) add(`data.playbooks[${index}].id`, `duplicate ID ${summary.id}`);
    ids.add(summary.id);
    if (KINDS.has(summary.kind)) stats[summary.kind]++;
    const descriptionKey = summary.description.toLowerCase().replace(/\s+/g, " ");
    if (descriptionKey.length >= 40) {
      if (descriptions.has(descriptionKey)) add(`data.playbooks[${index}].description`, `duplicates ${descriptions.get(descriptionKey)}`);
      else descriptions.set(descriptionKey, summary.id);
    }
  });

  if (!plainObject(meta.counts)) add("data.meta.counts", "must be an object");
  else Object.entries(stats).forEach(([key, expected]) => {
    if (meta.counts[key] !== expected) add(`data.meta.counts.${key}`, `is ${meta.counts[key]}, expected ${expected}`);
  });

  return { errors: collector.finish(), stats };
}

function validateManifest(manifest, add) {
  if (!plainObject(manifest)) {
    add("manifest", "must be an object");
    return;
  }
  ["name", "short_name", "description", "id", "start_url", "scope", "display", "background_color", "theme_color"].forEach(key => {
    stringValue(manifest[key], `manifest.${key}`, add, { max: 500 });
  });
  if (manifest.id !== "./" || manifest.start_url !== "./" || manifest.scope !== "./") {
    add("manifest", "id, start_url, and scope must all be relative './' values for GitHub Pages");
  }
  if (!Array.isArray(manifest.icons) || !manifest.icons.length) add("manifest.icons", "must contain an install icon");
  else {
    const hasMaskable = manifest.icons.some(icon => plainObject(icon)
      && icon.src === "assets/icon.svg" && icon.type === "image/svg+xml"
      && String(icon.purpose).split(/\s+/).includes("maskable"));
    if (!hasMaskable) add("manifest.icons", "must include the local maskable SVG icon");
  }
}

function assertSyntax(source, path, add) {
  try { new Function(source); } catch (error) { add(path, `JavaScript syntax error: ${error.message}`); }
}

async function readProjectFiles(add) {
  const paths = [
    "data/playbooks.json", "data/playbooks.schema.json", "index.html", "assets/core.js", "assets/app.js", "assets/style.css",
    "assets/icon.svg", "manifest.webmanifest", "service-worker.js", "standalone.html"
  ];
  const entries = await Promise.all(paths.map(async path => {
    try { return [path, await readFile(new URL(path, root), "utf8")]; }
    catch (error) { add(path, `cannot be read: ${error.message}`); return [path, ""]; }
  }));
  return Object.fromEntries(entries);
}

export async function validateProject() {
  const collector = makeCollector();
  const add = collector.add.bind(collector);
  const files = await readProjectFiles(add);
  let data;
  try { data = JSON.parse(files["data/playbooks.json"]); }
  catch (error) { add("data/playbooks.json", `invalid JSON: ${error.message}`); }
  const dataset = data ? validateDataset(data) : { errors: [], stats: { total: 0 } };
  dataset.errors.forEach(error => add("dataset", error));

  let manifest;
  try { manifest = JSON.parse(files["manifest.webmanifest"]); }
  catch (error) { add("manifest.webmanifest", `invalid JSON: ${error.message}`); }
  if (manifest) validateManifest(manifest, add);

  let schema;
  try { schema = JSON.parse(files["data/playbooks.schema.json"]); }
  catch (error) { add("data/playbooks.schema.json", `invalid JSON: ${error.message}`); }
  if (schema) {
    if (!plainObject(schema) || typeof schema.$schema !== "string") add("data/playbooks.schema.json", "must declare a JSON Schema dialect");
    const requiredArrays = [];
    const visit = (value, depth = 0) => {
      if (depth > 20 || value == null) return;
      if (Array.isArray(value)) return value.forEach(item => visit(item, depth + 1));
      if (!plainObject(value)) return;
      if (Array.isArray(value.required) && value.required.includes("id") && value.required.includes("schema_version")) requiredArrays.push(value.required);
      Object.values(value).forEach(item => visit(item, depth + 1));
    };
    visit(schema);
    if (!requiredArrays.length) add("data/playbooks.schema.json", "must define the v4 playbook required-field contract");
    else REQUIRED_PLAYBOOK_FIELDS.forEach(field => {
      if (!requiredArrays.some(required => required.includes(field))) add("data/playbooks.schema.json", `playbook schema does not require ${field}`);
    });
  }

  const index = files["index.html"];
  const core = files["assets/core.js"];
  const app = files["assets/app.js"];
  const css = files["assets/style.css"];
  const serviceWorker = files["service-worker.js"];
  const requiredIds = [
    "q", "kind", "technique", "platform", "source", "severity", "maturity", "status", "sort",
    "matrix", "list", "table", "dashboard", "panel", "p-body", "result-count", "update-banner", "command-palette"
  ];
  requiredIds.forEach(id => {
    if (!new RegExp(`\\bid=["']${id}["']`).test(index)) add("index.html", `missing #${id}`);
  });
  const coreAt = index.search(/assets\/core\.js/);
  const appAt = index.search(/assets\/app\.js/);
  if (coreAt < 0 || appAt < 0 || coreAt > appAt) add("index.html", "must load assets/core.js before assets/app.js");
  if (!/http-equiv=["']Content-Security-Policy["']/i.test(index)) add("index.html", "strict Content Security Policy meta is missing");
  if (/(?:src|href)=["']https?:\/\//i.test(index + css)) add("application", "unexpected remote runtime dependency found");
  if (/fonts\.googleapis\.com|fonts\.gstatic\.com/i.test(index + css)) add("application", "external font dependency found");
  if (!/\.column-header\s*\{[^}]*\btop:\s*0\s*;/s.test(css)) {
    add("assets/style.css", "matrix column headers must use a zero sticky inset so they do not overlap the first card row");
  }
  if (!/\.column-header h2\s*\{[^}]*\bwhite-space:\s*nowrap\s*;/s.test(css)) {
    add("assets/style.css", "matrix tactic labels must preserve a consistent single-line header height");
  }
  if (!core.includes('"use strict"') || !app.includes('"use strict"') || !serviceWorker.includes('"use strict"')) {
    add("application", "core, application, and service-worker scripts must use strict mode");
  }
  assertSyntax(core, "assets/core.js", add);
  assertSyntax(app, "assets/app.js", add);
  assertSyntax(serviceWorker, "service-worker.js", add);
  if (!core.includes("globalThis.PlaybookCore")) add("assets/core.js", "PlaybookCore global export is missing");
  if (!app.includes("__ATTACK_PLAYBOOK_STANDALONE__")) add("assets/app.js", "standalone service-worker guard is missing");

  ["4.0.0", "CACHE_PREFIX", "assets/core.js", "assets/icon.svg", "request.mode === \"navigate\"", "SKIP_WAITING", "event.waitUntil"].forEach(marker => {
    if (!serviceWorker.includes(marker)) add("service-worker.js", `missing required PWA control: ${marker}`);
  });
  if (/cache\.put\(event\.request/i.test(serviceWorker)) add("service-worker.js", "must not cache arbitrary request URLs");
  if (/caches\.match\(["']\.\/index\.html["']\)/i.test(serviceWorker)) add("service-worker.js", "must not use index.html as a fallback for every request type");

  if (files["assets/icon.svg"] && !/<svg\b[\s\S]*viewBox=["']0 0 512 512["']/i.test(files["assets/icon.svg"])) {
    add("assets/icon.svg", "must be a scalable 512-by-512 manifest icon");
  }

  if (index && css && core && app && files["data/playbooks.json"]) {
    try {
      const expected = renderStandalone({ html: index, css, core, app, data: files["data/playbooks.json"] });
      if (files["standalone.html"] !== expected) add("standalone.html", "is stale; run npm run build");
    } catch (error) {
      add("standalone.html", `cannot be rendered deterministically: ${error.message}`);
    }
  }

  return { errors: collector.finish(), stats: dataset.stats };
}

const isMain = process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (isMain) {
  validateProject().then(({ errors, stats }) => {
    if (errors.length) {
      console.error(`Validation failed with ${errors.length} error(s):\n- ${errors.join("\n- ")}`);
      process.exitCode = 1;
      return;
    }
    console.log(`Validated ${stats.total} v4 playbooks, strict schema, application assets, PWA, and deterministic standalone build.`);
  }).catch(error => {
    console.error(`Validation failed unexpectedly: ${error.stack || error.message}`);
    process.exitCode = 1;
  });
}
