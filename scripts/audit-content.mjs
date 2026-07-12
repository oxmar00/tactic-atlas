import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { validateDataset } from "./validate.mjs";

const root = new URL("../", import.meta.url);
const PLACEHOLDER = /\b(?:todo|tbd|fixme|lorem ipsum|add content here|placeholder text|coming soon)\b/i;
const RESPONSE_PHASES = [
  "triage", "investigation", "scoping", "containment", "eradication", "recovery",
  "post_incident", "escalation", "decision_tree", "closure_criteria"
];

function substantive(value) {
  if (typeof value === "string") return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0 && value.some(substantive);
  if (value && typeof value === "object") return Object.values(value).some(substantive);
  return typeof value === "number" || typeof value === "boolean";
}

function flattenStrings(value, output = [], depth = 0) {
  if (depth > 24 || value == null) return output;
  if (typeof value === "string") output.push(value);
  else if (Array.isArray(value)) value.forEach(item => flattenStrings(item, output, depth + 1));
  else if (typeof value === "object") Object.values(value).forEach(item => flattenStrings(item, output, depth + 1));
  return output;
}

function canonicalText(value) {
  return String(value || "").toLowerCase().replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

function increment(object, key) {
  const label = String(key || "unknown");
  object[label] = (object[label] || 0) + 1;
}

function duplicateGroups(entries, minimumLength = 80) {
  const groups = new Map();
  entries.forEach(({ id, value }) => {
    const key = canonicalText(value);
    if (key.length < minimumLength) return;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(id);
  });
  return [...groups.entries()]
    .filter(([, ids]) => new Set(ids).size > 1)
    .map(([text, ids]) => ({ ids: [...new Set(ids)], preview: text.slice(0, 180) }))
    .sort((a, b) => b.ids.length - a.ids.length);
}

function daysOld(date, now) {
  const timestamp = Date.parse(`${date || ""}T00:00:00Z`);
  return Number.isFinite(timestamp) ? Math.floor((now - timestamp) / 86_400_000) : null;
}

export function auditDataset(data, now = Date.now()) {
  const validation = validateDataset(data);
  const playbooks = Array.isArray(data?.playbooks) ? data.playbooks : [];
  const report = {
    schema_version: data?.meta?.schema_version || "unknown",
    content_version: data?.meta?.content_version || "unknown",
    total_playbooks: playbooks.length,
    playbooks_enhanced: 0,
    telemetry_mappings: 0,
    queries: 0,
    validation_procedures: 0,
    response_workflows_complete: 0,
    average_quality_score: 0,
    low_quality_playbooks: [],
    stale_playbooks: [],
    high_risk_gaps: [],
    placeholder_playbooks: [],
    duplicate_descriptions: [],
    duplicate_queries: [],
    severity: {},
    confidence: {},
    maturity: {},
    status: {},
    validation_errors: validation.errors
  };

  let qualityTotal = 0;
  const descriptions = [];
  const queries = [];
  playbooks.forEach(playbook => {
    const telemetryCount = Array.isArray(playbook.telemetry_requirements) ? playbook.telemetry_requirements.length : 0;
    const queryCount = Array.isArray(playbook.queries) ? playbook.queries.length : 0;
    const hasValidation = substantive(playbook.validation);
    const responseComplete = RESPONSE_PHASES.every(phase => substantive(playbook.response?.[phase]));
    const score = Number(playbook.quality_score) || 0;
    const age = daysOld(playbook.lifecycle?.last_reviewed, now);
    const highRisk = ["high", "critical"].includes(String(playbook.severity).toLowerCase());
    const complete = telemetryCount > 0 && queryCount > 0 && hasValidation && responseComplete;

    if (complete) report.playbooks_enhanced++;
    report.telemetry_mappings += telemetryCount;
    report.queries += queryCount;
    if (hasValidation) report.validation_procedures++;
    if (responseComplete) report.response_workflows_complete++;
    qualityTotal += score;
    if (score < 60) report.low_quality_playbooks.push({ id: playbook.id, score });
    if (age == null || age > 365) report.stale_playbooks.push({ id: playbook.id, days: age });
    if (highRisk && (!complete || score < 75)) report.high_risk_gaps.push(playbook.id);
    if (flattenStrings(playbook).some(value => PLACEHOLDER.test(value))) report.placeholder_playbooks.push(playbook.id);
    descriptions.push({ id: playbook.id, value: playbook.description });
    (playbook.queries || []).forEach(query => queries.push({
      id: `${playbook.id}:${query.id || query.name || "query"}`,
      value: query.query || query.code || query.text
    }));
    increment(report.severity, playbook.severity);
    increment(report.confidence, playbook.confidence);
    increment(report.maturity, playbook.maturity);
    increment(report.status, playbook.status);
  });

  report.average_quality_score = playbooks.length
    ? Math.round((qualityTotal / playbooks.length) * 10) / 10
    : 0;
  report.duplicate_descriptions = duplicateGroups(descriptions);
  report.duplicate_queries = duplicateGroups(queries).filter(group => group.ids.length >= 3);

  const blockers = [];
  if (validation.errors.length) blockers.push(`${validation.errors.length} strict validation error(s)`);
  if (report.playbooks_enhanced !== playbooks.length) blockers.push(`${playbooks.length - report.playbooks_enhanced} incomplete playbook(s)`);
  if (report.low_quality_playbooks.length) blockers.push(`${report.low_quality_playbooks.length} playbook(s) below quality score 60`);
  if (report.high_risk_gaps.length) blockers.push(`${report.high_risk_gaps.length} high-risk coverage gap(s)`);
  if (report.placeholder_playbooks.length) blockers.push(`${report.placeholder_playbooks.length} playbook(s) containing placeholders`);
  if (report.duplicate_descriptions.length) blockers.push(`${report.duplicate_descriptions.length} duplicate description group(s)`);
  if (report.duplicate_queries.length) blockers.push(`${report.duplicate_queries.length} query text shared across three or more playbooks`);
  return { report, blockers };
}

async function main() {
  let data;
  try {
    data = JSON.parse(await readFile(new URL("data/playbooks.json", root), "utf8"));
  } catch (error) {
    console.error(`Content audit failed: ${error.message}`);
    process.exitCode = 1;
    return;
  }
  const { report, blockers } = auditDataset(data);
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify({ ...report, blockers }, null, 2));
  } else {
    console.log([
      `Content audit v${report.content_version} (${report.total_playbooks} playbooks)`,
      `Enhanced: ${report.playbooks_enhanced}/${report.total_playbooks}`,
      `Telemetry mappings: ${report.telemetry_mappings}`,
      `Queries: ${report.queries}`,
      `Validation procedures: ${report.validation_procedures}`,
      `Complete response workflows: ${report.response_workflows_complete}`,
      `Average quality score: ${report.average_quality_score}`,
      `Stale playbooks: ${report.stale_playbooks.length}`,
      `High-risk gaps: ${report.high_risk_gaps.length}`
    ].join("\n"));
  }
  if (blockers.length) {
    console.error(`Content audit failed:\n- ${blockers.join("\n- ")}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main();
