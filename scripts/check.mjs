import { readFile } from "node:fs/promises";
import { auditDataset } from "./audit-content.mjs";
import { buildStandalone } from "./build-standalone.mjs";
import { validateProject } from "./validate.mjs";

const root = new URL("../", import.meta.url);
const testOnly = process.argv.includes("--test");

async function validate() {
  console.log("\n==> Strict validation");
  const { errors, stats } = await validateProject();
  if (errors.length) throw new Error(`Validation failed with ${errors.length} error(s):\n- ${errors.join("\n- ")}`);
  console.log(`Validated ${stats.total} v4 playbooks, application assets, PWA, and standalone consistency.`);
}

async function audit() {
  console.log("\n==> Content-quality audit");
  const data = JSON.parse(await readFile(new URL("data/playbooks.json", root), "utf8"));
  const { report, blockers } = auditDataset(data);
  console.log(`Audited ${report.total_playbooks} playbooks; quality ${report.average_quality_score}; ${report.queries} queries; ${report.telemetry_mappings} telemetry mappings.`);
  if (blockers.length) throw new Error(`Content audit failed:\n- ${blockers.join("\n- ")}`);
}

try {
  await validate();
  if (!testOnly) {
    console.log("\n==> Standalone consistency");
    await buildStandalone({ check: true });
    await audit();
  }
  console.log("\n==> Unit tests");
  await import("../tests/core.test.mjs");
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
