import { describe, expect, it } from 'vitest';
import { STARTER_PLAYBOOKS } from '../src/data/playbooks';
import {
  addFinding,
  addListItem,
  addTimelineEntry,
  answerDecision,
  createInvestigation,
  setEvidence,
  setStepDone,
  update,
} from '../src/lib/investigations/model';
import type { Playbook } from '../src/lib/playbooks/schema';
import { buildReport, mdFence, mdText, reportToJson, reportToMarkdown } from '../src/lib/report';

const pb = STARTER_PLAYBOOKS.find((p) => p.id === 'PB-PWSH-001') as Playbook;
const now = new Date('2026-10-10T15:00:00Z');

function sample() {
  let inv = createInvestigation({ playbook: pb, alertRef: 'ALERT-42', analyst: 'analyst.one', severity: 'High', now, random: () => 0.3 });
  inv = setEvidence(inv, 'hostname', 'WS-01');
  inv = setEvidence(inv, 'username', 'CORP\\jdoe');
  inv = setEvidence(inv, 'command_line', 'powershell -enc ``` <script>alert(1)</script>');
  inv = setEvidence(inv, 'detection_name', 'Encoded PowerShell');
  inv = setStepDone(inv, 'capture-command', true, now);
  inv = addFinding(inv, 'supporting', 'Parent is WINWORD.EXE');
  inv = addFinding(inv, 'contradicting', 'Signed admin script exists with similar name');
  inv = addTimelineEntry(inv, { time: '2026-10-10T14:00:00Z', description: 'PowerShell started', source: 'EDR' });
  inv = addListItem(inv, 'missingInfo', 'Script block logging not enabled on WS-01');
  inv = addListItem(inv, 'openQuestions', 'Who opened the document?');
  inv = answerDecision(inv, pb, pb.decisionTree.start, 'unknown');
  inv = update(inv, 'escalation', { reason: 'Unexplained encoded PowerShell from Office', recipient: 'Tier 2 on-call', nextSteps: 'Retrieve 4104 logs', escalatedAt: null });
  return inv;
}

describe('handoff report', () => {
  const inv = sample();
  const report = buildReport(inv, pb, (id) => (id === 'T1059' ? 'Command and Scripting Interpreter' : undefined), now);

  it('includes the required handoff sections from recorded data', () => {
    expect(report.investigation).toMatchObject({ id: inv.id, alertRef: 'ALERT-42', severity: 'High' });
    expect(report.affectedUsers).toEqual(['CORP\\jdoe']);
    expect(report.affectedAssets).toEqual(['WS-01']);
    expect(report.stepsCompleted.map((s) => s.title)).toEqual([pb.steps[0].title]);
    expect(report.stepsPending).toHaveLength(pb.steps.length - 1);
    expect(report.indicatorsSupportingSuspicion).toEqual(['Parent is WINWORD.EXE']);
    expect(report.benignExplanationsConsidered).toEqual(['Signed admin script exists with similar name']);
    expect(report.timeline[0].description).toBe('PowerShell started');
    expect(report.techniques[0]).toMatchObject({ id: 'T1059', name: 'Command and Scripting Interpreter' });
    expect(report.reasonForEscalation).toBe('Unexplained encoded PowerShell from Office');
    expect(report.recommendedNextSteps).toBe('Retrieve 4104 logs');
    expect(report.outstandingQuestions).toEqual(['Who opened the document?']);
    expect(report.executiveSummary).toMatch(/ALERT-42/);
  });

  it('lists missing telemetry, unanswered decisions, and missing required evidence', () => {
    const text = report.missingTelemetryAndLimitations.join('\n');
    expect(text).toContain('Script block logging not enabled');
    expect(text).toContain('Required evidence not recorded');
    expect(text).toContain('could not be answered');
  });

  it('states honestly that nothing was executed and the playbook is a draft', () => {
    expect(report.statements.join(' ')).toMatch(/did not execute any query/);
    expect(report.statements.join(' ')).toMatch(/Draft status/);
  });

  it('markdown fences untrusted command lines and neutralizes HTML', () => {
    const md = reportToMarkdown(report);
    expect(md).toContain('# Tier 2 Handoff');
    const outsideFences = md.replace(/(`{3,})text\n[\s\S]*?\n\1/g, '');
    expect(outsideFences).not.toContain('<');
    expect(md).toContain('````text\npowershell -enc ``` <script>alert(1)</script>\n````');
    expect(md).toContain('## Missing telemetry and limitations');
    expect(md).toContain('- [x] ' + pb.steps[0].title);
  });

  it('marks demo data', () => {
    const demo = buildReport({ ...inv, demo: true }, pb, undefined, now);
    expect(demo.statements[0]).toMatch(/DEMO DATA/);
    expect(reportToMarkdown(demo)).toContain('**DEMO DATA**');
  });

  it('JSON export round-trips', () => {
    expect(JSON.parse(reportToJson(report))).toEqual(report);
  });

  it('works without the playbook (e.g. deleted local playbook)', () => {
    const r = buildReport(inv, undefined, undefined, now);
    expect(r.playbook).toBeNull();
    expect(reportToMarkdown(r)).toContain('Not available');
  });

  it('helpers', () => {
    expect(mdText('a < b &amp; c')).toBe('a &lt; b &amp;amp; c');
    expect(mdFence('x')).toBe('```text\nx\n```');
  });
});
