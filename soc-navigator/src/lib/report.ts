import { OUTCOME_INFO } from './playbooks/outcomes';
import type { Playbook } from './playbooks/schema';
import { evaluateDecision, progressOf, sortedTimeline } from './investigations/model';
import type { Investigation } from './investigations/model';

/**
 * Tier 2 handoff report. Built only from what the analyst recorded plus playbook metadata;
 * it never claims that queries were executed or that ATT&CK techniques are confirmed.
 */

export interface HandoffReport {
  format: 'soc-navigator-handoff';
  formatVersion: 1;
  generatedAt: string;
  demo: boolean;
  investigation: {
    id: string;
    title: string;
    alertRef: string;
    alertSource: string;
    severity: string;
    status: string;
    analyst: string;
    createdAt: string;
    updatedAt: string;
  };
  playbook: { id: string; version: string; title: string; reviewStatus: string } | null;
  executiveSummary: string;
  alertContext: { label: string; value: string }[];
  affectedUsers: string[];
  affectedAssets: string[];
  timeline: { time: string; description: string; source: string }[];
  stepsCompleted: { title: string; completedAt: string | null; notes: string }[];
  stepsPending: string[];
  evidence: { label: string; value: string; required: boolean }[];
  techniques: { id: string; name: string; note: string }[];
  benignExplanationsConsidered: string[];
  indicatorsSupportingSuspicion: string[];
  observations: string[];
  assessment: { suspicion: string; confidence: string; rationale: string };
  decisionPath: { question: string; answer: string }[];
  decisionOutcome: string | null;
  missingTelemetryAndLimitations: string[];
  recommendedNextSteps: string;
  reasonForEscalation: string;
  disposition: { recommendation: string; rationale: string };
  escalationRecipient: string;
  outstandingQuestions: string[];
  analystNotes: string;
  statements: string[];
}

const ALERT_FIELDS = ['alert_id', 'detection_name', 'event_time'];
const USER_FIELDS = ['username', 'targeted_accounts', 'exposed_accounts'];
const ASSET_FIELDS = ['hostname', 'source_host', 'affected_assets', 'src_ip'];

function lines(value: string | undefined): string[] {
  return (value ?? '')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

function unique(xs: string[]): string[] {
  return [...new Set(xs)];
}

export function autoSummary(inv: Investigation, playbook: Playbook | undefined): string {
  const p = progressOf(inv, playbook);
  const detection = inv.evidence.detection_name?.trim();
  const parts = [
    `${inv.severity}-severity alert ${inv.alertRef || '(no reference)'}${detection ? ` ("${detection.split('\n')[0]}")` : ''} was investigated using playbook ${inv.playbookId} v${inv.playbookVersion}.`,
    `Analyst assessment: ${inv.assessment.suspicion} (${inv.assessment.confidence} confidence).`,
    `Recommended disposition: ${inv.disposition.recommendation}.`,
  ];
  if (playbook) {
    parts.push(`${p.stepsDone} of ${p.stepsTotal} playbook steps completed; ${p.requiredEvidenceTotal - p.requiredEvidenceDone} required evidence item(s) not recorded.`);
  }
  return parts.join(' ');
}

export function buildReport(
  inv: Investigation,
  playbook: Playbook | undefined,
  techniqueName: (id: string) => string | undefined = () => undefined,
  now = new Date(),
): HandoffReport {
  const progress = progressOf(inv, playbook);
  const labelOf = new Map((playbook?.evidence ?? []).map((e) => [e.id, e]));
  const decision = playbook ? evaluateDecision(playbook, inv.decisionPath) : null;

  const evidence = Object.entries(inv.evidence)
    .filter(([, v]) => v.trim())
    .map(([id, value]) => ({ label: labelOf.get(id)?.label ?? id, value: value.trim(), required: labelOf.get(id)?.required ?? false }));

  const missing = [
    ...inv.missingInfo.map((m) => m.text),
    ...progress.missingRequiredEvidence.map((label) => `Required evidence not recorded: ${label}`),
    ...inv.decisionPath.filter((d) => d.answer === 'unknown').map((d) => `Decision question could not be answered: ${playbook?.decisionTree.nodes.find((n) => n.id === d.nodeId)?.question ?? d.nodeId}`),
  ];

  const statements = [
    'This report contains analyst-recorded observations. SOC Navigator did not execute any query or connect to any SIEM, EDR, or identity system.',
    'ATT&CK techniques listed are investigation hypotheses mapped by the playbook and analyst; they are not confirmed by the presence of an alert alone.',
    'Missing telemetry is not evidence that activity did not occur.',
  ];
  if (playbook && playbook.status !== 'Approved') statements.push(`Playbook ${playbook.id} is in ${playbook.status} status${playbook.aiAssisted ? ' and contains AI-assisted content' : ''}; guidance has not been fully approved.`);
  if (inv.demo) statements.unshift('DEMO DATA: this investigation is fictional sample data, not real organizational telemetry.');

  return {
    format: 'soc-navigator-handoff',
    formatVersion: 1,
    generatedAt: now.toISOString(),
    demo: inv.demo,
    investigation: {
      id: inv.id,
      title: inv.title,
      alertRef: inv.alertRef,
      alertSource: inv.alertSource,
      severity: inv.severity,
      status: inv.status,
      analyst: inv.analyst,
      createdAt: inv.createdAt,
      updatedAt: inv.updatedAt,
    },
    playbook: playbook ? { id: playbook.id, version: playbook.version, title: playbook.title, reviewStatus: playbook.status } : null,
    executiveSummary: inv.executiveSummary.trim() || autoSummary(inv, playbook),
    alertContext: [
      { label: 'Alert reference', value: inv.alertRef },
      { label: 'Alert source', value: inv.alertSource || 'Not recorded' },
      ...ALERT_FIELDS.filter((f) => inv.evidence[f]?.trim()).map((f) => ({ label: labelOf.get(f)?.label ?? f, value: inv.evidence[f].trim() })),
    ],
    affectedUsers: unique(USER_FIELDS.flatMap((f) => lines(inv.evidence[f]))),
    affectedAssets: unique(ASSET_FIELDS.flatMap((f) => lines(inv.evidence[f]))),
    timeline: sortedTimeline(inv).map(({ time, description, source }) => ({ time, description, source })),
    stepsCompleted: (playbook?.steps ?? [])
      .filter((s) => inv.steps[s.id]?.done)
      .map((s) => ({ title: s.title, completedAt: inv.steps[s.id]?.completedAt ?? null, notes: inv.steps[s.id]?.notes ?? '' })),
    stepsPending: progress.pendingSteps,
    evidence,
    techniques: inv.relatedTechniques.map((t) => ({ id: t.id, name: techniqueName(t.id) ?? '', note: t.note })),
    benignExplanationsConsidered: inv.findings.filter((f) => f.kind === 'contradicting').map((f) => f.text),
    indicatorsSupportingSuspicion: inv.findings.filter((f) => f.kind === 'supporting').map((f) => f.text),
    observations: inv.findings.filter((f) => f.kind === 'observation').map((f) => f.text),
    assessment: { ...inv.assessment },
    decisionPath: (decision?.path ?? []).map((p) => ({ question: p.question, answer: p.answer === 'unknown' ? 'Cannot determine' : p.answer === 'yes' ? 'Yes' : 'No' })),
    decisionOutcome: decision?.outcome ? OUTCOME_INFO[decision.outcome].label : null,
    missingTelemetryAndLimitations: unique(missing),
    recommendedNextSteps: inv.escalation.nextSteps.trim(),
    reasonForEscalation: inv.escalation.reason.trim(),
    disposition: { ...inv.disposition },
    escalationRecipient: inv.escalation.recipient.trim(),
    outstandingQuestions: inv.openQuestions.map((q) => q.text),
    analystNotes: inv.notes.trim(),
    statements,
  };
}

// --- Markdown ----------------------------------------------------------------------------

/** Neutralizes raw HTML in free text so exported Markdown cannot render active content. */
export function mdText(text: string): string {
  return text.replace(/&(?=[a-zA-Z#][a-zA-Z0-9]*;)/g, '&amp;').replace(/</g, '&lt;');
}

/** Code fence longer than any backtick run inside the content. */
export function mdFence(text: string): string {
  const longest = Math.max(0, ...[...text.matchAll(/`+/g)].map((m) => m[0].length));
  const fence = '`'.repeat(Math.max(3, longest + 1));
  return `${fence}text\n${text}\n${fence}`;
}

function bullets(items: string[], empty = '_None recorded._'): string {
  return items.length ? items.map((i) => `- ${mdText(i).replace(/\n/g, '\n  ')}`).join('\n') : empty;
}

function needsFence(value: string): boolean {
  return value.includes('\n') || /[`*_<>|\\]/.test(value) || value.length > 120;
}

export function reportToMarkdown(r: HandoffReport): string {
  const out: string[] = [];
  out.push(`# Tier 2 Handoff - ${mdText(r.investigation.id)}`);
  if (r.demo) out.push('> **DEMO DATA** - fictional sample investigation. Not real telemetry.');
  out.push('');
  out.push(`| Field | Value |\n| --- | --- |`);
  const row = (k: string, v: string) => out.push(`| ${k} | ${mdText(v || '-').replace(/\|/g, '\\|').replace(/\n/g, ' ')} |`);
  row('Title', r.investigation.title);
  row('Alert reference', r.investigation.alertRef);
  row('Severity', r.investigation.severity);
  row('Status', r.investigation.status);
  row('Analyst', r.investigation.analyst);
  row('Created', r.investigation.createdAt);
  row('Last updated', r.investigation.updatedAt);
  row('Playbook', r.playbook ? `${r.playbook.id} v${r.playbook.version} - ${r.playbook.title} (${r.playbook.reviewStatus})` : 'Not available');
  row('Report generated', r.generatedAt);

  out.push('', '## Executive summary', '', mdText(r.executiveSummary));
  out.push('', '## Alert context', '');
  for (const c of r.alertContext) out.push(needsFence(c.value) ? `**${mdText(c.label)}**\n\n${mdFence(c.value)}` : `- **${mdText(c.label)}:** ${mdText(c.value)}`);
  out.push('', '## Affected users and assets', '', '**Users / accounts**', '', bullets(r.affectedUsers), '', '**Assets / systems**', '', bullets(r.affectedAssets));
  out.push('', '## Timeline of events', '');
  out.push(r.timeline.length ? r.timeline.map((t) => `- **${mdText(t.time || 'time unknown')}** - ${mdText(t.description)}${t.source ? ` _(source: ${mdText(t.source)})_` : ''}`).join('\n') : '_No timeline entries recorded._');
  out.push('', '## Investigation steps completed', '');
  out.push(
    r.stepsCompleted.length
      ? r.stepsCompleted.map((s) => `- [x] ${mdText(s.title)}${s.completedAt ? ` _(completed ${s.completedAt})_` : ''}${s.notes.trim() ? `\n  - Notes: ${mdText(s.notes.trim()).replace(/\n/g, ' ')}` : ''}`).join('\n')
      : '_No steps marked complete._',
  );
  if (r.stepsPending.length) out.push('', '**Not completed:**', '', r.stepsPending.map((s) => `- [ ] ${mdText(s)}`).join('\n'));
  out.push('', '## Evidence collected', '');
  out.push(r.evidence.length ? r.evidence.map((e) => (needsFence(e.value) ? `**${mdText(e.label)}**\n\n${mdFence(e.value)}` : `- **${mdText(e.label)}:** ${mdText(e.value)}`)).join('\n\n') : '_No evidence recorded._');
  out.push('', '## Relevant ATT&CK techniques (hypotheses)', '');
  out.push(bullets(r.techniques.map((t) => `${t.id}${t.name ? ` ${t.name}` : ''}${t.note ? ` - ${t.note}` : ''}`)));
  out.push('', '## Benign explanations considered', '', bullets(r.benignExplanationsConsidered));
  out.push('', '## Indicators supporting suspicion', '', bullets(r.indicatorsSupportingSuspicion));
  if (r.observations.length) out.push('', '## Other observations', '', bullets(r.observations));
  out.push('', '## Assessment', '', `- **Suspicion:** ${mdText(r.assessment.suspicion)}`, `- **Confidence:** ${mdText(r.assessment.confidence)}`, `- **Rationale:** ${mdText(r.assessment.rationale || 'Not recorded')}`);
  if (r.decisionPath.length) {
    out.push('', '**Decision path**', '', r.decisionPath.map((d, i) => `${i + 1}. ${mdText(d.question)} -> **${d.answer}**`).join('\n'));
    if (r.decisionOutcome) out.push('', `**Decision outcome:** ${mdText(r.decisionOutcome)}`);
  }
  out.push('', '## Missing telemetry and limitations', '', bullets(r.missingTelemetryAndLimitations));
  out.push('', '## Recommended next investigative steps', '', mdText(r.recommendedNextSteps || 'Not recorded.'));
  out.push('', '## Reason for escalation', '', mdText(r.reasonForEscalation || 'Not recorded.'));
  out.push('', '## Disposition', '', `- **Recommendation:** ${mdText(r.disposition.recommendation)}`, `- **Rationale:** ${mdText(r.disposition.rationale || 'Not recorded')}`);
  if (r.escalationRecipient) out.push(`- **Escalated to:** ${mdText(r.escalationRecipient)}`);
  out.push('', '## Outstanding questions', '', bullets(r.outstandingQuestions));
  if (r.analystNotes) out.push('', '## Analyst notes', '', mdFence(r.analystNotes));
  out.push('', '---', '', r.statements.map((s) => `_${mdText(s)}_`).join('\n\n'), '');
  return out.join('\n');
}

export function reportToJson(r: HandoffReport): string {
  return `${JSON.stringify(r, null, 2)}\n`;
}
