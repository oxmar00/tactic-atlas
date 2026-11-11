import { formatDuration, isActive, progressOf, slaState } from './investigations/model';
import type { Investigation, Severity } from './investigations/model';
import type { Playbook } from './playbooks/schema';
import { mdText } from './report';

const SEV_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low'];

/** Shift-handover summary of open investigations, most urgent first. */
export function buildHandover(
  investigations: readonly Investigation[],
  playbookById: Map<string, Playbook>,
  sla: Record<Severity, number>,
  analyst: string,
  now = new Date(),
): string {
  const open = investigations
    .filter(isActive)
    .map((inv) => ({ inv, sla: slaState(inv, sla, now) }))
    .sort((a, b) => SEV_ORDER.indexOf(a.inv.severity) - SEV_ORDER.indexOf(b.inv.severity) || (a.sla.remainingMinutes ?? 0) - (b.sla.remainingMinutes ?? 0));
  const out = [`# Shift handover - ${now.toISOString().slice(0, 16).replace('T', ' ')} UTC`, '', `Prepared by: ${mdText(analyst)}`, '', `Open investigations: ${open.length} (${open.filter((o) => o.sla.breached).length} past SLA target, ${open.filter((o) => o.inv.status === 'Escalation Recommended').length} awaiting escalation)`, ''];
  if (open.length === 0) out.push('_No open investigations._');
  for (const { inv, sla: s } of open) {
    const p = progressOf(inv, playbookById.get(inv.playbookId));
    out.push(`## ${mdText(inv.id)} - ${mdText(inv.title)}${inv.demo ? ' (DEMO)' : ''}`);
    out.push('');
    out.push(`- **Severity / status:** ${inv.severity} / ${inv.status}`);
    out.push(`- **Alert:** ${mdText(inv.alertRef)} - playbook ${mdText(inv.playbookId)}`);
    out.push(`- **Age:** ${formatDuration(s.ageMinutes)} (target ${formatDuration(s.targetMinutes)}${s.breached ? ', **past target**' : `, ${formatDuration(s.remainingMinutes ?? 0)} left`})`);
    out.push(`- **Progress:** ${p.stepsDone}/${p.stepsTotal} steps, ${p.requiredEvidenceDone}/${p.requiredEvidenceTotal} required evidence, decision ${p.decisionComplete ? 'complete' : 'pending'}`);
    out.push(`- **Assessment:** ${inv.assessment.suspicion} (${inv.assessment.confidence} confidence); disposition: ${inv.disposition.recommendation}`);
    if (p.pendingSteps.length) out.push(`- **Next step:** ${mdText(p.pendingSteps[0])}`);
    if (inv.missingInfo.length) out.push(`- **Waiting on:** ${inv.missingInfo.map((m) => mdText(m.text)).join('; ')}`);
    if (inv.openQuestions.length) out.push(`- **Open questions:** ${inv.openQuestions.map((m) => mdText(m.text)).join('; ')}`);
    out.push('');
  }
  out.push('---', '', '_Generated from investigation records in this browser. Verify status in your case system._', '');
  return out.join('\n');
}
