import { BadgeCheck, BookOpen, CircleDashed, FileWarning, ShieldCheck } from 'lucide-react';
import type { CoverageLevel } from '../lib/playbooks/library';
import { COVERAGE_LABEL } from '../lib/playbooks/library';
import type { InvestigationStatus } from '../lib/playbooks/outcomes';
import { OUTCOME_INFO } from '../lib/playbooks/outcomes';
import type { Outcome, PlaybookStatus } from '../lib/playbooks/schema';
import type { Severity } from '../lib/investigations/model';
import { Badge } from './ui';
import type { BadgeTone } from './ui';

const PB_STATUS: Record<PlaybookStatus, { tone: BadgeTone; icon: React.ReactNode; title: string }> = {
  Draft: { tone: 'warn', icon: <FileWarning className="h-3 w-3" aria-hidden />, title: 'Not yet reviewed by an authorized person - validate before relying on it.' },
  Reviewed: { tone: 'info', icon: <BadgeCheck className="h-3 w-3" aria-hidden />, title: 'Reviewed by a named reviewer; awaiting formal approval.' },
  Approved: { tone: 'ok', icon: <ShieldCheck className="h-3 w-3" aria-hidden />, title: 'Approved for operational use by a named approver.' },
};

export function PlaybookStatusBadge({ status }: { status: PlaybookStatus }) {
  const s = PB_STATUS[status];
  return (
    <Badge tone={s.tone} title={s.title}>
      {s.icon}
      {status}
    </Badge>
  );
}

const INV_TONE: Record<InvestigationStatus, BadgeTone> = {
  New: 'neutral',
  'In Progress': 'accent',
  'Awaiting Information': 'info',
  'Escalation Recommended': 'bad',
  Escalated: 'violet',
  Resolved: 'ok',
};

export function InvestigationStatusBadge({ status }: { status: InvestigationStatus }) {
  return <Badge tone={INV_TONE[status]}>{status}</Badge>;
}

const SEV_TONE: Record<Severity, BadgeTone> = { Low: 'neutral', Medium: 'info', High: 'warn', Critical: 'bad' };
export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge tone={SEV_TONE[severity]}>{severity}</Badge>;
}

const COV: Record<CoverageLevel, { tone: BadgeTone; icon: React.ReactNode; short: string }> = {
  direct: { tone: 'ok', icon: <BookOpen className="h-3 w-3" aria-hidden />, short: 'Playbook' },
  parent: { tone: 'info', icon: <BookOpen className="h-3 w-3" aria-hidden />, short: 'Parent PB' },
  sub: { tone: 'accent', icon: <BookOpen className="h-3 w-3" aria-hidden />, short: 'Sub PB' },
  none: { tone: 'neutral', icon: <CircleDashed className="h-3 w-3" aria-hidden />, short: 'No PB' },
};

export function CoverageBadge({ level, compact }: { level: CoverageLevel; compact?: boolean }) {
  const c = COV[level];
  return (
    <Badge tone={c.tone} title={COVERAGE_LABEL[level]}>
      {c.icon}
      {compact ? c.short : COVERAGE_LABEL[level]}
    </Badge>
  );
}

const OUT_TONE: Record<Outcome, BadgeTone> = { benign: 'ok', contained: 'warn', investigate: 'warn', escalate: 'bad', critical: 'bad', gap: 'info' };
export function OutcomeBadge({ outcome }: { outcome: Outcome }) {
  return <Badge tone={OUT_TONE[outcome]}>{OUTCOME_INFO[outcome].label}</Badge>;
}
