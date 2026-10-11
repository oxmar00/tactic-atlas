import type { DecisionBranch, Outcome } from './schema';

export interface OutcomeInfo {
  label: string;
  /** Short recommendation shown on the decision card. */
  summary: string;
  /** Disposition recommendation the analyst can apply to the investigation. */
  disposition: Disposition;
  /** Status the analyst will usually move the investigation to. */
  suggestedStatus: InvestigationStatus;
  tone: 'success' | 'info' | 'warning' | 'danger' | 'neutral';
}

export const INVESTIGATION_STATUSES = [
  'New',
  'In Progress',
  'Awaiting Information',
  'Escalation Recommended',
  'Escalated',
  'Resolved',
] as const;
export type InvestigationStatus = (typeof INVESTIGATION_STATUSES)[number];

export const DISPOSITIONS = [
  'Not yet determined',
  'Close as benign',
  'Close as true positive - no impact observed',
  'Continue investigation',
  'Escalate to Tier 2',
  'Critical incident escalation',
  'Insufficient evidence - escalate per policy',
] as const;
export type Disposition = (typeof DISPOSITIONS)[number];

export const OUTCOME_INFO: Record<Outcome, OutcomeInfo> = {
  benign: {
    label: 'Benign - follow closure procedure',
    summary:
      'Activity is authorized and supported by reliable evidence. Document why it is benign (who approved it, which evidence confirms it) and follow your closure procedure.',
    disposition: 'Close as benign',
    suggestedStatus: 'Resolved',
    tone: 'success',
  },
  contained: {
    label: 'Malicious, no impact observed - remediate and close per procedure',
    summary:
      'The activity is malicious or unwanted, but documented checks show it was blocked or never progressed. Request the remediation your procedure defines (purge, block, reset), record what you checked, and close only if Tier 1 closure is allowed for this case type.',
    disposition: 'Close as true positive - no impact observed',
    suggestedStatus: 'Resolved',
    tone: 'warning',
  },
  investigate: {
    label: 'Suspicious - keep investigating',
    summary:
      'Evidence supports suspicion but does not yet meet an escalation criterion. Continue with related-activity searches and re-check the escalation criteria as findings come in.',
    disposition: 'Continue investigation',
    suggestedStatus: 'In Progress',
    tone: 'warning',
  },
  escalate: {
    label: 'Escalate to Tier 2',
    summary:
      'Findings meet a documented Tier 2 escalation criterion. Complete the evidence checklist and generate the Tier 2 handoff report.',
    disposition: 'Escalate to Tier 2',
    suggestedStatus: 'Escalation Recommended',
    tone: 'danger',
  },
  critical: {
    label: 'Critical - follow incident escalation procedure now',
    summary:
      'An approved critical-incident threshold may be met. Follow your organization\'s incident escalation procedure immediately (phone/page the on-call lead). Do not wait to finish every playbook step.',
    disposition: 'Critical incident escalation',
    suggestedStatus: 'Escalation Recommended',
    tone: 'danger',
  },
  gap: {
    label: 'Evidence gap - document and escalate per policy',
    summary:
      'Telemetry is missing, access is unavailable, or the findings are inconclusive. Record exactly what you could not check and why. Missing data is not proof that nothing happened; escalate when policy requires.',
    disposition: 'Insufficient evidence - escalate per policy',
    suggestedStatus: 'Awaiting Information',
    tone: 'info',
  },
};

/** Default branch used when a node does not define its own "Cannot determine" answer. */
export const DEFAULT_UNKNOWN_BRANCH: DecisionBranch = {
  outcome: 'gap',
  guidance:
    'You cannot answer this with the data or access you have. Record which log, field, or person you would need, mark it under Missing information, and follow the evidence-gap branch.',
};
