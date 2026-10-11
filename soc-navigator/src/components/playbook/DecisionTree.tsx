import { CheckCircle2, CircleHelp, GitBranch, RotateCcw, XCircle } from 'lucide-react';
import { evaluateDecision } from '../../lib/investigations/model';
import type { Answer } from '../../lib/investigations/model';
import { OUTCOME_INFO } from '../../lib/playbooks/outcomes';
import type { Playbook } from '../../lib/playbooks/schema';
import { OutcomeBadge } from '../badges';
import { Button, Callout, cx } from '../ui';

const ANSWER_LABEL: Record<Answer, string> = { yes: 'Yes', no: 'No', unknown: 'Cannot determine' };

/**
 * Interactive Yes / No / Cannot-determine decision cards. The outcome is a recommendation:
 * applying it to an investigation is a separate, explicit analyst action.
 */
export function DecisionTree({
  playbook,
  answers,
  onAnswer,
  onReset,
  onApply,
  applied,
}: {
  playbook: Playbook;
  answers: { nodeId: string; answer: Answer }[];
  onAnswer: (nodeId: string, answer: Answer) => void;
  onReset: () => void;
  onApply?: (outcome: NonNullable<ReturnType<typeof evaluateDecision>['outcome']>, guidance: string) => void;
  applied?: boolean;
}) {
  const state = evaluateDecision(playbook, answers);
  return (
    <div className="space-y-2">
      {state.path.map((p, i) => (
        <div key={p.nodeId} className="rounded-md border border-line bg-panel-2 p-3">
          <div className="flex items-start gap-2">
            <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-panel-3 text-[11px] text-muted">{i + 1}</span>
            <div className="min-w-0 flex-1">
              <p className="text-sm text-fg">{p.question}</p>
              <p className="mt-1 flex flex-wrap items-center gap-2 text-xs">
                <span className={cx('inline-flex items-center gap-1 font-semibold', p.answer === 'yes' ? 'text-ok' : p.answer === 'no' ? 'text-bad' : 'text-info')}>
                  {p.answer === 'yes' ? <CheckCircle2 className="h-3.5 w-3.5" aria-hidden /> : p.answer === 'no' ? <XCircle className="h-3.5 w-3.5" aria-hidden /> : <CircleHelp className="h-3.5 w-3.5" aria-hidden />}
                  {ANSWER_LABEL[p.answer]}
                </span>
                <span className="text-muted">{p.branch.guidance}</span>
              </p>
            </div>
            <Button size="sm" variant="ghost" onClick={() => onAnswer(p.nodeId, p.answer === 'yes' ? 'no' : 'yes')} aria-label={`Change answer to question ${i + 1}`}>
              Change
            </Button>
          </div>
        </div>
      ))}

      {state.current && (
        <div className="rounded-md border border-accent/50 bg-accent/5 p-3" aria-live="polite">
          <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold tracking-wide text-accent uppercase">
            <GitBranch className="h-3.5 w-3.5" aria-hidden /> Question {state.path.length + 1}
          </p>
          <p className="font-medium text-fg-strong">{state.current.question}</p>
          {state.current.help && <p className="mt-1 text-sm text-muted">{state.current.help}</p>}
          <div className="mt-3 flex flex-wrap gap-2">
            <Button variant="secondary" icon={<CheckCircle2 className="h-4 w-4 text-ok" aria-hidden />} onClick={() => onAnswer(state.current!.id, 'yes')}>
              Yes
            </Button>
            <Button variant="secondary" icon={<XCircle className="h-4 w-4 text-bad" aria-hidden />} onClick={() => onAnswer(state.current!.id, 'no')}>
              No
            </Button>
            <Button variant="secondary" icon={<CircleHelp className="h-4 w-4 text-info" aria-hidden />} onClick={() => onAnswer(state.current!.id, 'unknown')}>
              Cannot determine
            </Button>
          </div>
        </div>
      )}

      {state.outcome && (
        <div aria-live="polite">
          <Callout
            tone={OUTCOME_INFO[state.outcome].tone === 'success' ? 'success' : OUTCOME_INFO[state.outcome].tone === 'danger' ? 'danger' : OUTCOME_INFO[state.outcome].tone === 'info' ? 'info' : 'warning'}
            title={
              <span className="flex flex-wrap items-center gap-2">
                Recommended outcome: <OutcomeBadge outcome={state.outcome} />
              </span>
            }
          >
            <p className="text-fg">{state.outcomeGuidance}</p>
            <p className="mt-1">{OUTCOME_INFO[state.outcome].summary}</p>
            {onApply && (
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Button size="sm" variant="primary" onClick={() => onApply(state.outcome!, state.outcomeGuidance ?? '')} disabled={applied}>
                  {applied ? 'Applied to investigation' : `Apply: set disposition and status to "${OUTCOME_INFO[state.outcome].suggestedStatus}"`}
                </Button>
                <span className="text-xs text-faint">You remain responsible for the disposition; this does not close or escalate anything automatically.</span>
              </div>
            )}
          </Callout>
        </div>
      )}

      {(state.path.length > 0 || state.outcome) && (
        <Button size="sm" variant="ghost" icon={<RotateCcw className="h-3.5 w-3.5" aria-hidden />} onClick={onReset}>
          Restart decision tree
        </Button>
      )}
    </div>
  );
}
