import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';
import { BookOpen, ExternalLink, Grid3x3, Info, PlayCircle, X } from 'lucide-react';
import { GENERAL_STEPS, TACTIC_GUIDANCE } from '../data/generalGuidance';
import { coverageLevel } from '../lib/playbooks/library';
import type { Playbook } from '../lib/playbooks/schema';
import { useApp } from '../state/AppState';
import { AttackText } from './AttackText';
import { CoverageBadge, PlaybookStatusBadge } from './badges';
import { StartInvestigationDialog } from './StartInvestigationDialog';
import { Badge, Button, Callout, cx } from './ui';

/** Technique details panel, available from every page without navigating away. */
export function TechniqueDrawer() {
  const { techniquePanel, openTechnique, attack, coverage } = useApp();
  const closeRef = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const [startFor, setStartFor] = useState<string | null>(null);
  const [showAllAnalytics, setShowAllAnalytics] = useState(false);

  useEffect(() => {
    if (techniquePanel) {
      if (!returnFocus.current) returnFocus.current = document.activeElement as HTMLElement | null;
      closeRef.current?.focus();
      setShowAllAnalytics(false);
    } else if (returnFocus.current) {
      returnFocus.current.focus?.();
      returnFocus.current = null;
    }
  }, [techniquePanel]);

  useEffect(() => {
    if (!techniquePanel) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !document.querySelector('dialog[open]')) openTechnique(null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [techniquePanel, openTechnique]);

  if (!techniquePanel) return null;
  const index = attack.index;
  const t = index?.get(techniquePanel);

  return (
    <>
      <div className="no-print fixed inset-0 z-40 bg-black/40" aria-hidden onClick={() => openTechnique(null)} />
      <aside
        role="dialog"
        aria-modal="true"
        aria-labelledby="technique-title"
        className="no-print fixed top-0 right-0 z-50 flex h-screen w-[min(44rem,100vw)] flex-col border-l border-line-strong bg-panel shadow-2xl"
      >
        <div className="flex items-start gap-3 border-b border-line px-5 py-3">
          <div className="min-w-0 flex-1">
            {t ? (
              <>
                <p className="font-mono text-xs text-accent">
                  {t.id}
                  {t.isSubtechnique && <span className="ml-2 text-faint">sub-technique</span>}
                </p>
                <h2 id="technique-title" className="text-lg leading-snug font-semibold text-fg-strong">
                  {t.parentId && <span className="font-normal text-muted">{index?.get(t.parentId)?.name}: </span>}
                  {t.name}
                </h2>
              </>
            ) : (
              <h2 id="technique-title" className="text-lg font-semibold">
                {techniquePanel}
              </h2>
            )}
          </div>
          <button ref={closeRef} type="button" onClick={() => openTechnique(null)} className="rounded p-1 text-muted hover:bg-panel-2 hover:text-fg" aria-label="Close technique details">
            <X className="h-5 w-5" aria-hidden />
          </button>
        </div>
        <div className="scroll-thin flex-1 space-y-5 overflow-y-auto px-5 py-4">
          {!t ? (
            <Callout tone="warning" title="Technique not available">
              {attack.status === 'ready'
                ? `${techniquePanel} is not an active technique in ATT&CK ${index?.dataset.meta.version}.`
                : 'ATT&CK data is not loaded. Check Settings and Data Sources.'}
            </Callout>
          ) : (
            (() => {
              const cov = coverage?.get(t.id);
              const level = coverageLevel(cov);
              const direct = cov?.direct ?? [];
              const directIds = new Set(direct.map((p) => p.id));
              const viaParent = (cov?.viaParent ?? []).filter((p) => !directIds.has(p.id));
              const viaSub = (cov?.viaSub ?? []).filter((p) => !directIds.has(p.id) && !viaParent.some((x) => x.id === p.id));
              const startCandidates = [...direct, ...viaParent];
              const parent = index!.parent(t);
              const subs = index!.subtechniques(t.id);
              const guidancePlaybooks = [...direct, ...viaParent];
              const considerations = guidancePlaybooks.flatMap((p) => p.detectionConsiderations.map((c) => ({ c, p: p.id })));
              const gaps = guidancePlaybooks.flatMap((p) => p.visibilityGaps.map((c) => ({ c, p: p.id })));
              const analytics = t.detectionStrategies.flatMap((d) => d.analytics.map((a) => ({ ...a, strategy: d })));
              return (
                <>
                  <div className="flex flex-wrap items-center gap-2">
                    <CoverageBadge level={level} />
                    {startCandidates.length > 0 && (
                      <Button variant="primary" icon={<PlayCircle className="h-4 w-4" aria-hidden />} onClick={() => setStartFor(startCandidates[0].id)}>
                        Start Investigation
                      </Button>
                    )}
                    <Link to={`/matrix?t=${encodeURIComponent(t.id)}`} onClick={() => openTechnique(null)} className="inline-flex items-center gap-1 rounded-md border border-line px-2.5 py-1.5 text-sm text-muted hover:text-fg">
                      <Grid3x3 className="h-4 w-4" aria-hidden />
                      Show in matrix
                    </Link>
                    <a href={t.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded-md border border-line px-2.5 py-1.5 text-sm text-muted hover:text-fg">
                      <ExternalLink className="h-4 w-4" aria-hidden />
                      MITRE ATT&amp;CK page
                      <span className="sr-only">(opens in new tab)</span>
                    </a>
                  </div>

                  <Section title="Associated playbooks">
                    {direct.length + viaParent.length + viaSub.length === 0 ? (
                      <p className="text-muted">No organization playbook covers this technique yet. General guidance is shown below.</p>
                    ) : (
                      <ul className="space-y-1.5">
                        {direct.map((p) => (
                          <PlaybookRow key={p.id} pb={p} relation="Covers this technique" onNavigate={() => openTechnique(null)} />
                        ))}
                        {viaParent.map((p) => (
                          <PlaybookRow key={p.id} pb={p} relation={`Covers parent ${t.parentId}`} onNavigate={() => openTechnique(null)} />
                        ))}
                        {viaSub.map((p) => (
                          <PlaybookRow key={p.id} pb={p} relation="Covers a sub-technique" onNavigate={() => openTechnique(null)} />
                        ))}
                      </ul>
                    )}
                  </Section>

                  <Section title="Official description (MITRE ATT&CK)">
                    <AttackText text={t.description} className="text-sm leading-relaxed text-fg" />
                  </Section>

                  <div className="grid gap-4 sm:grid-cols-2">
                    <Section title="Tactics">
                      <div className="flex flex-wrap gap-1.5">
                        {t.tactics.map((s) => (
                          <Badge key={s} tone="accent">
                            {index!.tacticByShortname.get(s)?.name ?? s}
                          </Badge>
                        ))}
                      </div>
                    </Section>
                    <Section title="Platforms">
                      <div className="flex flex-wrap gap-1.5">
                        {t.platforms.map((p) => (
                          <Badge key={p}>{p}</Badge>
                        ))}
                      </div>
                    </Section>
                  </div>

                  {(parent || subs.length > 0) && (
                    <Section title={parent ? 'Parent technique' : `Sub-techniques (${subs.length})`}>
                      <ul className="space-y-1">
                        {(parent ? [parent] : subs).map((s) => (
                          <li key={s.id} className="flex items-center gap-2">
                            <button type="button" className="font-mono text-xs text-accent hover:underline" onClick={() => openTechnique(s.id)}>
                              {s.id}
                            </button>
                            <span className="text-sm">{s.name}</span>
                            <CoverageBadge level={coverageLevel(coverage?.get(s.id))} compact />
                          </li>
                        ))}
                      </ul>
                    </Section>
                  )}

                  <Section title="Commonly relevant telemetry (from official MITRE analytics)">
                    {t.dataComponents.length === 0 ? (
                      <p className="text-muted">MITRE publishes no detection analytics for this technique in this release.</p>
                    ) : (
                      <>
                        <div className="mb-2 flex flex-wrap gap-1.5">
                          {t.dataComponents.map((d) => (
                            <Badge key={d} tone="info">
                              {d}
                            </Badge>
                          ))}
                        </div>
                        <table className="w-full text-left text-xs">
                          <thead className="text-faint">
                            <tr>
                              <th className="py-1 pr-2 font-medium">Data component</th>
                              <th className="py-1 pr-2 font-medium">Log source</th>
                              <th className="py-1 font-medium">Channel / event</th>
                            </tr>
                          </thead>
                          <tbody>
                            {t.logSources.slice(0, 12).map((l, i) => (
                              <tr key={i} className="border-t border-line align-top">
                                <td className="py-1 pr-2 text-muted">{l.dataComponent}</td>
                                <td className="py-1 pr-2 font-mono break-all">{l.name}</td>
                                <td className="py-1 break-words">{l.channel}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        {t.logSources.length > 12 && <p className="mt-1 text-xs text-faint">{t.logSources.length - 12} more log sources on the MITRE page.</p>}
                      </>
                    )}
                  </Section>

                  <Section title="Detection considerations">
                    {considerations.length > 0 && (
                      <ul className="mb-3 list-disc space-y-1 pl-5 text-sm">
                        {considerations.map(({ c, p }, i) => (
                          <li key={i}>
                            {c} <span className="text-xs text-faint">({p})</span>
                          </li>
                        ))}
                      </ul>
                    )}
                    {analytics.length > 0 ? (
                      <div className="space-y-2">
                        <p className="text-xs text-faint">Official MITRE detection strategy analytics (describe what to look for; they are not rules deployed in your SIEM):</p>
                        {(showAllAnalytics ? analytics : analytics.slice(0, 3)).map((a) => (
                          <div key={a.id} className="rounded-md border border-line bg-panel-2 p-2.5 text-sm">
                            <p className="mb-1 flex flex-wrap items-center gap-2 text-xs text-muted">
                              <a href={a.url} target="_blank" rel="noopener noreferrer" className="font-mono text-accent hover:underline">
                                {a.strategy.id} / {a.id}
                              </a>
                              {a.platforms.map((p) => (
                                <Badge key={p}>{p}</Badge>
                              ))}
                            </p>
                            <p>{a.description}</p>
                          </div>
                        ))}
                        {analytics.length > 3 && (
                          <Button size="sm" variant="ghost" onClick={() => setShowAllAnalytics((s) => !s)} aria-expanded={showAllAnalytics}>
                            {showAllAnalytics ? 'Show fewer analytics' : `Show all ${analytics.length} analytics`}
                          </Button>
                        )}
                      </div>
                    ) : (
                      considerations.length === 0 && <p className="text-muted">No technique-specific considerations recorded.</p>
                    )}
                  </Section>

                  <Section title="Known limitations and visibility gaps">
                    {gaps.length ? (
                      <ul className="list-disc space-y-1 pl-5 text-sm">
                        {gaps.map(({ c, p }, i) => (
                          <li key={i}>
                            {c} <span className="text-xs text-faint">({p})</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-sm text-muted">
                        No playbook documents visibility gaps for this technique. Before investigating, confirm the data components above are actually collected in your SIEM; missing telemetry is not proof that the activity did not occur.
                      </p>
                    )}
                  </Section>

                  {direct.length === 0 && <GeneralGuidance tactics={t.tactics} onNavigate={() => openTechnique(null)} />}

                  <Callout tone="info">
                    A technique being listed in ATT&amp;CK does not mean your security tools detect it. Coverage labels refer only to SOC Navigator playbooks.
                  </Callout>
                  <p className="text-xs text-faint">
                    Source: MITRE ATT&amp;CK Enterprise v{index!.dataset.meta.version} (modified {index!.dataset.meta.modified.slice(0, 10)}). Technique version {t.version ?? 'n/a'}. ATT&amp;CK® is a registered trademark of The MITRE Corporation.
                  </p>
                </>
              );
            })()
          )}
        </div>
      </aside>
      <StartInvestigationDialog open={!!startFor} playbookId={startFor ?? undefined} onClose={() => setStartFor(null)} />
    </>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-1.5 text-xs font-semibold tracking-wide text-muted uppercase">{title}</h3>
      {children}
    </section>
  );
}

function PlaybookRow({ pb, relation, onNavigate }: { pb: Playbook; relation: string; onNavigate: () => void }) {
  return (
    <li className="flex flex-wrap items-center gap-2 rounded-md border border-line bg-panel-2 px-2.5 py-1.5">
      <BookOpen className="h-4 w-4 text-ok" aria-hidden />
      <Link to={`/playbooks/${pb.id}`} onClick={onNavigate} className="font-medium text-fg-strong hover:underline">
        {pb.title}
      </Link>
      <span className="font-mono text-xs text-faint">{pb.id}</span>
      <PlaybookStatusBadge status={pb.status} />
      <span className="ml-auto text-xs text-muted">{relation}</span>
    </li>
  );
}

function GeneralGuidance({ tactics, onNavigate }: { tactics: string[]; onNavigate: () => void }) {
  const { playbookById } = useApp();
  const guides = tactics.map((s) => ({ s, g: TACTIC_GUIDANCE[s] })).filter((x) => x.g);
  const related = [...new Set(guides.flatMap((x) => x.g.relatedPlaybooks))].map((id) => playbookById.get(id)).filter((p): p is Playbook => !!p);
  return (
    <section className={cx('rounded-lg border border-dashed border-warn/50 p-3')}>
      <h3 className="mb-1 flex items-center gap-1.5 text-sm font-semibold text-warn">
        <Info className="h-4 w-4" aria-hidden />
        General investigative guidance - not a technique-specific reviewed playbook
      </h3>
      <ol className="mb-2 list-decimal space-y-1 pl-5 text-sm">
        {GENERAL_STEPS.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ol>
      {guides.map(({ s, g }) => (
        <div key={s} className="mt-2 text-sm">
          <p className="font-medium text-fg-strong">{g.question}</p>
          <p className="text-muted">Check: {g.checks.join('; ')}.</p>
          <p className="text-muted">Typical logs: {g.logs.join(', ')}.</p>
          <p className="text-muted">Escalate if: {g.escalateIf}</p>
        </div>
      ))}
      {related.length > 0 && (
        <p className="mt-2 text-sm">
          Related playbooks you may adapt:{' '}
          {related.map((p, i) => (
            <span key={p.id}>
              {i > 0 && ', '}
              <Link to={`/playbooks/${p.id}`} onClick={onNavigate} className="text-accent hover:underline">
                {p.title}
              </Link>
            </span>
          ))}
        </p>
      )}
    </section>
  );
}
