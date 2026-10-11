import { useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { BookOpen, Copy, Download, FilePlus2, Pencil, RotateCcw, Trash2, Upload } from 'lucide-react';
import { PlaybookStatusBadge } from '../components/badges';
import { Badge, Button, Callout, EmptyState, PageHeader, TabPanel, Tabs, downloadFile, formatDate } from '../components/ui';
import { STARTER_PLAYBOOKS } from '../data/playbooks';
import { exportPlaybooks, nextLocalId, parsePlaybookImport, withStatus } from '../lib/playbooks/library';
import type { LibraryEntry } from '../lib/playbooks/library';
import { PLAYBOOK_STATUSES } from '../lib/playbooks/schema';
import type { Playbook } from '../lib/playbooks/schema';
import { ROLE_LABEL } from '../lib/settings';
import { useApp } from '../state/AppState';

const ORIGIN: Record<LibraryEntry['origin'], { label: string; tone: 'neutral' | 'info' | 'accent' }> = {
  starter: { label: 'Starter library', tone: 'neutral' },
  'local-revision': { label: 'Local revision', tone: 'info' },
  local: { label: 'Locally authored', tone: 'accent' },
};

export function PlaybooksPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') === 'manage' ? 'manage' : 'library';
  return (
    <div className="space-y-4">
      <PageHeader
        icon={<BookOpen className="h-5 w-5 text-accent" aria-hidden />}
        title="Investigation Playbooks"
        subtitle="Organization-authored, technique-specific investigation guides. They are stored separately from MITRE ATT&CK data, so refreshing ATT&CK never overwrites them."
      />
      <Tabs
        label="Playbook views"
        value={tab}
        onChange={(t) => setParams(t === 'manage' ? { tab: 'manage' } : {}, { replace: true })}
        tabs={[
          { id: 'library', label: 'Library' },
          { id: 'manage', label: 'Author and review' },
        ]}
      />
      <TabPanel id={tab}>{tab === 'library' ? <Library /> : <Manage />}</TabPanel>
    </div>
  );
}

function Library() {
  const { library, attack } = useApp();
  const [q, setQ] = useState('');
  const [tactic, setTactic] = useState('');
  const [status, setStatus] = useState('');
  const list = useMemo(() => {
    const lower = q.trim().toLowerCase();
    return library.filter(({ playbook: p }) => {
      if (tactic && !p.tactics.includes(tactic)) return false;
      if (status && p.status !== status) return false;
      if (!lower) return true;
      const hay = [p.id, p.title, p.objective, ...p.techniques, ...p.techniques.map((id) => attack.index?.get(id)?.name ?? '')].join(' ').toLowerCase();
      return lower.split(/\s+/).every((t) => hay.includes(t));
    });
  }, [library, q, tactic, status, attack.index]);

  return (
    <div className="space-y-3 pt-3">
      <div className="flex flex-wrap items-end gap-2">
        <div className="min-w-[14rem] flex-1">
          <label htmlFor="pb-q" className="label">
            Search playbooks
          </label>
          <input id="pb-q" className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Title, technique ID, or keyword" />
        </div>
        <div>
          <label htmlFor="pb-tactic" className="label">
            Tactic
          </label>
          <select id="pb-tactic" className="input" value={tactic} onChange={(e) => setTactic(e.target.value)}>
            <option value="">All tactics</option>
            {(attack.index?.tactics ?? []).map((t) => (
              <option key={t.shortname} value={t.shortname}>
                {t.name}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="pb-status" className="label">
            Review status
          </label>
          <select id="pb-status" className="input" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">Any</option>
            {PLAYBOOK_STATUSES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>
      <Callout tone="warning">
        All starter playbooks are AI-assisted <strong>Draft</strong> content. They must be reviewed and adapted by an authorized person before they are treated as operational procedure.
      </Callout>
      {list.length === 0 ? (
        <EmptyState title="No playbooks match">Clear the search or filters.</EmptyState>
      ) : (
        <ul className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
          {list.map(({ playbook: p, origin }) => (
            <li key={p.id}>
              <Link to={`/playbooks/${p.id}`} className="block h-full rounded-lg border border-line bg-panel p-4 hover:border-accent/60">
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-faint">{p.id}</span>
                  <PlaybookStatusBadge status={p.status} />
                  <Badge tone={ORIGIN[origin].tone}>{ORIGIN[origin].label}</Badge>
                </div>
                <p className="font-semibold text-fg-strong">{p.title}</p>
                <p className="mt-1 line-clamp-2 text-sm text-muted">{p.objective}</p>
                <div className="mt-2 flex flex-wrap gap-1">
                  {p.techniques.slice(0, 5).map((id) => (
                    <Badge key={id} tone="accent">
                      {id}
                    </Badge>
                  ))}
                  {p.techniques.length > 5 && <Badge>+{p.techniques.length - 5}</Badge>}
                </div>
                <p className="mt-2 text-xs text-faint">
                  {p.difficulty} - {p.effort} - {p.steps.length} steps - {p.queries.length} queries
                </p>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Manage() {
  const { library, settings, localPlaybooks, savePlaybook, deleteLocalPlaybook, notify } = useApp();
  const navigate = useNavigate();
  const fileRef = useRef<HTMLInputElement>(null);
  const [importErrors, setImportErrors] = useState<string[]>([]);
  const canAuthor = settings.role !== 'analyst';
  const starterIds = new Set(STARTER_PLAYBOOKS.map((p) => p.id));

  const duplicate = (pb: Playbook) => {
    const id = nextLocalId(library.map((e) => e.playbook.id));
    const copy: Playbook = withStatus(
      { ...structuredClone(pb), id, title: `${pb.title} (copy)`.slice(0, 200), version: '0.1.0', source: 'local', status: 'Draft', review: { ...pb.review, author: settings.analystName, reviewer: null, reviewedAt: null, history: [] } },
      'Draft',
      settings.analystName,
      `Duplicated from ${pb.id} v${pb.version}.`,
    );
    if (savePlaybook(copy)) {
      notify(`Created ${id} as a Draft copy.`, 'success');
      navigate(`/playbooks/${id}/edit`);
    }
  };

  const onImport = async (file: File | undefined) => {
    if (!file) return;
    const text = await file.text();
    const r = parsePlaybookImport(text, settings.analystName);
    setImportErrors(r.errors);
    let saved = 0;
    for (const pb of r.playbooks) if (savePlaybook(pb)) saved += 1;
    notify(`Imported ${saved} playbook(s)${r.errors.length ? `; ${r.errors.length} rejected` : ''}.`, r.errors.length ? 'warning' : 'success');
    if (fileRef.current) fileRef.current.value = '';
  };

  return (
    <div className="space-y-3 pt-3">
      {!canAuthor && (
        <Callout tone="info" title={`Current role: ${ROLE_LABEL[settings.role]}`}>
          Editing and approval require the Playbook author or reviewer role. Change it in <Link to="/settings" className="text-accent hover:underline">Settings</Link>. This demo role switch is not an access control - production deployments need server-side authorization.
        </Callout>
      )}
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" icon={<FilePlus2 className="h-4 w-4" aria-hidden />} disabled={!canAuthor} onClick={() => navigate('/playbooks/new')}>
          New playbook
        </Button>
        <Button icon={<Upload className="h-4 w-4" aria-hidden />} disabled={!canAuthor} onClick={() => fileRef.current?.click()}>
          Import JSON
        </Button>
        <input ref={fileRef} type="file" accept="application/json,.json" className="hidden" aria-label="Import playbook JSON file" onChange={(e) => void onImport(e.target.files?.[0])} />
        <Button icon={<Download className="h-4 w-4" aria-hidden />} onClick={() => downloadFile('soc-navigator-playbooks.json', exportPlaybooks(library.map((e) => e.playbook)), 'application/json')}>
          Export all ({library.length})
        </Button>
        {localPlaybooks.length > 0 && (
          <Button icon={<Download className="h-4 w-4" aria-hidden />} onClick={() => downloadFile('soc-navigator-local-playbooks.json', exportPlaybooks(localPlaybooks), 'application/json')}>
            Export local only ({localPlaybooks.length})
          </Button>
        )}
      </div>
      {importErrors.length > 0 && (
        <Callout tone="danger" title="Some records were rejected">
          <ul className="list-disc pl-4">
            {importErrors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </Callout>
      )}
      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full text-left text-sm">
          <thead className="bg-panel-2 text-xs text-muted">
            <tr>
              <th className="px-3 py-2 font-medium">Playbook</th>
              <th className="px-3 py-2 font-medium">Version</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Origin</th>
              <th className="px-3 py-2 font-medium">Last reviewer</th>
              <th className="px-3 py-2 font-medium">Updated</th>
              <th className="px-3 py-2 font-medium">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {library.map(({ playbook: p, origin }) => (
              <tr key={p.id} className="border-t border-line align-top">
                <td className="px-3 py-2">
                  <Link to={`/playbooks/${p.id}`} className="font-medium text-fg-strong hover:underline">
                    {p.title}
                  </Link>
                  <p className="font-mono text-xs text-faint">{p.id}</p>
                </td>
                <td className="px-3 py-2 tabular-nums">{p.version}</td>
                <td className="px-3 py-2">
                  <PlaybookStatusBadge status={p.status} />
                </td>
                <td className="px-3 py-2">
                  <Badge tone={ORIGIN[origin].tone}>{ORIGIN[origin].label}</Badge>
                </td>
                <td className="px-3 py-2">{p.review.reviewer ?? <span className="text-faint">none</span>}</td>
                <td className="px-3 py-2 text-xs text-muted">{formatDate(p.updatedAt)}</td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap justify-end gap-1">
                    <Button size="sm" icon={<Pencil className="h-3.5 w-3.5" aria-hidden />} disabled={!canAuthor} onClick={() => navigate(`/playbooks/${p.id}/edit`)} aria-label={`Edit ${p.id}`}>
                      Edit
                    </Button>
                    <Button size="sm" icon={<Copy className="h-3.5 w-3.5" aria-hidden />} disabled={!canAuthor} onClick={() => duplicate(p)} aria-label={`Duplicate ${p.id}`}>
                      Duplicate
                    </Button>
                    <Button size="sm" icon={<Download className="h-3.5 w-3.5" aria-hidden />} onClick={() => downloadFile(`${p.id}.json`, `${JSON.stringify(p, null, 2)}\n`, 'application/json')} aria-label={`Export ${p.id}`}>
                      JSON
                    </Button>
                    {origin === 'local-revision' && (
                      <Button
                        size="sm"
                        variant="danger"
                        icon={<RotateCcw className="h-3.5 w-3.5" aria-hidden />}
                        disabled={!canAuthor}
                        onClick={() => {
                          if (window.confirm(`Discard the local revision of ${p.id} and return to the starter version?`)) {
                            deleteLocalPlaybook(p.id);
                            notify(`${p.id} reverted to the starter version.`, 'success');
                          }
                        }}
                      >
                        Revert
                      </Button>
                    )}
                    {origin === 'local' && !starterIds.has(p.id) && (
                      <Button
                        size="sm"
                        variant="danger"
                        icon={<Trash2 className="h-3.5 w-3.5" aria-hidden />}
                        disabled={!canAuthor}
                        onClick={() => {
                          if (window.confirm(`Delete local playbook ${p.id}? Existing investigations keep their data but lose the playbook reference.`)) {
                            deleteLocalPlaybook(p.id);
                            notify(`${p.id} deleted.`, 'success');
                          }
                        }}
                      >
                        Delete
                      </Button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-faint">Local playbooks and revisions are stored in this browser only. Export them regularly; production deployments should store playbooks in a version-controlled, access-controlled repository.</p>
    </div>
  );
}
