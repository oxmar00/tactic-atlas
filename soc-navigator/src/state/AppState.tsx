import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { STARTER_PLAYBOOKS } from '../data/playbooks';
import { AttackIndex } from '../lib/attack/attackIndex';
import { loadDataset } from '../lib/attack/loader';
import type { DatasetSource } from '../lib/attack/loader';
import type { AttackDataset } from '../lib/attack/types';
import { buildDemoInvestigations } from '../lib/demo';
import { createInvestigation as newInvestigation, investigationSchema } from '../lib/investigations/model';
import type { Investigation, NewInvestigationInput } from '../lib/investigations/model';
import { buildCoverage, mergeLibrary } from '../lib/playbooks/library';
import type { Coverage, LibraryEntry } from '../lib/playbooks/library';
import { playbookSchema } from '../lib/playbooks/schema';
import type { Playbook } from '../lib/playbooks/schema';
import { DEFAULT_SETTINGS, DEFAULT_USAGE, recordPlaybookOpen, recordTechniqueView, settingsSchema, usageSchema } from '../lib/settings';
import type { Settings, Usage } from '../lib/settings';
import { KEYS, createBrowserStorage, loadCollection, loadObject, saveCollection } from '../lib/storage';
import type { StorageAdapter } from '../lib/storage';

export type Tone = 'info' | 'success' | 'warning' | 'danger';
export interface Toast {
  id: number;
  message: string;
  tone: Tone;
}

export interface AttackState {
  status: 'loading' | 'ready' | 'error';
  index: AttackIndex | null;
  source: DatasetSource | null;
  warnings: string[];
  error: string | null;
}

export interface AppContextValue {
  attack: AttackState;
  reloadAttack: () => void;
  applyDataset: (dataset: AttackDataset, source: DatasetSource) => void;

  library: LibraryEntry[];
  playbookById: Map<string, Playbook>;
  coverage: Map<string, Coverage> | null;
  localPlaybooks: Playbook[];
  savePlaybook: (pb: Playbook) => boolean;
  deleteLocalPlaybook: (id: string) => void;
  replaceLocalPlaybooks: (list: Playbook[]) => void;

  investigations: Investigation[];
  createInvestigation: (input: Omit<NewInvestigationInput, 'analyst'> & { analyst?: string }) => Investigation;
  updateInvestigation: (id: string, fn: (inv: Investigation) => Investigation) => void;
  deleteInvestigation: (id: string) => void;
  replaceInvestigations: (list: Investigation[]) => void;
  loadDemoData: () => void;
  removeDemoData: () => void;

  settings: Settings;
  updateSettings: (patch: Partial<Settings>) => void;
  usage: Usage;
  notePlaybookOpened: (id: string) => void;

  techniquePanel: string | null;
  openTechnique: (id: string | null) => void;

  toasts: Toast[];
  notify: (message: string, tone?: Tone) => void;
  dismissToast: (id: number) => void;
  storage: StorageAdapter;
}

const AppContext = createContext<AppContextValue | null>(null);

export function useApp(): AppContextValue {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used inside <AppProvider>');
  return ctx;
}

const storage = createBrowserStorage();

export function AppProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastId = useRef(0);
  const notify = useCallback((message: string, tone: Tone = 'info') => {
    toastId.current += 1;
    const id = toastId.current;
    setToasts((t) => [...t.slice(-3), { id, message, tone }]);
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), tone === 'danger' ? 9000 : 5000);
  }, []);
  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  // --- Persistent slices --------------------------------------------------------------------
  const initial = useRef<{ settings: Settings; usage: Usage; playbooks: Playbook[]; investigations: Investigation[]; errors: string[] } | null>(null);
  if (!initial.current) {
    const errors: string[] = [];
    const pbs = loadCollection(storage, KEYS.playbooks, playbookSchema);
    const invs = loadCollection(storage, KEYS.investigations, investigationSchema);
    if (pbs.error) errors.push(`Local playbooks: ${pbs.error}`);
    if (invs.error) errors.push(`Investigations: ${invs.error}`);
    initial.current = {
      settings: loadObject(storage, KEYS.settings, settingsSchema, DEFAULT_SETTINGS),
      usage: loadObject(storage, KEYS.usage, usageSchema, DEFAULT_USAGE),
      playbooks: pbs.items,
      investigations: invs.items,
      errors,
    };
  }
  const [settings, setSettings] = useState<Settings>(initial.current.settings);
  const [usage, setUsage] = useState<Usage>(initial.current.usage);
  const [localPlaybooks, setLocalPlaybooks] = useState<Playbook[]>(initial.current.playbooks);
  const [investigations, setInvestigations] = useState<Investigation[]>(initial.current.investigations);

  useEffect(() => {
    for (const e of initial.current?.errors ?? []) notify(e, 'warning');
  }, [notify]);

  const persist = useCallback(
    (key: string, value: unknown, isCollection: boolean) => {
      if (isCollection) {
        const r = saveCollection(storage, key, value as unknown[]);
        if (!r.ok) notify(r.error, 'danger');
      } else {
        try {
          storage.write(key, JSON.stringify(value));
        } catch {
          /* preferences are best effort */
        }
      }
    },
    [notify],
  );
  const first = useRef(true);
  useEffect(() => {
    if (first.current) return;
    persist(KEYS.settings, settings, false);
  }, [settings, persist]);
  useEffect(() => {
    if (first.current) return;
    persist(KEYS.usage, usage, false);
  }, [usage, persist]);
  useEffect(() => {
    if (first.current) return;
    persist(KEYS.playbooks, localPlaybooks, true);
  }, [localPlaybooks, persist]);
  useEffect(() => {
    if (first.current) return;
    persist(KEYS.investigations, investigations, true);
  }, [investigations, persist]);
  useEffect(() => {
    first.current = false;
  }, []);

  // --- ATT&CK dataset ------------------------------------------------------------------------
  const [attack, setAttack] = useState<AttackState>({ status: 'loading', index: null, source: null, warnings: [], error: null });
  const reloadAttack = useCallback(() => {
    setAttack((a) => ({ ...a, status: 'loading', error: null }));
    loadDataset(import.meta.env.BASE_URL)
      .then((r) => setAttack({ status: 'ready', index: new AttackIndex(r.dataset), source: r.source, warnings: r.warnings, error: null }))
      .catch((err: unknown) =>
        setAttack({ status: 'error', index: null, source: null, warnings: [], error: err instanceof Error ? err.message : 'ATT&CK data could not be loaded.' }),
      );
  }, []);
  useEffect(() => reloadAttack(), [reloadAttack]);
  const applyDataset = useCallback((dataset: AttackDataset, source: DatasetSource) => {
    setAttack({ status: 'ready', index: new AttackIndex(dataset), source, warnings: [], error: null });
  }, []);

  // --- Playbooks -----------------------------------------------------------------------------
  const library = useMemo(() => mergeLibrary(STARTER_PLAYBOOKS, localPlaybooks), [localPlaybooks]);
  const playbookById = useMemo(() => new Map(library.map((e) => [e.playbook.id, e.playbook])), [library]);
  const coverage = useMemo(
    () => (attack.index ? buildCoverage(attack.index, library.map((e) => e.playbook)) : null),
    [attack.index, library],
  );

  const savePlaybook = useCallback(
    (pb: Playbook) => {
      const parsed = playbookSchema.safeParse({ ...pb, source: 'local' });
      if (!parsed.success) {
        notify('Playbook not saved: it failed validation.', 'danger');
        return false;
      }
      setLocalPlaybooks((list) => [...list.filter((p) => p.id !== parsed.data.id), parsed.data]);
      return true;
    },
    [notify],
  );
  const deleteLocalPlaybook = useCallback((id: string) => setLocalPlaybooks((list) => list.filter((p) => p.id !== id)), []);
  const replaceLocalPlaybooks = useCallback((list: Playbook[]) => setLocalPlaybooks(list), []);

  // --- Investigations ------------------------------------------------------------------------
  const createInvestigation = useCallback(
    (input: Omit<NewInvestigationInput, 'analyst'> & { analyst?: string }) => {
      const inv = newInvestigation({ ...input, analyst: input.analyst ?? settings.analystName });
      setInvestigations((list) => [inv, ...list]);
      setUsage((u) => recordPlaybookOpen(u, input.playbook.id));
      return inv;
    },
    [settings.analystName],
  );
  const updateInvestigation = useCallback((id: string, fn: (inv: Investigation) => Investigation) => {
    setInvestigations((list) => list.map((inv) => (inv.id === id ? fn(inv) : inv)));
  }, []);
  const deleteInvestigation = useCallback((id: string) => setInvestigations((list) => list.filter((i) => i.id !== id)), []);
  const replaceInvestigations = useCallback((list: Investigation[]) => setInvestigations(list), []);
  const loadDemoData = useCallback(() => {
    const demos = buildDemoInvestigations(new Map(STARTER_PLAYBOOKS.map((p) => [p.id, p])));
    setInvestigations((list) => [...list.filter((i) => !i.demo), ...demos]);
    setSettings((s) => ({ ...s, demoSeeded: true }));
  }, []);
  const removeDemoData = useCallback(() => setInvestigations((list) => list.filter((i) => !i.demo)), []);

  // Seed clearly labeled demo data exactly once for a first-time visitor.
  useEffect(() => {
    if (!initial.current?.settings.demoSeeded && initial.current?.investigations.length === 0) loadDemoData();
  }, [loadDemoData]);

  const updateSettings = useCallback((patch: Partial<Settings>) => setSettings((s) => ({ ...s, ...patch })), []);
  const notePlaybookOpened = useCallback((id: string) => setUsage((u) => recordPlaybookOpen(u, id)), []);

  const [techniquePanel, setTechniquePanel] = useState<string | null>(null);
  const openTechnique = useCallback((id: string | null) => {
    setTechniquePanel(id);
    if (id) setUsage((u) => recordTechniqueView(u, id));
  }, []);

  const value: AppContextValue = {
    attack,
    reloadAttack,
    applyDataset,
    library,
    playbookById,
    coverage,
    localPlaybooks,
    savePlaybook,
    deleteLocalPlaybook,
    replaceLocalPlaybooks,
    investigations,
    createInvestigation,
    updateInvestigation,
    deleteInvestigation,
    replaceInvestigations,
    loadDemoData,
    removeDemoData,
    settings,
    updateSettings,
    usage,
    notePlaybookOpened,
    techniquePanel,
    openTechnique,
    toasts,
    notify,
    dismissToast,
    storage,
  };
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}
