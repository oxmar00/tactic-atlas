import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router';
import {
  BookOpen,
  ChevronsLeft,
  ChevronsRight,
  Database,
  FileText,
  Grid3x3,
  LayoutDashboard,
  ListChecks,
  Search,
  Settings as SettingsIcon,
  Shield,
  X,
} from 'lucide-react';
import { useApp } from '../state/AppState';
import { TechniqueDrawer } from './TechniqueDrawer';
import { Badge, cx } from './ui';

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/matrix', label: 'ATT&CK Enterprise Matrix', icon: Grid3x3 },
  { to: '/playbooks', label: 'Investigation Playbooks', icon: BookOpen },
  { to: '/investigations', label: 'Active Investigations', icon: ListChecks },
  { to: '/reference', label: 'Detection and Log Reference', icon: Database },
  { to: '/reports', label: 'Reports and Escalations', icon: FileText },
  { to: '/settings', label: 'Settings and Data Sources', icon: SettingsIcon },
];

export function Layout({ children }: { children: ReactNode }) {
  const { settings, updateSettings, investigations, attack, openTechnique } = useApp();
  const { pathname } = useLocation();
  // Navigating to another view closes the technique details panel.
  const lastPath = useRef(pathname);
  // Layout effect: runs before child views' passive effects, so a deep link (/matrix?t=...) can reopen it.
  useLayoutEffect(() => {
    if (lastPath.current !== pathname) openTechnique(null);
    lastPath.current = pathname;
  }, [pathname, openTechnique]);
  const collapsed = settings.sidebarCollapsed;
  const awaiting = investigations.filter((i) => i.status === 'Escalation Recommended').length;
  const active = investigations.filter((i) => i.status !== 'Resolved' && i.status !== 'Escalated').length;

  return (
    <div className="flex min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-2 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-white">
        Skip to content
      </a>
      <aside
        className={cx('no-print sticky top-0 flex h-screen shrink-0 flex-col border-r border-line bg-panel transition-[width]', collapsed ? 'w-14' : 'w-64')}
        aria-label="Primary"
      >
        <div className={cx('flex items-center gap-2 border-b border-line px-3 py-3', collapsed && 'justify-center px-0')}>
          <Shield className="h-6 w-6 shrink-0 text-accent" aria-hidden />
          {!collapsed && (
            <div className="min-w-0 leading-tight">
              <p className="font-semibold text-fg-strong">SOC Navigator</p>
              <p className="truncate text-[11px] text-muted">ATT&amp;CK Tier 1 Investigation Guide</p>
            </div>
          )}
        </div>
        <nav className="scroll-thin flex-1 overflow-y-auto py-2">
          <ul className="space-y-0.5 px-2">
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <li key={to}>
                <NavLink
                  to={to}
                  end={end}
                  title={collapsed ? label : undefined}
                  className={({ isActive }) =>
                    cx(
                      'flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm',
                      collapsed && 'justify-center px-0',
                      isActive ? 'bg-accent/10 font-medium text-fg-strong' : 'text-muted hover:bg-panel-2 hover:text-fg',
                    )
                  }
                >
                  <Icon className="h-4 w-4 shrink-0" aria-hidden />
                  {collapsed ? <span className="sr-only">{label}</span> : <span className="flex-1 truncate">{label}</span>}
                  {!collapsed && to === '/investigations' && active > 0 && <Badge tone="accent">{active}</Badge>}
                  {!collapsed && to === '/reports' && awaiting > 0 && (
                    <Badge tone="bad" title="Investigations awaiting escalation">
                      {awaiting}
                    </Badge>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        {!collapsed && (
          <div className="border-t border-line px-3 py-2 text-[11px] text-faint">
            ATT&amp;CK {attack.index ? `v${attack.index.dataset.meta.version}` : attack.status === 'loading' ? 'loading...' : 'unavailable'}
            {attack.source === 'browser-update' && ' (browser update)'}
            <br />
            No SIEM connected - demo build
          </div>
        )}
        <button
          type="button"
          onClick={() => updateSettings({ sidebarCollapsed: !collapsed })}
          className="flex items-center justify-center gap-2 border-t border-line py-2 text-xs text-muted hover:text-fg"
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!collapsed}
        >
          {collapsed ? <ChevronsRight className="h-4 w-4" aria-hidden /> : <ChevronsLeft className="h-4 w-4" aria-hidden />}
          {!collapsed && 'Collapse'}
        </button>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="no-print sticky top-0 z-30 flex items-center gap-3 border-b border-line bg-bg/95 px-5 py-2.5 backdrop-blur">
          <GlobalSearch />
          <div className="ml-auto hidden items-center gap-2 text-xs text-muted md:flex">
            <span>
              Analyst: <span className="text-fg">{settings.analystName || 'not set'}</span>
            </span>
          </div>
        </header>
        <main id="main" className="min-w-0 flex-1 px-5 py-5">
          {children}
        </main>
      </div>
      <TechniqueDrawer />
      <Toasts />
    </div>
  );
}

function GlobalSearch() {
  const { attack, library, openTechnique } = useApp();
  const navigate = useNavigate();
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (e.key === '/' && target && !['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) && !target.isContentEditable) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const results = useMemo(() => {
    const query = q.trim();
    if (!query) return [];
    const lower = query.toLowerCase();
    const pbs = library
      .filter((e) => e.playbook.id.toLowerCase().includes(lower) || e.playbook.title.toLowerCase().includes(lower) || e.playbook.techniques.some((t) => t.toLowerCase() === lower))
      .slice(0, 4)
      .map((e) => ({ kind: 'playbook' as const, id: e.playbook.id, label: e.playbook.title, sub: e.playbook.id }));
    const techs = (attack.index?.search(query, 8) ?? []).map((h) => ({
      kind: 'technique' as const,
      id: h.technique.id,
      label: attack.index!.label(h.technique.id, true).replace(`${h.technique.id} `, ''),
      sub: `${h.technique.id} - matched ${h.matchedOn}`,
    }));
    const retired = attack.index?.retiredMatch(query);
    const retiredRow = retired
      ? [{ kind: 'retired' as const, id: retired.replacedBy ?? retired.id, label: `${retired.id} ${retired.name} is ${retired.status}`, sub: retired.replacedBy ? `Replaced by ${retired.replacedBy} - open replacement` : 'No replacement published' }]
      : [];
    return [...retiredRow, ...pbs, ...techs];
  }, [q, attack.index, library]);

  const choose = (r: (typeof results)[number]) => {
    setOpen(false);
    setQ('');
    if (r.kind === 'playbook') navigate(`/playbooks/${r.id}`);
    else if (attack.index?.get(r.id)) openTechnique(r.id);
  };

  return (
    <div className="relative w-full max-w-xl">
      <label htmlFor="global-search" className="sr-only">
        Search techniques and playbooks
      </label>
      <Search className="pointer-events-none absolute top-1/2 left-2.5 h-4 w-4 -translate-y-1/2 text-faint" aria-hidden />
      <input
        id="global-search"
        ref={inputRef}
        className="input pl-8"
        placeholder="Search technique ID, name, behavior, or playbook  ( / )"
        value={q}
        autoComplete="off"
        role="combobox"
        aria-expanded={open && results.length > 0}
        aria-controls="global-search-results"
        aria-activedescendant={open && results[active] ? `gs-${active}` : undefined}
        onChange={(e) => {
          setQ(e.target.value);
          setOpen(true);
          setActive(0);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => window.setTimeout(() => setOpen(false), 150)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            setActive((a) => Math.min(a + 1, results.length - 1));
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setActive((a) => Math.max(a - 1, 0));
          } else if (e.key === 'Enter' && results[active]) {
            e.preventDefault();
            choose(results[active]);
          } else if (e.key === 'Escape') {
            setOpen(false);
            (e.target as HTMLInputElement).blur();
          }
        }}
      />
      {q && (
        <button type="button" className="absolute top-1/2 right-2 -translate-y-1/2 text-faint hover:text-fg" onClick={() => setQ('')} aria-label="Clear search">
          <X className="h-4 w-4" aria-hidden />
        </button>
      )}
      {open && q.trim() && (
        <ul id="global-search-results" role="listbox" className="absolute top-full right-0 left-0 z-40 mt-1 max-h-96 overflow-y-auto rounded-md border border-line-strong bg-panel-2 py-1 shadow-2xl">
          {results.length === 0 && <li className="px-3 py-2 text-sm text-muted">{attack.index ? 'No matching technique or playbook.' : 'ATT&CK data not loaded; only playbooks are searchable.'}</li>}
          {results.map((r, i) => (
            <li
              key={`${r.kind}-${r.id}-${i}`}
              id={`gs-${i}`}
              role="option"
              aria-selected={i === active}
              onMouseDown={(e) => {
                e.preventDefault();
                choose(r);
              }}
              onMouseEnter={() => setActive(i)}
              className={cx('flex cursor-pointer items-start gap-2 px-3 py-1.5 text-sm', i === active && 'bg-accent/10')}
            >
              <Badge tone={r.kind === 'playbook' ? 'ok' : r.kind === 'retired' ? 'warn' : 'accent'}>{r.kind === 'playbook' ? 'Playbook' : r.kind === 'retired' ? 'Retired' : 'Technique'}</Badge>
              <span className="min-w-0">
                <span className="block truncate text-fg">{r.label}</span>
                <span className="block truncate text-xs text-faint">{r.sub}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Toasts() {
  const { toasts, dismissToast } = useApp();
  const tone = { info: 'border-info/40', success: 'border-ok/50', warning: 'border-warn/50', danger: 'border-bad/60' } as const;
  return (
    <div aria-live="polite" className="no-print fixed right-4 bottom-4 z-50 flex w-96 max-w-[90vw] flex-col gap-2">
      {toasts.map((t) => (
        <div key={t.id} role={t.tone === 'danger' ? 'alert' : 'status'} className={cx('flex items-start gap-2 rounded-md border bg-panel-2 px-3 py-2 text-sm shadow-xl', tone[t.tone])}>
          <p className="flex-1">{t.message}</p>
          <button type="button" onClick={() => dismissToast(t.id)} aria-label="Dismiss notification" className="text-faint hover:text-fg">
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>
      ))}
    </div>
  );
}
