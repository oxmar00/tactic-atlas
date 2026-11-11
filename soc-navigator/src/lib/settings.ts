import { z } from 'zod';
import { QUERY_LANGUAGES } from './playbooks/schema';

export const ROLES = ['analyst', 'author', 'reviewer'] as const;
export type Role = (typeof ROLES)[number];

export const ROLE_LABEL: Record<Role, string> = {
  analyst: 'Tier 1 analyst',
  author: 'Playbook author',
  reviewer: 'Playbook reviewer / approver',
};

export const THEMES = ['dark', 'light', 'system'] as const;
export type Theme = (typeof THEMES)[number];
const slaValue = z.number().int().min(1).max(43_200);

export const settingsSchema = z.object({
  analystName: z.string().trim().max(100),
  role: z.enum(ROLES),
  defaultLanguage: z.enum(QUERY_LANGUAGES),
  sidebarCollapsed: z.boolean(),
  assistant: z.object({
    mode: z.enum(['local', 'remote-proxy']),
    endpoint: z.string().max(200),
    consent: z.boolean(),
  }),
  demoSeeded: z.boolean(),
  theme: z.enum(THEMES).default('dark'),
  /** Target minutes from investigation start to escalation or resolution, per severity. */
  slaMinutes: z
    .object({ Critical: slaValue, High: slaValue, Medium: slaValue, Low: slaValue })
    .default({ Critical: 15, High: 60, Medium: 240, Low: 1440 }),
});
export type Settings = z.infer<typeof settingsSchema>;

export const DEFAULT_SETTINGS: Settings = {
  analystName: 'demo.analyst',
  role: 'analyst',
  defaultLanguage: 'kql',
  sidebarCollapsed: false,
  assistant: { mode: 'local', endpoint: '', consent: false },
  demoSeeded: false,
  theme: 'dark',
  slaMinutes: { Critical: 15, High: 60, Medium: 240, Low: 1440 },
};

const techniqueKey = z.string().regex(/^T\d{4}(\.\d{3})?$/);

export const usageSchema = z.object({
  recentPlaybooks: z.array(z.object({ id: z.string().max(60), at: z.string().max(40) })).max(20),
  techniqueViews: z.record(techniqueKey, z.number().int().nonnegative()),
});
export type Usage = z.infer<typeof usageSchema>;
export const DEFAULT_USAGE: Usage = { recentPlaybooks: [], techniqueViews: {} };

export function recordPlaybookOpen(usage: Usage, id: string, now = new Date()): Usage {
  const recentPlaybooks = [{ id, at: now.toISOString() }, ...usage.recentPlaybooks.filter((r) => r.id !== id)].slice(0, 10);
  return { ...usage, recentPlaybooks };
}

export function recordTechniqueView(usage: Usage, id: string): Usage {
  if (!/^T\d{4}(\.\d{3})?$/.test(id)) return usage;
  const views = { ...usage.techniqueViews, [id]: (usage.techniqueViews[id] ?? 0) + 1 };
  // Keep the map bounded.
  const entries = Object.entries(views).sort((a, b) => b[1] - a[1]).slice(0, 200);
  return { ...usage, techniqueViews: Object.fromEntries(entries) };
}
