import type { QueryLanguage, QueryPlaceholder, QueryTemplate } from './playbooks/schema';

/**
 * Fills {{placeholder}} tokens in query templates with analyst-supplied values.
 *
 * Safety model: string placeholders always sit inside double quotes in the templates, so values
 * are escaped for that context (backslash and quote). Non-string kinds (datetime, timespan,
 * number) are inserted unquoted and therefore must match a strict pattern - anything else is
 * rejected and the placeholder is left in place. The application never executes queries.
 */

const PATTERNS: Record<Exclude<QueryPlaceholder['kind'], 'string'>, { re: RegExp; hint: string }> = {
  datetime: { re: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,7})?)?(Z|[+-]\d{2}:\d{2})$/, hint: 'Use ISO 8601 with timezone, e.g. 2026-10-10T14:03:11Z' },
  timespan: { re: /^\d{1,4}[mhd]$/, hint: 'Use a number followed by m, h, or d, e.g. 24h or 7d' },
  number: { re: /^\d{1,9}$/, hint: 'Use a whole number' },
};

export const MAX_PLACEHOLDER_LENGTH = 300;

export function escapeForLanguage(value: string, language: QueryLanguage): string {
  if (language === 'generic') return value;
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

export function validatePlaceholder(ph: QueryPlaceholder, value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  if (v.length > MAX_PLACEHOLDER_LENGTH) return `Value is longer than ${MAX_PLACEHOLDER_LENGTH} characters.`;
  if (/[\r\n]/.test(v)) return 'Value must be a single line.';
  if (ph.kind !== 'string' && !PATTERNS[ph.kind].re.test(v)) return PATTERNS[ph.kind].hint;
  return null;
}

export interface FilledQuery {
  text: string;
  /** Placeholders still present (no value supplied or value rejected). */
  unresolved: string[];
  errors: { name: string; message: string }[];
}

export function fillQuery(template: Pick<QueryTemplate, 'query' | 'language' | 'placeholders'>, values: Record<string, string>): FilledQuery {
  const byName = new Map(template.placeholders.map((p) => [p.name, p]));
  const errors: FilledQuery['errors'] = [];
  const unresolved = new Set<string>();
  const text = template.query.replace(/\{\{([a-z][a-z0-9_]*)\}\}/g, (token, name: string) => {
    const ph = byName.get(name);
    const raw = values[name]?.trim() ?? '';
    if (!ph || !raw) {
      unresolved.add(name);
      return token;
    }
    const problem = validatePlaceholder(ph, raw);
    if (problem) {
      if (!errors.some((e) => e.name === name)) errors.push({ name, message: problem });
      unresolved.add(name);
      return token;
    }
    return ph.kind === 'string' ? escapeForLanguage(raw, template.language) : raw;
  });
  return { text, unresolved: [...unresolved], errors };
}

/**
 * Suggests placeholder values from recorded evidence (first non-empty line of the mapped field),
 * only when the value would pass validation.
 */
export function suggestFromEvidence(placeholders: QueryPlaceholder[], evidence: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const ph of placeholders) {
    if (!ph.evidenceField) continue;
    const first = (evidence[ph.evidenceField] ?? '').split('\n').map((l) => l.trim()).find(Boolean);
    if (first && !validatePlaceholder(ph, first)) out[ph.name] = first;
  }
  return out;
}

export const LANGUAGE_LABEL: Record<QueryLanguage, string> = {
  kql: 'KQL (Microsoft Sentinel / Defender XDR)',
  spl: 'SPL (Splunk)',
  generic: 'Generic procedure',
};
