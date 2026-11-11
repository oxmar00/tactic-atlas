/**
 * Extracts indicators (IPs, domains, URLs, hashes, email addresses) from analyst-recorded text.
 * Input may already be defanged (hxxp, [.]); output is always offered defanged so it cannot be
 * clicked by accident. Nothing here contacts a network.
 */

export type IndicatorType = 'ipv4' | 'domain' | 'url' | 'email' | 'sha256' | 'sha1' | 'md5';

export interface Indicator {
  type: IndicatorType;
  /** Normalized (refanged, lowercase where case-insensitive) value. */
  value: string;
  /** Where it was found, e.g. evidence field labels. */
  sources: string[];
  /** Context note such as "private address" or "documentation range". */
  note: string;
}

const TYPE_ORDER: IndicatorType[] = ['url', 'domain', 'ipv4', 'email', 'sha256', 'sha1', 'md5'];

/** Common file extensions that look like TLDs in paths and command lines. */
const FILE_EXTENSIONS = new Set([
  'exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'js', 'jse', 'hta', 'lnk', 'scr', 'msi', 'iso', 'img', 'zip', 'rar', '7z', 'gz', 'tar',
  'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pdf', 'txt', 'log', 'tmp', 'dat', 'dmp', 'json', 'xml', 'yml', 'yaml', 'csv', 'ini',
  'cfg', 'conf', 'png', 'jpg', 'jpeg', 'gif', 'html', 'htm', 'php', 'aspx', 'jsp', 'py', 'sh', 'local', 'lan', 'internal', 'corp', 'dit',
]);

export function refang(text: string): string {
  return text
    .replace(/hxxp(s?):\/\//gi, 'http$1://')
    .replace(/\[(\.|dot)\]|\((\.|dot)\)|\{\.\}/gi, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[(@|at)\]/gi, '@');
}

export function defang(value: string): string {
  return value.replace(/^http/i, 'hxxp').replace(/\./g, '[.]').replace(/@/g, '[@]');
}

function ipNote(ip: string): string {
  const [a, b, c] = ip.split('.').map(Number);
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private address';
  if (a === 127) return 'loopback';
  if (a === 169 && b === 254) return 'link-local';
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return 'documentation range (RFC 5737)';
  if (a === 100 && b >= 64 && b <= 127) return 'carrier-grade NAT';
  return 'public address';
}

const RE = {
  url: /\bhttps?:\/\/[^\s"'<>)\]]+/gi,
  email: /\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi,
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
  hash: /\b[a-f0-9]{32,64}\b/gi,
};

export function extractIndicators(fields: { label: string; value: string }[]): Indicator[] {
  const found = new Map<string, Indicator>();
  const add = (type: IndicatorType, value: string, source: string, note = '') => {
    const key = `${type}|${value}`;
    const existing = found.get(key);
    if (existing) {
      if (!existing.sources.includes(source)) existing.sources.push(source);
    } else if (found.size < 500) found.set(key, { type, value, sources: [source], note });
  };

  for (const f of fields) {
    const text = refang(f.value.slice(0, 20_000));
    const urlHosts = new Set<string>();
    for (const m of text.matchAll(RE.url)) {
      const url = m[0].replace(/[.,;:]+$/, '');
      add('url', url, f.label);
      try {
        urlHosts.add(new URL(url).hostname.toLowerCase());
      } catch {
        /* not a parsable URL */
      }
    }
    const emailDomains = new Set<string>();
    for (const m of text.matchAll(RE.email)) {
      const email = m[0].toLowerCase();
      add('email', email, f.label);
      emailDomains.add(email.split('@')[1]);
    }
    for (const m of text.matchAll(RE.ipv4)) add('ipv4', m[0], f.label, ipNote(m[0]));
    for (const m of text.matchAll(RE.domain)) {
      const d = m[0].toLowerCase();
      const tld = d.split('.').pop() ?? '';
      if (FILE_EXTENSIONS.has(tld) || /^\d+$/.test(tld)) continue;
      // Skip email domains (already captured), Windows path segments, and URL path segments.
      const before = text[(m.index ?? 0) - 1];
      if (before === '@' || before === '\\') continue;
      if (before === '/' && !urlHosts.has(d)) continue;
      add('domain', d, f.label, urlHosts.has(d) ? 'from URL' : emailDomains.has(d) ? 'from email address' : '');
    }
    for (const m of text.matchAll(RE.hash)) {
      const h = m[0].toLowerCase();
      if (h.length === 64) add('sha256', h, f.label);
      else if (h.length === 40) add('sha1', h, f.label);
      else if (h.length === 32) add('md5', h, f.label);
    }
  }
  return [...found.values()].sort((a, b) => TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type) || a.value.localeCompare(b.value));
}

/** Prevents spreadsheet formula execution when the CSV is opened. */
function csvCell(v: string): string {
  const safe = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
  return `"${safe.replace(/"/g, '""')}"`;
}

export function indicatorsToCsv(items: Indicator[], defanged = true): string {
  const rows = [['type', 'value', 'note', 'found_in'], ...items.map((i) => [i.type, defanged ? defang(i.value) : i.value, i.note, i.sources.join('; ')])];
  return `${rows.map((r) => r.map(csvCell).join(',')).join('\n')}\n`;
}

export function indicatorsToList(items: Indicator[], defanged = true): string {
  return items.map((i) => (defanged ? defang(i.value) : i.value)).join('\n');
}
