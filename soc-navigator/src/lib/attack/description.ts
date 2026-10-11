/**
 * Tokenizes official ATT&CK description text for safe rendering with React text nodes.
 *
 * MITRE descriptions contain a small Markdown subset: paragraphs, "* " bullets, [text](url)
 * links, `backticks`, and literal <code>...</code> tags. Nothing here produces HTML; the UI maps
 * tokens to elements and anything unrecognized stays plain text (including stray tags such as
 * "<script>" that appear in official text as examples).
 */

export type InlineToken =
  | { kind: 'text'; text: string }
  | { kind: 'code'; text: string }
  | { kind: 'technique'; text: string; id: string }
  | { kind: 'link'; text: string; href: string };

export type DescriptionBlock = { kind: 'paragraph'; inline: InlineToken[] } | { kind: 'list'; items: InlineToken[][] };

const INLINE = /\[([^\]]+)\]\(([^)\s]+)\)|<code>([\s\S]*?)<\/code>|`([^`]+)`/g;

export function tokenizeInline(text: string): InlineToken[] {
  const out: InlineToken[] = [];
  let last = 0;
  for (const m of text.matchAll(INLINE)) {
    const idx = m.index ?? 0;
    if (idx > last) out.push({ kind: 'text', text: text.slice(last, idx) });
    if (m[1] !== undefined && m[2] !== undefined) {
      const href = m[2];
      const tech = /^https:\/\/attack\.mitre\.org\/techniques\/(T\d{4})(?:\/(\d{3}))?\/?$/.exec(href);
      if (tech) out.push({ kind: 'technique', text: m[1], id: tech[2] ? `${tech[1]}.${tech[2]}` : tech[1] });
      else if (href.startsWith('https://')) out.push({ kind: 'link', text: m[1], href });
      else out.push({ kind: 'text', text: m[1] });
    } else if (m[3] !== undefined) {
      out.push({ kind: 'code', text: m[3] });
    } else if (m[4] !== undefined) {
      out.push({ kind: 'code', text: m[4] });
    }
    last = idx + m[0].length;
  }
  if (last < text.length) out.push({ kind: 'text', text: text.slice(last) });
  return out;
}

export function tokenizeDescription(text: string): DescriptionBlock[] {
  const blocks: DescriptionBlock[] = [];
  for (const raw of text.split(/\n{2,}/)) {
    const lines = raw.split('\n').map((l) => l.trimEnd()).filter((l) => l.trim().length > 0);
    if (lines.length === 0) continue;
    if (lines.every((l) => /^\s*[*-]\s+/.test(l))) {
      blocks.push({ kind: 'list', items: lines.map((l) => tokenizeInline(l.replace(/^\s*[*-]\s+/, ''))) });
    } else {
      blocks.push({ kind: 'paragraph', inline: tokenizeInline(lines.join(' ')) });
    }
  }
  return blocks;
}

/** Plain-text version (for search snippets, exports). */
export function plainDescription(text: string): string {
  return tokenizeDescription(text)
    .map((b) => (b.kind === 'paragraph' ? b.inline.map((t) => t.text).join('') : b.items.map((i) => `- ${i.map((t) => t.text).join('')}`).join('\n')))
    .join('\n\n');
}
