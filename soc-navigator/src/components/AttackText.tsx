import { ExternalLink } from 'lucide-react';
import { tokenizeDescription } from '../lib/attack/description';
import type { InlineToken } from '../lib/attack/description';
import { useApp } from '../state/AppState';

/** Renders official ATT&CK description text safely (React text nodes only, no HTML injection). */
export function AttackText({ text, className }: { text: string; className?: string }) {
  const blocks = tokenizeDescription(text);
  return (
    <div className={className}>
      {blocks.map((b, i) =>
        b.kind === 'paragraph' ? (
          <p key={i} className="mb-2 last:mb-0">
            <Inline tokens={b.inline} />
          </p>
        ) : (
          <ul key={i} className="mb-2 list-disc space-y-0.5 pl-5 last:mb-0">
            {b.items.map((item, j) => (
              <li key={j}>
                <Inline tokens={item} />
              </li>
            ))}
          </ul>
        ),
      )}
    </div>
  );
}

function Inline({ tokens }: { tokens: InlineToken[] }) {
  const { attack, openTechnique } = useApp();
  return (
    <>
      {tokens.map((t, i) => {
        switch (t.kind) {
          case 'code':
            return (
              <code key={i} className="rounded bg-panel-3 px-1 py-0.5 text-[12px] break-all text-fg">
                {t.text}
              </code>
            );
          case 'technique':
            return attack.index?.get(t.id) ? (
              <button key={i} type="button" className="text-accent underline-offset-2 hover:underline" onClick={() => openTechnique(t.id)}>
                {t.text}
              </button>
            ) : (
              <span key={i}>{t.text}</span>
            );
          case 'link':
            return (
              <a key={i} href={t.href} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-0.5 text-accent hover:underline">
                {t.text}
                <ExternalLink className="h-3 w-3" aria-hidden />
                <span className="sr-only">(opens in new tab)</span>
              </a>
            );
          default:
            return <span key={i}>{t.text}</span>;
        }
      })}
    </>
  );
}
