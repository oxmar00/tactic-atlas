import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { AttackIndex } from '../src/lib/attack/attackIndex';
import { plainDescription, tokenizeDescription, tokenizeInline } from '../src/lib/attack/description';
import { buildLayer } from '../src/lib/attack/layer';
import { compareVersions, parseDataset } from '../src/lib/attack/loader';
import { StixNormalizationError, compareTechniqueIds, normalizeStixBundle, stripCitations, validateDataset } from '../src/lib/attack/normalize';
import type { AttackDataset } from '../src/lib/attack/types';
import { miniBundle } from './fixtures/miniBundle';

const opts = { sourceUrl: 'test', retrievedAt: '2026-10-11T00:00:00Z' };

describe('normalizeStixBundle', () => {
  const ds = normalizeStixBundle(miniBundle(), opts);

  it('reads the release version and collection metadata', () => {
    expect(ds.meta.version).toBe('19.2');
    expect(ds.meta.modified).toBe('2026-08-05T21:33:58.496Z');
    expect(ds.meta.domain).toBe('enterprise-attack');
  });

  it('orders tactics by the official matrix and ignores dangling tactic refs', () => {
    expect(ds.tactics.map((t) => t.shortname)).toEqual(['execution', 'credential-access']);
    expect(ds.tactics.map((t) => t.id)).toEqual(['TA0002', 'TA0006']);
  });

  it('keeps only active enterprise techniques and lists retired objects separately', () => {
    expect(ds.techniques.map((t) => t.id)).toEqual(['T1003', 'T1059', 'T1059.001']);
    expect(ds.retired).toEqual([
      { id: 'T1562', name: 'Impair Defenses', status: 'revoked', replacedBy: 'T1003' },
      { id: 'T1999', name: 'Deprecated Thing', status: 'deprecated', replacedBy: null },
    ]);
    expect(ds.meta.counts).toMatchObject({ techniques: 2, subtechniques: 1, revoked: 1, deprecated: 1 });
  });

  it('links sub-techniques to parents', () => {
    const parent = ds.techniques.find((t) => t.id === 'T1059')!;
    const sub = ds.techniques.find((t) => t.id === 'T1059.001')!;
    expect(parent.subtechniqueIds).toEqual(['T1059.001']);
    expect(sub.isSubtechnique).toBe(true);
    expect(sub.parentId).toBe('T1059');
  });

  it('orders a technique\'s tactics by matrix order', () => {
    expect(ds.techniques.find((t) => t.id === 'T1003')!.tactics).toEqual(['execution', 'credential-access']);
  });

  it('derives telemetry only from official detection strategies and analytics', () => {
    const sub = ds.techniques.find((t) => t.id === 'T1059.001')!;
    expect(sub.dataComponents).toEqual(['Process Creation', 'Script Execution']);
    expect(sub.logSources).toContainEqual({ dataComponent: 'Script Execution', name: 'WinEventLog:Microsoft-Windows-PowerShell/Operational', channel: 'EventCode=4104' });
    expect(sub.detectionStrategies[0]).toMatchObject({ id: 'DET0001', name: 'Detect PowerShell abuse' });
    expect(sub.detectionStrategies[0].analytics[0].id).toBe('AN0001');
    expect(ds.techniques.find((t) => t.id === 'T1003')!.dataComponents).toEqual([]);
  });

  it('strips citation markers from descriptions', () => {
    expect(ds.techniques.find((t) => t.id === 'T1059')!.description).toBe('Adversaries may abuse interpreters. See [PowerShell](https://attack.mitre.org/techniques/T1059/001).');
  });

  it('rejects inputs that are not an Enterprise STIX bundle', () => {
    expect(() => normalizeStixBundle(null, opts)).toThrow(StixNormalizationError);
    expect(() => normalizeStixBundle({ type: 'bundle', objects: [] }, opts)).toThrow(/version/);
    const mobile = miniBundle();
    (mobile.objects[0] as { name: string }).name = 'Mobile ATT&CK';
    expect(() => normalizeStixBundle(mobile, opts)).toThrow(/Enterprise/);
    const noMatrix = miniBundle();
    noMatrix.objects = noMatrix.objects.filter((o) => o.type !== 'x-mitre-matrix');
    expect(() => normalizeStixBundle(noMatrix, opts)).toThrow(/matrix/);
  });

  it('validateDataset reports structural problems', () => {
    expect(validateDataset(ds, { minTechniques: 1 })).toEqual(['Expected at least 10 tactics, found 2.']);
    const broken = structuredClone(ds);
    broken.techniques[1].tactics = ['nope'];
    expect(validateDataset(broken, { minTechniques: 1 }).join(' ')).toMatch(/unknown tactic/);
  });
});

describe('helpers', () => {
  it('stripCitations handles nested parentheses', () => {
    expect(stripCitations('Text (Citation: Foo (2020) Bar) more.')).toBe('Text more.');
  });
  it('compares technique IDs numerically', () => {
    expect(['T1059.010', 'T1005', 'T1059.002', 'T1059'].sort(compareTechniqueIds)).toEqual(['T1005', 'T1059', 'T1059.002', 'T1059.010']);
  });
  it('compares versions', () => {
    expect(compareVersions('19.2', '19.10')).toBeLessThan(0);
    expect(compareVersions('20', '19.9')).toBeGreaterThan(0);
  });
});

describe('description tokenizer (safe rendering)', () => {
  it('maps ATT&CK links to internal technique tokens and keeps tags as text', () => {
    const toks = tokenizeInline('See [PowerShell](https://attack.mitre.org/techniques/T1059/001) and <code>a</code> or `b`, not <script>x</script>.');
    expect(toks).toContainEqual({ kind: 'technique', text: 'PowerShell', id: 'T1059.001' });
    expect(toks).toContainEqual({ kind: 'code', text: 'a' });
    expect(toks).toContainEqual({ kind: 'code', text: 'b' });
    expect(toks.filter((t) => t.kind === 'text').map((t) => t.text).join('')).toContain('<script>x</script>');
  });
  it('only keeps https external links', () => {
    expect(tokenizeInline('[x](javascript:alert(1))')[0]).toEqual({ kind: 'text', text: 'x' });
    expect(tokenizeInline('[x](https://example.com/a)')[0]).toEqual({ kind: 'link', text: 'x', href: 'https://example.com/a' });
  });
  it('splits paragraphs and bullet lists', () => {
    const blocks = tokenizeDescription('Intro line.\n\n* one\n* two');
    expect(blocks.map((b) => b.kind)).toEqual(['paragraph', 'list']);
    expect(plainDescription('A [B](https://attack.mitre.org/techniques/T1003).')).toBe('A B.');
  });
});

describe('committed ATT&CK snapshot', () => {
  const ds = parseDataset(JSON.parse(readFileSync('public/data/attack-enterprise.json', 'utf8'))) as AttackDataset;
  const index = new AttackIndex(ds);

  it('is a complete current Enterprise release', () => {
    expect(ds.meta.domain).toBe('enterprise-attack');
    expect(ds.tactics).toHaveLength(15);
    expect(ds.meta.counts.techniques).toBeGreaterThan(150);
    expect(ds.meta.counts.subtechniques).toBeGreaterThan(300);
    expect(ds.meta.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(validateDataset(ds)).toEqual([]);
  });

  it('starts with Reconnaissance and ends with Impact', () => {
    expect(ds.tactics[0].shortname).toBe('reconnaissance');
    expect(ds.tactics.at(-1)?.shortname).toBe('impact');
  });

  it('search ranks exact IDs first and finds by name and telemetry', () => {
    expect(index.search('T1059.001')[0].technique.id).toBe('T1059.001');
    expect(index.search('powershell')[0].technique.id).toBe('T1059.001');
    expect(index.search('lsass memory').map((h) => h.technique.id)).toContain('T1003.001');
    expect(index.search('4104').length).toBeGreaterThan(0);
    expect(index.search('')).toEqual([]);
  });

  it('explains revoked IDs', () => {
    expect(index.retiredMatch('t1562')).toMatchObject({ status: 'revoked', replacedBy: 'T1685' });
  });

  it('builds a Navigator layer with one entry per technique/tactic', () => {
    const layer = buildLayer(index, 'Test', 'desc', [{ id: 'T1053.005', score: 1 }, { id: 'T0000' }]);
    expect(layer.domain).toBe('enterprise-attack');
    expect(layer.versions.layer).toBe('4.5');
    expect(layer.techniques.map((t) => t.tactic).sort()).toEqual(['execution', 'persistence', 'privilege-escalation']);
  });
});
