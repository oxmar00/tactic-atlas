import type { AttackIndex } from './attackIndex';

/**
 * Builds an ATT&CK Navigator layer (format 4.5) so a selection or playbook coverage view can be
 * opened in https://mitre-attack.github.io/attack-navigator/.
 */

export interface LayerTechnique {
  techniqueID: string;
  tactic?: string;
  score?: number;
  color?: string;
  comment?: string;
  enabled: boolean;
  showSubtechniques: boolean;
}

export interface NavigatorLayer {
  name: string;
  versions: { attack: string; navigator: string; layer: string };
  domain: 'enterprise-attack';
  description: string;
  sorting: number;
  hideDisabled: boolean;
  techniques: LayerTechnique[];
  gradient: { colors: string[]; minValue: number; maxValue: number };
  legendItems: { label: string; color: string }[];
  metadata: { name: string; value: string }[];
  showTacticRowBackground: boolean;
  selectTechniquesAcrossTactics: boolean;
  selectSubtechniquesWithParent: boolean;
}

export function buildLayer(
  index: AttackIndex,
  name: string,
  description: string,
  entries: { id: string; score?: number; color?: string; comment?: string }[],
  legend: { label: string; color: string }[] = [],
): NavigatorLayer {
  const techniques: LayerTechnique[] = [];
  for (const e of entries) {
    const t = index.get(e.id);
    if (!t) continue;
    // Navigator expects one entry per technique/tactic pair.
    for (const tactic of t.tactics) {
      techniques.push({
        techniqueID: t.id,
        tactic,
        score: e.score,
        color: e.color,
        comment: e.comment?.slice(0, 500),
        enabled: true,
        showSubtechniques: !t.isSubtechnique && t.subtechniqueIds.length > 0,
      });
    }
  }
  return {
    name: name.slice(0, 100),
    versions: { attack: index.dataset.meta.version.split('.')[0], navigator: '5.1.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description: description.slice(0, 1000),
    sorting: 0,
    hideDisabled: false,
    techniques,
    gradient: { colors: ['#ffffff', '#66b1ff'], minValue: 0, maxValue: 1 },
    legendItems: legend,
    metadata: [
      { name: 'generator', value: 'SOC Navigator' },
      { name: 'attack_release', value: index.dataset.meta.version },
      { name: 'note', value: 'Presence in this layer does not imply detection coverage by your security tools.' },
    ],
    showTacticRowBackground: false,
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
  };
}
