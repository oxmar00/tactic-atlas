/**
 * Normalized MITRE ATT&CK Enterprise dataset.
 *
 * Produced from the official STIX 2.1 bundle (github.com/mitre-attack/attack-stix-data) by
 * `normalizeStixBundle`. Nothing in this structure is authored by SOC Navigator: it is a
 * lossless-enough projection of official MITRE content and is kept strictly separate from
 * organization-authored playbooks so a dataset refresh never overwrites local guidance.
 */

export interface AttackDatasetMeta {
  /** Always "enterprise-attack". */
  domain: 'enterprise-attack';
  /** ATT&CK release, e.g. "19.2" (from the x-mitre-collection object). */
  version: string;
  /** Collection modified timestamp published by MITRE. */
  modified: string;
  /** URL the STIX bundle was retrieved from (or "local-file:<name>"). */
  sourceUrl: string;
  /** SHA-256 of the raw STIX bundle bytes, when computed (CLI only). */
  sha256: string | null;
  /** When this normalized snapshot was produced. */
  retrievedAt: string;
  /** Tool that produced the snapshot. */
  generator: string;
  /** STIX ATT&CK spec version of the collection. */
  attackSpecVersion: string | null;
  counts: {
    tactics: number;
    techniques: number;
    subtechniques: number;
    revoked: number;
    deprecated: number;
    detectionStrategies: number;
    analytics: number;
  };
}

export interface Tactic {
  /** TA#### */
  id: string;
  /** Kill-chain phase name used by techniques, e.g. "credential-access". */
  shortname: string;
  name: string;
  description: string;
  url: string;
  /** Position in the Enterprise matrix (0-based). */
  order: number;
}

export interface LogSourceRef {
  /** Data component name, e.g. "Process Creation". */
  dataComponent: string;
  /** MITRE log source name, e.g. "WinEventLog:Security". */
  name: string;
  /** Channel / event selector, e.g. "EventCode=4688". */
  channel: string;
}

export interface AnalyticRef {
  /** AN#### */
  id: string;
  platforms: string[];
  description: string;
  url: string;
}

export interface DetectionStrategyRef {
  /** DET#### */
  id: string;
  name: string;
  url: string;
  analytics: AnalyticRef[];
}

export interface Technique {
  /** T#### or T####.### */
  id: string;
  name: string;
  /** Official description with STIX citation markers removed. May contain Markdown links and <code>. */
  description: string;
  url: string;
  /** Tactic shortnames in matrix order. */
  tactics: string[];
  platforms: string[];
  isSubtechnique: boolean;
  parentId: string | null;
  subtechniqueIds: string[];
  /** Data components referenced by this technique's official analytics. */
  dataComponents: string[];
  /** Distinct log sources referenced by official analytics (capped for size). */
  logSources: LogSourceRef[];
  detectionStrategies: DetectionStrategyRef[];
  version: string | null;
  modified: string;
}

export interface RetiredTechnique {
  id: string;
  name: string;
  status: 'revoked' | 'deprecated';
  /** For revoked objects: the ATT&CK ID that replaced it, when MITRE published one. */
  replacedBy: string | null;
}

export interface DataComponentRef {
  /** DC#### */
  id: string;
  name: string;
  description: string;
}

export interface AttackDataset {
  meta: AttackDatasetMeta;
  tactics: Tactic[];
  /** Active (not revoked, not deprecated) techniques and sub-techniques. */
  techniques: Technique[];
  /** Revoked or deprecated objects, kept so legacy IDs resolve with an explanation. */
  retired: RetiredTechnique[];
  dataComponents: DataComponentRef[];
}
