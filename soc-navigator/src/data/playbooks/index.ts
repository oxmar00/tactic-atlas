import type { Playbook } from '../../lib/playbooks/schema';
import { bruteForce } from './bruteForce';
import { commandAndControl } from './commandAndControl';
import { credentialDumping } from './credentialDumping';
import { exfiltration } from './exfiltration';
import { ingressTransfer } from './ingressTransfer';
import { lateralMovement } from './lateralMovement';
import { phishing } from './phishing';
import { powershell } from './powershell';
import { processInjection } from './processInjection';
import { ransomware } from './ransomware';
import { runKeys } from './runKeys';
import { scheduledTask } from './scheduledTask';
import { userExecution } from './userExecution';
import { validAccounts } from './validAccounts';
import { wmi } from './wmi';

/**
 * Starter playbook library shipped with the application. Organization-authored content that
 * is kept separate from MITRE ATT&CK data; every entry is AI-assisted and ships as Draft.
 */
export const STARTER_PLAYBOOKS: readonly Playbook[] = [
  phishing,
  userExecution,
  powershell,
  scheduledTask,
  wmi,
  credentialDumping,
  bruteForce,
  validAccounts,
  runKeys,
  lateralMovement,
  ingressTransfer,
  processInjection,
  commandAndControl,
  exfiltration,
  ransomware,
];
