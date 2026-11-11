import type { Playbook } from '../../lib/playbooks/schema';
import { accountChanges } from './accountChanges';
import { bruteForce } from './bruteForce';
import { cloudCredentials } from './cloudCredentials';
import { commandAndControl } from './commandAndControl';
import { credentialDumping } from './credentialDumping';
import { cron } from './cron';
import { defenseTampering } from './defenseTampering';
import { exfiltration } from './exfiltration';
import { withExtras } from './extras';
import { inboxRules } from './inboxRules';
import { ingressTransfer } from './ingressTransfer';
import { kerberoasting } from './kerberoasting';
import { lateralMovement } from './lateralMovement';
import { mfaFatigue } from './mfaFatigue';
import { phishing } from './phishing';
import { powershell } from './powershell';
import { processInjection } from './processInjection';
import { ransomware } from './ransomware';
import { runKeys } from './runKeys';
import { scheduledTask } from './scheduledTask';
import { userExecution } from './userExecution';
import { validAccounts } from './validAccounts';
import { webShell } from './webShell';
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
  mfaFatigue,
  inboxRules,
  defenseTampering,
  kerberoasting,
  accountChanges,
  webShell,
  cloudCredentials,
  cron,
].map(withExtras);
