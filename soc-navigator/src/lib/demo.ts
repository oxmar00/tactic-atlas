import {
  addFinding,
  addListItem,
  addTimelineEntry,
  answerDecision,
  applyOutcome,
  createInvestigation,
  evaluateDecision,
  setEvidence,
  setStatus,
  setStepDone,
  setStepNotes,
  update,
} from './investigations/model';
import type { Investigation } from './investigations/model';
import type { Playbook } from './playbooks/schema';

/**
 * Fictional demonstration investigations. All values use reserved documentation ranges
 * (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and example/.test domains, and every record is
 * flagged demo=true so the UI and reports label it as sample data.
 */

function seq(seed: number): () => number {
  let s = seed;
  return () => {
    s = (s * 9301 + 49297) % 233280;
    return s / 233280;
  };
}

function at(now: Date, minutesAgo: number): Date {
  return new Date(now.getTime() - minutesAgo * 60_000);
}

export function buildDemoInvestigations(playbooks: Map<string, Playbook>, now = new Date()): Investigation[] {
  const out: Investigation[] = [];
  const rnd = seq(42);

  const phish = playbooks.get('PB-PHISH-001');
  if (phish) {
    const t0 = at(now, 180);
    let inv = createInvestigation({
      playbook: phish,
      alertRef: 'DEMO-ALERT-1001',
      title: 'DEMO - User-reported invoice email with credential link',
      alertSource: 'Email security (demo)',
      severity: 'High',
      analyst: 'demo.analyst',
      demo: true,
      now: t0,
      random: rnd,
    });
    const ev: Record<string, string> = {
      alert_id: 'DEMO-ALERT-1001',
      detection_name: 'User reported phishing',
      event_time: '2026-10-10T13:41:00Z delivered; first click 2026-10-10T13:52:30Z (UTC)',
      message_id: 'NetworkMessageId 00000000-demo-0000-0000-000000001001',
      sender: 'From: accounts@examp1e-billing.test\nMailFrom: bounce@mailer.example.net\nSending IP: 198.51.100.7',
      auth_results: 'SPF=fail; DKIM=none; DMARC=fail; CompAuth=fail',
      subject: 'Invoice overdue - action required',
      recipients: '14 delivered to Inbox, 3 quarantined (finance team)',
      urls: 'hxxps://login.examp1e-billing[.]test/auth',
      interaction: 'j.doe@example.com clicked 2026-10-10T13:52:30Z (Safe Links ClickAllowed)',
      username: 'j.doe@example.com',
      auth_outcome: 'Successful sign-in from 203.0.113.50 (new country) at 2026-10-10T14:05:12Z, single-factor',
    };
    let m = 170;
    for (const [k, v] of Object.entries(ev)) inv = setEvidence(inv, k, v, at(now, (m -= 1)));
    for (const step of phish.steps.slice(0, 6)) inv = setStepDone(inv, step.id, true, at(now, (m -= 4)));
    inv = setStepNotes(inv, 'check-follow-on', 'Sign-in from 203.0.113.50 followed the click by 13 minutes. No new inbox rules found in the last 24h.', at(now, (m -= 1)));
    inv = addFinding(inv, 'supporting', 'DMARC fail and lookalike domain examp1e-billing.test impersonating the billing vendor.', at(now, (m -= 1)), rnd);
    inv = addFinding(inv, 'supporting', 'Successful single-factor sign-in from a new country 13 minutes after the click.', at(now, (m -= 1)), rnd);
    inv = addFinding(inv, 'contradicting', 'User says they closed the page without typing a password (not supported by sign-in logs).', at(now, (m -= 1)), rnd);
    inv = addTimelineEntry(inv, { time: '2026-10-10T13:41:00Z', description: 'Phishing email delivered to 14 inboxes', source: 'EmailEvents' }, at(now, (m -= 1)), rnd);
    inv = addTimelineEntry(inv, { time: '2026-10-10T13:52:30Z', description: 'j.doe@example.com clicked the link (ClickAllowed)', source: 'UrlClickEvents' }, at(now, (m -= 1)), rnd);
    inv = addTimelineEntry(inv, { time: '2026-10-10T14:05:12Z', description: 'Successful sign-in for j.doe from 203.0.113.50', source: 'SigninLogs' }, at(now, (m -= 1)), rnd);
    inv = addListItem(inv, 'missingInfo', 'Non-interactive sign-in logs are not collected in the demo workspace.', at(now, (m -= 1)), rnd);
    inv = addListItem(inv, 'openQuestions', 'Did any of the other 13 recipients submit credentials?', at(now, (m -= 1)), rnd);
    for (const a of ['yes', 'yes', 'yes', 'yes', 'no'] as const) {
      const state = evaluateDecision(phish, inv.decisionPath);
      if (!state.current) break;
      inv = answerDecision(inv, phish, state.current.id, a, at(now, (m -= 1)));
    }
    const outcome = evaluateDecision(phish, inv.decisionPath);
    if (outcome.outcome) inv = applyOutcome(inv, outcome.outcome, outcome.outcomeGuidance ?? '', at(now, (m -= 1)));
    inv = update(inv, 'assessment', { suspicion: 'Confirmed malicious', confidence: 'High', rationale: 'Lookalike domain, failed authentication, and an anomalous successful sign-in after the click.' }, at(now, (m -= 1)));
    inv = update(inv, 'escalation', { reason: 'User interacted with confirmed credential phishing and a suspicious successful sign-in followed.', recipient: '', nextSteps: 'Revoke sessions and reset password for j.doe; check the other 13 recipients for clicks; purge the campaign.', escalatedAt: null }, at(now, (m -= 1)));
    out.push(inv);
  }

  const pwsh = playbooks.get('PB-PWSH-001');
  if (pwsh) {
    let inv = createInvestigation({
      playbook: pwsh,
      alertRef: 'DEMO-ALERT-1002',
      title: 'DEMO - Encoded PowerShell launched by WINWORD.EXE',
      alertSource: 'EDR (demo)',
      severity: 'High',
      analyst: 'demo.analyst',
      demo: true,
      now: at(now, 75),
      random: rnd,
    });
    inv = setEvidence(inv, 'alert_id', 'DEMO-ALERT-1002', at(now, 70));
    inv = setEvidence(inv, 'hostname', 'WS-DEMO-0142.corp.example.com', at(now, 70));
    inv = setEvidence(inv, 'username', 'CORP\\a.analyst-demo', at(now, 69));
    inv = setEvidence(inv, 'parent_process', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE (PID 5120)', at(now, 69));
    inv = setEvidence(inv, 'command_line', 'powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA...', at(now, 68));
    inv = setStepDone(inv, 'capture-command', true, at(now, 66));
    inv = addFinding(inv, 'observation', 'Command line is truncated in the alert; full script block (4104) not yet retrieved.', at(now, 60), rnd);
    out.push(inv);
  }

  const brute = playbooks.get('PB-BRUTE-001');
  if (brute) {
    let inv = createInvestigation({
      playbook: brute,
      alertRef: 'DEMO-ALERT-1003',
      title: 'DEMO - Repeated failed sign-ins for one user',
      alertSource: 'SIEM (demo)',
      severity: 'Low',
      analyst: 'demo.analyst',
      demo: true,
      now: at(now, 1440),
      random: rnd,
    });
    inv = setEvidence(inv, 'alert_id', 'DEMO-ALERT-1003', at(now, 1430));
    inv = setEvidence(inv, 'src_ip', '192.0.2.44 (corporate egress)', at(now, 1430));
    inv = setEvidence(inv, 'targeted_accounts', 'm.lee@example.com - 38 failures - no lockout - not privileged', at(now, 1429));
    inv = setEvidence(inv, 'pattern', 'Guessing against one account from the corporate egress IP; ActiveSync client', at(now, 1428));
    inv = setEvidence(inv, 'auth_outcome', 'No success from other IPs; user changed password 2026-10-09', at(now, 1428));
    for (const step of brute.steps) inv = setStepDone(inv, step.id, true, at(now, 1420));
    for (const a of ['no', 'yes'] as const) {
      const state = evaluateDecision(brute, inv.decisionPath);
      if (!state.current) break;
      inv = answerDecision(inv, brute, state.current.id, a, at(now, 1410));
    }
    const outcome = evaluateDecision(brute, inv.decisionPath);
    if (outcome.outcome) inv = applyOutcome(inv, outcome.outcome, 'Phone mail client retrying the old password after a password change; confirmed by service desk ticket DEMO-SD-77.', at(now, 1405));
    inv = update(inv, 'assessment', { suspicion: 'Likely benign', confidence: 'High', rationale: 'Stale credentials on the user\'s phone; service desk confirmed.' }, at(now, 1404));
    inv = setStatus(inv, 'Resolved', at(now, 1400));
    out.push(inv);
  }
  return out;
}
