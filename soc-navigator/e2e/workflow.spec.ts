import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

/** Fails the test on any console error/warning or uncaught exception (CSP violations included). */
function trackConsole(page: Page): string[] {
  const problems: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error' || m.type() === 'warning') problems.push(`${m.type()}: ${m.text()}`);
  });
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
  return problems;
}

test.describe('principal Tier 1 workflow', () => {
  test('matrix -> technique -> investigation -> report -> authoring', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const problems = trackConsole(page);

    // Dashboard loads with clearly labeled demo data and real dataset counts.
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await expect(page.getByText('Demo data present')).toBeVisible();
    await expect(page.getByText('Enterprise v19.2')).toBeVisible();

    // Matrix search and technique details.
    await page.getByRole('link', { name: 'ATT&CK Enterprise Matrix' }).click();
    await page.getByLabel('Search', { exact: true }).fill('T1059.001');
    const cell = page.getByRole('button', { name: /^T1059\.001 PowerShell \(sub-technique\)/ });
    await expect(cell).toBeVisible();
    await cell.click();
    const drawer = page.getByRole('dialog', { name: /PowerShell/ });
    await expect(drawer).toBeVisible();
    await expect(drawer.getByText('T1059.001', { exact: false }).first()).toBeVisible();
    await expect(drawer.getByRole('link', { name: /MITRE ATT&CK page/ })).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1059/001');
    await expect(drawer.getByText('Draft').first()).toBeVisible();

    // Start an investigation from the technique.
    await drawer.getByRole('button', { name: 'Start Investigation' }).click();
    const dialog = page.getByRole('dialog', { name: 'Start an investigation' });
    await expect(dialog.getByLabel(/Playbook/)).toHaveValue('PB-PWSH-001');
    await dialog.getByLabel(/Alert \/ ticket reference/).fill('E2E-ALERT-77');
    await dialog.getByRole('button', { name: 'Start investigation' }).click();
    await expect(page).toHaveURL(/#\/investigations\/INV-\d{8}-[A-Z0-9]{4}$/);
    const invUrl = page.url();
    await expect(page.getByText('E2E-ALERT-77').first()).toBeVisible();

    // Complete a step and add notes; status moves to In Progress.
    await page.getByLabel(/Mark step 1 complete/).check();
    await expect(page.getByLabel('Status')).toHaveValue('In Progress');
    const notes = page.getByLabel('Step notes (optional)').first();
    await notes.fill('Checked full command line in EDR.');
    await notes.blur();

    // Record evidence.
    const host = page.getByLabel(/Hostname \/ asset ID/);
    await host.fill('WS-E2E-01');
    await host.blur();

    // Walk the decision tree to an outcome and apply it.
    await page.getByRole('button', { name: 'Yes', exact: true }).click(); // clearly malicious
    await page.getByRole('button', { name: 'No', exact: true }).click(); // not multi-host
    await expect(page.getByText('Recommended outcome:')).toBeVisible();
    await page.getByRole('button', { name: /^Apply:/ }).click();
    await expect(page.getByLabel('Status')).toHaveValue('Escalation Recommended');

    // Progress persists across a reload.
    await page.reload();
    await expect(page.getByLabel(/Mark step 1 complete/)).toBeChecked();
    await expect(page.getByLabel(/Hostname \/ asset ID/)).toHaveValue('WS-E2E-01');
    await expect(page.getByText('Recommended outcome:')).toBeVisible();

    // Query templates are pre-filled from evidence and copyable.
    const queryToggle = page.getByRole('button', { name: /Risky PowerShell command-line patterns on a host/ }).last();
    await queryToggle.click();
    await page.getByRole('button', { name: 'Copy query' }).last().click();
    await expect(page.getByRole('button', { name: 'Copied' })).toBeVisible();
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    expect(clip).toContain('DeviceProcessEvents');
    expect(clip).toContain('DeviceName =~ "WS-E2E-01"');

    // Tier 2 handoff report contains the recorded information and exports Markdown.
    await page.getByRole('link', { name: 'Tier 2 handoff report' }).click();
    await expect(page.getByRole('heading', { name: /Tier 2 Handoff - INV-/ })).toBeVisible();
    await expect(page.getByText('WS-E2E-01').first()).toBeVisible();
    await expect(page.getByText(/\[x\] Capture the full command line/)).toBeVisible();
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export Markdown' }).click()]);
    const md = readFileSync((await download.path())!, 'utf8');
    expect(md).toContain('# Tier 2 Handoff');
    expect(md).toContain('WS-E2E-01');
    expect(md).toContain('did not execute any query');

    // Report edit -> mark escalated.
    await page.getByLabel('Escalated to (team / person)').fill('Tier 2 on-call');
    await page.getByLabel('Escalated to (team / person)').blur();
    await page.getByLabel('Reason for escalation').fill('Malicious encoded PowerShell from Office.');
    await page.getByLabel('Reason for escalation').blur();
    await page.getByRole('button', { name: 'Mark as escalated' }).click();
    await expect(page.getByText('Escalated', { exact: true }).first()).toBeVisible();

    // Authoring: switch role, duplicate a playbook, edit, save, export.
    await page.getByRole('link', { name: 'Settings and Data Sources' }).click();
    await page.getByLabel('Role (demo)').selectOption('author');
    await page.getByRole('link', { name: 'Investigation Playbooks' }).click();
    await page.getByRole('tab', { name: 'Author and review' }).click();
    await page.getByRole('button', { name: 'Duplicate PB-PHISH-001' }).click();
    await expect(page).toHaveURL(/#\/playbooks\/PB-LOCAL-001\/edit$/);
    await page.locator('#ov-title').fill('E2E phishing variant');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByText(/PB-LOCAL-001 v0\.1\.1 saved/)).toBeVisible();
    await page.getByRole('tab', { name: /Preview as Tier 1 analyst/ }).click();
    await expect(page.getByText('Draft guidance - not yet reviewed')).toBeVisible();
    await page.getByRole('link', { name: 'Playbook management' }).click();
    const [pbDownload] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export PB-LOCAL-001' }).click()]);
    const exported = JSON.parse(readFileSync((await pbDownload.path())!, 'utf8'));
    expect(exported.title).toBe('E2E phishing variant');
    expect(exported.status).toBe('Draft');

    // Investigation still listed after navigation; nothing logged to the console.
    await page.goto(invUrl);
    await expect(page.getByText('E2E-ALERT-77').first()).toBeVisible();
    expect(problems).toEqual([]);
  });

  test('every primary view renders without console errors', async ({ page }) => {
    const problems = trackConsole(page);
    for (const route of ['/', '/matrix', '/playbooks', '/playbooks?tab=manage', '/playbooks/PB-RANSOM-001', '/investigations', '/reference', '/reference?tab=queries', '/reference?tab=events', '/reference?tab=glossary', '/reports', '/settings', '/nope']) {
      await page.goto(`/#${route}`);
      await expect(page.locator('main h1, main [role="alert"], main p').first()).toBeVisible();
    }
    await page.goto('/#/matrix?t=T1486');
    await expect(page.getByRole('dialog', { name: /Data Encrypted for Impact/ })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    expect(problems).toEqual([]);
  });

  test('ATT&CK data failure degrades gracefully', async ({ page }) => {
    await page.route('**/data/attack-enterprise.json', (route) => route.fulfill({ status: 503, body: 'unavailable' }));
    await page.goto('/#/matrix');
    await expect(page.getByText('ATT&CK data could not be loaded')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible();
    // Playbooks and investigations keep working without ATT&CK data.
    await page.getByRole('link', { name: 'Investigation Playbooks' }).click();
    await expect(page.getByText('Reported or detected phishing email')).toBeVisible();
    await page.goto('/#/playbooks/PB-PHISH-001');
    await expect(page.getByRole('heading', { name: 'Reported or detected phishing email' })).toBeVisible();
  });
});
