import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, esql, ev, evCustom, genericProcedure, sigma, starterReview } from './helpers';

export const cron: Playbook = {
  schemaVersion: 1,
  id: 'PB-CRON-001',
  version: '1.0.0',
  title: 'Suspicious cron job on Linux',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1053.003'],
  tactics: ['execution', 'persistence', 'privilege-escalation'],
  objective: 'Find what the new or changed cron entry runs, who added it and how, and whether it is system administration or attacker persistence.',
  alertMeaning: 'A crontab was edited or a file was written under a cron directory on a Linux host, and the entry or the way it was created looks unusual - for example it downloads and runs a script, or was added by a web service account.',
  whyItMatters: 'Cron is the simplest way to keep code running on Linux. Attackers use it to relaunch miners, backdoors, and reverse shells every few minutes.',
  difficulty: 'Intermediate',
  effort: '30-45 minutes',
  platforms: ['Linux'],
  logSources: ['edr', 'mde', 'cloud-audit', 'firewall'],
  alertContext: {
    triggers: ['File created or modified in /etc/cron.d, /etc/cron.hourly (daily, weekly), /etc/crontab, or /var/spool/cron.', 'crontab command run by a service account or from a script.', 'Cron entry containing curl, wget, base64, /dev/tcp, or a path under /tmp or /dev/shm.'],
    reviewFirst: ['Host, cron file path, and owning user.', 'The entry: schedule and command.', 'Process and account that wrote it.'],
    oftenMissing: ['The content of the script the entry calls.', 'How the writing account got a shell.'],
  },
  prerequisites: [
    { text: 'File and process telemetry on the Linux host (EDR or auditd rules on cron paths).', type: 'telemetry', required: true },
    { text: 'Syslog cron execution lines (CMD entries).', type: 'telemetry', required: false },
    { text: 'Configuration-management records (Ansible, Puppet, packages) for the host.', type: 'information', required: false },
  ],
  steps: [
    {
      id: 'entry-content',
      title: 'Record the cron entry',
      action: 'Record the file path, the user whose crontab it is, the schedule, and the full command. If the entry calls a script, record its path and get its content through the EDR (do not run it).',
      why: 'The command is the evidence. A schedule of every minute or every few minutes that fetches remote content is typical of malware.',
      where: ['DeviceFileEvents', 'EDR file view', 'auditd records'],
      fields: ['FolderPath', 'FileName', 'Cron line', 'Script path'],
      suspicious: ['curl or wget piped to sh or bash', 'base64 -d, /dev/tcp/, nc, or python -c one-liners', 'Scripts under /tmp, /var/tmp, /dev/shm, or hidden dot-directories', 'Output redirected to /dev/null with "* * * * *" schedule'],
      legitimate: ['Package-installed jobs (logrotate, backups) under /etc/cron.d with package ownership'],
      next: 'Identify who wrote it.',
      queryIds: ['kql-cron-files', 'esql-cron-files'],
    },
    {
      id: 'writer',
      title: 'Identify the process and account that wrote it',
      action: 'Find the process that modified the cron file (crontab, a shell redirect, a package manager, configuration management) and its parent chain and user.',
      why: 'A cron entry written by the web server\'s account or by a shell spawned from a network service indicates compromise of that service.',
      where: ['DeviceProcessEvents', 'auditd execve records'],
      fields: ['InitiatingProcessFileName', 'ProcessCommandLine', 'AccountName', 'Parent chain'],
      suspicious: ['Written by www-data, apache, nginx, tomcat, or a database account', 'Shell whose parent is a web server or sshd session from an unusual source'],
      legitimate: ['ansible, puppet, dpkg, rpm, or a named administrator via sudo'],
      next: 'Check whether the job has run.',
      queryIds: ['kql-crontab-commands'],
    },
    {
      id: 'executions',
      title: 'Check executions and what they did',
      action: 'Look for cron CMD lines in syslog and for processes whose parent is cron/crond matching the command. Review their network connections and files written.',
      why: 'If the job ran, its payload is active and may have contacted a control server.',
      where: ['Syslog (cron facility)', 'DeviceProcessEvents', 'DeviceNetworkEvents', 'Firewall logs'],
      fields: ['Execution times', 'Remote IP / domain', 'Files created'],
      suspicious: ['Regular outbound connections to an unknown host after each run', 'High CPU process started by cron (miner)'],
      legitimate: ['Backup or maintenance script contacting internal systems'],
      next: 'Check authorization.',
      queryIds: ['spl-cron-executions'],
    },
    {
      id: 'authorization',
      title: 'Check configuration management and change records',
      action: 'Ask the system owner or check configuration-management history for a matching job on this host.',
      why: 'Most legitimate cron jobs are deployed by tooling and exist on similar hosts.',
      where: ['Configuration-management repository', 'Change tickets', 'Other hosts in the same role'],
      fields: ['Matching job definition', 'Ticket'],
      suspicious: ['Not in configuration management and unique to this host'],
      legitimate: ['Defined in the host role and present across the fleet'],
      next: 'Look for other persistence.',
      queryIds: [],
    },
    {
      id: 'other-persistence',
      title: 'Look for related persistence and access',
      action: 'Check for new systemd units or timers, changes to shell profiles and authorized_keys, and recent SSH logons for the writing account.',
      why: 'Attackers rarely rely on one mechanism; SSH keys and systemd services often accompany cron.',
      where: ['DeviceFileEvents', 'auth log / sshd', 'EDR timeline'],
      fields: ['~/.ssh/authorized_keys changes', '/etc/systemd/system/*.service', 'SSH source IPs'],
      suspicious: ['New SSH key added around the same time', 'New service unit running from /tmp'],
      legitimate: ['No other changes'],
      next: 'Use the decision tree.',
      queryIds: [],
    },
  ],
  decisionTree: {
    start: 'managed',
    nodes: [
      { id: 'managed', question: 'Is the job defined in configuration management or a package, or confirmed by the system owner, and written by the expected tool?', yes: { outcome: 'benign', guidance: 'Record the source (repository, package, ticket).' }, no: { next: 'malicious-command', guidance: 'Unmanaged cron entry.' } },
      { id: 'malicious-command', question: 'Does the entry download or decode and run content, open a network shell, or run from a temporary/hidden path - or was it written by a service account?', yes: { next: 'spread', guidance: 'Likely attacker persistence.' }, no: { outcome: 'investigate', guidance: 'Unmanaged but not clearly malicious. Get the owner\'s confirmation; escalate if unverified.' } },
      { id: 'spread', question: 'Is the host internet-facing or critical, has the job already run and connected out, or does the same entry exist on other hosts?', yes: { outcome: 'critical', guidance: 'Follow the incident escalation procedure now.' }, no: { outcome: 'escalate', guidance: 'Escalate with the entry, writer, and any script content.' } },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true),
    ev('hostname', true),
    ev('username', true, 'Account that wrote the entry and the crontab owner.'),
    evCustom('cron_entry', 'Cron file and entry', 'File path, schedule, and full command.', true, true),
    ev('process', true, 'Process that wrote the entry.'),
    ev('command_line', false),
    ev('file_hash', false, 'Script called by the entry: path and SHA-256.'),
    ev('destination', false, 'Network destinations contacted by executions.'),
    evCustom('authorization', 'Configuration management / owner check', 'Where you looked and the result.', true),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: ['Cron entry that downloads, decodes, or runs content from temporary or hidden paths.', 'Entry written by a service account or from a network-service shell.', 'Unmanaged entry the owner cannot explain.'],
    immediate: ['Job already executed and contacted external hosts.', 'Same entry on multiple hosts.', 'Internet-facing or critical server affected.'],
    benignClosure: ['Job is defined in configuration management or a package, or confirmed by the owner with a record.'],
  },
  queries: [
    {
      id: 'kql-cron-files',
      title: 'Cron files created or modified on a Linux host',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Lists changes under cron directories with the writing process.',
      dataSources: ['DeviceFileEvents (Defender for Endpoint on Linux)'],
      query: `DeviceFileEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where FolderPath startswith "/etc/cron" or FolderPath startswith "/var/spool/cron"
| project Timestamp, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc`,
      placeholders: [PH.lookback('14d'), PH.hostname('srv-demo-lnx01')],
      keyFields: [{ name: 'InitiatingProcessAccountName', meaning: 'Service accounts writing cron files are suspicious.' }],
      positive: 'Each change needs an owner.',
      negative: 'Requires the Linux sensor; crontab edits through temporary files may show the temp file name.',
      prerequisites: 'Defender for Endpoint on Linux.',
      schemaNotes: 'Paths differ by distribution (/var/spool/cron/crontabs on Debian-based systems).',
      example: 'hostname = srv-demo-lnx01',
    },
    {
      id: 'kql-crontab-commands',
      title: 'crontab and cron-path write commands',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds crontab invocations and shell commands that reference cron paths.',
      dataSources: ['DeviceProcessEvents (Linux)'],
      query: `DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where FileName == "crontab" or ProcessCommandLine has_any ("/etc/cron", "/var/spool/cron")
| project Timestamp, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc`,
      placeholders: [PH.lookback('14d'), PH.hostname('srv-demo-lnx01')],
      keyFields: [{ name: 'InitiatingProcessFileName', meaning: 'Parent of the command (shell, web server, sshd).' }],
      positive: 'Shows how the entry was added.',
      negative: 'Editors writing the file directly may not match.',
      prerequisites: 'Defender for Endpoint on Linux.',
      schemaNotes: 'Standard Defender columns.',
      example: 'hostname = srv-demo-lnx01',
    },
    {
      id: 'spl-cron-executions',
      title: 'Cron command executions from syslog',
      language: 'spl',
      platform: 'Splunk Enterprise (Linux syslog)',
      purpose: 'Counts cron CMD lines per user and command on a host.',
      dataSources: ['Linux syslog / cron log'],
      query: `index="{{index}}" host="{{hostname}}" earliest=-{{lookback}} (CRON OR crond) "CMD"
| rex "\\((?<cron_user>[^)]+)\\) CMD \\((?<cron_command>.+)\\)"
| stats count min(_time) as first_seen max(_time) as last_seen by cron_user cron_command
| convert ctime(first_seen) ctime(last_seen)
| sort first_seen`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding Linux syslog.', example: 'os' }, PH.hostname('srv-demo-lnx01'), PH.lookback('7d')],
      keyFields: [{ name: 'first_seen', meaning: 'Commands first seen recently are new jobs.' }],
      positive: 'Shows which jobs ran and since when.',
      negative: 'Requires cron logging to syslog and forwarding from the host.',
      prerequisites: 'Linux syslog in Splunk.',
      schemaNotes: 'Message format differs slightly between cron implementations.',
      example: 'index = os, hostname = srv-demo-lnx01',
    },
    esql(
      'esql-cron-files',
      'Cron files created or modified on a host',
      'Lists file changes under cron directories on one host over the last 14 days.',
      ['logs-endpoint.events.file-*'],
      `FROM logs-endpoint.events.file-*
| WHERE @timestamp > NOW() - 14 days AND host.name == "{{hostname}}"
| WHERE file.path LIKE "/etc/cron*" OR file.path LIKE "/var/spool/cron*"
| KEEP @timestamp, event.action, file.path, user.name, process.name, process.command_line
| SORT @timestamp ASC
| LIMIT 200`,
      [PH.hostname('srv-demo-lnx01')],
      'Each change needs an owner.',
      'Requires Elastic Defend on the Linux host.',
    ),
    genericProcedure('generic-cron', 'Generic cron procedure', `1. Record the cron file, owner, schedule, and command; get any called script's content.
2. Identify the writing process, its parent chain, and account.
3. Find executions (cron CMD log lines, children of cron) and their network activity.
4. Check configuration management, packages, and the system owner.
5. Check systemd units/timers, shell profiles, authorized_keys, and recent SSH logons.`),
  ],
  sigmaRules: [
    sigma(
      'sigma-cron-file-write',
      '41f515e9-37e5-478b-b32b-9cb3a9f9438a',
      'Cron File Written By Uncommon Process',
      'Detects files written under cron directories by processes other than common package and configuration managers.',
      ['attack.persistence', 'attack.t1053.003'],
      '    category: file_event\n    product: linux',
      `    selection:
        TargetFilename|startswith:
            - '/etc/cron.d/'
            - '/etc/cron.hourly/'
            - '/etc/cron.daily/'
            - '/etc/crontab'
            - '/var/spool/cron/'
    filter_managers:
        Image|endswith:
            - '/dpkg'
            - '/rpm'
            - '/yum'
            - '/dnf'
            - '/apt-get'
            - '/ansible-playbook'
            - '/puppet'
    condition: selection and not filter_managers`,
      ['Administrators editing crontabs', 'Software installers not listed in the filter'],
      'medium',
    ),
  ],
  detectionConsiderations: ['Systemd timers are a modern equivalent and need separate monitoring.', 'Content inspection of the entry matters more than the fact a file changed.'],
  visibilityGaps: ['Many Linux servers have no EDR and no auditd rules on cron paths.', 'Containers may run cron inside images without host-level visibility.'],
  relatedTechniques: [
    { id: 'T1059.004', reason: 'Cron entries run Unix shell commands.' },
    { id: 'T1105', reason: 'Entries often download the payload on each run.' },
    { id: 'T1543.002', reason: 'Systemd services are an alternative persistence mechanism.' },
    { id: 'T1021.004', reason: 'SSH access is commonly how the entry was added.' },
    { id: 'T1546.004', reason: 'Shell profile changes often accompany cron persistence.' },
  ],
  references: [attackRef('T1053.003', 'Cron')],
  assumptions: ['Tier 1 does not remove cron entries on production servers.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};
