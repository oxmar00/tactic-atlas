import type { Playbook, QueryTemplate, SigmaRule } from '../../lib/playbooks/schema';
import { PH, esql, sigma } from './helpers';

/**
 * Additions layered onto the original starter playbooks: Elastic ES|QL templates, Sigma rule
 * companions, and Linux coverage. Kept in one place so each playbook file stays readable.
 */

const WIN = '    category: process_creation\n    product: windows';
const none = 'A clean result only covers hosts shipping this data stream in the chosen window.';

export const EXTRA_QUERIES: Record<string, QueryTemplate[]> = {
  'PB-PHISH-001': [
    esql('esql-phish-recipients', 'Recipients of mail from a sender', 'Lists recipients and subjects of messages from the reported sender over the last 7 days, where email logs are mapped to ECS.', ['logs-*'],
      `FROM logs-*
| WHERE @timestamp > NOW() - 7 days AND email.from.address == "{{sender}}"
| STATS messages = COUNT(*), first_seen = MIN(@timestamp) BY email.to.address, email.subject
| SORT first_seen ASC
| LIMIT 500`,
      [{ name: 'sender', kind: 'string', description: 'Sender address.', example: 'billing@examp1e.com' }],
      'Shows who received the campaign; it does not show clicks.', 'Email gateways are often not mapped to ECS email fields; an empty result may be a mapping gap.'),
  ],
  'PB-USEREXEC-001': [
    esql('esql-office-children', 'Interpreters started by Office, browsers, or Explorer', 'Finds script hosts and shells whose parent is a common lure application on one host over the last 24 hours.', ['logs-endpoint.events.process-*'],
      `FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 24 hours AND host.name == "{{hostname}}"
| WHERE process.parent.name IN ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE", "ONENOTE.EXE", "explorer.exe", "msedge.exe", "chrome.exe")
| WHERE process.name IN ("wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "powershell.exe", "cmd.exe")
| KEEP @timestamp, user.name, process.parent.name, process.name, process.command_line, process.hash.sha256
| SORT @timestamp ASC
| LIMIT 200`,
      [PH.hostname()], 'An interpreter under an Office application or browser is a strong lead.', none),
  ],
  'PB-PWSH-001': [
    esql('esql-pwsh-flags', 'PowerShell with encoded, download, or hidden-window flags', 'Finds risky PowerShell command lines on one host over the last 24 hours.', ['logs-endpoint.events.process-*'],
      `FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 24 hours AND host.name == "{{hostname}}"
| WHERE process.name IN ("powershell.exe", "pwsh.exe")
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE cmd LIKE "* -enc*" OR cmd LIKE "*downloadstring*" OR cmd LIKE "*invoke-webrequest*"
    OR cmd LIKE "*frombase64string*" OR cmd LIKE "*-w hidden*" OR cmd LIKE "*-windowstyle hidden*"
| KEEP @timestamp, user.name, process.parent.name, process.command_line
| SORT @timestamp ASC
| LIMIT 200`,
      [PH.hostname()], 'Each row is a command to decode and review; management tools use these flags too.', none),
  ],
  'PB-SCHTASK-001': [
    esql('esql-schtasks-create', 'schtasks.exe task creation', 'Lists schtasks /create executions over the last 7 days with the launching parent.', ['logs-endpoint.events.process-*'],
      `FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 7 days AND process.name == "schtasks.exe"
| WHERE TO_LOWER(process.command_line) LIKE "*/create*"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line
| SORT @timestamp ASC
| LIMIT 500`,
      [], 'Command-line evidence of task creation; look for /s, /ru SYSTEM, and user-writable paths.', 'Tasks created through the COM API or PowerShell cmdlets do not start schtasks.exe.'),
  ],
  'PB-WMI-001': [
    esql('esql-wmiprvse-children', 'Processes started by WmiPrvSE.exe', 'Lists children of the WMI provider host on one host over the last 24 hours.', ['logs-endpoint.events.process-*'],
      `FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 24 hours AND host.name == "{{hostname}}"
| WHERE TO_LOWER(process.parent.name) == "wmiprvse.exe"
| KEEP @timestamp, user.name, process.name, process.command_line
| SORT @timestamp ASC
| LIMIT 200`,
      [PH.hostname()], 'Shows what WMI executed; check the account and source.', none),
  ],
  'PB-CREDDUMP-001': [
    esql('esql-dump-commands', 'Credential-dumping command lines', 'Finds LSASS dump, hive save, and NTDS extraction command lines over the last 7 days.', ['logs-endpoint.events.process-*'],
      `FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 7 days
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE (cmd LIKE "*lsass*" AND (cmd LIKE "*minidump*" OR cmd LIKE "*comsvcs*" OR cmd LIKE "*procdump*"))
    OR (process.name == "reg.exe" AND cmd LIKE "* save *" AND (cmd LIKE "*hklm*sam*" OR cmd LIKE "*hklm*security*" OR cmd LIKE "*hklm*system*"))
    OR cmd LIKE "*ntds.dit*"
| KEEP @timestamp, host.name, user.name, process.name, process.command_line, process.parent.name
| SORT @timestamp ASC
| LIMIT 200`,
      [], 'Matching rows are high-priority leads; verify backup or forensic tooling.', 'Custom and in-memory tools do not produce these command lines.'),
  ],
  'PB-BRUTE-001': [
    esql('esql-auth-failures', 'Authentication failures by source', 'Counts failed authentications and distinct users per source IP over the last 24 hours.', ['logs-system.security-*', 'logs-system.auth-*'],
      `FROM logs-system.security-*, logs-system.auth-*
| WHERE @timestamp > NOW() - 24 hours
| WHERE event.category == "authentication" AND event.outcome == "failure"
| STATS failures = COUNT(*), distinct_users = COUNT_DISTINCT(user.name) BY source.ip
| WHERE failures >= 20
| SORT distinct_users DESC
| LIMIT 100`,
      [], 'Sources with many failures across many users suggest spraying; check for successes next.', none),
    {
      id: 'kql-ssh-failures',
      title: 'Linux SSH failed logons by source (Syslog)',
      language: 'kql',
      platform: 'Microsoft Sentinel (Syslog via Azure Monitor Agent)',
      purpose: 'Counts sshd failed-password messages per source IP and lists targeted users.',
      dataSources: ['Syslog (auth / authpriv facility)'],
      query: `Syslog
| where TimeGenerated > ago({{lookback}})
| where ProcessName == "sshd" and SyslogMessage has "Failed password"
| extend SrcIp = extract(@"from ([0-9a-fA-F:.]+) port", 1, SyslogMessage),
         TargetUser = extract(@"for (?:invalid user )?(\\S+) from", 1, SyslogMessage)
| summarize Failures = count(), Users = make_set(TargetUser, 50), Hosts = make_set(Computer, 20) by SrcIp
| order by Failures desc`,
      placeholders: [PH.lookback('24h')],
      keyFields: [{ name: 'Users', meaning: 'Many invalid or system users indicate automated guessing.' }],
      positive: 'Identifies attacking sources against SSH. Search "Accepted password" or "Accepted publickey" from the same source for successes.',
      negative: 'Requires auth-facility syslog from the Linux hosts; internet-facing SSH sees constant background noise.',
      prerequisites: 'Syslog auth/authpriv collection from Linux hosts.',
      schemaNotes: 'Message wording differs slightly between OpenSSH versions and distributions.',
      example: 'lookback = 24h',
    },
    {
      id: 'spl-ssh-failures',
      title: 'Linux SSH failed logons by source',
      language: 'spl',
      platform: 'Splunk Enterprise (Linux secure / auth logs)',
      purpose: 'Counts sshd failed-password events per source and lists targeted users.',
      dataSources: ['sourcetype linux_secure (or your auth log sourcetype)'],
      query: `index="{{index}}" sourcetype=linux_secure "Failed password" earliest=-{{lookback}}
| rex "for (invalid user )?(?<target_user>\\S+) from (?<src_ip>\\S+) port"
| stats count dc(target_user) as distinct_users values(target_user) as users by src_ip
| sort - count`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding Linux auth logs.', example: 'os' }, PH.lookback('24h')],
      keyFields: [{ name: 'distinct_users', meaning: 'Many users per source indicates guessing or spraying.' }],
      positive: 'Attacking sources against SSH; check "Accepted" lines from the same source.',
      negative: 'Only hosts forwarding auth logs are covered.',
      prerequisites: 'Linux auth logs in Splunk.',
      schemaNotes: 'Sourcetype names vary (linux_secure, syslog).',
      example: 'index = os',
    },
  ],
  'PB-VALIDACCT-001': [
    esql('esql-user-signins', 'Successful sign-ins for a user by source', 'Summarizes where a user successfully signed in from over the last 30 days.', ['logs-azure.signinlogs-*', 'logs-system.security-*'],
      `FROM logs-azure.signinlogs-*, logs-system.security-*
| WHERE @timestamp > NOW() - 30 days
| WHERE event.category == "authentication" AND event.outcome == "success" AND user.name == "{{username}}"
| STATS sign_ins = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY source.ip, source.geo.country_name
| SORT first_seen ASC`,
      [PH.username()], 'Sources first seen near the alert are anomalies to explain.', 'User name formats differ between sources; try UPN and short name.'),
  ],
  'PB-RUNKEY-001': [
    esql('esql-run-keys', 'Run key values set on a host', 'Lists registry values written under Run keys on one host over the last 7 days.', ['logs-endpoint.events.registry-*'],
      `FROM logs-endpoint.events.registry-*
| WHERE @timestamp > NOW() - 7 days AND host.name == "{{hostname}}"
| WHERE registry.path LIKE "*CurrentVersion*Run*"
| KEEP @timestamp, user.name, process.name, registry.path, registry.data.strings
| SORT @timestamp ASC
| LIMIT 200`,
      [PH.hostname()], 'Each value needs an owner; common software creates many.', none),
  ],
  'PB-LATMOVE-001': [
    esql('esql-remote-logons', 'Network and RDP logons to a host', 'Summarizes successful remote logons to one host over the last 7 days.', ['logs-system.security-*'],
      `FROM logs-system.security-*
| WHERE @timestamp > NOW() - 7 days AND host.name == "{{hostname}}"
| WHERE event.code == "4624" AND winlog.logon.type IN ("Network", "RemoteInteractive")
| STATS logons = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name, source.ip, winlog.logon.type
| SORT first_seen ASC`,
      [PH.hostname('srv-demo-app01')], 'Shows who connected remotely and from where.', 'Requires the destination host to ship its Security log.'),
  ],
  'PB-INGRESS-001': [
    esql('esql-lolbin-downloads', 'Built-in utilities used to download files', 'Finds certutil, bitsadmin, curl, and wget download command lines over the last 7 days.', ['logs-endpoint.events.process-*'],
      `FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 7 days
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE (process.name == "certutil.exe" AND cmd LIKE "*urlcache*")
    OR (process.name == "bitsadmin.exe" AND cmd LIKE "*transfer*")
    OR (process.name IN ("curl.exe", "wget.exe", "curl", "wget") AND cmd LIKE "*http*")
| KEEP @timestamp, host.name, user.name, process.name, process.command_line, process.parent.name
| SORT @timestamp ASC
| LIMIT 500`,
      [], 'Each row is a download to attribute.', 'PowerShell and custom downloaders are not covered by this query.'),
  ],
  'PB-INJECT-001': [
    esql('esql-unusual-network', 'Network connections from rarely-networking processes', 'Finds outbound connections from processes commonly used as injection targets on one host over the last 24 hours.', ['logs-endpoint.events.network-*'],
      `FROM logs-endpoint.events.network-*
| WHERE @timestamp > NOW() - 24 hours AND host.name == "{{hostname}}"
| WHERE process.name IN ("notepad.exe", "rundll32.exe", "regsvr32.exe", "dllhost.exe", "werfault.exe")
| STATS connections = COUNT(*), first_seen = MIN(@timestamp) BY process.name, destination.ip, destination.port
| SORT connections DESC
| LIMIT 100`,
      [PH.hostname()], 'Connections from these processes are leads for injected code.', 'Injected browsers and service hosts blend in and are not listed.'),
  ],
  'PB-C2-001': [
    esql('esql-dest-prevalence', 'Hosts and processes contacting a destination IP', 'Lists hosts and processes that connected to the destination over the last 30 days.', ['logs-endpoint.events.network-*'],
      `FROM logs-endpoint.events.network-*
| WHERE @timestamp > NOW() - 30 days AND destination.ip == "{{dest_ip}}"
| STATS connections = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.name, process.name, user.name
| SORT connections DESC`,
      [{ name: 'dest_ip', kind: 'string', description: 'Destination IP address.', example: '198.51.100.23' }], 'Shows which hosts and processes are involved.', 'For domains, search dns.question.name in DNS data streams instead.'),
  ],
  'PB-EXFIL-001': [
    esql('esql-exfil-tools', 'Bulk-transfer tool executions', 'Finds rclone, WinSCP, and MEGA client executions over the last 7 days.', ['logs-endpoint.events.process-*'],
      `FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 7 days
| WHERE process.name IN ("rclone.exe", "winscp.exe", "pscp.exe", "megasync.exe", "megacmd.exe", "rclone")
    OR TO_LOWER(process.command_line) LIKE "*rclone*"
| KEEP @timestamp, host.name, user.name, process.name, process.executable, process.command_line
| SORT @timestamp ASC
| LIMIT 200`,
      [], 'Tool usage to attribute; IT may use some legitimately.', 'Renamed tools with different command lines are missed.'),
  ],
  'PB-RANSOM-001': [
    esql('esql-recovery-inhibit', 'Recovery inhibition commands', 'Finds shadow-copy deletion and recovery-disabling commands over the last 24 hours.', ['logs-endpoint.events.process-*'],
      `FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 24 hours
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE (process.name == "vssadmin.exe" AND cmd LIKE "*delete*shadows*")
    OR (process.name == "wmic.exe" AND cmd LIKE "*shadowcopy*delete*")
    OR (process.name == "bcdedit.exe" AND cmd LIKE "*recoveryenabled*")
    OR (process.name == "wbadmin.exe" AND cmd LIKE "*delete*")
| KEEP @timestamp, host.name, user.name, process.name, process.command_line, process.parent.name
| SORT @timestamp ASC`,
      [], 'Any match outside documented maintenance is a strong ransomware precursor.', 'Deletion through APIs produces no such command line.'),
  ],
};

export const EXTRA_SIGMA: Record<string, SigmaRule[]> = {
  'PB-USEREXEC-001': [
    sigma('sigma-office-child', '4fe0f7d7-ab25-488e-9c70-2697c4126310', 'Office Application Spawning Script Interpreter', 'Detects Microsoft Office applications starting a script host, shell, or common proxy binary.', ['attack.execution', 'attack.t1204.002'], WIN,
      `    selection_parent:
        ParentImage|endswith:
            - '\\WINWORD.EXE'
            - '\\EXCEL.EXE'
            - '\\POWERPNT.EXE'
            - '\\OUTLOOK.EXE'
            - '\\ONENOTE.EXE'
    selection_child:
        Image|endswith:
            - '\\wscript.exe'
            - '\\cscript.exe'
            - '\\mshta.exe'
            - '\\powershell.exe'
            - '\\cmd.exe'
            - '\\rundll32.exe'
            - '\\regsvr32.exe'
    condition: all of selection_*`, ['Office add-ins and macros used by the business'], 'high'),
  ],
  'PB-PWSH-001': [
    sigma('sigma-pwsh-download-cradle', '6dfc3659-1275-436d-8a46-7b811ecad46f', 'PowerShell Download And Execute Pattern', 'Detects PowerShell command lines combining a web download with in-memory execution.', ['attack.execution', 'attack.t1059.001'], WIN,
      `    selection_img:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_download:
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
            - 'Net.WebClient'
    selection_exec:
        CommandLine|contains:
            - 'IEX'
            - 'Invoke-Expression'
    condition: all of selection_*`, ['Administrative bootstrap scripts', 'Software installers'], 'high'),
  ],
  'PB-SCHTASK-001': [
    sigma('sigma-schtasks-suspicious', '4c90d194-0ee6-4f11-9bc0-0c010cd18086', 'Scheduled Task Created With Interpreter Or User-Writable Path', 'Detects schtasks.exe creating a task whose action uses a script interpreter or a user-writable path.', ['attack.persistence', 'attack.t1053.005'], WIN,
      `    selection_img:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains: '/create'
    selection_action:
        CommandLine|contains:
            - 'powershell'
            - 'mshta'
            - 'wscript'
            - 'rundll32'
            - '\\AppData\\'
            - '\\Users\\Public\\'
            - '\\ProgramData\\'
            - '\\Temp\\'
    condition: all of selection_*`, ['Software updaters installed per user', 'IT automation'], 'medium'),
  ],
  'PB-WMI-001': [
    sigma('sigma-wmiprvse-shell', '66b99d6e-40eb-4e92-8837-34244458138e', 'WMI Provider Host Spawning Shell', 'Detects WmiPrvSE.exe starting a command shell or PowerShell, typical of remote WMI execution.', ['attack.execution', 'attack.t1047'], WIN,
      `    selection:
        ParentImage|endswith: '\\WmiPrvSE.exe'
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\pwsh.exe'
    condition: selection`, ['Systems management and monitoring platforms'], 'medium'),
  ],
  'PB-CREDDUMP-001': [
    sigma('sigma-lsass-dump-cmd', 'f0c63699-2b1d-4575-bf10-3127e0f30095', 'LSASS Memory Dump Via Command Line', 'Detects command lines that dump LSASS memory with comsvcs.dll or procdump.', ['attack.credential-access', 'attack.t1003.001'], WIN,
      `    selection_comsvcs:
        CommandLine|contains|all:
            - 'comsvcs'
            - 'MiniDump'
    selection_procdump:
        CommandLine|contains|all:
            - 'procdump'
            - 'lsass'
    condition: 1 of selection_*`, ['Authorized diagnostics with a support ticket'], 'critical'),
  ],
  'PB-RUNKEY-001': [
    sigma('sigma-run-key-suspicious', '752bb11c-c140-4b62-8074-6b367db2c4ae', 'Run Key Pointing To Interpreter Or User-Writable Path', 'Detects Run or RunOnce values whose data references a script interpreter or user-writable location.', ['attack.persistence', 'attack.t1547.001'], '    category: registry_set\n    product: windows',
      `    selection_key:
        TargetObject|contains: '\\CurrentVersion\\Run'
    selection_data:
        Details|contains:
            - 'powershell'
            - 'mshta'
            - 'wscript'
            - 'rundll32'
            - '\\Users\\Public\\'
            - '\\Temp\\'
    condition: all of selection_*`, ['Per-user applications that register updaters'], 'medium'),
  ],
  'PB-INGRESS-001': [
    sigma('sigma-certutil-bits-download', 'c3148730-5efb-4b55-90a9-55854216d4f5', 'File Download Via Certutil Or Bitsadmin', 'Detects certutil or bitsadmin used to download a file.', ['attack.command-and-control', 'attack.t1105'], WIN,
      `    selection_certutil:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains:
            - 'urlcache'
            - 'verifyctl'
    selection_bits:
        Image|endswith: '\\bitsadmin.exe'
        CommandLine|contains: '/transfer'
    condition: 1 of selection_*`, ['Administrative scripts', 'Certificate revocation checks'], 'medium'),
  ],
  'PB-RANSOM-001': [
    sigma('sigma-shadow-copy-delete', '7917c06d-92ff-482b-ac54-3e8c8d480694', 'Shadow Copies Deleted Or Recovery Disabled', 'Detects commands that delete volume shadow copies or disable Windows recovery.', ['attack.impact', 'attack.t1490'], WIN,
      `    selection_vssadmin:
        Image|endswith: '\\vssadmin.exe'
        CommandLine|contains|all:
            - 'delete'
            - 'shadows'
    selection_wmic:
        Image|endswith: '\\wmic.exe'
        CommandLine|contains|all:
            - 'shadowcopy'
            - 'delete'
    selection_bcdedit:
        Image|endswith: '\\bcdedit.exe'
        CommandLine|contains: 'recoveryenabled'
    condition: 1 of selection_*`, ['Backup software and disk-space maintenance scripts'], 'high'),
  ],
};

/** Returns the playbook with its extra queries and Sigma rules appended. */
export function withExtras(pb: Playbook): Playbook {
  const queries = EXTRA_QUERIES[pb.id];
  const rules = EXTRA_SIGMA[pb.id];
  if (!queries && !rules) return pb;
  return { ...pb, queries: [...pb.queries, ...(queries ?? [])], sigmaRules: [...(pb.sigmaRules ?? []), ...(rules ?? [])] };
}
