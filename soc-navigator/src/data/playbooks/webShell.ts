import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, esql, ev, evCustom, genericProcedure, sigma, starterReview } from './helpers';

export const webShell: Playbook = {
  schemaVersion: 1,
  id: 'PB-WEBSHELL-001',
  version: '1.0.0',
  title: 'Exploited public-facing application or web shell',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1190', 'T1505', 'T1505.003'],
  tactics: ['initial-access', 'persistence'],
  objective: 'Determine whether an internet-facing server was exploited, whether a web shell or other foothold was planted, and what the attacker did through it.',
  alertMeaning: 'A web or application server process started a command shell or system utility, a new script file appeared in a web directory, or the web application firewall reported an exploit attempt that may have succeeded.',
  whyItMatters: 'Internet-facing servers are attacked continuously. A successful exploit gives direct access inside the perimeter, and a web shell lets the attacker return at will.',
  difficulty: 'Advanced',
  effort: '45-90 minutes (escalate early)',
  platforms: ['Windows', 'Linux', 'Network Devices'],
  logSources: ['mde', 'edr', 'firewall', 'proxy', 'sysmon', 'win-security'],
  alertContext: {
    triggers: ['w3wp.exe, httpd, nginx, php-fpm, tomcat/java, or a similar server process spawning cmd, powershell, sh, bash, whoami, or net.', 'New .aspx, .ashx, .php, or .jsp file in a web root, especially created by the web server itself.', 'WAF or IPS exploit alert followed by HTTP 200 responses.', 'Vendor advisory for a vulnerability under active exploitation on a product you run.'],
    reviewFirst: ['Server name, role, and whether it is internet-facing.', 'Web server process, child process, and command line.', 'New files in web directories.'],
    oftenMissing: ['The HTTP request that triggered the execution.', 'Patch level of the application.'],
  },
  prerequisites: [
    { text: 'Process and file telemetry on the server (EDR or Sysmon).', type: 'telemetry', required: true },
    { text: 'Web server access logs or WAF logs.', type: 'telemetry', required: true },
    { text: 'Application owner contact and patch status.', type: 'information', required: true },
  ],
  steps: [
    {
      id: 'server-children',
      title: 'Review processes started by the web server',
      action: 'List child processes of the web or application server process around the alert. Record command lines and the service account.',
      why: 'Web servers rarely start shells. Discovery commands under the web service account are the classic sign of a web shell or exploit.',
      where: ['DeviceProcessEvents', 'Sysmon 1', 'Linux auditd / EDR'],
      fields: ['InitiatingProcessFileName', 'FileName', 'ProcessCommandLine', 'AccountName'],
      suspicious: ['whoami, ipconfig, net user, id, uname run by the web service account', 'Download utilities or encoded PowerShell under the web server'],
      legitimate: ['Known application behavior, e.g. a CMS calling an image converter (confirm with the owner)'],
      next: 'Look for files written to web directories.',
      queryIds: ['kql-webserver-children', 'spl-webserver-children', 'esql-webserver-children'],
    },
    {
      id: 'web-files',
      title: 'Look for new or modified files in web directories',
      action: 'List script files created or modified in web roots in the last 14 days, with the creating process. Record names, paths, hashes, and times. Do not open them in a browser.',
      why: 'A web shell is a small script file dropped where the server will execute it.',
      where: ['DeviceFileEvents', 'Sysmon 11', 'File integrity monitoring'],
      fields: ['FolderPath', 'FileName', 'SHA256', 'InitiatingProcessFileName'],
      suspicious: ['Script written by the web server process itself', 'Random or misleading names (e.g. error.aspx, a1.php) in upload or static folders', 'File timestamp close to the first suspicious child process'],
      legitimate: ['Files deployed by the release pipeline at a documented time'],
      next: 'Find the requests that reached those files.',
      queryIds: ['kql-web-root-files'],
    },
    {
      id: 'http-requests',
      title: 'Find the HTTP requests involved',
      action: 'In web access or WAF logs, find requests to the suspicious file or the vulnerable path around the alert time. Record source IPs, methods, status codes, and user agents.',
      why: 'The requests identify the attacker\'s addresses and show when access began.',
      where: ['Web server access logs', 'WAF / reverse-proxy logs', 'Firewall logs'],
      fields: ['Source IP', 'URI path', 'Method', 'Status', 'User agent', 'Bytes'],
      suspicious: ['POST requests to a newly created script returning 200', 'Exploit strings followed by successful responses', 'Requests from one IP to a file nobody else requests'],
      legitimate: ['Authorized vulnerability scan from documented addresses'],
      next: 'Check what happened after the foothold.',
      queryIds: ['spl-web-requests'],
    },
    {
      id: 'post-exploitation',
      title: 'Check for follow-on activity from the server',
      action: 'Review outbound connections, new accounts, scheduled tasks or cron entries, credential access, and connections from the server to internal hosts since the first suspicious event.',
      why: 'A web server is a stepping stone. Lateral movement from it turns one server incident into a network intrusion.',
      where: ['DeviceNetworkEvents', 'Security 4624 on internal hosts', 'EDR timeline'],
      fields: ['RemoteIP / RemotePort', 'New persistence', 'Logons from the server'],
      suspicious: ['Outbound connection to an unknown host from the web server process', 'SMB, RDP, or SSH from the web server to internal systems'],
      legitimate: ['Connections only to documented back-end services'],
      next: 'Confirm exposure and patch state with the owner.',
      queryIds: [],
    },
    {
      id: 'exposure',
      title: 'Confirm exposure and patch state',
      action: 'With the application owner, confirm whether the server is internet-facing, which product and version it runs, and whether a known exploited vulnerability applies.',
      why: 'An unpatched, exposed product with a public exploit makes compromise far more likely and suggests other servers are at risk.',
      where: ['Asset inventory', 'Vulnerability management', 'Vendor advisories'],
      fields: ['Product and version', 'Exposure', 'Relevant advisory'],
      suspicious: ['Version affected by a vulnerability known to be exploited', 'Other servers running the same version'],
      legitimate: ['Fully patched and not reachable from the internet'],
      next: 'Use the decision tree.',
      queryIds: [],
    },
  ],
  decisionTree: {
    start: 'expected-behavior',
    nodes: [
      { id: 'expected-behavior', question: 'Is the activity confirmed as normal application behavior or an authorized scan/deployment by the application owner?', yes: { outcome: 'benign', guidance: 'Document the owner\'s confirmation and the matching process or schedule.' }, no: { next: 'executed', guidance: 'Unexplained server activity.' } },
      { id: 'executed', question: 'Did the web server run shell or system commands, or was a script file written into a web directory by the server process?', yes: { outcome: 'critical', guidance: 'Treat as a compromised internet-facing server. Follow the incident escalation procedure now and preserve the files and logs.' }, no: { next: 'attempt-only', guidance: 'No execution evidence yet.' } },
      { id: 'attempt-only', question: 'Do logs show the exploit attempts were blocked or returned errors, with no new files or processes on the server?', yes: { outcome: 'contained', guidance: 'Blocked attempt. Record source IPs and confirm patch status with the owner; close per procedure.' }, no: { outcome: 'escalate', guidance: 'Success cannot be ruled out. Escalate with the requests and server details.' }, unknown: { outcome: 'gap', guidance: 'Web or endpoint logs are missing for this server. Record the gap and escalate per policy.' } },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true, 'First suspicious request or process (UTC).'),
    ev('hostname', true, 'Server name, role, and whether internet-facing.'),
    ev('process', true, 'Web server process and the child it started.'),
    ev('command_line', true),
    ev('username', false, 'Service account the commands ran as.'),
    ev('file_hash', false, 'Suspicious files in web directories: path, time, SHA-256.'),
    ev('src_ip', true, 'Source IPs of the requests.'),
    evCustom('http_requests', 'HTTP requests', 'Method, path, status, user agent (one per line).', false, true),
    evCustom('product_version', 'Product, version, and patch state', 'From the application owner.', false),
    ev('affected_assets', false, 'Internal hosts contacted from the server.'),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: ['Exploit attempts where success cannot be ruled out.', 'Unexplained script file in a web directory.', 'Server runs a version with a known exploited vulnerability and shows any anomaly.'],
    immediate: ['Web server process executed shell or system commands.', 'Web shell file confirmed.', 'Outbound or lateral connections from the server after the event.'],
    benignClosure: ['Application owner confirms expected behavior, authorized scan, or documented deployment matching time and files.'],
  },
  queries: [
    {
      id: 'kql-webserver-children',
      title: 'Processes started by web and application servers',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Lists shells and system utilities whose parent is a web server process on the host.',
      dataSources: ['DeviceProcessEvents'],
      query: `DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "tomcat9.exe",
        "java.exe", "httpd", "apache2", "nginx", "php-fpm", "java", "node")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe",
        "certutil.exe", "sh", "bash", "dash", "python", "python3", "perl", "curl", "wget", "nc")
| project Timestamp, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
| order by Timestamp asc`,
      placeholders: [PH.lookback('7d'), PH.hostname('srv-demo-web01.corp.example.com')],
      keyFields: [{ name: 'ProcessCommandLine', meaning: 'Commands the attacker ran through the server.' }],
      positive: 'Shells under a web server are a strong sign of exploitation or a web shell; some applications do call utilities legitimately.',
      negative: 'In-process web shells that never spawn a child are not visible here; check files and web logs.',
      prerequisites: 'Defender for Endpoint on the server (Windows or Linux).',
      schemaNotes: 'java and node parents are noisy on application servers; narrow by service account.',
      example: 'hostname = srv-demo-web01.corp.example.com',
    },
    {
      id: 'kql-web-root-files',
      title: 'Script files created in web directories',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds server-side script files created or modified on the host.',
      dataSources: ['DeviceFileEvents'],
      query: `DeviceFileEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName matches regex @"(?i)\\.(aspx|ashx|asmx|asp|php|phtml|jsp|jspx|war)$"
| project Timestamp, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc`,
      placeholders: [PH.lookback('14d'), PH.hostname('srv-demo-web01.corp.example.com')],
      keyFields: [{ name: 'InitiatingProcessFileName', meaning: 'A web server writing its own script files is suspicious.' }],
      positive: 'Unexpected script files need an owner; compare with deployment times.',
      negative: 'Fileless and in-memory implants leave no file.',
      prerequisites: 'Defender for Endpoint file telemetry.',
      schemaNotes: 'Add extensions used by your platforms.',
      example: 'hostname = srv-demo-web01.corp.example.com, lookback = 14d',
    },
    {
      id: 'spl-webserver-children',
      title: 'Shells spawned by web servers (CIM Endpoint.Processes)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Finds shells and utilities started by web server processes across hosts.',
      dataSources: ['CIM Endpoint.Processes'],
      query: `| tstats summariesonly=false count min(_time) as first_seen values(Processes.process) as command_lines
    from datamodel=Endpoint.Processes
    where earliest=-{{lookback}}
      (Processes.parent_process_name="w3wp.exe" OR Processes.parent_process_name="httpd*"
       OR Processes.parent_process_name="nginx*" OR Processes.parent_process_name="php*"
       OR Processes.parent_process_name="apache2")
      (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe"
       OR Processes.process_name="whoami.exe" OR Processes.process_name="sh"
       OR Processes.process_name="bash")
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| convert ctime(first_seen)
| sort first_seen`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'command_lines', meaning: 'Commands run through the server.' }],
      positive: 'Candidates for exploitation or web shells.',
      negative: 'Needs process telemetry from servers in the data model.',
      prerequisites: 'Process data mapped to CIM.',
      schemaNotes: 'Parent names may be full paths in some sources.',
      example: 'lookback = 7d',
    },
    {
      id: 'spl-web-requests',
      title: 'Requests to a suspicious path (CIM Web)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Lists clients, methods, and status codes for requests whose URL contains the suspicious path.',
      dataSources: ['CIM Web (web server or WAF logs)'],
      query: `| tstats summariesonly=false count min(_time) as first_seen max(_time) as last_seen
    values(Web.http_user_agent) as user_agents
    from datamodel=Web
    where earliest=-{{lookback}} Web.url="*{{uri_path}}*"
    by Web.src Web.http_method Web.status
| convert ctime(first_seen) ctime(last_seen)
| sort first_seen`,
      placeholders: [PH.lookback('14d'), { name: 'uri_path', kind: 'string', description: 'Path or file name of the suspicious script or vulnerable endpoint.', example: '/uploads/a1.aspx' }],
      keyFields: [{ name: 'Web.src', meaning: 'Client addresses reaching the file.' }, { name: 'Web.status', meaning: '200 on a POST to a new script suggests it executed.' }],
      positive: 'Identifies attacker addresses and first access time.',
      negative: 'Requests through a CDN or load balancer may show the proxy address; check forwarded-for fields.',
      prerequisites: 'Web or WAF logs mapped to CIM Web.',
      schemaNotes: 'Leading wildcards are slow; narrow the time range.',
      example: 'uri_path = /uploads/a1.aspx',
    },
    esql(
      'esql-webserver-children',
      'Shells spawned by web servers on a host',
      'Lists shells and utilities started by web server processes on one host over the last 7 days.',
      ['logs-endpoint.events.process-*'],
      `FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 7 days AND host.name == "{{hostname}}"
| WHERE process.parent.name IN ("w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "httpd", "apache2", "nginx", "php-fpm")
| WHERE process.name IN ("cmd.exe", "powershell.exe", "whoami.exe", "net.exe", "sh", "bash", "curl", "wget")
| KEEP @timestamp, user.name, process.parent.name, process.name, process.command_line
| SORT @timestamp ASC
| LIMIT 200`,
      [PH.hostname('srv-demo-web01')],
      'Shells under a web server are a strong sign of exploitation or a web shell.',
      'In-process web shells that never spawn a child are not visible here.',
    ),
    genericProcedure('generic-webshell', 'Generic web-server compromise procedure', `1. Child processes of the web/application server process: commands and service account.
2. Script files created or modified in web directories in the last 14 days, and what wrote them.
3. HTTP requests to those files or the vulnerable path: sources, methods, status codes.
4. Outbound and internal connections from the server since the first event; new accounts or persistence.
5. Product, version, exposure, and applicable advisories from the owner.`),
  ],
  sigmaRules: [
    sigma(
      'sigma-webserver-shell',
      'a77636b6-8c5b-489c-8c0c-c522cb9c1adb',
      'Web Server Process Spawning Command Shell',
      'Detects a Windows web server process starting a command shell or discovery utility.',
      ['attack.persistence', 'attack.t1505.003', 'attack.initial-access', 'attack.t1190'],
      '    category: process_creation\n    product: windows',
      `    selection_parent:
        ParentImage|endswith:
            - '\\w3wp.exe'
            - '\\httpd.exe'
            - '\\nginx.exe'
            - '\\php-cgi.exe'
    selection_child:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\pwsh.exe'
            - '\\whoami.exe'
            - '\\net.exe'
    condition: all of selection_*`,
      ['Applications that legitimately call command-line utilities', 'Administrative scripts run through the web application'],
      'high',
    ),
  ],
  detectionConsiderations: ['Baseline what each application legitimately spawns; most spawn nothing.', 'WAF "blocked" does not cover requests that bypass the WAF by going straight to the server address.'],
  visibilityGaps: ['Appliances and network devices often have no EDR; rely on vendor integrity tools and logs.', 'Web access logs are frequently kept only on the server.'],
  relatedTechniques: [
    { id: 'T1059.003', reason: 'Web shells run commands through the Windows command shell.' },
    { id: 'T1059.004', reason: 'Web shells run commands through Unix shells.' },
    { id: 'T1105', reason: 'Tools are downloaded onto the server after the foothold.' },
    { id: 'T1210', reason: 'Attackers exploit internal services from the compromised server.' },
    { id: 'T1068', reason: 'Privilege escalation from the web service account often follows.' },
  ],
  references: [attackRef('T1190', 'Exploit Public-Facing Application'), attackRef('T1505.003', 'Web Shell'), { title: 'CISA Known Exploited Vulnerabilities Catalog', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' }],
  assumptions: ['Tier 1 does not remove files or restart services on production servers.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};
