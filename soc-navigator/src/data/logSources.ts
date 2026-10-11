/**
 * Detection and log reference catalog (organization-authored guidance, not MITRE content).
 *
 * Table, sourcetype, and event identifiers below are the commonly documented defaults.
 * Index names, sourcetypes, and parsed field names vary with collection agents, add-on
 * versions, and normalization (CIM/ASIM). Always confirm against your own environment.
 */

export interface LogSourceEvent {
  id: string;
  description: string;
}

export interface LogSource {
  id: string;
  name: string;
  category: 'Endpoint' | 'Identity' | 'Network' | 'Email' | 'Cloud' | 'Application';
  description: string;
  keyEvents: LogSourceEvent[];
  keyFields: string[];
  sentinel: string[];
  splunk: string[];
  prerequisites: string[];
  gaps: string[];
}

export const LOG_SOURCES: LogSource[] = [
  {
    id: 'edr',
    name: 'EDR telemetry (vendor-neutral)',
    category: 'Endpoint',
    description:
      'Endpoint detection and response sensors record process, file, registry, network, and module-load activity with process lineage. Usually the richest single source for host investigations.',
    keyEvents: [
      { id: 'Process start', description: 'Image path, command line, parent/child lineage, user, integrity level, hash.' },
      { id: 'Network connection', description: 'Remote IP/port/domain attributed to the initiating process.' },
      { id: 'File / registry change', description: 'Created, modified, renamed, deleted objects attributed to a process.' },
      { id: 'Alert / prevention', description: 'Vendor detections and blocked actions, with severity and verdict.' },
    ],
    keyFields: ['Device / hostname', 'Process image and command line', 'Parent process', 'User', 'SHA-256', 'Remote IP / domain'],
    sentinel: ['Depends on the vendor connector (for Defender, see the Microsoft Defender for Endpoint entry).'],
    splunk: ['Vendor add-on sourcetypes; CIM data models Endpoint.Processes, Endpoint.Filesystem, Endpoint.Registry, Network_Traffic'],
    prerequisites: ['Sensor installed and healthy on the host', 'Your role can view device timelines'],
    gaps: [
      'Hosts without a sensor (servers excluded for performance, unmanaged devices, appliances).',
      'Sensors throttle or summarize high-volume events; absence of an event is not proof it did not happen.',
      'Retention in the EDR console is often shorter than in the SIEM.',
    ],
  },
  {
    id: 'mde',
    name: 'Microsoft Defender for Endpoint (advanced hunting)',
    category: 'Endpoint',
    description:
      'Defender XDR advanced hunting tables. Also available in Microsoft Sentinel through the Microsoft Defender XDR connector (Sentinel adds TimeGenerated alongside Timestamp).',
    keyEvents: [
      { id: 'DeviceProcessEvents', description: 'Process creation with command line and initiating (parent) process.' },
      { id: 'DeviceNetworkEvents', description: 'Network connections (ActionType ConnectionSuccess, ConnectionFailed, InboundConnectionAccepted, ...).' },
      { id: 'DeviceFileEvents', description: 'FileCreated, FileModified, FileRenamed, FileDeleted; FileOriginUrl for downloads when available.' },
      { id: 'DeviceRegistryEvents', description: 'RegistryValueSet, RegistryKeyCreated, RegistryValueDeleted, ...' },
      { id: 'DeviceLogonEvents', description: 'LogonSuccess / LogonFailed with LogonType and RemoteIP.' },
      { id: 'DeviceEvents', description: 'Miscellaneous ActionTypes such as ScheduledTaskCreated, PowerShellCommand, AntivirusDetection, CreateRemoteThreadApiCall. Details in AdditionalFields (JSON).' },
      { id: 'DeviceImageLoadEvents', description: 'DLL / module loads.' },
    ],
    keyFields: ['Timestamp', 'DeviceName', 'DeviceId', 'ActionType', 'FileName', 'FolderPath', 'ProcessCommandLine', 'InitiatingProcessFileName', 'InitiatingProcessCommandLine', 'AccountName', 'SHA256', 'RemoteIP', 'RemoteUrl', 'ReportId'],
    sentinel: ['DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents', 'DeviceRegistryEvents', 'DeviceLogonEvents', 'DeviceEvents', 'DeviceImageLoadEvents'],
    splunk: ['Microsoft Defender add-on for Splunk (sourcetypes vary by add-on version); streaming API exports'],
    prerequisites: ['Defender for Endpoint P2 / Defender XDR licensing', 'Advanced hunting read permission (e.g. Security Reader) or Sentinel workspace read access'],
    gaps: [
      'Advanced hunting retains 30 days by default; older data requires Sentinel or other archive.',
      'Some ActionTypes are sampled or capped per device per day (for example certain API-call events).',
      'Devices in passive mode or onboarded without full telemetry produce fewer events.',
    ],
  },
  {
    id: 'win-security',
    name: 'Windows Security Event Log',
    category: 'Endpoint',
    description:
      'Built-in Windows auditing. Coverage depends entirely on Advanced Audit Policy configuration; many useful events are off by default.',
    keyEvents: [
      { id: '4624 / 4625', description: 'Successful / failed logon. LogonType: 2 interactive, 3 network, 4 batch, 5 service, 7 unlock, 9 new credentials, 10 RemoteInteractive (RDP), 11 cached.' },
      { id: '4648', description: 'Logon attempted using explicit credentials (e.g. runas, PsExec with -u).' },
      { id: '4672', description: 'Special privileges assigned to new logon (admin-equivalent session).' },
      { id: '4688', description: 'Process creation. Command line only if "Include command line in process creation events" is enabled.' },
      { id: '4697', description: 'A service was installed (requires Audit Security System Extension).' },
      { id: '4698 / 4699 / 4700 / 4702', description: 'Scheduled task created / deleted / enabled / updated (requires Audit Other Object Access Events).' },
      { id: '4720 / 4728 / 4732 / 4756', description: 'User created; member added to global / local / universal security group.' },
      { id: '4740', description: 'Account locked out (logged on domain controllers).' },
      { id: '4768 / 4769 / 4771 / 4776', description: 'Kerberos TGT request, service ticket request, Kerberos pre-auth failure, NTLM credential validation (domain controllers).' },
      { id: '4657', description: 'Registry value modified (only where a SACL is configured on the key).' },
      { id: '5140 / 5145', description: 'Network share accessed / detailed file share access check.' },
      { id: '1102', description: 'Security audit log cleared.' },
    ],
    keyFields: ['EventID', 'Computer', 'TargetUserName', 'SubjectUserName', 'LogonType', 'IpAddress', 'WorkstationName', 'Status / SubStatus', 'NewProcessName', 'CommandLine', 'ParentProcessName'],
    sentinel: ['SecurityEvent (legacy agent / AMA via Windows Security Events connector)', 'WindowsEvent (for forwarded non-Security channels)'],
    splunk: ['source="WinEventLog:Security" or source="XmlWinEventLog:Security" (Splunk Add-on for Microsoft Windows)', 'CIM: Authentication, Change, Endpoint.Processes'],
    prerequisites: ['Advanced Audit Policy enabled for the relevant subcategories', 'Logs forwarded from the host (and from domain controllers for Kerberos/NTLM/lockout events)'],
    gaps: [
      'Command-line logging for 4688 is disabled by default.',
      'Workstation logs are frequently not forwarded; only DC/server logs are collected in many SOCs.',
      'Status codes (e.g. 0xC000006A bad password, 0xC0000064 unknown user) live in Status/SubStatus and may be parsed differently per add-on.',
    ],
  },
  {
    id: 'sysmon',
    name: 'Sysmon (System Monitor)',
    category: 'Endpoint',
    description:
      'Free Microsoft Sysinternals driver that writes detailed process, network, file, registry, and WMI events to Microsoft-Windows-Sysmon/Operational. Coverage depends on the deployed configuration file.',
    keyEvents: [
      { id: '1', description: 'Process creation (Image, CommandLine, ParentImage, Hashes, User, ProcessGuid).' },
      { id: '3', description: 'Network connection (Image, DestinationIp, DestinationPort, DestinationHostname).' },
      { id: '7', description: 'Image loaded (DLL).' },
      { id: '8', description: 'CreateRemoteThread (SourceImage, TargetImage, StartAddress).' },
      { id: '10', description: 'ProcessAccess (SourceImage, TargetImage, GrantedAccess, CallTrace).' },
      { id: '11', description: 'FileCreate (TargetFilename).' },
      { id: '12 / 13 / 14', description: 'Registry object create/delete, value set (TargetObject, Details), rename.' },
      { id: '19 / 20 / 21', description: 'WMI event filter, consumer, and filter-to-consumer binding.' },
      { id: '22', description: 'DNS query (QueryName, QueryResults, Image).' },
      { id: '23 / 26', description: 'File delete (archived) / file delete logged.' },
    ],
    keyFields: ['EventID', 'Computer', 'Image', 'CommandLine', 'ParentImage', 'User', 'Hashes', 'TargetFilename', 'TargetObject', 'DestinationIp', 'QueryName', 'ProcessGuid'],
    sentinel: ['Event table (Source == "Microsoft-Windows-Sysmon", EventData XML) - usually queried through a parser function or ASIM (imProcessCreate, imNetworkSession, imRegistry, imDns, imFileEvent)'],
    splunk: ['source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (Splunk Add-on for Sysmon); CIM Endpoint data models'],
    prerequisites: ['Sysmon installed with a maintained configuration', 'Channel forwarded to the SIEM'],
    gaps: [
      'Event types not enabled in the config are never generated (e.g. Event 10 is often filtered heavily).',
      'Configs commonly exclude noisy paths that attackers can abuse.',
    ],
  },
  {
    id: 'powershell',
    name: 'PowerShell logging',
    category: 'Endpoint',
    description:
      'Script block logging records de-obfuscated script content as it executes; module logging records pipeline execution. Both are configured by Group Policy.',
    keyEvents: [
      { id: '4104', description: 'Script block logging (Microsoft-Windows-PowerShell/Operational). Field ScriptBlockText; long scripts are split across multiple events.' },
      { id: '4103', description: 'Module logging / pipeline execution details.' },
      { id: '400 / 600', description: 'Engine and provider lifecycle (Windows PowerShell log); HostApplication shows the launching command line.' },
    ],
    keyFields: ['ScriptBlockText', 'ScriptBlockId', 'Path', 'HostApplication', 'Computer', 'UserID'],
    sentinel: ['Event or WindowsEvent table (channel Microsoft-Windows-PowerShell/Operational)', 'DeviceEvents ActionType "PowerShellCommand" (Defender, partial)'],
    splunk: ['source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104'],
    prerequisites: ['"Turn on PowerShell Script Block Logging" policy enabled', 'Operational channel forwarded'],
    gaps: ['Not enabled by default for all scripts (only suspicious blocks are auto-logged).', 'PowerShell 2.0 engine does not support script block logging.'],
  },
  {
    id: 'task-scheduler',
    name: 'Task Scheduler Operational log',
    category: 'Endpoint',
    description: 'Microsoft-Windows-TaskScheduler/Operational records task registration and execution. Disabled by default on many Windows versions.',
    keyEvents: [
      { id: '106', description: 'Task registered (created).' },
      { id: '140', description: 'Task registration updated.' },
      { id: '141', description: 'Task registration deleted.' },
      { id: '200 / 201', description: 'Action started / completed.' },
    ],
    keyFields: ['TaskName', 'UserContext', 'ActionName', 'Computer'],
    sentinel: ['WindowsEvent / Event (if channel collected)', 'DeviceEvents ActionType ScheduledTaskCreated / ScheduledTaskUpdated / ScheduledTaskDeleted (Defender)'],
    splunk: ['source="XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational"'],
    prerequisites: ['Channel enabled and forwarded, or Security 4698 auditing enabled'],
    gaps: ['Channel is often disabled; rely on Security 4698 or EDR events instead.'],
  },
  {
    id: 'wmi-activity',
    name: 'WMI-Activity Operational log',
    category: 'Endpoint',
    description: 'Microsoft-Windows-WMI-Activity/Operational records WMI provider activity and permanent event subscriptions.',
    keyEvents: [
      { id: '5857', description: 'WMI provider loaded (provider DLL and host process).' },
      { id: '5858', description: 'WMI query error.' },
      { id: '5860 / 5861', description: 'Temporary / permanent event consumer registered (5861 is a strong persistence signal).' },
    ],
    keyFields: ['Namespace', 'ESS', 'Consumer', 'PossibleCause', 'Operation'],
    sentinel: ['WindowsEvent / Event (if collected)', 'DeviceEvents ActionType WmiBindEventFilterToConsumer (Defender)'],
    splunk: ['source="XmlWinEventLog:Microsoft-Windows-WMI-Activity/Operational"'],
    prerequisites: ['Channel forwarded'],
    gaps: ['Does not record full remote WMI command lines; pair with process creation (WmiPrvSE.exe children).'],
  },
  {
    id: 'av',
    name: 'Antivirus / Microsoft Defender Antivirus',
    category: 'Endpoint',
    description: 'Malware detections, remediation results, and protection state changes.',
    keyEvents: [
      { id: '1116 / 1117', description: 'Malware detected / action taken (Microsoft-Windows-Windows Defender/Operational).' },
      { id: '5001', description: 'Real-time protection disabled.' },
      { id: '5007', description: 'Antivirus configuration changed (e.g. exclusions added).' },
    ],
    keyFields: ['Threat Name', 'Path', 'Action', 'Detection User', 'Process Name'],
    sentinel: ['DeviceEvents ActionType AntivirusDetection', 'SecurityAlert', 'Event / WindowsEvent (Defender channel)'],
    splunk: ['source="XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational"'],
    prerequisites: ['AV events forwarded'],
    gaps: ['A "remediated" verdict does not mean the initial execution did not succeed.'],
  },
  {
    id: 'entra-signin',
    name: 'Microsoft Entra ID sign-in logs',
    category: 'Identity',
    description: 'Interactive and non-interactive sign-ins to Entra ID (Azure AD) with result codes, Conditional Access outcome, location, device, and risk.',
    keyEvents: [
      { id: 'ResultType 0', description: 'Success.' },
      { id: 'ResultType 50126', description: 'Invalid username or password.' },
      { id: 'ResultType 50053', description: 'Account locked (Smart Lockout) or sign-in from a malicious IP blocked.' },
      { id: 'ResultType 50074 / 50076', description: 'Strong authentication (MFA) required.' },
      { id: 'ResultType 500121', description: 'Authentication failed during strong authentication request (MFA not completed or denied).' },
      { id: 'ResultType 53003', description: 'Blocked by Conditional Access.' },
    ],
    keyFields: ['TimeGenerated', 'UserPrincipalName', 'IPAddress', 'Location', 'ResultType', 'ResultDescription', 'AppDisplayName', 'ClientAppUsed', 'UserAgent', 'ConditionalAccessStatus', 'AuthenticationRequirement', 'DeviceDetail', 'RiskLevelDuringSignIn', 'CorrelationId'],
    sentinel: ['SigninLogs (interactive)', 'AADNonInteractiveUserSignInLogs', 'AADServicePrincipalSignInLogs'],
    splunk: ['Splunk Add-on for Microsoft Cloud Services / Microsoft Azure add-on (sourcetype such as azure:aad:signin; varies by add-on)'],
    prerequisites: ['Entra ID P1/P2 for full sign-in log export', 'Diagnostic settings sending sign-in categories to the workspace'],
    gaps: [
      'Non-interactive sign-ins are a separate table and are often not collected.',
      'Legacy authentication protocols may show limited device detail.',
      'Location is IP-geolocation based and can be wrong for VPN, mobile carriers, and cloud egress.',
    ],
  },
  {
    id: 'entra-audit',
    name: 'Microsoft Entra ID audit logs',
    category: 'Identity',
    description: 'Directory changes: users, groups, roles, applications, MFA methods, and policy changes.',
    keyEvents: [
      { id: 'User registered security info', description: 'New MFA method added (account takeover persistence indicator).' },
      { id: 'Add member to role', description: 'Directory role assignment.' },
      { id: 'Consent to application', description: 'OAuth consent grant.' },
      { id: 'Update user / Reset password', description: 'Account modifications.' },
    ],
    keyFields: ['OperationName', 'Category', 'Result', 'InitiatedBy', 'TargetResources', 'TimeGenerated'],
    sentinel: ['AuditLogs'],
    splunk: ['Microsoft Azure / Cloud Services add-on audit sourcetype (varies)'],
    prerequisites: ['Diagnostic settings sending AuditLogs'],
    gaps: ['InitiatedBy and TargetResources are nested JSON and need parsing.'],
  },
  {
    id: 'm365-audit',
    name: 'Microsoft 365 unified audit (Exchange / SharePoint / OneDrive)',
    category: 'Cloud',
    description: 'Mailbox rules, mailbox access, file sharing and download activity in Microsoft 365 workloads.',
    keyEvents: [
      { id: 'New-InboxRule / Set-InboxRule', description: 'Inbox rule created or changed (forwarding/deletion rules are a common post-compromise step).' },
      { id: 'MailItemsAccessed', description: 'Mailbox items accessed (availability depends on licensing/audit configuration).' },
      { id: 'FileDownloaded / FileSyncDownloadedFull', description: 'SharePoint / OneDrive downloads.' },
      { id: 'AnonymousLinkCreated / SharingSet', description: 'External sharing.' },
    ],
    keyFields: ['Operation', 'UserId', 'ClientIP', 'OfficeWorkload', 'Parameters', 'OfficeObjectId'],
    sentinel: ['OfficeActivity', 'CloudAppEvents (Defender for Cloud Apps)'],
    splunk: ['Splunk Add-on for Microsoft Office 365 (sourcetype o365:management:activity)'],
    prerequisites: ['Unified audit log enabled', 'Office 365 connector configured'],
    gaps: ['Audit events can arrive with significant delay (minutes to hours).'],
  },
  {
    id: 'email-security',
    name: 'Email security logs (Defender for Office 365 / secure email gateway)',
    category: 'Email',
    description: 'Message delivery, authentication results, URL and attachment verdicts, user clicks, and post-delivery actions.',
    keyEvents: [
      { id: 'EmailEvents', description: 'Message metadata: sender, recipients, subject, delivery action/location, threat types, authentication details.' },
      { id: 'EmailUrlInfo / EmailAttachmentInfo', description: 'URLs and attachments per NetworkMessageId.' },
      { id: 'UrlClickEvents', description: 'Safe Links clicks: allowed, blocked, clicked-through.' },
      { id: 'EmailPostDeliveryEvents', description: 'ZAP and manual remediation after delivery.' },
    ],
    keyFields: ['NetworkMessageId', 'InternetMessageId', 'SenderFromAddress', 'SenderMailFromAddress', 'SenderIPv4', 'RecipientEmailAddress', 'Subject', 'DeliveryAction', 'DeliveryLocation', 'ThreatTypes', 'AuthenticationDetails', 'Url', 'SHA256'],
    sentinel: ['EmailEvents', 'EmailUrlInfo', 'EmailAttachmentInfo', 'UrlClickEvents', 'EmailPostDeliveryEvents'],
    splunk: ['Gateway-specific sourcetypes (e.g. Proofpoint, Mimecast add-ons); CIM Email data model'],
    prerequisites: ['Defender for Office 365 Plan 2 for advanced hunting email tables, or gateway logs in the SIEM'],
    gaps: ['Clicks are only logged when the URL was rewritten/protected and the click went through the protection service.', 'Personal devices and webmail clients may bypass URL protection.'],
  },
  {
    id: 'dns',
    name: 'DNS logs',
    category: 'Network',
    description: 'Domain resolution by internal clients (DNS server analytical/debug logs, resolver logs, Sysmon 22, EDR, or protective DNS service).',
    keyEvents: [
      { id: 'Query', description: 'Client IP, queried name, record type, response code, resolved addresses.' },
    ],
    keyFields: ['Client IP / host', 'Query name', 'Query type', 'Response code', 'Answer'],
    sentinel: ['DnsEvents (Windows DNS via legacy connector)', 'ASIM: _Im_Dns / imDns', 'DeviceEvents DnsQueryResponse (Defender, where present)'],
    splunk: ['CIM Network_Resolution (DNS.query, DNS.src)', 'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22'],
    prerequisites: ['DNS server or resolver logging enabled and forwarded'],
    gaps: ['DNS server logs show the forwarding server as client if clients use a local cache/forwarder.', 'DNS-over-HTTPS from browsers or malware bypasses enterprise resolvers.'],
  },
  {
    id: 'firewall',
    name: 'Firewall logs',
    category: 'Network',
    description: 'Allowed/denied connections at network boundaries; some next-generation firewalls add application and URL identification.',
    keyEvents: [{ id: 'Session', description: 'Source/destination IP and port, action, bytes sent/received, application, rule name.' }],
    keyFields: ['SourceIP', 'DestinationIP', 'DestinationPort', 'DeviceAction', 'SentBytes', 'ReceivedBytes', 'ApplicationProtocol'],
    sentinel: ['CommonSecurityLog (CEF)', 'AzureDiagnostics / AZFW* tables (Azure Firewall)', 'ASIM: _Im_NetworkSession'],
    splunk: ['Vendor add-on sourcetypes (pan:traffic, fortigate_traffic, cisco:asa, ...); CIM Network_Traffic'],
    prerequisites: ['Session-end logging enabled (for byte counts)'],
    gaps: ['NAT hides the internal source unless NAT translation fields are logged.', 'East-west traffic inside a subnet never crosses the firewall.'],
  },
  {
    id: 'proxy',
    name: 'Web proxy / secure web gateway',
    category: 'Network',
    description: 'HTTP(S) requests with URL, category, user, user agent, and bytes. TLS inspection determines whether full URLs are visible.',
    keyEvents: [{ id: 'Request', description: 'User, source IP, URL / host, method, status, category, bytes in/out, user agent.' }],
    keyFields: ['src', 'user', 'url', 'dest', 'http_method', 'status', 'bytes_out', 'bytes_in', 'http_user_agent', 'category'],
    sentinel: ['CommonSecurityLog (many proxies use CEF)', 'ASIM: _Im_WebSession'],
    splunk: ['Vendor sourcetypes (e.g. Zscaler, Bluecoat); CIM Web data model'],
    prerequisites: ['Proxy enforced (not bypassable) and logs forwarded'],
    gaps: ['Without TLS inspection only the hostname (SNI/CONNECT) is visible.', 'Roaming devices off-network may bypass an on-premises proxy.'],
  },
  {
    id: 'vpn',
    name: 'VPN / remote access logs',
    category: 'Network',
    description: 'Remote-access session establishment with user, public source IP, assigned internal IP, and duration.',
    keyEvents: [{ id: 'Session start / end', description: 'User, public IP, assigned IP, client version, MFA result.' }],
    keyFields: ['user', 'src (public IP)', 'assigned IP', 'session duration', 'bytes'],
    sentinel: ['CommonSecurityLog or vendor tables'],
    splunk: ['Vendor sourcetypes; CIM Authentication / Network_Sessions'],
    prerequisites: ['VPN logs forwarded'],
    gaps: ['Mapping an internal IP back to a user requires the assigned-IP field and accurate time.'],
  },
  {
    id: 'cloud-audit',
    name: 'Cloud control-plane audit logs',
    category: 'Cloud',
    description: 'AWS CloudTrail, Azure Activity Log, and Google Cloud Audit Logs record API calls that change or read cloud resources.',
    keyEvents: [
      { id: 'AWS CloudTrail', description: 'eventName, userIdentity, sourceIPAddress, errorCode (e.g. ConsoleLogin, PutBucketPolicy, CreateAccessKey).' },
      { id: 'Azure Activity', description: 'OperationNameValue, Caller, CallerIpAddress, ActivityStatusValue.' },
      { id: 'GCP Audit', description: 'methodName, principalEmail, callerIp.' },
    ],
    keyFields: ['Actor / principal', 'Action / API name', 'Source IP', 'Result', 'Target resource'],
    sentinel: ['AWSCloudTrail', 'AzureActivity', 'GCPAuditLogs (connector-dependent)'],
    splunk: ['aws:cloudtrail (Splunk Add-on for AWS)', 'Azure / GCP add-on sourcetypes'],
    prerequisites: ['Trails / diagnostic settings enabled in every account and region', 'Data events (e.g. S3 object reads) enabled where needed'],
    gaps: ['Data-plane events (object reads) are often not logged by default.', 'Multi-account organizations may only log a subset of accounts.'],
  },
  {
    id: 'backup',
    name: 'Backup and storage platform logs',
    category: 'Application',
    description: 'Backup job results, deletions, retention changes and snapshot operations. Critical for ransomware recovery decisions.',
    keyEvents: [{ id: 'Job / admin activity', description: 'Failed jobs, deleted restore points, changed retention, admin logins.' }],
    keyFields: ['Job name', 'Result', 'Admin user', 'Source IP', 'Object'],
    sentinel: ['Vendor-specific (Syslog / CommonSecurityLog / custom tables)'],
    splunk: ['Vendor-specific sourcetypes'],
    prerequisites: ['Backup platform forwards audit logs'],
    gaps: ['Often not onboarded to the SIEM at all; contact the backup team directly.'],
  },
];

export const LOG_SOURCE_BY_ID = new Map(LOG_SOURCES.map((s) => [s.id, s]));

/** Quick reference for Windows event IDs commonly used in Tier 1 investigations. */
export const WINDOWS_EVENT_REFERENCE: { id: string; log: string; meaning: string; note: string }[] = [
  { id: '4624', log: 'Security', meaning: 'Successful logon', note: 'Check LogonType and IpAddress/WorkstationName.' },
  { id: '4625', log: 'Security', meaning: 'Failed logon', note: 'Status/SubStatus 0xC000006A = bad password, 0xC0000064 = user does not exist, 0xC0000234 = locked out, 0xC0000072 = disabled.' },
  { id: '4648', log: 'Security', meaning: 'Logon with explicit credentials', note: 'Common with runas, scheduled tasks, and lateral-movement tools.' },
  { id: '4672', log: 'Security', meaning: 'Special privileges assigned', note: 'Session has admin-equivalent privileges.' },
  { id: '4688', log: 'Security', meaning: 'Process created', note: 'Command line only when the policy is enabled.' },
  { id: '4697', log: 'Security', meaning: 'Service installed', note: 'Requires Security System Extension auditing.' },
  { id: '7045', log: 'System', meaning: 'Service installed (Service Control Manager)', note: 'Enabled by default; PsExec creates PSEXESVC.' },
  { id: '4698', log: 'Security', meaning: 'Scheduled task created', note: 'TaskContent contains the task XML (actions, triggers, principal).' },
  { id: '4702', log: 'Security', meaning: 'Scheduled task updated', note: 'Attackers sometimes modify an existing task instead of creating one.' },
  { id: '4720', log: 'Security', meaning: 'User account created', note: '' },
  { id: '4732', log: 'Security', meaning: 'Member added to security-enabled local group', note: 'e.g. Administrators.' },
  { id: '4740', log: 'Security', meaning: 'Account locked out', note: 'Logged on the DC that processed the lockout; Caller Computer Name shows the source.' },
  { id: '4768', log: 'Security (DC)', meaning: 'Kerberos TGT requested', note: '' },
  { id: '4769', log: 'Security (DC)', meaning: 'Kerberos service ticket requested', note: 'Ticket encryption 0x17 (RC4) for service accounts can indicate Kerberoasting.' },
  { id: '4771', log: 'Security (DC)', meaning: 'Kerberos pre-authentication failed', note: 'Failure code 0x18 = bad password.' },
  { id: '4776', log: 'Security (DC)', meaning: 'NTLM credential validation', note: 'Error code 0xC000006A = bad password.' },
  { id: '5140', log: 'Security', meaning: 'Network share accessed', note: 'ADMIN$ / C$ access from workstations is unusual.' },
  { id: '1102', log: 'Security', meaning: 'Audit log cleared', note: 'Rarely legitimate outside of documented maintenance.' },
  { id: '4104', log: 'PowerShell/Operational', meaning: 'Script block logged', note: 'ScriptBlockText may be split across events.' },
  { id: '106', log: 'TaskScheduler/Operational', meaning: 'Task registered', note: 'Channel often disabled by default.' },
  { id: '5861', log: 'WMI-Activity/Operational', meaning: 'Permanent WMI event consumer registered', note: 'Strong persistence indicator.' },
  { id: '21 / 24 / 25', log: 'TerminalServices-LocalSessionManager/Operational', meaning: 'RDP session logon / disconnect / reconnect', note: 'Source Network Address shows the client IP.' },
  { id: '1149', log: 'TerminalServices-RemoteConnectionManager/Operational', meaning: 'RDP network authentication succeeded', note: 'Logged before the session is created.' },
  { id: '1116 / 1117', log: 'Windows Defender/Operational', meaning: 'Malware detected / action taken', note: '' },
];
