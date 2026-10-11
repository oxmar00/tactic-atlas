import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const exfiltration: Playbook = {
  schemaVersion: 1,
  id: 'PB-EXFIL-001',
  version: '1.0.0',
  title: 'Potential data exfiltration',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1041', 'T1048', 'T1567', 'T1567.002'],
  tactics: ['exfiltration'],
  objective:
    'Establish what data left (or tried to leave), how much, by which tool and account, to which destination - and whether it reflects an intrusion, insider risk, or legitimate business use.',
  alertMeaning:
    'A detection saw unusually large outbound transfer volume, an upload to an unsanctioned cloud storage or file-transfer service, use of a bulk-transfer tool (e.g. rclone, SFTP clients), archive creation followed by upload, or a DLP policy match.',
  whyItMatters:
    'Data theft is the goal of many intrusions and of most double-extortion ransomware operations. Early detection limits what is lost and is often a legal/regulatory trigger.',
  difficulty: 'Intermediate',
  effort: '45-90 minutes',
  platforms: ['Windows', 'macOS', 'Linux', 'SaaS', 'Office Suite'],
  logSources: ['firewall', 'proxy', 'mde', 'edr', 'm365-audit', 'cloud-audit', 'dns'],
  alertContext: {
    triggers: [
      'Outbound volume from a host/user far above its baseline.',
      'Uploads to personal or unsanctioned cloud storage / file-transfer services.',
      'Execution of bulk-transfer tools (rclone, WinSCP/pscp, MEGA clients, curl uploads).',
      'Large archive creation followed by outbound transfer.',
      'DLP policy match on sensitive content leaving via web, email, or removable media.',
    ],
    reviewFirst: ['User, host, destination, protocol, volume, and time window.', 'Tool or application used.', 'Whether the transfer completed or was blocked.'],
    oftenMissing: ['What data was transferred (file names, classification).', 'Staging activity (archives, mass reads from file shares) before the upload.', 'Whether the destination is sanctioned.'],
  },
  prerequisites: [
    { text: 'Network logs with byte counts (firewall session-end, proxy).', type: 'telemetry', required: true },
    { text: 'Endpoint process and file telemetry for the source host.', type: 'telemetry', required: true },
    { text: 'Cloud/SaaS audit logs (SharePoint/OneDrive, cloud storage) and DLP events where available.', type: 'telemetry', required: false },
    { text: 'List of sanctioned cloud services and transfer tools.', type: 'information', required: true },
    { text: 'Insider-risk procedure (who must be involved before contacting a user).', type: 'information', required: true },
  ],
  steps: [
    {
      id: 'quantify',
      title: 'Quantify the transfer',
      action: 'Record source host/user, destination (domain/IP/service), protocol and port, bytes sent, number of sessions, time window, and whether the transfer completed or was blocked.',
      why: 'Volume and completion define potential impact. A blocked attempt and a completed 40 GB upload are very different cases.',
      where: ['Firewall / proxy logs (SentBytes, bytes_out)', 'DLP console', 'Cloud app security logs'],
      fields: ['SentBytes / bytes_out', 'DestinationHostName / Web.dest', 'DeviceAction / action', 'Session count and duration'],
      suspicious: ['Gigabytes outbound outside business hours', 'Sustained upload over hours to a single destination'],
      legitimate: ['Backup or sync to a sanctioned corporate service at a known schedule'],
      next: 'Compare with the baseline.',
      queryIds: ['kql-outbound-volume', 'spl-outbound-volume'],
    },
    {
      id: 'baseline',
      title: 'Compare with the host and user baseline',
      action: 'Compare outbound volume and destinations with the previous 30 days for the same host and user. Note first-time destinations.',
      why: 'Some roles legitimately move large data (media, engineering). A sudden change is the signal.',
      where: ['Firewall / proxy history', 'Web data model'],
      fields: ['Daily bytes out', 'Destinations seen before'],
      suspicious: ['First-ever contact with the destination', 'Volume several times the normal daily maximum'],
      legitimate: ['Matches recurring transfers for a known project'],
      next: 'Identify the tool that performed the transfer.',
      queryIds: ['spl-user-web-upload'],
    },
    {
      id: 'tool',
      title: 'Identify the transfer tool and process',
      action: 'On the source host, find which process made the connections: browser, sanctioned sync client, or tools such as rclone, WinSCP/pscp, MEGA clients, curl with upload flags, or PowerShell. Record command lines (e.g. rclone copy <path> <remote>: --config ...).',
      why: 'Bulk-transfer tools are favored by intrusion operators; their command lines often reveal the destination and what was copied.',
      where: ['DeviceProcessEvents', 'DeviceNetworkEvents', 'EDR timeline'],
      fields: ['FileName', 'ProcessCommandLine', 'InitiatingProcessFileName', 'AccountName'],
      suspicious: ['rclone.exe or a renamed copy of it', 'Transfer tool executed from Temp/ProgramData/Public', 'Tool config file referencing cloud storage credentials'],
      legitimate: ['Corporate sync client signed into a corporate tenant'],
      next: 'Look for staging before the transfer.',
      queryIds: ['kql-exfil-tools'],
    },
    {
      id: 'staging',
      title: 'Look for data staging and collection',
      action: 'Search for large archives created before the transfer, mass reads from file shares or SharePoint/OneDrive, and data copied into staging folders.',
      why: 'Attackers compress and gather data before uploading. Staging evidence shows what data was targeted.',
      where: ['DeviceFileEvents (archives, FileSize)', 'Security 5145 on file servers', 'OfficeActivity (FileDownloaded, FileSyncDownloadedFull)'],
      fields: ['Archive names, sizes, paths', 'Source share paths', 'Downloaded file names'],
      suspicious: ['Multi-GB 7z/rar/zip created in Temp or Public shortly before upload', 'Thousands of files downloaded from SharePoint in an hour'],
      legitimate: ['Archives created by a known backup job'],
      next: 'Assess the destination.',
      queryIds: ['kql-archive-staging', 'kql-cloud-downloads'],
    },
    {
      id: 'destination',
      title: 'Assess the destination',
      action: 'Determine whether the destination is sanctioned (corporate tenant, approved partner) or unsanctioned (personal cloud storage, anonymous transfer services, paste sites, raw IPs over SFTP/FTP). For corporate SaaS, check whether the tenant is your organization\'s.',
      why: 'The same service (e.g. cloud storage) can be sanctioned for the corporate tenant and unsanctioned for personal accounts.',
      where: ['Proxy categories', 'Cloud app discovery', 'Firewall logs'],
      fields: ['Destination category', 'Tenant / account identifiers if visible'],
      suspicious: ['Personal storage account, anonymous file-transfer service, or IP-based SFTP'],
      legitimate: ['Corporate tenant or approved partner portal'],
      next: 'Consider insider vs. intrusion context.',
      queryIds: [],
    },
    {
      id: 'context',
      title: 'Consider intrusion and insider-risk context',
      action: 'Check for related intrusion signals on the host/account (C2, compromised sign-ins, ransomware precursors). If insider risk is plausible, follow the insider-risk procedure: do not contact the user, and limit who is informed.',
      why: 'Exfiltration is often the step before ransomware encryption. Insider cases have legal and HR handling requirements.',
      where: ['Alert queue', 'Identity logs', 'Insider-risk procedure'],
      fields: ['Related alerts', 'Account compromise indicators'],
      suspicious: ['C2 or ransomware precursor alerts on the same host', 'Compromised account indicators'],
      legitimate: ['Documented business request with manager approval'],
      next: 'Use the decision tree.',
      queryIds: [],
    },
  ],
  decisionTree: {
    start: 'sanctioned',
    nodes: [
      {
        id: 'sanctioned',
        question: 'Is the transfer to a sanctioned corporate destination, by an approved application, consistent with the user\'s role and baseline (or a documented business request)?',
        yes: { outcome: 'benign', guidance: 'Record destination ownership, application, and baseline/business justification.' },
        no: { next: 'meaningful', guidance: 'Unsanctioned or unexplained transfer.' },
      },
      {
        id: 'meaningful',
        question: 'Was a meaningful amount of data actually transferred (not blocked), or does DLP/file evidence show sensitive data involved?',
        yes: { next: 'context', guidance: 'Data likely left the organization.' },
        no: { outcome: 'investigate', guidance: 'Small or blocked transfer to an unsanctioned destination. Confirm what was involved; record as contained if blocked, per procedure.' },
        unknown: { outcome: 'gap', guidance: 'Byte counts or content visibility are missing. Record the gap and escalate per policy - assume data may have left.' },
      },
      {
        id: 'context',
        question: 'Are there intrusion indicators (exfil tools like rclone, staging archives, C2, compromised account, ransomware precursors), insider-risk indicators, or regulated/highly sensitive data?',
        yes: { outcome: 'critical', guidance: 'Follow the incident escalation procedure now. For insider risk, use the insider-risk channel and do not alert the user.' },
        no: { outcome: 'escalate', guidance: 'Unsanctioned transfer of meaningful volume. Escalate with volume, destination, tool, and data details.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true, 'Transfer start/end (UTC).'),
    ev('username', true),
    ev('hostname', true),
    ev('src_ip', false, 'Internal source IP used for the transfer.'),
    ev('destination', true, 'Destination service/domain/IP/port; sanctioned?'),
    evCustom('volume', 'Volume transferred', 'Bytes out, sessions, completed vs blocked.', true),
    ev('process', true, 'Transfer tool/process.'),
    ev('command_line', false),
    evCustom('data_involved', 'Data involved', 'File names, archives, source shares, DLP classification (as visible).', false, true),
    evCustom('staging', 'Staging evidence', 'Archives, mass downloads, staging folders.', false, true),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'Meaningful volume to an unsanctioned destination.',
      'Bulk-transfer tools (rclone, SFTP clients, MEGA clients) used outside approved purposes.',
      'Staging archives created before an outbound transfer.',
      'DLP match on sensitive data leaving the organization.',
      'Byte counts or content visibility missing for a suspicious transfer.',
    ],
    immediate: ['Exfiltration with intrusion indicators (C2, compromised account, ransomware precursors).', 'Regulated or highly sensitive data confirmed involved.', 'Insider-risk indicators (follow the insider-risk channel).'],
    benignClosure: ['Sanctioned destination and application consistent with baseline or documented request.'],
  },
  queries: [
    {
      id: 'kql-outbound-volume',
      title: 'Outbound volume by destination for a source IP (firewall CEF)',
      language: 'kql',
      platform: 'Microsoft Sentinel (CEF / CommonSecurityLog)',
      purpose: 'Totals bytes sent from the source IP per destination using firewall logs.',
      dataSources: ['CommonSecurityLog'],
      query: `CommonSecurityLog
| where TimeGenerated > ago({{lookback}})
| where SourceIP == "{{src_ip}}"
| where isnotempty(SentBytes)
| summarize TotalSentMB = round(sum(SentBytes) / 1048576.0, 1), Sessions = count(),
            First = min(TimeGenerated), Last = max(TimeGenerated)
            by DestinationIP, DestinationHostName, DestinationPort, DeviceVendor
| order by TotalSentMB desc`,
      placeholders: [PH.lookback('24h'), PH.srcIp('10.20.30.40')],
      keyFields: [{ name: 'TotalSentMB', meaning: 'Total upload volume per destination.' }, { name: 'DestinationHostName', meaning: 'Present when the firewall/proxy logs hostnames.' }],
      positive: 'Large totals to unsanctioned destinations are leads.',
      negative: 'Requires session-end logging with byte counts; VPN/NAT may hide the internal source.',
      prerequisites: 'Firewall/proxy CEF logs in Sentinel.',
      schemaNotes: 'Byte counters depend on vendor mapping; some devices put upload volume in ReceivedBytes depending on direction semantics - validate with a known transfer.',
      example: 'src_ip = 10.20.30.40',
    },
    {
      id: 'kql-exfil-tools',
      title: 'Bulk-transfer tool executions',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds executions of common exfiltration tools and upload command lines across devices.',
      dataSources: ['DeviceProcessEvents'],
      query: `DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where FileName in~ ("rclone.exe", "winscp.exe", "pscp.exe", "megasync.exe", "megacmd.exe")
    or ProcessCommandLine has_any ("rclone", "mega.nz", "transfer.sh")
    or (FileName =~ "curl.exe" and (ProcessCommandLine contains "--upload-file"
        or ProcessCommandLine contains " -T " or ProcessCommandLine contains " -F "))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, SHA256
| order by Timestamp asc`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'ProcessCommandLine', meaning: 'Source paths and remote destination (e.g. remote:bucket).' }],
      positive: 'Tool usage to attribute; IT may use some legitimately.',
      negative: 'Renamed tools with custom command lines may evade name matching; check the original file name in the EDR.',
      prerequisites: 'Defender for Endpoint.',
      schemaNotes: 'Extend the tool list with your environment\'s unsanctioned tools.',
      example: 'lookback = 7d',
    },
    {
      id: 'kql-archive-staging',
      title: 'Archives created on a host (staging)',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Lists archive files created on the host, largest first.',
      dataSources: ['DeviceFileEvents'],
      query: `DeviceFileEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where ActionType == "FileCreated"
| where FileName matches regex @"(?i)\\.(zip|7z|rar|tar|gz|tgz)$"
| project Timestamp, FileName, FolderPath, FileSize, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by FileSize desc`,
      placeholders: [PH.lookback('7d'), PH.hostname()],
      keyFields: [{ name: 'FileSize', meaning: 'Large archives are more likely staging.' }],
      positive: 'Large archives near the transfer time support staging.',
      negative: 'Archives on network shares or created by tools the sensor does not see are missed.',
      prerequisites: 'Defender for Endpoint file telemetry.',
      schemaNotes: 'FileSize may be empty for some events.',
      example: 'hostname = ws-demo-0142.corp.example.com',
    },
    {
      id: 'kql-cloud-downloads',
      title: 'SharePoint/OneDrive download and sharing activity for a user',
      language: 'kql',
      platform: 'Microsoft Sentinel (Microsoft 365 connector)',
      purpose: 'Shows hourly download, sync, and sharing activity by a user to detect mass collection.',
      dataSources: ['OfficeActivity'],
      query: `OfficeActivity
| where TimeGenerated > ago({{lookback}})
| where UserId =~ "{{upn}}"
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "AnonymousLinkCreated", "SharingSet")
| summarize Events = count(), Files = make_set(SourceFileName, 25)
            by Operation, ClientIP, bin(TimeGenerated, 1h)
| order by TimeGenerated asc`,
      placeholders: [PH.lookback('7d'), PH.upn()],
      keyFields: [{ name: 'Events per hour', meaning: 'Spikes indicate mass collection.' }, { name: 'ClientIP', meaning: 'Compare with the user\'s normal IPs.' }],
      positive: 'Mass downloads or anonymous links before the transfer support data theft.',
      negative: 'Audit events can be delayed by hours.',
      prerequisites: 'Office 365 connector with SharePoint/OneDrive audit.',
      schemaNotes: 'Operation names are defined by the Microsoft 365 unified audit log.',
      example: 'upn = jdoe@example.com',
    },
    {
      id: 'spl-outbound-volume',
      title: 'Outbound volume by destination for a source (CIM Network_Traffic)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Top destinations by bytes sent from the source.',
      dataSources: ['CIM Network_Traffic'],
      query: `| tstats summariesonly=false sum(All_Traffic.bytes_out) as bytes_out count
    from datamodel=Network_Traffic
    where earliest=-{{lookback}} All_Traffic.src_ip="{{src_ip}}"
    by All_Traffic.dest_ip All_Traffic.dest_port
| eval mb_out=round(bytes_out/1024/1024, 1)
| sort - mb_out
| head 25`,
      placeholders: [PH.lookback('24h'), PH.srcIp('10.20.30.40')],
      keyFields: [{ name: 'mb_out', meaning: 'Upload volume per destination.' }],
      positive: 'Large destinations to evaluate.',
      negative: 'Byte fields need session-end logging.',
      prerequisites: 'Firewall logs mapped to CIM.',
      schemaNotes: 'Direction semantics of bytes_out depend on the add-on.',
      example: 'src_ip = 10.20.30.40',
    },
    {
      id: 'spl-user-web-upload',
      title: 'Web upload volume by destination for a user (CIM Web)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Shows a user\'s upload volume per destination and HTTP method.',
      dataSources: ['CIM Web (proxy)'],
      query: `| tstats summariesonly=false sum(Web.bytes_out) as bytes_out count from datamodel=Web
    where earliest=-{{lookback}} Web.user="{{username}}"
    by Web.dest Web.http_method
| eval mb_out=round(bytes_out/1024/1024, 1)
| sort - mb_out`,
      placeholders: [PH.lookback('30d'), PH.username()],
      keyFields: [{ name: 'Web.http_method', meaning: 'POST/PUT carry uploads.' }],
      positive: 'First-time or unusually large destinations stand out.',
      negative: 'Without TLS inspection, some proxies cannot measure request bodies accurately.',
      prerequisites: 'Proxy logs mapped to CIM Web.',
      schemaNotes: 'User format depends on proxy authentication.',
      example: 'username = jdoe',
    },
    {
      id: 'generic-exfil',
      title: 'Generic exfiltration procedure',
      language: 'generic',
      platform: 'Any SIEM / EDR / DLP',
      purpose: 'Platform-neutral checklist.',
      dataSources: ['Network, endpoint, cloud audit, DLP'],
      query: `1. Quantify: bytes out, destination, time window, completed vs blocked.
2. Baseline: 30-day volume and destinations for the host/user.
3. Tool: process/command line performing the transfer.
4. Staging: archives, mass share reads, cloud mass downloads before the transfer.
5. Destination: sanctioned vs unsanctioned; corporate tenant?
6. Context: intrusion signals vs insider risk (follow the insider procedure).`,
      placeholders: [],
      keyFields: [],
      positive: 'Unsanctioned + meaningful volume drives escalation.',
      negative: 'Missing byte counts are a gap.',
      prerequisites: 'Network and endpoint telemetry.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: ['Exfiltration to sanctioned services (corporate tenant vs personal tenant) is hard to separate without tenant-aware controls.', 'Low-and-slow exfiltration stays under volume thresholds; review destinations, not only bytes.'],
  visibilityGaps: ['Encrypted uploads hide content; only volume and destination are visible.', 'Removable media and printing are outside network logs.'],
  relatedTechniques: [
    { id: 'T1560.001', reason: 'Data is archived with utilities before exfiltration.' },
    { id: 'T1074.001', reason: 'Data is staged locally before upload.' },
    { id: 'T1071.001', reason: 'Web protocols carry most exfiltration.' },
    { id: 'T1537', reason: 'Data can be transferred to attacker-controlled cloud accounts.' },
    { id: 'T1486', reason: 'Exfiltration often precedes ransomware encryption (double extortion).' },
  ],
  references: [attackRef('T1567.002', 'Exfiltration to Cloud Storage'), attackRef('T1048', 'Exfiltration Over Alternative Protocol'), { title: 'CISA #StopRansomware Guide', url: 'https://www.cisa.gov/stopransomware/ransomware-guide' }],
  assumptions: ['Insider-risk cases follow a separate, restricted procedure.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};
