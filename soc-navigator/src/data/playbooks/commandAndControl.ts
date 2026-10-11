import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

const INDICATOR = {
  name: 'indicator',
  kind: 'string' as const,
  description: 'Destination IP address or domain from the alert (not defanged).',
  example: 'cdn-update.example.net',
};

export const commandAndControl: Playbook = {
  schemaVersion: 1,
  id: 'PB-C2-001',
  version: '1.0.0',
  title: 'Potential command-and-control (C2) communication',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1071', 'T1071.001', 'T1071.004'],
  tactics: ['command-and-control'],
  objective:
    'Determine which process on which host is communicating with the flagged destination, whether the pattern looks like automated C2 (beaconing, DNS tunneling), and how many hosts are involved.',
  alertMeaning:
    'Network activity matched a threat-intelligence indicator, showed periodic "beacon" timing, used unusual DNS patterns (very long or random subdomains, high TXT volume), contacted a newly registered or rare domain, or used an uncommon user agent.',
  whyItMatters:
    'C2 traffic means malware or an attacker tool is running and can receive commands. It is often the first network-visible sign of a compromise that started elsewhere.',
  difficulty: 'Intermediate',
  effort: '30-60 minutes',
  platforms: ['Windows', 'Linux', 'macOS', 'Network Devices'],
  logSources: ['mde', 'edr', 'proxy', 'dns', 'firewall', 'sysmon'],
  alertContext: {
    triggers: [
      'Threat-intelligence match on destination IP/domain.',
      'Beaconing analytics: regular intervals and similar payload sizes over hours.',
      'DNS anomalies: long high-entropy subdomains, many unique subdomains under one domain, high TXT/NULL query volume.',
      'Connection to a newly registered, uncategorized, or dynamic-DNS domain by a non-browser process.',
    ],
    reviewFirst: ['Source host and process.', 'Destination IP/domain/port and protocol.', 'Indicator source, confidence, and age.', 'Connection count and time span.'],
    oftenMissing: ['The process responsible (network logs show only IPs).', 'Whether the destination is shared infrastructure (CDN, cloud hosting).', 'Other hosts talking to the same destination.'],
  },
  prerequisites: [
    { text: 'Network telemetry attributed to processes (EDR / Sysmon 3) - or at least proxy/firewall logs with source IP.', type: 'telemetry', required: true },
    { text: 'DNS logs for domain-based indicators.', type: 'telemetry', required: false },
    { text: 'Threat-intelligence and domain reputation lookups (domain age, ASN, category).', type: 'tool', required: true },
    { text: 'DHCP/VPN logs to map IPs to hosts when EDR is absent.', type: 'telemetry', required: false },
  ],
  steps: [
    {
      id: 'validate-indicator',
      title: 'Validate the indicator and its quality',
      action: 'Record the destination, port, protocol, and the indicator source. Check how old the indicator is, its confidence, and whether the IP belongs to shared hosting or a CDN (where many unrelated sites share one IP).',
      why: 'Stale or shared-infrastructure indicators are a major source of false positives. A fresh, high-confidence domain indicator is far more meaningful than an old IP.',
      where: ['Threat-intelligence platform', 'WHOIS / passive DNS / ASN lookup', 'Alert details'],
      fields: ['Indicator type and value', 'Source feed', 'First/last seen in TI', 'ASN / hosting provider', 'Domain registration date'],
      suspicious: ['Domain registered in the last 30 days', 'Dedicated IP on a hosting provider used by known C2 frameworks', 'Dynamic DNS domain'],
      legitimate: ['IP belongs to a major CDN/cloud provider and the indicator is months old', 'Domain is a well-known SaaS used by the business'],
      next: 'Identify which process made the connection.',
      queryIds: ['kql-dest-prevalence'],
    },
    {
      id: 'process',
      title: 'Identify the process making the connection',
      action: 'Use EDR network events to find the initiating process, its path, signer, command line, parent, and user on the source host. Without EDR, map the source IP to a host via DHCP/VPN and request endpoint data.',
      why: 'A browser visiting a site is very different from an unknown binary or rundll32.exe contacting the same site every 60 seconds.',
      where: ['DeviceNetworkEvents', 'Sysmon 3 / 22', 'DHCP / VPN logs'],
      fields: ['InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessCommandLine', 'InitiatingProcessSHA256'],
      suspicious: ['Non-browser process in AppData/Temp', 'rundll32/regsvr32/powershell as the initiator', 'Process signed by an unknown or revoked certificate'],
      legitimate: ['Browser with a user session at the time', 'Signed software updater'],
      next: 'Analyze the traffic pattern.',
      queryIds: ['kql-dest-prevalence', 'spl-traffic-to-dest'],
    },
    {
      id: 'pattern',
      title: 'Analyze timing and protocol patterns',
      action: 'Compute the interval between connections (average and variation), session sizes, and duration. For DNS indicators, measure subdomain length, number of unique subdomains, and record types.',
      why: 'Automated C2 beacons at regular intervals (with some jitter) and keeps small, similar request sizes. DNS tunneling encodes data in many long, unique subdomains.',
      where: ['DeviceNetworkEvents (sorted)', 'Proxy / firewall logs', 'DNS logs'],
      fields: ['Inter-arrival time average / standard deviation', 'Bytes per session', 'Query name length', 'Unique subdomain count', 'Query type'],
      suspicious: ['Consistent intervals (e.g. every 60 s +/- 10 %) over hours, including outside working hours', 'Hundreds of unique 40+ character subdomains under one domain', 'High TXT query volume'],
      legitimate: ['Regular polling by known software (update checks, telemetry, chat clients) to vendor domains'],
      next: 'Record the pattern metrics in evidence.',
      queryIds: ['kql-beacon-intervals', 'kql-dns-tunneling', 'spl-beacon-intervals', 'spl-dns-domain'],
    },
    {
      id: 'origin',
      title: 'Trace the origin and persistence of the process',
      action: 'Find when and how the initiating binary or script arrived, what launched it, and whether persistence (Run key, task, service) exists.',
      why: 'C2 implants are delivered by an earlier stage; finding it reveals the initial access path.',
      where: ['DeviceFileEvents', 'DeviceProcessEvents', 'DeviceRegistryEvents / task events'],
      fields: ['File creation time and origin', 'Parent chain', 'Persistence artifacts'],
      suspicious: ['Binary created shortly after an email attachment was opened', 'Run key or task referencing the binary'],
      legitimate: ['Installed by the management platform'],
      next: 'Scope across the environment.',
      queryIds: [],
    },
    {
      id: 'scope',
      title: 'Scope other hosts and data volume',
      action: 'Find all hosts that contacted the destination in the last 30 days and total bytes sent. High outbound volume may indicate exfiltration over the C2 channel.',
      why: 'Multiple infected hosts or large uploads change severity and response.',
      where: ['DeviceNetworkEvents', 'Firewall / proxy logs', 'Network_Traffic data model'],
      fields: ['Host list', 'Bytes out per host', 'First contact time'],
      suspicious: ['Several hosts, especially servers', 'Large or growing outbound volume'],
      legitimate: ['Only browsers on many hosts visiting a popular site'],
      next: 'Use the decision tree.',
      queryIds: ['kql-dest-prevalence', 'spl-traffic-to-dest'],
    },
  ],
  decisionTree: {
    start: 'legit-dest',
    nodes: [
      {
        id: 'legit-dest',
        question: 'Is the destination verified legitimate for the initiating process (known vendor/CDN/SaaS, expected software), with a stale or low-confidence indicator?',
        yes: { outcome: 'benign', guidance: 'Record destination ownership, process, and why the indicator is not applicable. Report the indicator quality issue to the TI owner.' },
        no: { next: 'c2-traits', guidance: 'Destination not verified.' },
      },
      {
        id: 'c2-traits',
        question: 'Is the traffic made by a non-browser, unsigned/rare, or injected process - or does it show beaconing or DNS-tunneling characteristics?',
        yes: { next: 'scope', guidance: 'Likely automated C2.' },
        no: { outcome: 'investigate', guidance: 'Likely user browsing to a flagged site. Check what was downloaded or submitted (phishing / drive-by), then decide.' },
        unknown: { outcome: 'gap', guidance: 'Process attribution is not possible (no EDR). Document the gap and escalate per policy with network evidence.' },
      },
      {
        id: 'scope',
        question: 'Are multiple hosts communicating with the destination, is the host a server/privileged system, or is outbound volume large enough to suggest exfiltration?',
        yes: { outcome: 'critical', guidance: 'Follow the incident escalation procedure now.' },
        no: { outcome: 'escalate', guidance: 'Single-host C2. Escalate with process, destination, pattern metrics, and origin.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true, 'First and last connection (UTC).'),
    ev('hostname', true),
    ev('destination', true, 'IP/domain/port/protocol (defanged in notes).'),
    evCustom('indicator_quality', 'Indicator source and quality', 'Feed, confidence, age, ASN, domain age, shared hosting?', true, true),
    ev('process', true, 'Initiating process, path, signer.'),
    ev('src_ip', false, 'Internal IP of the source host at the time (DHCP/VPN can change it).'),
    ev('username', false),
    evCustom('pattern_metrics', 'Traffic pattern metrics', 'Connections, average interval, variation, bytes out/in; DNS subdomain stats.', false, true),
    ev('file_hash', false, 'Initiating binary hash.'),
    ev('affected_assets', false, 'Other hosts contacting the destination.'),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'Non-browser or unsigned/rare process communicating with an unverified external destination.',
      'Beaconing or DNS-tunneling characteristics.',
      'High-confidence, recent threat-intelligence match.',
      'Process attribution impossible and the destination is suspicious.',
    ],
    immediate: ['Multiple hosts communicating with the same C2 destination.', 'C2 from a server, domain controller, or privileged workstation.', 'Large outbound data volume to the destination.'],
    benignClosure: ['Destination ownership verified and appropriate for the process; indicator stale/low-confidence or shared infrastructure.'],
  },
  queries: [
    {
      id: 'kql-dest-prevalence',
      title: 'Hosts and processes contacting a destination',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Lists every device/process that connected to the IP or domain, with counts and time span.',
      dataSources: ['DeviceNetworkEvents'],
      query: `DeviceNetworkEvents
| where Timestamp > ago({{lookback}})
| where RemoteIP == "{{indicator}}" or RemoteUrl has "{{indicator}}"
| summarize Connections = count(), First = min(Timestamp), Last = max(Timestamp),
            Ports = make_set(RemotePort, 10)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
               InitiatingProcessSHA256, InitiatingProcessAccountName
| order by Connections desc`,
      placeholders: [PH.lookback('30d'), INDICATOR],
      keyFields: [{ name: 'InitiatingProcessFileName / FolderPath', meaning: 'Process responsible for the traffic.' }, { name: 'First / Last', meaning: 'Duration of the communication.' }],
      positive: 'Shows which hosts and processes are involved.',
      negative: 'RemoteUrl is only populated for some connections; for HTTPS without inspection, search the IP. Unmanaged devices are not covered.',
      prerequisites: 'Defender for Endpoint network telemetry.',
      schemaNotes: 'Use the IP or the domain as the indicator.',
      example: 'indicator = cdn-update.example.net, lookback = 30d',
    },
    {
      id: 'kql-beacon-intervals',
      title: 'Beacon interval statistics for a host and destination',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Calculates the average and variation of time between connections per initiating process.',
      dataSources: ['DeviceNetworkEvents'],
      query: `DeviceNetworkEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where RemoteIP == "{{indicator}}" or RemoteUrl has "{{indicator}}"
| sort by InitiatingProcessFileName asc, Timestamp asc
| extend DeltaSec = iff(prev(InitiatingProcessFileName) == InitiatingProcessFileName,
                        datetime_diff('second', Timestamp, prev(Timestamp)), long(null))
| where isnotnull(DeltaSec)
| summarize Connections = count() + 1, AvgIntervalSec = avg(DeltaSec), StdevIntervalSec = stdev(DeltaSec),
            MinIntervalSec = min(DeltaSec), MaxIntervalSec = max(DeltaSec)
            by InitiatingProcessFileName
| extend VariationRatio = round(StdevIntervalSec / AvgIntervalSec, 2)`,
      placeholders: [PH.lookback('24h'), PH.hostname(), INDICATOR],
      keyFields: [
        { name: 'AvgIntervalSec', meaning: 'Typical time between connections.' },
        { name: 'VariationRatio', meaning: 'Low values (e.g. below ~0.2) with many connections suggest automated beaconing.' },
      ],
      positive: 'Regular intervals support automated communication - legitimate software also polls regularly.',
      negative: 'Irregular intervals do not rule out C2 (jitter and sleep can be large).',
      prerequisites: 'Defender for Endpoint network telemetry.',
      schemaNotes: 'Defender may aggregate repeated identical connections, which affects interval maths.',
      example: 'hostname = ws-demo-0142.corp.example.com, indicator = 198.51.100.23',
    },
    {
      id: 'kql-dns-tunneling',
      title: 'DNS query characteristics for a domain',
      language: 'kql',
      platform: 'Microsoft Sentinel (Windows DNS Events connector)',
      purpose: 'Measures unique subdomains, name length, and query types per client for the suspect domain.',
      dataSources: ['DnsEvents'],
      query: `DnsEvents
| where TimeGenerated > ago({{lookback}})
| where Name endswith "{{domain}}"
| summarize Queries = count(), UniqueNames = dcount(Name), AvgNameLength = avg(strlen(Name)),
            MaxNameLength = max(strlen(Name)), QueryTypes = make_set(QueryType, 10)
            by ClientIP
| order by UniqueNames desc`,
      placeholders: [PH.lookback('24h'), { name: 'domain', kind: 'string', description: 'Suspect parent domain.', example: 'tunnel.example.org' }],
      keyFields: [{ name: 'UniqueNames / AvgNameLength', meaning: 'Many unique long names suggest data encoded in DNS.' }, { name: 'QueryTypes', meaning: 'TXT/NULL heavy usage is unusual for normal clients.' }],
      positive: 'High unique-name counts with long names are consistent with DNS tunneling.',
      negative: 'Some security and CDN services use long generated subdomains; check the domain owner.',
      prerequisites: 'Windows DNS server logs in Sentinel (DnsEvents) - or adapt to ASIM _Im_Dns (DnsQuery, SrcIpAddr).',
      schemaNotes: 'If DNS is collected via ASIM, use _Im_Dns(starttime=ago(1d)) | where DnsQuery endswith ... ; ClientIP will be the forwarder if clients use local caching resolvers.',
      example: 'domain = tunnel.example.org',
    },
    {
      id: 'spl-traffic-to-dest',
      title: 'Traffic to a destination IP (CIM Network_Traffic)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Summarizes sources, ports, actions, and bytes to the destination IP.',
      dataSources: ['CIM Network_Traffic (firewall)'],
      query: `| tstats summariesonly=false count sum(All_Traffic.bytes_out) as bytes_out sum(All_Traffic.bytes_in) as bytes_in
    min(_time) as first_seen max(_time) as last_seen
    from datamodel=Network_Traffic
    where earliest=-{{lookback}} All_Traffic.dest_ip="{{dest_ip}}"
    by All_Traffic.src_ip All_Traffic.dest_port All_Traffic.action
| convert ctime(first_seen) ctime(last_seen)
| sort - bytes_out`,
      placeholders: [PH.lookback('30d'), { name: 'dest_ip', kind: 'string', description: 'Destination IP address.', example: '198.51.100.23' }],
      keyFields: [{ name: 'bytes_out', meaning: 'Outbound volume per source.' }, { name: 'All_Traffic.action', meaning: 'allowed vs blocked.' }],
      positive: 'Shows internal sources and volumes.',
      negative: 'NAT may hide the real internal source; traffic within the same network segment is not logged by perimeter firewalls.',
      prerequisites: 'Firewall logs mapped to CIM.',
      schemaNotes: 'Byte fields depend on session-end logging.',
      example: 'dest_ip = 198.51.100.23',
    },
    {
      id: 'spl-beacon-intervals',
      title: 'Beacon interval statistics (raw events)',
      language: 'spl',
      platform: 'Splunk Enterprise',
      purpose: 'Computes connection interval statistics between one source and one destination.',
      dataSources: ['Proxy or firewall index with src and dest fields'],
      query: `index="{{index}}" earliest=-{{lookback}} src="{{src_ip}}" dest="{{indicator}}"
| sort 0 _time
| streamstats current=f last(_time) as prev_time
| eval delta=_time-prev_time
| stats count avg(delta) as avg_interval stdev(delta) as stdev_interval
    min(delta) as min_interval max(delta) as max_interval
| eval variation_ratio=round(stdev_interval/avg_interval, 2)`,
      placeholders: [
        { name: 'index', kind: 'string', description: 'Index with proxy or firewall events.', example: 'proxy' },
        PH.lookback('24h'),
        PH.srcIp('10.20.30.40'),
        INDICATOR,
      ],
      keyFields: [{ name: 'variation_ratio', meaning: 'Low values with many events suggest regular beaconing.' }],
      positive: 'Regular timing supports automated communication.',
      negative: 'Large jitter configurations hide beacons.',
      prerequisites: 'Network events with normalized src/dest fields.',
      schemaNotes: 'Field names (src, dest, dest_host, url) vary by add-on.',
      example: 'index = proxy, src_ip = 10.20.30.40',
    },
    {
      id: 'spl-dns-domain',
      title: 'DNS queries for a domain (CIM Network_Resolution)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Counts queries and unique names under the suspect domain by client.',
      dataSources: ['CIM Network_Resolution'],
      query: `| tstats summariesonly=false count dc(DNS.query) as unique_names values(DNS.record_type) as record_types
    from datamodel=Network_Resolution
    where earliest=-{{lookback}} DNS.query="*{{domain}}"
    by DNS.src
| sort - unique_names`,
      placeholders: [PH.lookback('24h'), { name: 'domain', kind: 'string', description: 'Suspect parent domain.', example: 'tunnel.example.org' }],
      keyFields: [{ name: 'unique_names', meaning: 'Many unique names under one domain suggest tunneling or DGA activity.' }],
      positive: 'Clients querying the domain, with volume.',
      negative: 'DNS-over-HTTPS bypasses enterprise DNS logs.',
      prerequisites: 'DNS logs mapped to CIM Network_Resolution.',
      schemaNotes: 'record_type availability depends on source.',
      example: 'domain = tunnel.example.org',
    },
    {
      id: 'generic-c2',
      title: 'Generic C2 procedure',
      language: 'generic',
      platform: 'Any EDR / SIEM / NDR',
      purpose: 'Platform-neutral checklist.',
      dataSources: ['Network, DNS, proxy, endpoint logs'],
      query: `1. Indicator quality: source, confidence, age, ASN, domain age, shared hosting.
2. Process attribution on the source host (EDR) or IP->host mapping (DHCP/VPN).
3. Pattern: interval average/variation, bytes per session, DNS subdomain stats.
4. Origin and persistence of the initiating binary.
5. Scope: other hosts contacting the destination; outbound volume.`,
      placeholders: [],
      keyFields: [],
      positive: 'Non-browser + beaconing + unverified destination supports escalation.',
      negative: 'Lack of process attribution is a gap, not exoneration.',
      prerequisites: 'Network and endpoint telemetry.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: ['Encrypted C2 over HTTPS to cloud services blends with normal traffic; process context is essential.', 'Threat-intelligence IP indicators age quickly, especially on cloud and CDN ranges.'],
  visibilityGaps: ['Without TLS inspection only SNI/hostnames are visible.', 'DNS-over-HTTPS and direct-to-IP connections bypass DNS logging.'],
  relatedTechniques: [
    { id: 'T1573', reason: 'C2 channels are usually encrypted.' },
    { id: 'T1568', reason: 'Dynamic resolution (DGA, fast flux) hides C2 infrastructure.' },
    { id: 'T1102', reason: 'Legitimate web services are abused for C2.' },
    { id: 'T1219', reason: 'Remote access tools provide C2-like control.' },
    { id: 'T1041', reason: 'Data is often exfiltrated over the C2 channel.' },
    { id: 'T1105', reason: 'Tools are downloaded through the C2 channel.' },
  ],
  references: [attackRef('T1071', 'Application Layer Protocol'), attackRef('T1071.004', 'DNS'), { title: 'Microsoft Learn - DeviceNetworkEvents table', url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table' }, { title: 'Splunk CIM - Network Resolution (DNS) data model', url: 'https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution' }],
  assumptions: ['Blocking destinations and isolating hosts are containment actions requested through escalation.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};
