import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const TODAY = "2026-07-12";
const SCHEMA_VERSION = "4.0.0";
const CURRENT_TACTICS = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
  "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery",
  "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"
];

const NAME_UPDATES = new Map([
  ["T1176", "Software Extensions"],
  ["T1207", "Rogue Domain Controller"],
  ["T1211", "Exploitation for Stealth"],
  ["T1219", "Remote Access Tools"],
  ["T1649", "Steal or Forge Authentication Certificates"]
]);
const SUPERSEDED = new Map([["T1562", "T1685"], ["T1656", "T1684.001"]]);
const OMIT_HEADINGS = new Set([
  "telemetry engineering standard", "collection readiness & quality gates",
  "detection engineering specification", "correlation blueprint",
  "validation, tuning & detection-as-code gates", "analyst triage pivots",
  "operational response standard", "first 15 minutes", "evidence & scoping checklist",
  "containment decision points", "recovery, monitoring & closure gates"
]);

const MOJIBAKE = new Map([
  ["â€”", "—"], ["â€“", "–"], ["â€™", "’"], ["â€˜", "‘"], ["â€œ", "“"],
  ["â€", "”"], ["â€¦", "…"], ["Â±", "±"], ["Â·", "·"], ["Â®", "®"],
  ["â†’", "→"], ["â†", "←"], ["â†—", "↗"], ["â˜…", "★"], ["â˜†", "☆"],
  ["âœ•", "✕"], ["â§‰", "⧉"]
]);

const TACTIC_PROFILE = {
  "Reconnaissance": { severity: "medium", window: "30 minutes with a 24-hour targeting lookback", model: "Correlate repeated external discovery against the same organization, domain, address range, identity, or exposed service and enrich infrastructure ownership.", gap: "Much reconnaissance occurs outside enterprise-controlled telemetry; exposure-management and external intelligence are compensating sources.", action: "Reduce the exposed condition and block confirmed hostile infrastructure without disrupting legitimate research solely on weak evidence." },
  "Resource Development": { severity: "medium", window: "24 hours with a 30-day infrastructure lookback", model: "Link newly created infrastructure, identities, certificates, domains, repositories, or payload traits to organization-specific targeting and later delivery.", gap: "Adversary preparation commonly occurs off-network and may only be visible through external intelligence or later campaign correlation.", action: "Block confirmed infrastructure and coordinate authorized takedown or abuse reporting after preserving evidence." },
  "Initial Access": { severity: "high", window: "15 minutes with a 7-day identity, email, and network lookback", model: "Correlate the delivery or exploitation signal with authentication, file, process, email, web, and vulnerability context on the same user or asset.", gap: "Encrypted traffic, unmanaged devices, external SaaS, and applications without audit logging can hide the entry point.", action: "Block the entry vector, isolate confirmed hosts, and revoke affected sessions according to evidence and business impact." },
  "Execution": { severity: "high", window: "5 minutes with a 24-hour process and authentication lookback", model: "Join process start, parent-child lineage, command or script content, signer, prevalence, user context, and subsequent file or network behavior.", gap: "In-memory execution, truncated command lines, disabled script logging, and unmanaged interpreters reduce confidence.", action: "Stop confirmed malicious execution and contain the initiating identity or delivery path while preserving volatile evidence." },
  "Persistence": { severity: "high", window: "15 minutes with a 30-day configuration baseline", model: "Detect new or modified autostarts, services, tasks, accounts, cloud objects, application components, or boot artifacts outside approved change activity.", gap: "Unlogged configuration stores and weak golden-state baselines can make persistence appear legitimate.", action: "Disable the persistence mechanism after evidence capture and contain the creator when it is not trusted." },
  "Privilege Escalation": { severity: "high", window: "10 minutes with a 7-day privilege and vulnerability lookback", model: "Correlate privilege-sensitive process, token, group, role, exploit, and configuration changes with the initiating identity and prior execution chain.", gap: "Kernel activity, inherited cloud roles, and missing privilege-change auditing require dedicated sources beyond process telemetry.", action: "Revoke the elevated context and correct the escalation path; rotate credentials when privileged material may be exposed." },
  "Stealth": { severity: "high", window: "10 minutes with a 24-hour process and artifact baseline", model: "Correlate concealment, masquerading, obfuscation, artifact removal, and trusted-binary abuse with process lineage and independent telemetry.", gap: "Successful concealment may remove the evidence used to detect it; retain off-host logs and independent control-health signals.", action: "Preserve remaining evidence, stop the actor path, and restore visibility before making broad remediation changes." },
  "Defense Impairment": { severity: "high", window: "10 minutes with a 24-hour control-health baseline", model: "Correlate security-control, firewall, logging, policy, sensor, or recovery tampering with the responsible identity, process, and change context.", gap: "Telemetry may become unavailable precisely when impairment succeeds; independent monitoring and off-host retention are required.", action: "Restore or isolate affected controls, preserve the last known forensic state, and contain the responsible access path." },
  "Credential Access": { severity: "critical", window: "5 minutes with a 30-day credential-use lookback", model: "Join sensitive store or process access, directory replication, vault or token activity, and subsequent authentication from new contexts.", gap: "Memory-only access, unmanaged vaults, and incomplete directory auditing can obscure exactly which credentials were exposed.", action: "Isolate the source, revoke affected sessions, and rotate exposed secrets in dependency-safe order." },
  "Discovery": { severity: "medium", window: "15 minutes with a 24-hour process and identity baseline", model: "Aggregate related discovery commands, APIs, and enumeration across the same process tree, user, session, workload, or host.", gap: "Legitimate administration resembles discovery; ancestry, novelty, volume, and approved change context are essential.", action: "Contain only when discovery is linked to compromise or abnormal privilege; otherwise preserve evidence and increase monitoring." },
  "Lateral Movement": { severity: "high", window: "10 minutes with a 7-day remote-access baseline", model: "Correlate remote authentication, share or service access, protocol telemetry, payload transfer, and process creation across source and destination hosts.", gap: "East-west blind spots, shared administrative accounts, NAT, and missing destination logs can hide the true source.", action: "Isolate affected nodes, restrict abused identities, and block the movement path while preserving both endpoint perspectives." },
  "Collection": { severity: "high", window: "30 minutes with a 7-day data-access baseline", model: "Correlate unusual reads, searches, exports, screenshots, archive creation, database activity, and staging by the same user, process, or host.", gap: "Metadata-only logs may not identify content; classification, DLP, application audit, and file telemetry improve confidence.", action: "Restrict access to affected data and identities, preserve staged artifacts, and determine whether disclosure is possible." },
  "Command and Control": { severity: "high", window: "15 minutes with a 30-day destination baseline", model: "Join network flow, DNS, proxy, TLS, destination reputation, periodicity, process attribution, and endpoint signals.", gap: "Encrypted, domain-fronted, peer-to-peer, and dead-drop channels can evade reputation-only analytics.", action: "Block confirmed infrastructure and isolate controlled hosts after preserving volatile process, network, and memory evidence." },
  "Exfiltration": { severity: "critical", window: "30 minutes with a 30-day user, destination, and volume baseline", model: "Correlate staging and archive activity with unusual outbound volume, destination novelty, channel misuse, and data classification.", gap: "TLS, sanctioned cloud services, removable media, and low-and-slow transfer can bypass simple thresholds.", action: "Stop active transfer, revoke the abused channel or token, preserve staged data, and engage legal or privacy decision-makers." },
  "Impact": { severity: "critical", window: "5 minutes with a 24-hour change, identity, process, and backup lookback", model: "Correlate destructive commands, encryption or deletion patterns, service disruption, recovery inhibition, and privileged changes.", gap: "Telemetry may stop during disruption; independent service, network, and backup monitoring is essential.", action: "Prioritize safety and continuity, isolate spread, revoke actor access, protect recovery systems, and invoke crisis procedures." },
  "Operational": { severity: "high", window: "the complete incident timeline with a pre-event and post-event buffer", model: "Normalize alerts into a case, correlate common entities and chronology, validate evidence quality, and track decisions, approvals, and ownership.", gap: "Case quality fails when provenance, timestamps, ownership, or evidence-backed closure criteria are missing.", action: "Use approved response actions with documented impact, evidence preservation, verification, and rollback." },
  "Platform": { severity: "high", window: "15 minutes with a 30-day alert and sensor-health baseline", model: "Normalize vendor detections, prevention outcome, confidence, process lineage, endpoint identity, and correlated activity into product-independent fields.", gap: "Agent health, policy drift, exclusions, version lag, and vendor-cloud connectivity can create silent blind spots.", action: "Use vendor response actions only after verifying endpoint identity, supported action, authorization, and business criticality." }
};

const SOURCE_DEFS = [
  { id: "sysmon", re: /sysmon/i, name: "Microsoft Sysmon", category: "endpoint", event: "process, network, registry, file, image-load, and process-access telemetry", raw: ["EventID", "UtcTime", "Computer", "User", "ProcessGuid", "ProcessId", "Image", "CommandLine", "ParentProcessGuid", "Hashes", "TargetObject", "DestinationIp"], norm: ["@timestamp", "host.id", "user.id", "process.entity_id", "process.executable", "process.command_line", "process.parent.entity_id", "file.hash.sha256", "registry.path", "destination.ip"], maps: ["ECS process/file/registry/network", "CIM Endpoint.Processes", "ASIM ProcessEvent"], products: ["Microsoft Sysmon", "Windows Event Forwarding"] },
  { id: "windows-security", re: /windows.*(?:security|event log)|\bwel\b|domain controller|active directory replication|ad cs|gpo|task scheduler|terminalservices|wmi-activity|bits client|certificationauthority/i, name: "Windows Security and operational logs", category: "endpoint", event: "authentication, process, object-access, directory, service, task, policy, and operational events", raw: ["EventID", "TimeCreated", "Computer", "SubjectUserSid", "SubjectUserName", "TargetUserName", "LogonId", "LogonType", "IpAddress", "ProcessName", "ObjectName", "AccessMask", "Status", "SubStatus"], norm: ["@timestamp", "event.code", "host.id", "user.id", "source.ip", "process.executable", "file.path", "event.outcome", "session.id"], maps: ["ECS authentication/process/file", "CIM Authentication/Endpoint", "ASIM Authentication/ProcessEvent"], products: ["Windows Security", "Windows Event Forwarding", "Microsoft Sentinel"] },
  { id: "powershell", re: /powershell|script block|amsi/i, name: "PowerShell and AMSI telemetry", category: "endpoint", event: "engine, module, script-block, transcription, and antimalware scan events", raw: ["EventID", "Computer", "User", "HostApplication", "EngineVersion", "ScriptBlockId", "ScriptBlockText", "Path", "RunspaceId"], norm: ["@timestamp", "host.id", "user.id", "process.command_line", "script.id", "script.content", "file.path"], maps: ["ECS process/code_signature", "CIM Endpoint.Processes", "ASIM ProcessEvent"], products: ["PowerShell Operational Log", "Microsoft Defender Antivirus AMSI"] },
  { id: "edr", re: /\bedr\b|\bxdr\b|endpoint|apex|kaspersky|trellix|symantec|sepm|sep client|sensor-health|behavioral monitoring|pml|sonar|exploit prevention|host telemetry/i, name: "EDR/XDR telemetry", category: "endpoint", event: "process lineage, file, registry, network, memory, prevention, detection, response, and sensor-health events", raw: ["event_time", "endpoint_id", "hostname", "user", "process_id", "process_path", "command_line", "parent_process", "file_sha256", "signer", "action", "detection_name", "confidence", "sensor_health"], norm: ["@timestamp", "host.id", "user.id", "process.entity_id", "process.executable", "process.command_line", "process.parent.entity_id", "file.hash.sha256", "event.action", "event.outcome"], maps: ["ECS Endpoint", "CIM Endpoint", "ASIM ProcessEvent"], products: ["Microsoft Defender for Endpoint", "CrowdStrike Falcon", "Trend Micro Vision One", "Trellix EDR", "Kaspersky EDR", "Symantec EDR"] },
  { id: "identity", re: /entra|azure ad|identity|authentication|active directory|adfs|iam|ldap|radius|nps|credential|sign-in|okta/i, name: "Identity-provider and directory audit", category: "identity", event: "sign-in, token, session, directory, role, group, application, and authentication-policy events", raw: ["event_time", "principal_id", "user", "source_ip", "device_id", "application", "authentication_method", "result", "failure_reason", "session_id", "token_id", "risk", "location", "role"], norm: ["@timestamp", "user.id", "source.ip", "device.id", "service.name", "event.action", "event.outcome", "session.id", "user.roles"], maps: ["ECS authentication", "CIM Authentication/Change", "ASIM Authentication"], products: ["Microsoft Entra ID", "Okta System Log", "Active Directory", "Ping Identity"] },
  { id: "email", re: /email|mail|exchange|m365|fortimail|cisco esa|message trace/i, name: "Email security and Microsoft 365 audit", category: "email", event: "message trace, delivery, URL, attachment, authentication, user-action, mailbox, and unified audit events", raw: ["event_time", "message_id", "sender", "return_path", "recipient", "subject", "source_ip", "urls", "attachment_name", "attachment_hash", "authentication_results", "delivery_action", "user_action"], norm: ["@timestamp", "email.message_id", "email.from.address", "email.to.address", "source.ip", "url.full", "file.hash.sha256", "event.action", "event.outcome"], maps: ["ECS email", "CIM Email", "ASIM EmailEvent"], products: ["Microsoft 365 Unified Audit Log", "Exchange Message Trace", "FortiMail", "Cisco Secure Email"] },
  { id: "aws-cloudtrail", re: /cloudtrail/i, name: "AWS CloudTrail", category: "cloud", event: "management, data, authentication, IAM, resource, and control-plane API events", raw: ["eventTime", "eventSource", "eventName", "awsRegion", "sourceIPAddress", "userAgent", "userIdentity", "requestParameters", "responseElements", "errorCode", "resources"], norm: ["@timestamp", "cloud.provider", "cloud.region", "user.id", "source.ip", "event.action", "event.outcome", "cloud.resource.id"], maps: ["ECS cloud", "CIM Change/Authentication", "ASIM AuditEvent"], products: ["AWS CloudTrail", "AWS Security Lake"] },
  { id: "aws-guardduty", re: /guardduty/i, name: "AWS GuardDuty", category: "cloud", event: "managed threat findings with affected resource, actor, action, and evidence", raw: ["updatedAt", "type", "severity", "resource", "service.action", "service.additionalInfo", "accountId", "region", "arn"], norm: ["@timestamp", "rule.name", "event.severity", "cloud.account.id", "cloud.region", "cloud.resource.id", "threat.indicator"], maps: ["ECS threat", "CIM Alerts", "ASIM AlertEvent"], products: ["AWS GuardDuty", "AWS Security Hub"] },
  { id: "cloud-audit", re: /azure activity|azure resource|gcp|google workspace|cloud audit|cloud provider|cloud org|cloud storage|cloud billing|cloud image|gke|eks|aks|function execution|instance agent|saas/i, name: "Cloud and SaaS audit", category: "cloud", event: "control-plane, authentication, resource, workload, data-access, configuration, and administrative events", raw: ["event_time", "actor", "principal_id", "source_ip", "user_agent", "action", "resource", "resource_id", "region", "request_parameters", "response_elements", "result", "error_code", "session_id"], norm: ["@timestamp", "cloud.provider", "cloud.account.id", "cloud.region", "user.id", "source.ip", "event.action", "event.outcome", "cloud.resource.id", "session.id"], maps: ["ECS cloud", "CIM Change/Authentication", "ASIM AuditEvent"], products: ["Azure Activity Log", "Azure resource logs", "Google Cloud Audit Logs", "Microsoft 365 Unified Audit Log", "SaaS audit APIs"] },
  { id: "dns", re: /\bdns\b|resolver/i, name: "DNS telemetry", category: "network", event: "query, response, answer, resolver, policy, and registration events", raw: ["event_time", "client_ip", "client_host", "user", "query", "query_type", "response_code", "answers", "resolver", "response_time", "bytes"], norm: ["@timestamp", "source.ip", "host.id", "user.id", "dns.question.name", "dns.question.type", "dns.response_code", "dns.answers"], maps: ["ECS DNS", "CIM Network Resolution", "ASIM Dns"], products: ["Windows DNS Server", "Infoblox", "BIND", "Protective DNS"] },
  { id: "dhcp", re: /dhcp/i, name: "DHCP telemetry", category: "network", event: "lease, reservation, assignment, renewal, and client-identity events", raw: ["event_time", "client_ip", "client_mac", "hostname", "lease_id", "server", "action", "result"], norm: ["@timestamp", "source.ip", "source.mac", "host.hostname", "event.action", "event.outcome"], maps: ["ECS host/network", "CIM Network Sessions", "ASIM DhcpEvent"], products: ["Windows DHCP", "Infoblox DHCP", "network appliance DHCP"] },
  { id: "vpn", re: /vpn|remote access|rd gateway|citrix|vdi|rdp/i, name: "VPN and remote-access audit", category: "network", event: "authentication, session, posture, assigned address, tunnel, and administrative events", raw: ["event_time", "user", "source_ip", "assigned_ip", "device_id", "gateway", "authentication_method", "session_id", "duration", "bytes_in", "bytes_out", "result"], norm: ["@timestamp", "user.id", "source.ip", "host.id", "observer.name", "session.id", "event.outcome", "network.bytes"], maps: ["ECS authentication/network", "CIM Authentication/Network Sessions", "ASIM Authentication"], products: ["Palo Alto GlobalProtect", "Cisco Secure Client", "Fortinet FortiGate VPN", "Microsoft RD Gateway"] },
  { id: "firewall", re: /firewall|switch|network device syslog|perimeter|egress/i, name: "Firewall and network-device logs", category: "network", event: "connection, policy, deny/allow, NAT, administrative, and configuration events", raw: ["event_time", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "action", "rule", "bytes_in", "bytes_out", "device", "administrator"], norm: ["@timestamp", "source.ip", "source.port", "destination.ip", "destination.port", "network.transport", "event.action", "rule.name", "network.bytes", "observer.name"], maps: ["ECS network", "CIM Network Traffic", "ASIM NetworkSession"], products: ["Palo Alto Networks", "Cisco Secure Firewall", "Fortinet FortiGate", "cloud firewalls"] },
  { id: "ndr", re: /\bndr\b|netflow|protocol telemetry|zeek|packet|network flow/i, name: "NDR and network-flow telemetry", category: "network", event: "flow, protocol, connection, anomaly, DNS, HTTP, TLS, and sensor events", raw: ["flow_start", "flow_end", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "direction", "bytes_in", "bytes_out", "packets", "sensor", "dns", "http", "tls"], norm: ["@timestamp", "source.ip", "source.port", "destination.ip", "destination.port", "network.transport", "network.direction", "network.bytes", "observer.name", "tls.server.x509.subject.common_name"], maps: ["ECS network", "CIM Network Traffic", "ASIM NetworkSession"], products: ["Zeek", "Vectra AI", "ExtraHop", "Corelight", "NetFlow/IPFIX"] },
  { id: "ids-ips", re: /ids|ips|wips|network ips|vulnerability protection/i, name: "IDS/IPS telemetry", category: "network", event: "signature, exploit, protocol, policy, prevention, and affected-flow events", raw: ["event_time", "signature_id", "signature_name", "severity", "source_ip", "destination_ip", "destination_port", "protocol", "action", "sensor", "rule_version"], norm: ["@timestamp", "rule.id", "rule.name", "event.severity", "source.ip", "destination.ip", "destination.port", "network.transport", "event.action", "observer.name"], maps: ["ECS intrusion_detection", "CIM Intrusion Detection", "ASIM AlertEvent"], products: ["Suricata", "Snort", "network IPS", "EDR network protection"] },
  { id: "proxy", re: /proxy|web filter|secure web|casb|tls-inspection|url filtering|cdn/i, name: "Secure web gateway, proxy, and CASB", category: "network", event: "request, URL, TLS, category, upload/download, policy, user, and response events", raw: ["event_time", "user", "source_ip", "host", "url", "method", "status", "request_bytes", "response_bytes", "user_agent", "category", "action", "tls_server_name"], norm: ["@timestamp", "user.id", "source.ip", "host.hostname", "url.full", "http.request.method", "http.response.status_code", "http.request.bytes", "http.response.bytes", "user_agent.original", "event.action"], maps: ["ECS HTTP/URL", "CIM Web", "ASIM WebSession"], products: ["Zscaler", "Netskope", "Microsoft Defender for Cloud Apps", "Blue Coat/Symantec Proxy"] },
  { id: "waf-app", re: /\bwaf\b|web server|application logs|edge|api gateway|app telemetry/i, name: "WAF, application, and API gateway logs", category: "application", event: "request, route, authentication, policy, exception, response, and application audit events", raw: ["event_time", "request_id", "source_ip", "user", "method", "host", "path", "query", "status", "bytes", "user_agent", "rule", "application", "resource"], norm: ["@timestamp", "trace.id", "source.ip", "user.id", "http.request.method", "url.path", "http.response.status_code", "http.response.bytes", "rule.name", "service.name"], maps: ["ECS HTTP/Tracing", "CIM Web", "ASIM WebSession"], products: ["AWS WAF", "Azure Web Application Firewall", "Cloudflare", "application/API audit logs"] },
  { id: "linux-audit", re: /linux|auditd|journald|auth\.log|unix/i, name: "Linux audit and authentication logs", category: "endpoint", event: "syscall, execution, file, identity, authentication, service, and kernel audit events", raw: ["event_time", "host", "uid", "euid", "auid", "session", "executable", "command", "arguments", "syscall", "path", "inode", "source_ip", "result"], norm: ["@timestamp", "host.id", "user.id", "user.effective.id", "session.id", "process.executable", "process.command_line", "event.action", "file.path", "source.ip", "event.outcome"], maps: ["ECS process/file/authentication", "CIM Endpoint/Authentication", "ASIM ProcessEvent"], products: ["Linux auditd", "systemd journal", "Linux authentication logs"] },
  { id: "macos", re: /macos|unifiedlog|unified log|endpoint security/i, name: "macOS Unified Log and Endpoint Security", category: "endpoint", event: "process, authentication, file, persistence, privacy, signing, and endpoint-security events", raw: ["event_time", "host", "user", "process", "parent_process", "command", "signing_id", "team_id", "file_path", "event_type", "result"], norm: ["@timestamp", "host.id", "user.id", "process.executable", "process.parent.executable", "process.command_line", "code_signature.subject_name", "file.path", "event.action", "event.outcome"], maps: ["ECS Endpoint", "CIM Endpoint", "ASIM ProcessEvent"], products: ["macOS Unified Log", "Apple Endpoint Security", "macOS EDR"] },
  { id: "kubernetes", re: /kubernetes|gke|eks|aks|cluster/i, name: "Kubernetes audit", category: "container", event: "API request, admission, RBAC, workload, exec, secret, and cluster-administration events", raw: ["event_time", "cluster", "actor", "source_ip", "verb", "resource", "namespace", "name", "request_object", "response_status", "service_account", "audit_id"], norm: ["@timestamp", "orchestrator.cluster.id", "user.id", "source.ip", "event.action", "orchestrator.resource.type", "kubernetes.namespace", "kubernetes.pod.name", "event.outcome", "trace.id"], maps: ["ECS orchestrator", "CIM Change", "ASIM AuditEvent"], products: ["Kubernetes API audit", "Amazon EKS", "Azure Kubernetes Service", "Google Kubernetes Engine"] },
  { id: "container-runtime", re: /container runtime|docker|container daemon|image scanning|container registry/i, name: "Container runtime and registry telemetry", category: "container", event: "container create/start/exec, image pull/push, runtime, daemon, registry, and admission events", raw: ["event_time", "cluster", "host", "container_id", "image", "image_digest", "command", "user", "namespace", "pod", "action", "result"], norm: ["@timestamp", "host.id", "container.id", "container.image.name", "container.image.hash.all", "process.command_line", "user.id", "event.action", "event.outcome"], maps: ["ECS container", "CIM Endpoint", "ASIM ProcessEvent"], products: ["containerd", "Docker", "CRI-O", "Falco", "cloud workload protection"] },
  { id: "data-audit", re: /\bdlp\b|file integrity|file access|storage|sharepoint|drive|database|sql|oracle|device control|usb/i, name: "File, DLP, storage, and database audit", category: "data", event: "file, object, record, export, sharing, device, classification, and data-access events", raw: ["event_time", "user", "host", "process", "object_path", "operation", "bytes", "classification", "owner", "source", "destination", "database", "statement", "rows", "result"], norm: ["@timestamp", "user.id", "host.id", "process.executable", "file.path", "event.action", "file.size", "data_stream.dataset", "source.address", "destination.address", "event.outcome"], maps: ["ECS file/database", "CIM Data Access", "ASIM FileEvent"], products: ["Microsoft Purview DLP", "database audit", "file integrity monitoring", "SaaS storage audit"] },
  { id: "security-control", re: /security-product|anti-virus|antivirus|sandbox|detonation|atd|threat prevention|download insight|auto-protect|hips|tamper|boot\/state|device integrity|firmware|uefi/i, name: "Security-control and workload-protection telemetry", category: "security_control", event: "detection, prevention, quarantine, policy, exclusion, health, integrity, scan, sandbox, and remediation events", raw: ["event_time", "product", "sensor_id", "host", "user", "detection", "severity", "confidence", "action", "result", "policy", "rule_version", "object", "hash", "health"], norm: ["@timestamp", "observer.product", "agent.id", "host.id", "user.id", "rule.name", "event.severity", "event.action", "event.outcome", "file.hash.sha256"], maps: ["ECS Alert/Endpoint", "CIM Alerts", "ASIM AlertEvent"], products: ["EDR/EPP", "cloud workload protection", "sandbox", "firmware and platform monitoring"] },
  { id: "siem-soar", re: /siem|soar|console access|case|help desk|ticketing/i, name: "SIEM, SOAR, and case audit", category: "case_management", event: "normalized event, analytic, alert, correlation, case, analyst, and response-action records", raw: ["event_time", "ingest_time", "source_type", "event_id", "event_category", "actor", "target", "action", "outcome", "entity_ids", "rule_version", "correlation_id", "case_id"], norm: ["@timestamp", "event.ingested", "event.dataset", "event.code", "event.category", "user.id", "event.action", "event.outcome", "related.hosts", "rule.version", "trace.id"], maps: ["ECS event/rule", "CIM Alerts", "ASIM AlertEvent"], products: ["Microsoft Sentinel", "Splunk Enterprise Security", "Elastic Security", "QRadar", "SOAR/case platform"] },
  { id: "threat-intel", re: /threat intel|dark-web|certificate transparency|\bct\b|easm|shodan|censys|brand|paste|osint|newly-registered|partner comms|cisa kev|epss/i, name: "Threat intelligence and external exposure", category: "threat_intel", event: "indicator, infrastructure, certificate, exposure, reputation, campaign, and source-provenance records", raw: ["observed_at", "indicator", "indicator_type", "source", "confidence", "first_seen", "last_seen", "owner", "registrant", "certificate", "exposure", "campaign"], norm: ["@timestamp", "threat.indicator.name", "threat.indicator.type", "threat.feed.name", "threat.indicator.confidence", "threat.indicator.first_seen", "threat.indicator.last_seen"], maps: ["ECS threat", "CIM Threat Intelligence", "ASIM AlertEvent"], products: ["MISP", "OpenCTI", "exposure-management", "certificate-transparency monitoring"] },
  { id: "generic-audit", re: /.*/, name: "Normalized security audit", category: "other", event: "actor, action, target, result, chronology, and source-health events relevant to the behavior", raw: ["event_time", "ingest_time", "source_type", "event_id", "host", "asset_id", "user", "principal_id", "source_ip", "destination_ip", "action", "target", "outcome", "process_id", "session_id", "correlation_id"], norm: ["@timestamp", "event.ingested", "event.dataset", "event.code", "host.id", "user.id", "source.ip", "destination.ip", "event.action", "event.outcome", "process.entity_id", "session.id", "trace.id"], maps: ["ECS event", "CIM normalized data model", "ASIM normalized schema"], products: ["SIEM connector", "platform-native audit log"] }
];

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? resolve(process.argv[index + 1]) : fallback;
}

function fix(value) {
  let output = String(value ?? "");
  for (const [bad, good] of MOJIBAKE) output = output.replaceAll(bad, good);
  return output
    .replace(/\b(?:TODO|TBD|FIXME|add content here|placeholder text|coming soon)\b/gi, "not documented in the supplied source")
    .replace(/\u00a0/g, " ");
}

function decode(value) {
  return fix(value)
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/&#x([0-9a-f]+);/gi, (_, code) => String.fromCodePoint(parseInt(code, 16)))
    .replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(Number(code)))
    .replace(/&(amp|lt|gt|quot|apos|nbsp|reg);/gi, (_, name) => ({ amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", reg: "®" })[name.toLowerCase()]);
}

function clean(value, preserveLines = false) {
  const output = decode(String(value ?? "").replace(/<[^>]+>/g, " "));
  if (preserveLines) return output.split(/\r?\n/).map(line => line.replace(/[ \t]+/g, " ").trim()).join("\n").replace(/\n{3,}/g, "\n\n").trim();
  return output.replace(/\s+/g, " ").trim();
}

function slug(value) {
  return clean(value).normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "section";
}

function sha(value) { return createHash("sha256").update(value, "utf8").digest("hex"); }
function uniq(values) {
  const seen = new Set();
  return values.filter(Boolean).filter(value => {
    const key = typeof value === "string" ? value.toLowerCase() : JSON.stringify(value);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
function escCsv(value) { const text = String(value ?? ""); const safe = /^[\t\r ]*[=+\-@]/.test(text) ? `'${text}` : text; return /[",\r\n]/.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe; }

function parseTable(html) {
  const rows = [...html.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)].map(match => [...match[1].matchAll(/<t[hd]\b[^>]*>([\s\S]*?)<\/t[hd]>/gi)].map(cell => clean(cell[1]))).filter(row => row.length);
  if (!rows.length) return null;
  const headers = rows[0].map((label, index) => ({ key: `${slug(label)}-${index + 1}`, label: label || `Column ${index + 1}` }));
  const dataRows = rows.slice(1).map(row => Object.fromEntries(headers.map((column, index) => [column.key, row[index] || ""])));
  return { type: "table", columns: headers, rows: dataRows };
}

function parseSections(html) {
  const source = fix(html);
  const headings = [...source.matchAll(/<h3\b[^>]*>([\s\S]*?)<\/h3>/gi)];
  return headings.map((match, index) => {
    const title = clean(match[1]).replace(/^\d+\.\s*/, "");
    const body = source.slice(match.index + match[0].length, headings[index + 1]?.index ?? source.length);
    const blocks = [];
    let skip = false;
    for (const token of body.matchAll(/<(h4|p|pre|ol|ul|table)\b[^>]*>([\s\S]*?)<\/\1>/gi)) {
      const type = token[1].toLowerCase();
      if (type === "h4") {
        const text = clean(token[2]);
        skip = OMIT_HEADINGS.has(text.toLowerCase());
        if (!skip && text) blocks.push({ type: "heading", level: 3, text });
        continue;
      }
      if (skip) continue;
      if (type === "p") {
        const strong = token[2].match(/<strong\b[^>]*>([\s\S]*?)<\/strong>\s*:?\s*([\s\S]*)/i);
        if (strong) blocks.push({ type: "key_value", items: [{ label: clean(strong[1]).replace(/:$/, ""), value: clean(strong[2]) }] });
        else if (clean(token[2])) blocks.push({ type: "paragraph", text: clean(token[2]) });
      } else if (type === "pre") {
        const code = clean(token[2].replace(/<\/?code\b[^>]*>/gi, ""), true);
        if (code) blocks.push({ type: "code", language: "text", code, caption: "Vendor-neutral source guidance; adapt and validate before deployment." });
      } else if (type === "ol" || type === "ul") {
        const items = [...token[2].matchAll(/<li\b[^>]*>([\s\S]*?)<\/li>/gi)].map(item => clean(item[1])).filter(Boolean);
        if (items.length) blocks.push({ type: "list", ordered: type === "ol", items });
      } else {
        const table = parseTable(token[2]);
        if (table) blocks.push(table);
      }
    }
    return { id: `${index + 1}-${slug(title)}`, title: title || `Section ${index + 1}`, order: index + 1, blocks };
  }).filter(section => section.blocks.length);
}

function section(sections, pattern) { return sections.find(item => pattern.test(item.title)); }
function blockText(block) {
  if (!block) return "";
  if (block.type === "heading" || block.type === "paragraph") return block.text || "";
  if (block.type === "code") return block.code || "";
  if (block.type === "list") return (block.items || []).join(" ");
  if (block.type === "key_value") return (block.items || []).map(item => `${item.label}: ${item.value}`).join(" ");
  if (block.type === "table") return (block.rows || []).flatMap(row => Object.values(row)).join(" ");
  return "";
}

function descriptionFrom(sections, fallback) {
  const mapping = section(sections, /technique mapping|overview|platform/i) || sections[0];
  const blocks = mapping?.blocks || [];
  const technical = blocks.findIndex(block => block.type === "heading" && /technical description|description|purpose/i.test(block.text));
  const paragraph = technical >= 0 ? blocks.slice(technical + 1).find(block => block.type === "paragraph") : blocks.find(block => block.type === "paragraph");
  const text = paragraph?.text || `Operational detection and incident-response guidance for ${fallback}.`;
  return text.length >= 40 ? text.slice(0, 5000) : `${text} This playbook defines the telemetry, detection, investigation, containment, recovery, and validation evidence required for safe operational use.`;
}

function groupsFromLogSection(sections) {
  const log = section(sections, /log source mapping/i);
  const groups = [];
  let current;
  for (const block of log?.blocks || []) {
    if (block.type === "heading") {
      current = { heading: block.text, blocks: [] };
      groups.push(current);
    } else if (current) current.blocks.push(block);
  }
  return groups;
}

function sourceMatches(label) {
  const matches = SOURCE_DEFS.slice(0, -1).filter(def => def.re.test(label));
  return matches.length ? matches : [SOURCE_DEFS.at(-1)];
}

function extractEventIds(text, sourceName) {
  const ids = new Set();
  for (const match of text.matchAll(/(?:event(?:\s+id)?s?|eid)\s*(?:id)?\s*[:#]?\s*([0-9][0-9\s,\/\-]{0,80})/gi)) {
    for (const id of match[1].match(/\b\d{1,5}\b/g) || []) ids.add(id);
  }
  return [...ids].slice(0, 30).map(id => ({ provider: sourceName, id, description: "Identifier extracted from the supplied v3 mapping; confirm the channel and audit policy in the target environment.", provenance: "legacy-authored-unverified" }));
}

function inferredSourceIds(tactic, name) {
  const value = `${tactic} ${name}`;
  if (/Reconnaissance|Resource Development/.test(tactic)) return ["threat-intel", "dns", "waf-app", "siem-soar"];
  if (/Command and Control|Exfiltration/.test(tactic)) return ["ndr", "dns", "proxy", "firewall", "edr", "siem-soar"];
  if (/Initial Access/.test(tactic)) return /phish|email/i.test(value) ? ["email", "identity", "proxy", "edr", "siem-soar"] : ["waf-app", "firewall", "edr", "identity", "siem-soar"];
  if (/Credential Access|Privilege Escalation|Lateral Movement/.test(tactic)) return ["edr", "windows-security", "identity", "ndr", "siem-soar"];
  if (/Stealth|Defense Impairment/.test(tactic)) return ["edr", "security-control", "windows-security", "siem-soar"];
  if (/Collection/.test(tactic)) return ["data-audit", "edr", "identity", "siem-soar"];
  if (/Impact/.test(tactic)) return ["edr", "security-control", "data-audit", "identity", "siem-soar"];
  return ["edr", "windows-security", "linux-audit", "siem-soar"];
}

function telemetryFor(playbook, sections, tactic) {
  const groups = groupsFromLogSection(sections);
  const selected = new Map();
  for (const group of groups) {
    const text = group.blocks.map(blockText).join(" ");
    for (const def of sourceMatches(`${group.heading} ${text}`)) {
      if (selected.has(def.id)) continue;
      selected.set(def.id, { def, heading: group.heading, text });
    }
  }
  if (!selected.size || (selected.size === 1 && selected.has("siem-soar"))) {
    for (const id of inferredSourceIds(tactic, playbook.name)) {
      const def = SOURCE_DEFS.find(item => item.id === id);
      if (def && !selected.has(id)) selected.set(id, { def, heading: def.name, text: "Compensating source inferred from the behavior and tactic; confirm applicability." });
    }
  }
  const ordered = [...selected.values()];
  let primaryAssigned = false;
  return ordered.slice(0, 8).map(({ def, heading, text }, index) => {
    const tier = !primaryAssigned && def.id !== "siem-soar" ? (primaryAssigned = true, "required") : index < 4 ? "recommended" : def.id === "siem-soar" ? "recommended" : "optional";
    const relevance = text.match(/Detection Relevance:\s*([^]+?)(?:Investigation Relevance:|$)/i)?.[1]?.trim() || `${def.name} provides evidence needed to identify or corroborate ${playbook.name}.`;
    return {
      id: def.id,
      source_name: def.name,
      source_heading: heading,
      category: def.category,
      tier,
      priority: tier,
      event_types: [def.event],
      event_ids: extractEventIds(text, heading),
      raw_fields: def.raw,
      normalized_fields: def.norm,
      mappings: def.maps,
      correlation_fields: ["identity: user.id or principal_id", "asset: host.id, device.id, cloud.resource.id", "process: process.entity_id and parent entity", "session: session.id, logon_id, token_id", "network: source/destination address, port, protocol, request_id", "cloud: account, tenant, region, resource identifier"],
      retention: /identity|cloud|data/.test(def.category) ? "90 days searchable and at least 365 days policy-aligned archive" : "30 days searchable and at least 180 days policy-aligned archive",
      latency: tier === "required" ? "Target under 5 minutes; alert when the 15-minute maximum is exceeded" : "Target under 15 minutes with monitored delay percentiles",
      prerequisites: [`Enable and scope ${def.name} collection on every relevant asset or tenant.`, "Retain immutable raw-event references and document excluded assets."],
      audit_policy: ["Enable the platform audit policy and required event categories before relying on this source.", "Record connector, parser, schema, and policy versions."],
      blind_spots: [TACTIC_PROFILE[tactic]?.gap || TACTIC_PROFILE.Operational.gap, `The supplied ${heading} mapping is inherited and must be validated against the deployed product version.`],
      data_quality: ["At least 95% population for mandatory time, actor, asset, action, target, outcome, and correlation fields.", "Alert on parser errors, duplicates, truncation, volume discontinuities, and ingestion delay."],
      time_sync: ["Normalize to UTC, retain original timezone, and monitor source clock drift against NTP."],
      normalization: ["Preserve raw values alongside normalized ECS, CIM, or ASIM fields; do not overwrite immutable identifiers."],
      health: ["Monitor connector heartbeat, last event time, delay percentiles, parser failures, and per-source volume."],
      example_products: def.products,
      detection_relevance: [relevance.slice(0, 1000)],
      investigation_relevance: [`Use ${def.name} to pivot on the actor, asset, process or session, target, and chronology associated with ${playbook.id}.`],
      evidence_value: [tier === "required" ? "Primary evidence when raw records and collection health are preserved." : "Corroborating or compensating evidence; do not treat source absence as proof of benign activity."]
    };
  });
}

function currentTactics(playbook) {
  if (playbook.kind !== "technique") return { tactics: [], mappings: [] };
  const output = [];
  const mappings = [];
  for (const old of playbook.tactics || []) {
    let tactic = old;
    let verified = true;
    let provenance = "legacy-v3-preserved";
    if (old === "Defense Evasion") {
      verified = false;
      provenance = "v19.1-migration-inference-review-required";
      tactic = /impair|disable|inhibit|firewall|logging|security software|defense|endpoint protection|safe mode|downgrade/i.test(playbook.name) ? "Defense Impairment" : "Stealth";
    }
    if (playbook.id === "T1562") tactic = "Defense Impairment";
    if (playbook.id === "T1656") tactic = "Stealth";
    if (!output.includes(tactic)) output.push(tactic);
    mappings.push({ tactic, legacy_tactic: old === tactic ? null : old, provenance, verified, note: verified ? "Mapping preserved from the supplied source." : "ATT&CK v19.1 split Defense Evasion; this inferred assignment requires authoritative review." });
  }
  if (!output.length && playbook.kind === "technique") {
    output.push("Stealth");
    mappings.push({ tactic: "Stealth", legacy_tactic: null, provenance: "migration-fallback-review-required", verified: false, note: "The supplied record lacked a tactic mapping." });
  }
  return { tactics: output, mappings };
}

function parseSubtechniques(value) {
  const text = clean(value);
  if (!text || /^none$/i.test(text)) return [];
  const matches = [...text.matchAll(/(T\d{4}\.\d{3})\s*(?:\(([^)]+)\)|[-–—:]?\s*([^,;·]+))/g)];
  return matches.map(match => ({ id: match[1], name: clean(match[2] || match[3] || match[1]), relationship: "in_scope", provenance: "legacy-v3" }));
}

function inferPlatforms(playbook, sections, telemetry) {
  const haystack = clean(`${playbook.name} ${(playbook.platforms || []).join(" ")} ${sections.flatMap(item => item.blocks.map(blockText)).join(" ")} ${telemetry.map(item => item.source_name).join(" ")}`);
  const rules = [[/windows|sysmon|powershell|active directory|lsass|registry/i, "Windows"], [/linux|auditd|systemd|bash|cron/i, "Linux"], [/macos|osx|launchd|unified log/i, "macOS"], [/kubernetes|container|docker|pod/i, "Containers"], [/aws|azure|gcp|cloudtrail|iaas|cloud resource/i, "IaaS"], [/m365|office|email|saas|entra|google workspace/i, "SaaS"], [/firewall|router|switch|network device|vpn/i, "Network Devices"], [/esxi|vcenter|hypervisor/i, "ESXi"]];
  const platforms = uniq([...(playbook.platforms || []), ...rules.filter(([pattern]) => pattern.test(haystack)).map(([, name]) => name)].map(value => value === "PRE" ? "External" : value));
  if (!platforms.length) platforms.push(/Reconnaissance|Resource Development/.test((playbook.tactics || []).join(" ")) ? "External" : "Cross-platform");
  return platforms;
}

function detectionSource(sections) {
  const detection = section(sections, /detection logic/i);
  const useCases = [];
  const falsePositives = [];
  const tuning = [];
  let heading = "Primary behavioral detection";
  for (const block of detection?.blocks || []) {
    if (block.type === "heading") heading = block.text;
    if (block.type === "code") useCases.push({ title: heading, code: block.code });
    if (block.type === "key_value") for (const item of block.items || []) {
      if (/false positive/i.test(item.label)) falsePositives.push(item.value);
      if (/tuning/i.test(item.label)) tuning.push(item.value);
    }
  }
  return { useCases, falsePositives, tuning };
}

function buildDetection(playbook, tactic, telemetry, source) {
  const profile = TACTIC_PROFILE[tactic] || (playbook.kind === "platform" ? TACTIC_PROFILE.Platform : TACTIC_PROFILE.Operational);
  const primary = source.useCases[0]?.code || `MATCH behavior specific to ${playbook.id} ${playbook.name}\nJOIN actor, asset, process or session, target, result, and chronology\nALERT when the documented risk threshold is crossed.`;
  const common = {
    primary_logic: source.useCases.map(item => `${item.title}: ${item.code.split(/\n/)[0]}`).slice(0, 6),
    supporting_signals: telemetry.map(item => item.detection_relevance[0]),
    event_sequence: [`Observe the ${playbook.name} primary signal.`, "Correlate the same actor, asset, process or session, and target.", "Search for preceding access and following persistence, movement, collection, control, exfiltration, or impact."],
    aggregation: `Group stable entities within ${profile.window}; retain first seen, last seen, count, and immutable raw references.`,
    correlation_keys: uniq(telemetry.flatMap(item => item.correlation_fields)),
    window: profile.window,
    baseline: "Compare with the same entity, role, asset class, approved change window, signer, process ancestry, and peer group over at least 30 days where history exists.",
    thresholds: "Start in shadow mode; set thresholds from reviewed history and require corroboration for high-impact actions rather than using a universal count.",
    entity_grouping: "Group by actor plus asset and process/session; separate unrelated tenants, customers, and network zones.",
    risk_scoring: `Base ${profile.severity} risk; add weight for privilege, critical assets, prevention failure, novelty, repetition, threat intelligence, and adjacent techniques.`,
    suppression: "Suppress only an exact approved combination of actor, asset, executable/application, action, target, and bounded change window with owner and expiry.",
    deduplication: "Deduplicate identical rule-version/entity/evidence combinations while preserving the first, last, and total event count.",
    alert_grouping: "Group related signals into one case by stable entities and incident window; do not merge separate customers or independent assets solely by technique ID.",
    dependencies: telemetry.map(item => item.id)
  };
  const strategies = (source.useCases.length ? source.useCases : [{ title: "Primary behavior", code: primary }]).slice(0, 6).map((item, index) => ({
    id: `strategy-${index + 1}`,
    title: item.title,
    maturity_level: Math.min(4, index + 1),
    primary_signals: [item.code.split(/\n/).filter(Boolean)[0]],
    supporting_signals: common.supporting_signals.slice(0, 4),
    sequence: common.event_sequence,
    correlation_keys: common.correlation_keys,
    window: profile.window,
    aggregation: common.aggregation,
    baseline: common.baseline,
    thresholds: [{ metric: "risk_score", operator: ">=", value: profile.severity === "critical" ? 80 : profile.severity === "high" ? 70 : 55, unit: "0-100", rationale: "Initial deployment value; calibrate with reviewed historical data and documented risk tolerance." }],
    grouping_keys: ["actor", "asset", "process_or_session", "target"],
    risk_scoring: { base: profile.severity === "critical" ? 70 : profile.severity === "high" ? 55 : 40, alert_threshold: profile.severity === "critical" ? 80 : profile.severity === "high" ? 70 : 55, modifiers: ["privileged identity +15", "critical asset +15", "prevention failed +15", "approved exact change -25"] },
    suppression: { safe: ["Exact signed binary, expected parent, approved actor, expected asset, and active change record"], unsafe: ["Filename-only, administrator-only, service-account-only, or subnet-wide exclusions"], expiry_days: 30 },
    telemetry_dependencies: telemetry.map(entry => entry.id),
    pseudocode: item.code
  }));
  return {
    objective: `Identify behavior consistent with ${playbook.id} ${playbook.name} with enough actor, asset, process or session, target, outcome, and chronology evidence for an analyst to validate the alert without reconstructing basic context.`,
    hypothesis: `If ${playbook.name} is occurring maliciously, the technique-specific signal will align with related identity, endpoint, network, cloud, application, or data activity on the same entities within ${profile.window} and will not be fully explained by an exact approved change.`,
    strategy: common,
    strategies,
    maturity_levels: [
      `Level 1 — high-recall: match the strongest documented ${playbook.name} signal and include complete entity evidence.`,
      `Level 2 — correlated: join the signal with a second telemetry domain or follow-on behavior on the same entities within ${profile.window}.`,
      `Level 3 — contextual risk: weight privilege, asset criticality, prevalence, prevention result, baseline deviation, and approved changes.`,
      `Level 4 — advanced: evaluate peer-group anomaly, sequence rarity, cross-domain campaign linkage, and detection-health drift with human review.`
    ],
    pseudocode: primary,
    false_positives: (source.falsePositives.length ? source.falsePositives : ["Documented administration, deployment, backup, scanner, monitoring, development, exercise, or recovery activity may resemble part of this behavior."]).map(cause => ({ cause, distinguishing_evidence: "Require the exact actor, asset, parent/process or application, target, signed change or exercise record, expected outcome, and bounded time window." })),
    tuning: {
      safe_exclusions: ["Exact multi-attribute approved activity with an accountable owner and expiry."],
      unsafe_exclusions: ["Broad administrator, service-account, management-server, filename, IP range, or business-hours exclusions."],
      allowlist_keys: ["actor", "asset", "process hash or signed application ID", "parent/process lineage", "target", "change ID", "start and expiry"],
      guidance: source.tuning.length ? source.tuning : ["Baseline peer groups and roles; raise risk for privilege and critical assets; review exception volume and expiry at least monthly."]
    },
    severity: { default: profile.severity, confidence: telemetry.length >= 2 ? "high" : "medium", fidelity: source.useCases.length >= 2 ? "high" : "medium", telemetry_confidence: "medium", risk_score: profile.severity === "critical" ? 85 : profile.severity === "high" ? 75 : 60, modifiers: ["privileged identity", "critical asset", "failed prevention", "confirmed threat intelligence", "adjacent ATT&CK behavior"], escalation_conditions: [`Escalate when ${playbook.name} is confirmed, ongoing, affects privileged or critical entities, defeats prevention, or expands scope.`] }
  };
}

function queriesFor(playbook, source, telemetry) {
  const cases = source.useCases.length ? source.useCases : [{ title: `Detect ${playbook.name}`, code: `MATCH ${playbook.id} technique-specific behavior\nJOIN actor, asset, process or session, target, outcome, and chronology\nWITHIN the documented evaluation window\nALERT when the risk threshold is met.` }];
  return cases.slice(0, 6).map((item, index) => ({
    id: `${playbook.id.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-q${index + 1}`,
    name: item.title,
    title: item.title,
    strategy_id: `strategy-${index + 1}`,
    platform: "vendor_neutral",
    language: "pseudocode",
    maturity_level: Math.min(4, index + 1),
    query: item.code,
    adaptation_required: true,
    assumptions: ["Field names and source tables must be mapped to the target ECS, CIM, ASIM, or product schema."],
    required_fields: uniq(telemetry.flatMap(entry => entry.normalized_fields)).slice(0, 40),
    telemetry_ids: telemetry.map(entry => entry.id),
    limitations: ["This inherited example has not been syntax-validated against a named product or the deployment's parser version."],
    status: "example",
    last_validated: null
  }));
}

function itemsAfterHeading(responseSection, pattern) {
  const blocks = responseSection?.blocks || [];
  let active = false;
  const items = [];
  for (const block of blocks) {
    if (block.type === "heading") {
      active = pattern.test(block.text);
      continue;
    }
    if (active && block.type === "list") items.push(...block.items);
  }
  return uniq(items);
}

function step(action, playbook, telemetry, index, phase) {
  const fields = uniq(telemetry.flatMap(item => item.normalized_fields)).slice(0, 14);
  return {
    id: `${phase}-${index + 1}`,
    title: action.replace(/[.:].*$/, "").slice(0, 120),
    action,
    rationale: `This step helps confirm, scope, or safely resolve ${playbook.id} ${playbook.name} while preserving decision evidence.`,
    systems: uniq(telemetry.map(item => item.source_name)).slice(0, 8),
    fields_or_artifacts: fields,
    suspicious_findings: [`Unapproved or unexplained evidence consistent with ${playbook.name}, especially on privileged identities or critical assets.`],
    legitimate_findings: ["An exact approved change, exercise, deployment, recovery, or administrative workflow with matching actor, asset, target, lineage, and time window."],
    decision: `If evidence supports malicious ${playbook.name}, escalate and expand scope; if evidence supports authorized activity, document the proof and assess whether tuning is safe.`
  };
}

function containmentAction(action, playbook, index, horizon) {
  return {
    id: `${horizon}-${index + 1}`,
    action,
    preconditions: [`Confirm the entity and current evidence for ${playbook.id}; verify the action is supported and authorized.`],
    business_impact: "May interrupt user, endpoint, network, cloud, application, or business-service availability; identify dependencies before execution.",
    approval: horizon === "immediate" ? "Use the approved emergency-response matrix for confirmed high/critical active harm; otherwise obtain incident commander and system-owner approval." : "Incident commander and affected service or identity owner approval is required.",
    evidence_preservation: "Preserve raw events, volatile state, session/process lineage, affected objects, and the response request/result before remediation changes the state.",
    rollback: "Record the prior state and action identifier; restore access or configuration only after independent validation and owner approval.",
    contraindications: "Do not use when the entity is uncertain, the action would create greater safety or availability risk, or volatile evidence must first be captured and no compensating control exists."
  };
}

function responseFor(playbook, sections, telemetry, tactic) {
  const response = section(sections, /incident response/i);
  const triageRaw = itemsAfterHeading(response, /phase\s*1|detection.*triage|initial triage/i);
  const investigationRaw = itemsAfterHeading(response, /phase\s*2|investigation/i);
  const containmentRaw = itemsAfterHeading(response, /phase\s*3|containment/i);
  const eradicationRaw = itemsAfterHeading(response, /phase\s*4|eradication/i);
  const recoveryRaw = itemsAfterHeading(response, /phase\s*5|recovery/i);
  const postRaw = itemsAfterHeading(response, /phase\s*6|lesson|post/i);
  const triage = (triageRaw.length ? triageRaw : [`Validate the ${playbook.name} alert, source health, raw evidence, actor, asset, target, and prevention outcome.`, "Set the initial time range to at least 30 minutes before the first signal through current time and identify related alerts.", "Record identity privilege, asset criticality, confidence, and initial severity."]).map((item, index) => step(item, playbook, telemetry, index, "triage"));
  const investigation = (investigationRaw.length ? investigationRaw : [`Build a process, session, authentication, network, cloud, application, and data timeline for ${playbook.name}.`, "Review parent-child process lineage, persistence, privilege changes, lateral movement, command and control, exfiltration, and impact."]).map((item, index) => step(item, playbook, telemetry, index, "investigation"));
  const scopingRaw = [
    `Identify patient zero and the earliest and latest ${playbook.name} evidence.`,
    "Search all users, hosts, cloud resources, processes, hashes, IP addresses, domains, sessions, credentials, and persistence mechanisms sharing the observed indicators or behavior.",
    "Maintain an entity ledger with suspected, confirmed, contained, eradicated, and recovered status plus evidence and owner.",
    "Hunt for the same behavior across every customer, tenant, network zone, platform, and peer group without assuming the alerting source defines the full scope."
  ];
  const immediate = (containmentRaw.length ? containmentRaw : [TACTIC_PROFILE[tactic]?.action || TACTIC_PROFILE.Operational.action]).slice(0, 8).map((item, index) => containmentAction(item, playbook, index, "immediate"));
  const shortTerm = [
    `Block or restrict confirmed ${playbook.name} infrastructure, identities, sessions, payloads, applications, or access paths using narrowly scoped controls.`,
    "Re-scope after each action and independently verify the requested isolation, revocation, block, quarantine, or policy change actually took effect."
  ].map((item, index) => containmentAction(item, playbook, index, "short-term"));
  const longTerm = [
    `Remove the root access and control weakness that enabled ${playbook.name}; replace temporary blocks with reviewed least-privilege and segmentation controls.`,
    "Retire emergency exceptions after monitoring confirms no recurrence and business owners accept the restored operating state."
  ].map((item, index) => containmentAction(item, playbook, index, "long-term"));
  const eradication = (eradicationRaw.length ? eradicationRaw : ["Remove malicious persistence, files, accounts, keys, roles, policies, and configuration drift; patch the exploited weakness and define reimage criteria.", "Verify removal using independent telemetry and a known-good baseline."]).map((item, index) => step(item, playbook, telemetry, index, "eradication"));
  const recovery = (recoveryRaw.length ? recoveryRaw : ["Restore only from trusted sources; validate credentials, endpoint/workload health, service dependencies, security controls, logging, and business function.", "Define a heightened-monitoring period with owners, queries, recurrence thresholds, and explicit recovery exit criteria."]).map((item, index) => step(item, playbook, telemetry, index, "recovery"));
  const postIncident = (postRaw.length ? postRaw : ["Complete root-cause, lessons-learned, detection-gap, telemetry-gap, and control-gap analysis.", "Retain the timeline and evidence, decide legal/compliance/privacy reporting, extract intelligence and hunts, and assign dated playbook improvements."]).map((item, index) => step(item, playbook, telemetry, index, "post-incident"));
  const escalation = [
    ["SOC Tier 2", "The alert cannot be dispositioned with available evidence, spans multiple entities, or needs broader correlation.", "Immediate"],
    ["SOC Tier 3 / Detection Engineering", "Detection logic, parser behavior, query performance, advanced hunting, or an unknown technique variant requires specialist review.", "Within the investigation target"],
    ["Incident Response / DFIR", `Malicious ${playbook.name} is confirmed, volatile or forensic collection is required, or scope is expanding.`, "Immediate for high/critical"],
    ["Identity / Network / Cloud / Application owner", "A specialist control plane, session, resource, route, or service requires validated containment or restoration.", "Before disruptive action unless emergency authority applies"],
    ["Threat Intelligence", "Infrastructure, campaign, malware, victimology, or attribution context can materially change scope or risk.", "During scoping"],
    ["Legal / Compliance / Privacy", "Regulated data, contractual duties, monitoring restrictions, notification, evidence handling, or material impact may apply.", "As soon as the trigger is credible"],
    ["Management / Business owner", "Critical services, safety, material financial impact, widespread disruption, or significant residual risk is involved.", "Immediate for major incidents"],
    ["Law enforcement", "Only when legal counsel and authorized management approve and organizational policy or jurisdictional obligations support contact.", "Authorized decision only"]
  ].map(([destination, criteria, urgency]) => ({ destination, criteria, urgency }));
  const decisionTree = [
    { condition: `Does raw and correlated evidence confirm ${playbook.name}?`, if_true: "Classify as true positive and scope all linked entities.", if_false: "Document the benign evidence or retain suspicious status and collect the next discriminating source." },
    { condition: "Is actor activity ongoing, privileged, spreading, destructive, or capable of material harm?", if_true: "Use approved immediate containment and incident command.", if_false: "Preserve evidence and perform a bounded investigation before disruptive action." },
    { condition: "Is evidence isolated to one entity after an environment-wide behavioral and indicator search?", if_true: "Continue standard incident handling with recurrence monitoring.", if_false: "Treat as a campaign or major incident and coordinate cross-domain containment." },
    { condition: "Can integrity and access be proven after remediation?", if_true: "Recover with heightened monitoring and owner acceptance.", if_false: "Reimage/rebuild, rotate dependent credentials, or restore from a verified clean source." }
  ];
  const closureCriteria = [
    "Alert disposition and severity rationale are documented with raw evidence references.",
    "Patient zero, affected entities, earliest/latest activity, related indicators, and behavioral variants were scoped.",
    "Root cause is established or explicitly recorded as unknown with residual risk ownership.",
    "Containment, eradication, and recovery are independently verified rather than inferred from console success messages.",
    "Exposed credentials, tokens, keys, roles, applications, and sessions were addressed in dependency-safe order.",
    "Required evidence and the UTC timeline are retained under policy and chain-of-custody requirements.",
    "Required legal, compliance, privacy, management, and business stakeholders made or recorded notification decisions.",
    "Detection, telemetry, parser, control, and playbook improvements have owners and review dates.",
    "Heightened monitoring completed without recurrence or re-escalation triggers.",
    "The accountable owner accepts documented residual risk."
  ].map((criterion, index) => ({ id: `closure-${index + 1}`, criterion, evidence_required: "Case note, query/export, action verification, owner decision, or retained artifact", required: true }));
  return { triage, investigation, scoping: scopingRaw.map((item, index) => step(item, playbook, telemetry, index, "scoping")), containment: { immediate, short_term: shortTerm, long_term: longTerm }, eradication, recovery, post_incident: postIncident, escalation, decision_tree: decisionTree, closure_criteria: closureCriteria };
}

function qualityFor(playbook, telemetry, detectionSourceValue, queries, response, tacticMappings) {
  const weights = {
    attack_mapping: tacticMappings.every(item => item.verified) ? 8 : 6,
    telemetry_specificity: telemetry.length >= 3 ? 18 : telemetry.length === 2 ? 15 : 12,
    detection_implementation: detectionSourceValue.useCases.length ? 15 : 12,
    query_coverage: queries.length ? 5 : 0,
    false_positive_tuning: detectionSourceValue.falsePositives.length || detectionSourceValue.tuning.length ? 7 : 5,
    validation: 6,
    triage: response.triage.length ? 5 : 0,
    investigation: response.investigation.length ? 9 : 0,
    containment: response.containment.immediate.length && response.containment.short_term.length && response.containment.long_term.length ? 8 : 0,
    recovery_closure: response.recovery.length && response.closure_criteria.length ? 6 : 0,
    references: playbook.url ? 2 : 1,
    freshness: 4
  };
  return { breakdown: weights, score: Object.values(weights).reduce((sum, value) => sum + value, 0) };
}

function searchTerms(playbook, sections, telemetry, queries, oldName) {
  const text = sections.flatMap(sectionValue => sectionValue.blocks.map(blockText)).join(" ");
  const artifacts = [
    ...(text.match(/\b[\w.-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|sh|py|dmp|key|pfx|kdbx)\b/gi) || []),
    ...(text.match(/\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s<,;]+/gi) || []),
    ...(text.match(/\b(?:Event\s*(?:ID)?\s*)?\d{3,5}\b/gi) || [])
  ];
  return uniq([playbook.id, playbook.name, oldName, playbook.kind, ...(playbook.tactics || []), ...(playbook.platforms || []), ...telemetry.flatMap(item => [item.id, item.source_name, item.category, ...item.event_ids.map(event => event.id)]), ...queries.flatMap(query => [query.name, query.platform, query.language]), ...artifacts]).slice(0, 500);
}

function migratePlaybook(legacy, index) {
  const oldName = fix(legacy.name);
  const name = NAME_UPDATES.get(legacy.id) || oldName;
  const working = { ...legacy, name };
  const { tactics, mappings } = currentTactics(working);
  working.tactics = tactics;
  const tactic = working.kind === "technique" ? (tactics[0] || "Stealth") : working.kind === "platform" ? "Platform" : "Operational";
  const sections = parseSections(legacy.html || "");
  const telemetry = telemetryFor(working, sections, tactic);
  working.platforms = inferPlatforms(working, sections, telemetry);
  const detectionSourceValue = detectionSource(sections);
  const detection = buildDetection(working, tactic, telemetry, detectionSourceValue);
  const queries = queriesFor(working, detectionSourceValue, telemetry);
  const response = responseFor(working, sections, telemetry, tactic);
  const quality = qualityFor(working, telemetry, detectionSourceValue, queries, response, mappings);
  const deprecated = SUPERSEDED.has(working.id);
  const gaps = uniq([
    TACTIC_PROFILE[tactic]?.gap || TACTIC_PROFILE.Operational.gap,
    ...mappings.filter(item => !item.verified).map(item => item.note),
    "Vendor-neutral query examples require target-platform field mapping, syntax adaptation, performance testing, and peer review.",
    "Validation procedures are documented but no deployment-specific execution evidence or last-validation date was supplied."
  ]);
  const severity = TACTIC_PROFILE[tactic]?.severity || "high";
  const profile = TACTIC_PROFILE[tactic] || TACTIC_PROFILE.Operational;
  const validation = {
    status: "planned",
    safe_method: `On an isolated, authorized non-production asset or tenant, reproduce the least-destructive observable behavior from the ${working.id} detection example; do not access real credentials, disrupt controls, exfiltrate data, or affect production.`,
    atomic_red_team: [],
    atomic_mapping_status: "not verified against the current Atomic Red Team catalog; no test ID is asserted",
    purple_team_tests: [{ id: `${working.id.toLowerCase()}-purple-1`, objective: `Generate the primary ${working.name} signal safely and confirm source-to-alert-to-case evidence.`, safety: "Use synthetic data, bounded accounts, approved infrastructure, and an observer able to stop the exercise." }],
    prerequisites: telemetry.map(item => `${item.source_name} is healthy and mapped to the required normalized fields.`),
    expected_telemetry: telemetry.map(item => `${item.id}: ${item.event_types.join("; ")}`),
    expected_detection: [`One grouped ${working.id} alert containing matched conditions, actor, asset, process/session, target, first/last seen, risk, exclusions, and raw-event references.`],
    negative_tests: detection.false_positives.slice(0, 4).map(item => `Replay authorized ${item.cause}; confirm it is distinguishable without a broad exclusion.`),
    regression_tests: ["Store one positive and at least two negative normalized fixtures; rerun after query, parser, source, operating-system, or product changes."],
    cleanup_steps: ["Remove test files, accounts, sessions, policies, rules, infrastructure, and synthetic indicators; verify the environment returned to the recorded baseline."],
    safety_warnings: ["Obtain written authorization and owner approval. Stop immediately if the test leaves the isolated scope, affects availability, or exposes non-synthetic data."],
    last_validated: null,
    evidence: []
  };
  const aliases = oldName !== name ? [oldName] : [];
  const lifecycleStatus = deprecated ? "deprecated" : "active";
  const record = {
    schema_version: SCHEMA_VERSION,
    id: working.id,
    name,
    kind: working.kind,
    description: descriptionFrom(sections, name),
    tactics,
    tactic_mappings: mappings,
    techniques: working.kind === "technique" ? [{ id: working.id, name, relationship: "primary", url: `https://attack.mitre.org/techniques/${working.id}/`, provenance: deprecated ? "legacy-deprecated" : "attack-v19.1-migration" }] : [],
    subtechniques: parseSubtechniques(legacy.subtechniques),
    platforms: working.platforms,
    data_sources: telemetry.map(item => item.id),
    data_source_summary: telemetry.map(item => `${item.priority}: ${item.source_name}`).join("; "),
    telemetry_requirements: telemetry,
    detection,
    queries,
    validation,
    response,
    lifecycle: {
      version: SCHEMA_VERSION,
      status: lifecycleStatus,
      owner: "SOC Detection Engineering owns the analytic; Incident Response owns confirmed incidents; telemetry source owners maintain collection health.",
      review_frequency: ["critical", "high"].includes(severity) ? "Every 90 days and after ATT&CK, source, parser, platform, or material incident changes" : "Every 180 days and after ATT&CK, source, parser, platform, or material incident changes",
      last_reviewed: TODAY,
      next_review: ["critical", "high"].includes(severity) ? "2026-10-10" : "2027-01-08",
      last_validation_date: null,
      data_source_dependencies: telemetry.map(item => item.id),
      known_gaps: gaps,
      change_history: [{ version: SCHEMA_VERSION, date: TODAY, summary: "Migrated legacy HTML to a structured, text-only detection and response contract with explicit provenance and quality scoring.", author_role: "Security content migration" }],
      performance_considerations: [`Bound ${profile.window}; filter on indexed time/entity fields before enrichment; measure event-to-alert delay, result volume, memory, and repeated-entity cardinality in shadow mode.`],
      deployment_prerequisites: ["Required telemetry readiness gates pass.", "Query and field mapping receive peer review.", "Positive and negative fixtures pass.", "Alert evidence, severity, ownership, runbook, suppression expiry, and rollback are configured."],
      rollback_guidance: ["Disable or revert the analytic to the prior version, preserve generated alerts, document the reason and time, and keep source collection active while corrections are tested."],
      superseded_by: SUPERSEDED.get(working.id) || null
    },
    references: legacy.url ? [{ title: `MITRE ATT&CK ${working.id}`, url: legacy.url.replace(/\/?$/, "/"), type: "authoritative", accessed_at: TODAY }] : [],
    tags: uniq([working.kind, ...tactics, ...working.platforms, ...telemetry.map(item => item.category), deprecated ? "deprecated" : "active", "detection-engineering", "incident-response"]),
    severity,
    confidence: telemetry.length >= 2 && detectionSourceValue.useCases.length ? "high" : "medium",
    maturity: 3,
    status: lifecycleStatus,
    quality_score: quality.score,
    quality_breakdown: quality.breakdown,
    coverage: {
      attack_mapping_complete: mappings.length > 0,
      attack_mapping_verified: mappings.every(item => item.verified),
      telemetry_readiness: "partial",
      required_telemetry: telemetry.filter(item => item.tier === "required").length,
      recommended_telemetry: telemetry.filter(item => item.tier === "recommended").length,
      optional_telemetry: telemetry.filter(item => item.tier === "optional").length,
      compensating_telemetry: telemetry.filter(item => item.tier === "compensating").length,
      query_platforms: uniq(queries.map(query => query.platform)),
      validation_status: validation.status,
      response_phases_present: Object.keys(response),
      response_completeness_percent: 100,
      assumptions: ["Top-level platforms may combine supplied values with content-based inference; verify against the current ATT&CK object and deployed environment."],
      gap_count: gaps.length
    },
    known_gaps: gaps,
    content_sections: sections,
    search_terms: [],
    aliases,
    url: legacy.url || null,
    legacy: { source_version: "3.0.0", html_sha256: sha(legacy.html || ""), migration_status: "converted-to-structured-text", original_name: oldName, superseded_by: SUPERSEDED.get(working.id) || null }
  };
  record.search_terms = searchTerms(record, sections, telemetry, queries, oldName);
  if (record.search_terms.length < 3) record.search_terms.push(record.kind, ...record.tactics);
  return record;
}

function qualityReport(data) {
  const playbooks = data.playbooks;
  const scores = playbooks.map(item => item.quality_score);
  const report = {
    schema_version: SCHEMA_VERSION,
    generated: TODAY,
    total_playbooks: playbooks.length,
    playbooks_enhanced: playbooks.filter(item => item.telemetry_requirements.length && item.queries.length && item.validation && item.response.closure_criteria.length).length,
    telemetry_mappings: playbooks.reduce((sum, item) => sum + item.telemetry_requirements.length, 0),
    queries: playbooks.reduce((sum, item) => sum + item.queries.length, 0),
    validation_procedures: playbooks.filter(item => item.validation?.safe_method).length,
    response_workflows_complete: playbooks.filter(item => item.coverage.response_completeness_percent === 100).length,
    average_quality_score: Math.round((scores.reduce((sum, value) => sum + value, 0) / scores.length) * 10) / 10,
    minimum_quality_score: Math.min(...scores),
    maximum_quality_score: Math.max(...scores),
    validation_status: Object.fromEntries([...new Set(playbooks.map(item => item.validation.status))].map(status => [status, playbooks.filter(item => item.validation.status === status).length])),
    telemetry_readiness: Object.fromEntries([...new Set(playbooks.map(item => item.coverage.telemetry_readiness))].map(status => [status, playbooks.filter(item => item.coverage.telemetry_readiness === status).length])),
    unverified_attack_mappings: playbooks.filter(item => !item.coverage.attack_mapping_verified).map(item => item.id),
    deprecated_playbooks: playbooks.filter(item => item.status === "deprecated").map(item => ({ id: item.id, superseded_by: item.lifecycle.superseded_by })),
    vendor_specific_query_gap: playbooks.map(item => item.id),
    executed_validation_gap: playbooks.map(item => item.id),
    scoring_model: data.meta.quality_model
  };
  return report;
}

function reportMarkdown(report) {
  return `# Content quality report\n\nGenerated: ${report.generated}\n\n## Summary\n\n| Metric | Value |\n| --- | ---: |\n| Total playbooks | ${report.total_playbooks} |\n| Structurally enhanced | ${report.playbooks_enhanced} |\n| Telemetry mappings | ${report.telemetry_mappings} |\n| Vendor-neutral query examples | ${report.queries} |\n| Safe validation procedures | ${report.validation_procedures} |\n| Complete response workflows | ${report.response_workflows_complete} |\n| Average quality score | ${report.average_quality_score} |\n| Score range | ${report.minimum_quality_score}–${report.maximum_quality_score} |\n\n## Interpretation\n\nAll playbooks contain structured operational guidance. Telemetry readiness remains **partial** until environment-specific collection gates pass. Validation is **planned**, not executed, because the supplied project did not include deployment evidence. Query examples are vendor-neutral and explicitly require field mapping, syntax adaptation, performance testing, and peer review. Scores summarize documented evidence and do not replace analyst judgment.\n\n## ATT&CK migration gaps\n\n${report.unverified_attack_mappings.length} playbooks retain a review-required inferred mapping caused by ATT&CK v19.1 splitting Defense Evasion into Stealth and Defense Impairment. Deprecated legacy IDs are preserved with explicit replacement relationships: ${report.deprecated_playbooks.map(item => `${item.id} → ${item.superseded_by}`).join(", ")}.\n`;
}

function coverageCsv(data) {
  const headers = ["id", "name", "kind", "tactics", "platforms", "severity", "confidence", "maturity", "status", "quality_score", "telemetry_count", "query_count", "validation_status", "response_completeness", "attack_mapping_verified", "last_reviewed"];
  const rows = data.playbooks.map(item => [item.id, item.name, item.kind, item.tactics.join("; "), item.platforms.join("; "), item.severity, item.confidence, item.maturity, item.status, item.quality_score, item.telemetry_requirements.length, item.queries.length, item.validation.status, item.coverage.response_completeness_percent, item.coverage.attack_mapping_verified, item.lifecycle.last_reviewed]);
  return [headers, ...rows].map(row => row.map(escCsv).join(",")).join("\r\n") + "\r\n";
}

function schemaDocument() {
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://example.invalid/attack-playbook-console/playbooks.schema.json",
    title: "ATT&CK Playbook Console v4 dataset",
    type: "object",
    required: ["meta", "playbooks"],
    properties: {
      meta: { type: "object", required: ["schema_version", "content_version", "generated", "counts", "tactic_order", "attack", "quality_model"] },
      playbooks: { type: "array", minItems: 1, items: { $ref: "#/$defs/playbook" } }
    },
    additionalProperties: false,
    $defs: {
      playbook: {
        type: "object",
        required: ["schema_version", "id", "name", "kind", "description", "tactics", "tactic_mappings", "techniques", "subtechniques", "platforms", "data_source_summary", "telemetry_requirements", "detection", "queries", "validation", "response", "lifecycle", "tags", "severity", "confidence", "maturity", "status", "quality_score", "quality_breakdown", "coverage", "content_sections", "search_terms"],
        properties: {
          schema_version: { const: SCHEMA_VERSION }, id: { type: "string" }, name: { type: "string" }, kind: { enum: ["technique", "operational", "platform"] }, description: { type: "string", minLength: 40 },
          tactics: { type: "array", items: { type: "string" } }, tactic_mappings: { type: "array", items: { type: "object" } }, techniques: { type: "array" }, subtechniques: { type: "array" }, platforms: { type: "array", items: { type: "string" } },
          telemetry_requirements: { type: "array", minItems: 1, items: { type: "object", required: ["id", "category", "tier", "priority", "event_types", "raw_fields", "normalized_fields"] } },
          detection: { type: "object", required: ["objective", "hypothesis", "strategy", "strategies", "maturity_levels"] }, queries: { type: "array", minItems: 1 }, validation: { type: "object" }, response: { type: "object" }, lifecycle: { type: "object" },
          severity: { enum: ["informational", "low", "medium", "high", "critical"] }, confidence: { enum: ["low", "medium", "high"] }, maturity: { type: "integer", minimum: 1, maximum: 4 }, status: { enum: ["draft", "testing", "pilot", "active", "production", "deprecated", "retired"] }, quality_score: { type: "number", minimum: 0, maximum: 100 }, quality_breakdown: { type: "object" }, coverage: { type: "object" }, content_sections: { type: "array", minItems: 1 }, search_terms: { type: "array", minItems: 3 }
        }
      }
    }
  };
}

async function main() {
  const input = arg("input", resolve(ROOT, "data/playbooks.json"));
  const output = arg("output", resolve(ROOT, "data/playbooks.json"));
  const reports = arg("reports", resolve(ROOT, "reports"));
  const sourceText = await readFile(input, "utf8");
  const legacy = JSON.parse(sourceText);
  if (!Array.isArray(legacy.playbooks) || !legacy.playbooks.length) throw new Error("Input is not a v3 playbook dataset.");
  if (legacy.meta?.schema_version === SCHEMA_VERSION) throw new Error("Input is already schema v4.0.0; migration requires the original v3 dataset.");
  const playbooks = legacy.playbooks.map(migratePlaybook);
  const counts = { total: playbooks.length, technique: playbooks.filter(item => item.kind === "technique").length, operational: playbooks.filter(item => item.kind === "operational").length, platform: playbooks.filter(item => item.kind === "platform").length };
  const data = {
    meta: {
      schema_version: SCHEMA_VERSION,
      content_version: SCHEMA_VERSION,
      generated: TODAY,
      counts,
      tactic_order: CURRENT_TACTICS,
      attack: {
        domain: "enterprise-attack",
        version: "19.1",
        release_date: "2026-04-28",
        retrieved_at: TODAY,
        source_url: "https://attack.mitre.org/resources/updates/",
        stix_source_url: "https://github.com/mitre-attack/attack-stix-data",
        snapshot_sha256: null,
        mapping_policy: "Canonical name updates and deprecated redirects are verified against v19.1. Defense Evasion split assignments derived from legacy titles are explicitly marked unverified and require authoritative STIX review."
      },
      quality_model: { version: "1.0.0", weights: { attack_mapping: 8, telemetry_specificity: 18, detection_implementation: 15, query_coverage: 8, false_positive_tuning: 7, validation: 8, triage: 5, investigation: 9, containment: 8, recovery_closure: 6, references: 4, freshness: 4 }, note: "The generated score awards partial query, validation, and reference credit until product-specific execution evidence is supplied." },
      migration: { source_version: legacy.meta?.content_version || "3.0.0", source_sha256: sha(sourceText), source_playbooks: legacy.playbooks.length, structured_playbooks: playbooks.length, html_runtime_removed: true },
      notices: ["Quality scores summarize documented coverage and do not replace analyst judgment.", "Example queries and inherited event identifiers require environment-specific validation before production use."]
    },
    playbooks
  };
  const report = qualityReport(data);
  data.meta.quality_summary = { average: report.average_quality_score, minimum: report.minimum_quality_score, maximum: report.maximum_quality_score, validation_status: report.validation_status, telemetry_readiness: report.telemetry_readiness };
  await mkdir(dirname(output), { recursive: true });
  await mkdir(reports, { recursive: true });
  // Keep the runtime payload compact. Human-readable audit artifacts remain pretty-printed.
  await writeFile(output, `${JSON.stringify(data)}\n`, "utf8");
  await writeFile(resolve(dirname(output), "playbooks.schema.json"), `${JSON.stringify(schemaDocument(), null, 2)}\n`, "utf8");
  await writeFile(resolve(reports, "content-quality.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
  await writeFile(resolve(reports, "content-quality.md"), reportMarkdown(report), "utf8");
  await writeFile(resolve(reports, "coverage.csv"), coverageCsv(data), "utf8");
  console.log(JSON.stringify({ output, ...report }, null, 2));
}

main().catch(error => {
  console.error(`Migration failed: ${error.stack || error.message}`);
  process.exitCode = 1;
});
