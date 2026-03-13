export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
export type Confidence = "Confirmed" | "Likely" | "Needs Validation";
export type FindingCategory = "Exposure" | "Secret" | "Asset" | "Historical";
export type ReconMode = "quick" | "live" | "full" | "custom";
export type ScanDepth = "standard" | "aggressive" | "deep" | "custom";
export type ToolTimeoutKey =
  | "subfinder"
  | "amass"
  | "findomain"
  | "assetfinder"
  | "chaos"
  | "subcat"
  | "gau"
  | "waybackurls"
  | "dnsx"
  | "httpx"
  | "katana"
  | "waymore"
  | "arjun"
  | "subzy";

export type ScanOptions = {
  subdomainEnum: boolean;
  dnsAnalysis: boolean;
  httpProbing: boolean;
  parameterDiscovery: boolean;
  jsAnalysis: boolean;
  waybackUrls: boolean;
  historicalRobots: boolean;
  sensitiveFiles: boolean;
  backups: boolean;
  adminPanels: boolean;
  cloudStorage: boolean;
  directoryListing: boolean;
  apiKeys: boolean;
  jwtTokens: boolean;
  oauthTokens: boolean;
  riskScoring: boolean;
};

export type ScanRuntimeConfig = {
  depth: ScanDepth;
  directoryMaxDepth: number;
  directoryBreadth: number;
  archiveRetryCount: number;
  archiveRetryBackoffMs: number;
  archiveZeroYieldThreshold: number;
  toolTimeouts: Partial<Record<ToolTimeoutKey, number>>;
};

export type ProbeResult = {
  alive: boolean;
  status: number;
  title: string;
  finalUrl?: string;
  contentType?: string;
  contentLength?: number | null;
  server?: string | null;
  contentHash?: string | null;
};

export type DnsInfo = {
  a: string[];
  cname: string[];
  mx: { exchange: string; priority: number }[];
  ns?: string[];
  hostingProvider?: string;
  mailProvider?: string;
};

export type IpIntel = {
  ip: string;
  network?: string;
  country?: string;
  owner?: string;
  emails: string[];
};

export type SslInfo = {
  subject: string;
  issuer: string;
  validFrom?: string;
  validTo?: string;
  san: string[];
  fingerprint256?: string;
  protocol?: string;
  expired: boolean;
  daysRemaining?: number | null;
};

export type ToolExecution = {
  name: string;
  category: "subdomain" | "archive" | "dns" | "probe" | "native";
  available: boolean;
  used: boolean;
  status: "pending" | "running" | "completed" | "missing" | "failed" | "skipped";
  details?: string;
  count?: number;
  host?: string;
  reasonKind?: "timeout" | "network" | "installation" | "rate-limit" | "config" | "crash" | "partial" | "success" | "info";
};

export type Finding = {
  id: string;
  scanId?: string;
  category: FindingCategory;
  type: string;
  title: string;
  asset: string;
  host: string;
  path: string;
  source: string;
  match: string;
  redactedMatch?: string;
  severity: Severity;
  confidence: Confidence;
  summary: string;
  impact: string;
  recommendation: string;
  evidence: string[];
  tags: string[];
  archive: {
    firstSeen?: string;
    lastSeen?: string;
    seenCount: number;
    sourceCount: number;
    sources?: string[];
    latestStatusCode?: number | null;
    latestMimeType?: string | null;
  };
  validation: {
    checked: boolean;
    live: boolean | null;
    status: "live" | "archived-only" | "unreachable" | "not-checked";
    httpStatus?: number | null;
    title?: string;
    contentType?: string;
    contentHash?: string | null;
    validatedAt?: string;
    notes: string[];
  };
  jwt?: {
    user: string;
    email: string;
    roles: string[];
    issuer?: string;
    audience?: string | string[];
    expiry?: number | string;
    algorithm?: string;
    riskFlags: string[];
    error?: string;
    header?: Record<string, unknown>;
    payload?: Record<string, unknown>;
  };
};

export type Asset = {
  hostname: string;
  urls: number;
  firstSeen?: string;
  lastSeen?: string;
  findings: number;
  probe?: ProbeResult | null;
  topIssues: string[];
  discoveredBy?: string[];
  archiveUrls?: number;
  live?: boolean | null;
  dnsResolved?: boolean;
  dns?: {
    a: string[];
    cname: string[];
  };
};

export type TimelinePoint = {
  period: string;
  findings: number;
  secrets: number;
  exposures: number;
};

export type ScanSummary = {
  id: string;
  domain: string;
  startedAt: string;
  finishedAt?: string;
  status: "running" | "finished" | "stopped" | "error";
  mode?: ReconMode;
  stats: {
    urlsScanned: number;
    findings: number;
    secretFindings: number;
    exposureFindings: number;
    subdomainsCount: number;
    validatedFindings: number;
    liveFindings: number;
    uniqueSources?: number;
    liveHosts?: number;
  };
  riskScore?: {
    score: number;
    level: "Low" | "Medium" | "High" | "Critical";
    reasons: string[];
  };
};

export type SavedScan = {
  summary: ScanSummary;
  findings: Finding[];
  assets: Asset[];
  dnsInfo: DnsInfo | null;
  targetProfile: {
    ips: string[];
    hostingProvider?: string;
    mailProvider?: string;
    ownerName?: string;
    ownerEmails?: string[];
    firstSeen?: string;
    lastSeen?: string;
    ssl: SslInfo | null;
    loginUrls: string[];
    criticalUrls: string[];
    vpnUrls: string[];
    subdomains: string[];
    ipIntel?: IpIntel[];
    possibleVulns: Array<{
      type: string;
      label: string;
      urls: string[];
    }>;
  };
  parameters: string[];
  directories: string[];
  jsFiles: string[];
  robotsLatest: string;
  robotsArchive: string[];
  timeline: TimelinePoint[];
  logs: string[];
  reconMeta?: {
    mode: ReconMode;
    depth?: ScanDepth;
    config?: ScanRuntimeConfig;
    sourceCounts: Record<string, number>;
    liveHosts: string[];
    toolExecutions: ToolExecution[];
  };
};
