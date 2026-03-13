import fs from "fs";
import express from "express";
import { randomUUID } from "crypto";
import path from "path";
import { detectFindings, detectLiveFindings, extractParameters, extractSubdomain, checkDirectoryListing, checkJsFile } from "./backend/services/analyzer";
import { clearSavedScans, deleteSavedScan, getSavedScan, listScanSummaries, saveScan } from "./backend/services/db";
import { getDnsRecords, getIpIntelligence, getTlsDetails, inferProviderFromSignals, probeUrl, resolveHostname, resolveHostnamesWithDnsx } from "./backend/services/recon";
import { buildValidationFromProbe, canonicalizeUrl, normalizeDomainInput, upsertFindingCapture } from "./backend/services/scan-runtime";
import {
  checkSubdomainTakeoverWithSubzy,
  collectArchiveRecordsForHost,
  discoverParametersWithArjun,
  discoverSubdomains,
  getModeBudget,
  probeHostsWithHttpx,
} from "./backend/services/source-orchestrator";
import { getToolAvailability } from "./backend/services/tool-runner";
import { ArchiveRecord, Asset, Finding, ProbeResult, ReconMode, SavedScan, ScanDepth, ScanOptions, ScanRuntimeConfig, ScanSummary, TimelinePoint, ToolExecution, ToolTimeoutKey } from "./backend/types";

const DEFAULT_OPTIONS: ScanOptions = {
  subdomainEnum: true,
  dnsAnalysis: true,
  httpProbing: true,
  parameterDiscovery: true,
  jsAnalysis: true,
  waybackUrls: true,
  historicalRobots: true,
  sensitiveFiles: true,
  backups: true,
  adminPanels: true,
  cloudStorage: true,
  directoryListing: true,
  apiKeys: true,
  jwtTokens: true,
  oauthTokens: true,
  riskScoring: true,
};

const DEFAULT_RUNTIME_CONFIG: ScanRuntimeConfig = {
  depth: "standard",
  directoryMaxDepth: 1,
  directoryBreadth: 10,
  archiveRetryCount: 2,
  archiveRetryBackoffMs: 1800,
  archiveZeroYieldThreshold: 4,
  toolTimeouts: {},
};

const DIRECTORY_WORDLIST = [
  "admin",
  "api",
  "app",
  "assets",
  "backup",
  "backups",
  "config",
  "dashboard",
  "debug",
  "docs",
  "download",
  "files",
  "graphql",
  "internal",
  "login",
  "manage",
  "panel",
  "portal",
  "private",
  "public",
  "server-status",
  "signin",
  "static",
  "storage",
  "swagger-ui",
  "uploads",
  "user",
  "wp-admin",
  ".git",
  ".well-known",
];

const DEPTH_PRESETS: Record<Exclude<ScanDepth, "custom">, Pick<ScanRuntimeConfig, "directoryMaxDepth" | "directoryBreadth" | "archiveRetryCount" | "archiveRetryBackoffMs" | "archiveZeroYieldThreshold">> = {
  standard: { directoryMaxDepth: 1, directoryBreadth: 10, archiveRetryCount: 2, archiveRetryBackoffMs: 1200, archiveZeroYieldThreshold: 4 },
  aggressive: { directoryMaxDepth: 2, directoryBreadth: 20, archiveRetryCount: 3, archiveRetryBackoffMs: 1800, archiveZeroYieldThreshold: 6 },
  deep: { directoryMaxDepth: 4, directoryBreadth: 40, archiveRetryCount: 5, archiveRetryBackoffMs: 2600, archiveZeroYieldThreshold: 10 },
};

function mergeOptions(input: unknown): ScanOptions {
  if (!input || typeof input !== "object") {
    return DEFAULT_OPTIONS;
  }
  return { ...DEFAULT_OPTIONS, ...(input as Partial<ScanOptions>) };
}

function clampNumber(value: unknown, fallback: number, min: number, max: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(min, Math.min(max, Math.round(numeric)));
}

function parseDepth(input: unknown): ScanDepth {
  const value = String(input || "").toLowerCase();
  if (value === "standard" || value === "aggressive" || value === "deep" || value === "custom") {
    return value;
  }
  return "standard";
}

function mergeRuntimeConfig(input: unknown): ScanRuntimeConfig {
  const partial = input && typeof input === "object" ? input as Partial<ScanRuntimeConfig> : {};
  const depth = parseDepth(partial.depth);
  const preset = DEPTH_PRESETS[depth === "custom" ? "standard" : depth];
  const timeoutInput = partial.toolTimeouts && typeof partial.toolTimeouts === "object" ? partial.toolTimeouts : {};
  const allowedTimeoutKeys: ToolTimeoutKey[] = [
    "subfinder",
    "amass",
    "findomain",
    "assetfinder",
    "chaos",
    "subcat",
    "gau",
    "waybackurls",
    "dnsx",
    "httpx",
    "katana",
    "waymore",
    "arjun",
    "subzy",
  ];
  const toolTimeouts = Object.fromEntries(
    allowedTimeoutKeys
      .filter((key) => timeoutInput[key] !== undefined && timeoutInput[key] !== null)
      .map((key) => [key, clampNumber(timeoutInput[key], 0, 4000, 120000)]),
  ) as Partial<Record<ToolTimeoutKey, number>>;

  return {
    ...DEFAULT_RUNTIME_CONFIG,
    depth,
    directoryMaxDepth: clampNumber(partial.directoryMaxDepth, preset.directoryMaxDepth, 1, 4),
    directoryBreadth: clampNumber(partial.directoryBreadth, preset.directoryBreadth, 4, 40),
    archiveRetryCount: clampNumber(partial.archiveRetryCount, preset.archiveRetryCount, 0, 6),
    archiveRetryBackoffMs: clampNumber(partial.archiveRetryBackoffMs, preset.archiveRetryBackoffMs, 500, 10000),
    archiveZeroYieldThreshold: clampNumber(partial.archiveZeroYieldThreshold, preset.archiveZeroYieldThreshold, 2, 12),
    toolTimeouts,
  };
}

function formatPeriod(timestamp?: string): string | null {
  if (!timestamp || timestamp.length < 6) return null;
  return `${timestamp.slice(0, 4)}-${timestamp.slice(4, 6)}`;
}

function calculateRiskScore(findings: Finding[], assets: Asset[]): NonNullable<ScanSummary["riskScore"]> {
  let score = 0;
  const reasons: string[] = [];
  const critical = findings.filter((finding) => finding.severity === "Critical").length;
  const high = findings.filter((finding) => finding.severity === "High").length;
  const live = findings.filter((finding) => finding.validation.live).length;
  const secrets = findings.filter((finding) => finding.category === "Secret").length;
  const livePortals = findings.filter((finding) => ["admin_panel", "live_login_surface", "xmlrpc_surface", "api_docs_exposure", "debug_endpoint"].includes(finding.type)).length;
  const liveAssets = assets.filter((asset) => asset.live).length;

  if (critical > 0) {
    score += Math.min(critical * 18, 40);
    reasons.push(`${critical} critical finding(s)`);
  }
  if (high > 0) {
    score += Math.min(high * 8, 24);
    reasons.push(`${high} high-severity finding(s)`);
  }
  if (live > 0) {
    score += Math.min(live * 6, 18);
    reasons.push(`${live} finding(s) validated as live`);
  }
  if (secrets > 0) {
    score += Math.min(secrets * 5, 20);
    reasons.push(`${secrets} secret exposure(s)`);
  }
  if (livePortals > 0) {
    score += Math.min(livePortals * 4, 16);
    reasons.push(`${livePortals} login or privileged surface(s) identified`);
  }
  if (liveAssets >= 3) {
    score += 6;
    reasons.push(`${liveAssets} live host(s) expanded the exposed surface`);
  }
  if (assets.length > 15) {
    score += 8;
    reasons.push("Broad attack surface across subdomains");
  }

  score = Math.min(score, 100);
  const level = score >= 80 ? "Critical" : score >= 55 ? "High" : score >= 25 ? "Medium" : "Low";
  return { score, level, reasons };
}

function toAssets(assetMap: Map<string, Asset>): Asset[] {
  return Array.from(assetMap.values()).sort((a, b) => b.findings - a.findings || b.urls - a.urls);
}

function parseReconMode(input: unknown): ReconMode {
  const value = String(input || "").toLowerCase();
  if (value === "quick" || value === "live" || value === "full" || value === "custom") {
    return value;
  }
  return "full";
}

function summarizeToolExecutions(entries: ToolExecution[]): ToolExecution[] {
  const grouped = new Map<string, ToolExecution & {
    statuses: Set<ToolExecution["status"]>;
    detailSamples: string[];
    statusDetails: Partial<Record<ToolExecution["status"], string[]>>;
  }>();

  for (const entry of entries) {
    const existing = grouped.get(entry.name);
    if (!existing) {
      grouped.set(entry.name, {
        ...entry,
        statuses: new Set([entry.status]),
        detailSamples: entry.details ? [entry.details] : [],
        statusDetails: entry.details ? { [entry.status]: [entry.details] } : {},
      });
      continue;
    }
    existing.count = (existing.count || 0) + (entry.count || 0);
    existing.available = existing.available || entry.available;
    existing.used = existing.used || entry.used;
    existing.statuses.add(entry.status);
    if (entry.details && !existing.detailSamples.includes(entry.details)) {
      existing.detailSamples.push(entry.details);
    }
    if (entry.details) {
      existing.statusDetails[entry.status] = [
        ...(existing.statusDetails[entry.status] || []),
        entry.details,
      ].filter((detail, index, all) => all.indexOf(detail) === index);
    }
  }

  return Array.from(grouped.values()).map((entry) => {
    const statuses = entry.statuses;
    const count = entry.count || 0;
    const partial = entry.detailSamples.some((detail) => /partial results captured/i.test(detail))
      || (count > 0 && (statuses.has("failed") || statuses.has("skipped")));
    let status: ToolExecution["status"] = "missing";
    if (count > 0 || statuses.has("completed")) {
      status = "completed";
    } else if (statuses.has("running")) {
      status = "running";
    } else if (statuses.has("pending")) {
      status = "pending";
    } else if (statuses.has("skipped") && !statuses.has("failed")) {
      status = "skipped";
    } else if (statuses.has("failed")) {
      status = "failed";
    }

    const nonTransientDetails = entry.detailSamples.filter((detail) => !/^(Queued|Running)\b/i.test(detail));
    const completedDetails = (entry.statusDetails.completed || []).filter((detail) => !/^(Queued|Running)\b/i.test(detail));
    const failedDetails = (entry.statusDetails.failed || []).filter((detail) => !/^(Queued|Running)\b/i.test(detail));
    const skippedDetails = (entry.statusDetails.skipped || []).filter((detail) => !/^(Queued|Running)\b/i.test(detail));
    const runningDetails = (entry.statusDetails.running || []).filter((detail) => !/^(Queued|Running)\b/i.test(detail));
    const pendingDetails = (entry.statusDetails.pending || []).filter((detail) => !/^(Queued|Running)\b/i.test(detail));

    let details = status === "completed"
      ? completedDetails[0]
      : status === "failed"
        ? failedDetails[0]
        : status === "skipped"
          ? skippedDetails[0]
          : status === "running"
            ? runningDetails[0]
            : pendingDetails[0];

    if (status === "completed" && partial && !details) {
      details = count > 0
        ? `${count} result(s) found. Lower-priority hosts were skipped or timed out during focused collection`
        : "Completed with focused collection limits applied";
    } else if (status === "completed" && (!details || /^(Queued|Running)\b/i.test(details))) {
      details = count > 0 ? `${count} result(s) found` : "0 result(s) found";
    } else if (status === "completed" && count === 0 && !details) {
      details = "0 result(s) found";
    } else if (status === "failed" && !details) {
      details = count > 0 ? `${count} partial result(s) recovered before failure` : "No results returned";
    } else if ((status === "running" || status === "pending") && !details) {
      details = status === "running" ? "Running now" : "Queued to start";
    } else if (status === "skipped" && !details) {
      details = "Skipped for this scan";
    }

    return {
      name: entry.name,
      category: entry.category,
      available: entry.available,
      used: entry.used,
      status,
      details,
      count: entry.count,
      host: entry.host,
      reasonKind: status === "completed"
        ? (partial ? "partial" : "success")
        : status === "failed"
          ? entry.reasonKind || "crash"
          : status === "skipped"
            ? "config"
            : entry.reasonKind,
    };
  }).sort((left, right) => left.name.localeCompare(right.name));
}

const LIVE_TRIAGE_PATHS = [
  "/.env",
  "/.git/config",
  "/backup.zip",
  "/db.sql",
  "/vpn",
  "/vpn/",
  "/sslvpn/",
  "/remote/",
  "/remote/login",
  "/citrix/",
  "/owa/",
  "/ecp/",
  "/adfs/",
  "/global-protect/login.esp",
  "/xmlrpc.php",
  "/graphql",
  "/swagger-ui/",
  "/swagger-ui/index.html",
  "/openapi.json",
  "/api-docs",
  "/login",
  "/signin",
  "/admin",
  "/wp-admin/",
  "/wp-login.php",
  "/user/login",
  "/server-status",
  "/phpinfo.php",
];

const LIVE_TRIAGE_BUDGET: Record<ReconMode, { hosts: number; paths: number; concurrency: number }> = {
  quick: { hosts: 3, paths: 8, concurrency: 4 },
  live: { hosts: 5, paths: 12, concurrency: 5 },
  full: { hosts: 7, paths: 16, concurrency: 6 },
  custom: { hosts: 5, paths: 12, concurrency: 5 },
};

const ROBOTS_CLUE_REGEX = /(admin|login|signin|auth|xmlrpc|graphql|swagger|openapi|api-docs|server-status|phpinfo|backup|config|\.env|\.git|webmail|portal|wp-admin)/i;
const LIVE_FILE_EXPOSURE_REGEX = /(?:\/\.env|\/\.git\/config|(?:^|\/)[^/?#]+\.(?:sql|bak|zip|pem|key|log|ini|yaml|yml|conf|json))(?:$|[?#])/i;

function buildLiveRecord(url: string, probe: ProbeResult): ArchiveRecord {
  return {
    url,
    source: "live",
    statusCode: probe.status || null,
    mimeType: probe.contentType ?? null,
  };
}

async function runTaskPool<T>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<void>,
): Promise<void> {
  let cursor = 0;
  const workerCount = Math.max(1, Math.min(concurrency, items.length));
  const runners = Array.from({ length: workerCount }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      await worker(items[index], index);
    }
  });
  await Promise.all(runners);
}

function extractRobotsHintPaths(robotsText: string): string[] {
  const candidates = new Set<string>();
  for (const line of robotsText.split(/\r?\n/)) {
    const match = line.match(/^(?:allow|disallow)\s*:\s*(.+)$/i);
    if (!match) continue;
    let candidate = match[1].trim();
    if (!candidate || candidate === "/" || candidate === "*") continue;
    candidate = candidate.split("#")[0]?.trim() || candidate;
    candidate = candidate.replace(/\*+$/g, "");
    candidate = candidate.replace(/\$$/, "");
    if (!candidate.startsWith("/")) {
      candidate = `/${candidate}`;
    }
    if (candidate.length < 2 || !ROBOTS_CLUE_REGEX.test(candidate)) continue;
    candidates.add(candidate);
  }
  return Array.from(candidates);
}

function uniqueLimited(values: Array<string | undefined | null>, limit: number): string[] {
  return Array.from(new Set(values.filter((value): value is string => Boolean(value && value.trim())))).slice(0, limit);
}

function getDepthTriageMultiplier(depth: ScanDepth): number {
  if (depth === "aggressive") return 1.6;
  if (depth === "deep") return 2.2;
  return 1;
}

function buildDirectoryDiscoveryTargets(hosts: string[], config: ScanRuntimeConfig, robotsHintPaths: string[]): string[] {
  const discovered = new Set<string>();
  const baseWords = DIRECTORY_WORDLIST.slice(0, config.directoryBreadth);
  const nestedWords = baseWords.filter((word) => ![
    "backup",
    "backups",
    ".git",
    ".well-known",
    "graphql",
    "login",
    "signin",
    "server-status",
    "swagger-ui",
    "wp-admin",
  ].includes(word));
  const seedPaths = Array.from(new Set([
    ...baseWords.map((word) => `/${word}`),
    ...robotsHintPaths.map((value) => value.replace(/\/+$/, "")).filter(Boolean),
  ]));

  for (const host of hosts) {
    let currentLevel = seedPaths;
    for (let depthLevel = 1; depthLevel <= config.directoryMaxDepth; depthLevel += 1) {
      const nextLevel: string[] = [];
      for (const currentPath of currentLevel.slice(0, config.directoryBreadth)) {
        const normalizedPath = currentPath.startsWith("/") ? currentPath : `/${currentPath}`;
        const cleanPath = normalizedPath.replace(/\/{2,}/g, "/").replace(/\/+$/, "");
        if (cleanPath && cleanPath !== "/") {
          discovered.add(`https://${host}${cleanPath}/`);
        }
        const existingSegments = cleanPath.split("/").filter(Boolean);
        const terminalPath = /(?:^|\/)(?:\.git|\.well-known|graphql|server-status|swagger-ui|wp-admin|xmlrpc\.php)$/i.test(cleanPath);
        if (depthLevel >= config.directoryMaxDepth || existingSegments.length >= 2 || terminalPath) {
          continue;
        }
        const lastSegment = existingSegments.at(-1);
        for (const child of nestedWords.slice(0, Math.max(4, Math.floor(config.directoryBreadth / 2)))) {
          if (child === lastSegment || existingSegments.includes(child)) {
            continue;
          }
          nextLevel.push(`${cleanPath}/${child}`);
        }
      }
      currentLevel = nextLevel;
    }
  }

  return Array.from(discovered);
}

function buildSkippedProbe(host: string, reason: string): ProbeResult {
  return {
    alive: false,
    status: 0,
    title: reason,
    finalUrl: `https://${host}`,
    contentLength: null,
    server: null,
    contentHash: null,
  };
}

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT || "3000");

  app.use(express.json());

  app.get("/api/scans", (_req, res) => {
    res.json({ scans: listScanSummaries(25) });
  });

  app.get("/api/scans/:id", (req, res) => {
    const scan = getSavedScan(req.params.id);
    if (!scan) {
      return res.status(404).json({ error: "Scan not found" });
    }
    return res.json(scan);
  });

  app.delete("/api/scans/:id", (req, res) => {
    const deleted = deleteSavedScan(req.params.id);
    if (!deleted) {
      return res.status(404).json({ error: "Scan not found" });
    }
    return res.json({ ok: true });
  });

  app.delete("/api/scans", (_req, res) => {
    const removed = clearSavedScans();
    return res.json({ ok: true, removed });
  });

  app.get("/api/scan/stream", async (req, res) => {
    const domain = normalizeDomainInput(String(req.query.domain || ""));
    const optionsStr = String(req.query.options || "{}");
    const configStr = String(req.query.config || "{}");
    const mode = parseReconMode(req.query.mode);

    if (!domain) {
      return res.status(400).json({ error: "Domain is required" });
    }

    let options = DEFAULT_OPTIONS;
    let runtimeConfig = DEFAULT_RUNTIME_CONFIG;
    try {
      options = mergeOptions(JSON.parse(optionsStr));
    } catch {
      options = DEFAULT_OPTIONS;
    }
    try {
      runtimeConfig = mergeRuntimeConfig(JSON.parse(configStr));
    } catch {
      runtimeConfig = DEFAULT_RUNTIME_CONFIG;
    }

    res.setHeader("Content-Type", "application/x-ndjson");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    const abortController = new AbortController();
    req.on("close", () => abortController.abort());

    const scanId = randomUUID();
    const startedAt = new Date().toISOString();
    const logs: string[] = [];
    const sourceCounts = new Map<string, number>();
    const toolExecutions: ToolExecution[] = [];
    const seenUrls = new Set<string>();
    const parameterSet = new Set<string>();
    const directorySet = new Set<string>();
    const jsFileSet = new Set<string>();
    const robotsArchiveSet = new Set<string>();
    const uniqueSubdomains = new Set<string>();
    const subdomainSources = new Map<string, Set<string>>();
    const findingsMap = new Map<string, Finding>();
    const assetMap = new Map<string, Asset>();
    const timelineMap = new Map<string, TimelinePoint>();
    let dnsInfo = null;
    let sslInfo = null;
    let firstSeen: string | undefined;
    let lastSeen: string | undefined;
    let robotsLatest = "";
    let urlsScanned = 0;
    let phase = "Collecting archive records";
    const modeBudget = getModeBudget(mode, runtimeConfig.depth);

    const send = (payload: unknown) => {
      res.write(`${JSON.stringify(payload)}\n`);
    };

    const log = (message: string) => {
      const entry = `[${new Date().toLocaleTimeString()}] ${message}`;
      logs.push(entry);
      send({ type: "log", message: entry });
    };

    const emitToolStatus = (execution: ToolExecution) => {
      send({ type: "tool_status", execution });
    };

    const ensureAsset = (hostname: string): Asset => {
      const existing = assetMap.get(hostname);
      if (existing) return existing;
      const asset: Asset = {
        hostname,
        urls: 0,
        findings: 0,
        probe: null,
        topIssues: [],
        discoveredBy: [],
        archiveUrls: 0,
        live: null,
        dnsResolved: false,
        dns: { a: [], cname: [] },
      };
      assetMap.set(hostname, asset);
      return asset;
    };

    const recordSource = (source: string) => {
      sourceCounts.set(source, (sourceCounts.get(source) || 0) + 1);
    };

    const registerAssetSource = (hostname: string, source: string) => {
      const asset = ensureAsset(hostname);
      const sources = new Set(asset.discoveredBy || []);
      sources.add(source);
      asset.discoveredBy = Array.from(sources).sort();
      const hostSources = subdomainSources.get(hostname) ?? new Set<string>();
      hostSources.add(source);
      subdomainSources.set(hostname, hostSources);
      recordSource(source);
      return asset;
    };

    const updateTimeline = (category: Finding["category"], timestamp?: string) => {
      const period = formatPeriod(timestamp);
      if (!period) return;
      const point = timelineMap.get(period) ?? { period, findings: 0, secrets: 0, exposures: 0 };
      point.findings += 1;
      if (category === "Secret") {
        point.secrets += 1;
      }
      if (category === "Exposure") {
        point.exposures += 1;
      }
      timelineMap.set(period, point);
    };

    const emitProgress = (detail?: string) => {
      send({
        type: "progress",
        phase,
        detail,
        stats: {
          urlsScanned,
          findings: findingsMap.size,
          subdomainsCount: uniqueSubdomains.size,
          validatedFindings: Array.from(findingsMap.values()).filter((finding) => finding.validation.checked).length,
          liveFindings: Array.from(findingsMap.values()).filter((finding) => finding.validation.live).length,
          uniqueSources: sourceCounts.size,
          liveHosts: Array.from(assetMap.values()).filter((asset) => asset.live).length,
          trackedHosts: assetMap.size,
        },
      });
    };

    const initialToolChecklist: ToolExecution[] = [
      { name: "subfinder", category: "subdomain", available: true, used: false, status: "pending", details: "Queued for passive discovery", reasonKind: "info" },
      { name: "amass", category: "subdomain", available: true, used: false, status: "pending", details: "Queued for passive discovery", reasonKind: "info" },
      { name: "findomain", category: "subdomain", available: true, used: false, status: "pending", details: "Queued for passive discovery", reasonKind: "info" },
      { name: "assetfinder", category: "subdomain", available: true, used: false, status: "pending", details: "Queued for passive discovery", reasonKind: "info" },
      { name: "chaos", category: "subdomain", available: true, used: false, status: "pending", details: "Queued for passive discovery", reasonKind: "info" },
      { name: "subcat", category: "subdomain", available: true, used: false, status: "pending", details: "Queued for passive discovery", reasonKind: "info" },
      { name: "crtsh", category: "native", available: true, used: false, status: "pending", details: "Queued for certificate lookup", reasonKind: "info" },
      { name: "certspotter", category: "native", available: true, used: false, status: "pending", details: "Queued for certificate lookup", reasonKind: "info" },
      { name: "bufferover", category: "native", available: true, used: false, status: "pending", details: "Queued for passive DNS lookup", reasonKind: "info" },
      { name: "dnsx", category: "dns", available: true, used: false, status: "pending", details: "Queued for DNS validation", reasonKind: "info" },
      { name: "puredns", category: "dns", available: true, used: false, status: "pending", details: "Queued for wildcard cleanup review", reasonKind: "info" },
      { name: "httpx", category: "probe", available: true, used: false, status: "pending", details: "Queued for batch HTTP probing", reasonKind: "info" },
      { name: "subzy", category: "probe", available: true, used: false, status: "pending", details: "Queued for subdomain takeover review", reasonKind: "info" },
      { name: "waybackurls", category: "archive", available: true, used: false, status: "pending", details: "Queued for archive expansion", reasonKind: "info" },
      { name: "gau", category: "archive", available: true, used: false, status: "pending", details: "Queued for archive expansion", reasonKind: "info" },
      { name: "katana", category: "archive", available: true, used: false, status: "pending", details: "Queued for live crawl expansion", reasonKind: "info" },
      { name: "waymore", category: "archive", available: true, used: false, status: "pending", details: "Queued for deep archive expansion", reasonKind: "info" },
      { name: "arjun", category: "archive", available: true, used: false, status: "pending", details: "Queued for hidden parameter discovery", reasonKind: "info" },
      { name: "wayback-native", category: "native", available: true, used: false, status: "pending", details: "Queued for native web archive lookup", reasonKind: "info" },
      { name: "live-recursion", category: "probe", available: true, used: false, status: "pending", details: "Queued for live directory recursion", reasonKind: "info" },
    ];
    initialToolChecklist.forEach(emitToolStatus);

    const captureFinding = (candidate: Finding, record: ArchiveRecord) => {
      const { finding, inserted } = upsertFindingCapture(findingsMap, candidate, record);
      if (candidate.validation.checked && (
        !finding.validation.checked
        || finding.validation.httpStatus !== candidate.validation.httpStatus
        || finding.validation.status !== candidate.validation.status
      )) {
        finding.validation = candidate.validation;
        send({ type: "finding_update", finding });
      }
      if (inserted) {
        updateTimeline(finding.category, record.timestamp);
      }
      const findingAsset = ensureAsset(finding.host);
      findingAsset.findings = Array.from(findingsMap.values()).filter((item) => item.host === finding.host).length;
      if (!findingAsset.topIssues.includes(finding.title)) {
        findingAsset.topIssues = [...findingAsset.topIssues, finding.title].slice(0, 3);
      }
      if (inserted) {
        send({ type: "finding", finding });
      }
      return { finding, inserted };
    };

    const processRecord = (record: ArchiveRecord, liveProbe?: ProbeResult) => {
      urlsScanned += 1;
      recordSource(record.source);

      let parsed: URL;
      try {
        parsed = new URL(record.url);
      } catch {
        return;
      }
      const canonicalUrl = canonicalizeUrl(record.url);
      const isNewUrl = !seenUrls.has(canonicalUrl);
      if (isNewUrl) {
        seenUrls.add(canonicalUrl);
      }
      if (record.timestamp && (!firstSeen || record.timestamp < firstSeen)) firstSeen = record.timestamp;
      if (record.timestamp && (!lastSeen || record.timestamp > lastSeen)) lastSeen = record.timestamp;
      const asset = registerAssetSource(parsed.hostname, record.source);
      if (isNewUrl) {
        asset.urls += 1;
        if (record.source !== "live") {
          asset.archiveUrls = (asset.archiveUrls || 0) + 1;
        }
      }
      if (!asset.firstSeen || (record.timestamp && record.timestamp < asset.firstSeen)) {
        asset.firstSeen = record.timestamp;
      }
      if (!asset.lastSeen || (record.timestamp && record.timestamp > asset.lastSeen)) {
        asset.lastSeen = record.timestamp;
      }

      const subdomain = options.subdomainEnum !== false ? extractSubdomain(record.url, domain) : null;
      if (subdomain && !uniqueSubdomains.has(subdomain)) {
        uniqueSubdomains.add(subdomain);
        registerAssetSource(subdomain, record.source);
        send({ type: "subdomain", subdomain });
      }

      if (isNewUrl && options.parameterDiscovery !== false) {
        for (const parameter of extractParameters(record.url)) {
          if (!parameterSet.has(parameter)) {
            parameterSet.add(parameter);
            send({ type: "parameter", parameter });
          }
        }
      }

      if (isNewUrl && options.directoryListing !== false && checkDirectoryListing(record.url) && !directorySet.has(record.url)) {
        directorySet.add(record.url);
        send({ type: "directory", url: record.url });
      }

      if (isNewUrl && options.jsAnalysis !== false && checkJsFile(record.url) && !jsFileSet.has(record.url)) {
        jsFileSet.add(record.url);
        send({ type: "js_file", url: record.url });
      }

      if (isNewUrl && options.historicalRobots && record.source !== "live" && record.url.endsWith("/robots.txt") && !robotsArchiveSet.has(record.url)) {
        robotsArchiveSet.add(record.url);
        send({ type: "robots_archive", url: record.url });
      }

      for (const candidate of detectFindings(record, options)) {
        if (liveProbe) {
          candidate.validation = buildValidationFromProbe(liveProbe);
        }
        captureFinding(candidate, record);
      }

      if (liveProbe) {
        for (const candidate of detectLiveFindings(record.url, liveProbe, options)) {
          candidate.validation = buildValidationFromProbe(liveProbe);
          captureFinding(candidate, record);
        }
      }

      if (urlsScanned % 200 === 0) {
        emitProgress();
      }
    };

    try {
      log(`Starting ${mode} scan for ${domain}`);

      phase = "Collecting target intelligence";
      emitProgress(`Gathering root DNS, TLS, and robots.txt for ${domain}`);
      if (options.historicalRobots && !abortController.signal.aborted) {
        log("Fetching current robots.txt for live comparison");
        try {
          const robotsResponse = await fetch(`https://${domain}/robots.txt`, { signal: abortController.signal });
          if (robotsResponse.ok) {
            robotsLatest = await robotsResponse.text();
            send({ type: "robots_latest", content: robotsLatest });
          }
        } catch {
          log("Current robots.txt could not be fetched");
        }
      }
      if (options.dnsAnalysis !== false && !abortController.signal.aborted) {
        dnsInfo = await getDnsRecords(domain);
        send({ type: "dns", records: dnsInfo });
        log(`DNS analysis finished with ${dnsInfo.a.length} A record(s) and ${dnsInfo.mx.length} MX record(s)`);
      }
      if (!abortController.signal.aborted) {
        sslInfo = await getTlsDetails(domain);
        if (sslInfo) {
          send({ type: "ssl", records: sslInfo });
          log(`TLS certificate captured: issuer ${sslInfo.issuer}`);
        } else {
          log("TLS certificate details were not available");
        }
      }

      if (options.subdomainEnum !== false && !abortController.signal.aborted) {
        phase = "Discovering passive subdomains";
        emitProgress();
        const discovery = await discoverSubdomains(domain, mode, abortController.signal, runtimeConfig, emitToolStatus);
        toolExecutions.push(...discovery.toolExecutions);
        for (const hit of discovery.hits.slice(0, modeBudget.maxSubdomains)) {
          if (!uniqueSubdomains.has(hit.hostname)) {
            uniqueSubdomains.add(hit.hostname);
            send({ type: "subdomain", subdomain: hit.hostname });
          }
          registerAssetSource(hit.hostname, hit.source);
        }
        log(`Passive discovery produced ${uniqueSubdomains.size} in-scope host(s)`);
        emitProgress(`Discovered ${uniqueSubdomains.size} in-scope host(s)`);
      } else {
        uniqueSubdomains.add(domain);
        registerAssetSource(domain, "scope-root");
      }

      phase = "Running infrastructure analysis";
      emitProgress();

      const sortedHosts = Array.from(subdomainSources.keys())
        .sort((left, right) => {
          if (left === domain) return -1;
          if (right === domain) return 1;
          return left.localeCompare(right);
        })
        .slice(0, modeBudget.maxSubdomains);

      let dnsxResults = new Map<string, { a: string[]; cname: string[]; resolved: boolean }>();
      if (options.dnsAnalysis !== false && !abortController.signal.aborted && sortedHosts.length > 0) {
        emitToolStatus({
          name: "dnsx",
          category: "dns",
          available: true,
          used: true,
          status: "running",
          details: `Resolving ${sortedHosts.length} host(s) with dnsx`,
          reasonKind: "info",
        });
        const dnsxBatch = await resolveHostnamesWithDnsx(sortedHosts, abortController.signal);
        if (dnsxBatch) {
          dnsxResults = dnsxBatch.results;
          toolExecutions.push(dnsxBatch.execution);
          emitToolStatus(dnsxBatch.execution);
          const resolvedCount = Array.from(dnsxBatch.results.values()).filter((result) => result.resolved).length;
          log(`dnsx resolved ${resolvedCount}/${sortedHosts.length} tracked host(s)`);
        } else {
          const dnsxAvailability = getToolAvailability("dnsx");
          const execution = {
            ...dnsxAvailability,
            category: "dns",
            details: dnsxAvailability.available
              ? "Installed locally but batch DNS validation could not be used; native DNS validation is active"
              : "Binary not installed; using native DNS validation",
            reasonKind: dnsxAvailability.available ? "network" : "installation",
          } satisfies ToolExecution;
          toolExecutions.push(execution);
          emitToolStatus(execution);
        }
      } else {
        const execution = {
          ...getToolAvailability("dnsx"),
          category: "dns",
          status: "skipped",
          details: "DNS analysis disabled for this scan",
          reasonKind: "config",
        } satisfies ToolExecution;
        toolExecutions.push(execution);
        emitToolStatus(execution);
      }

      const purednsAvailability = getToolAvailability("puredns");
      const massdnsAvailability = getToolAvailability("massdns");
      const purednsExecution = {
        ...purednsAvailability,
        category: "dns",
        status: purednsAvailability.available
          ? "skipped"
          : purednsAvailability.status,
        details: purednsAvailability.available
          ? (massdnsAvailability.available
            ? "Installed locally for dedicated wildcard-cleanup workflows; fast dnsx/native validation remains the active path"
            : "Installed locally, but puredns requires massdns; native/dnsx validation remains active")
          : "Binary not installed; using dnsx/native DNS validation",
        reasonKind: purednsAvailability.available ? "config" : "installation",
      } satisfies ToolExecution;
      toolExecutions.push(purednsExecution);
      emitToolStatus(purednsExecution);
      const bbotAvailability = getToolAvailability("bbot");
      const bbotExecution = {
        ...bbotAvailability,
        category: "subdomain",
        details: bbotAvailability.available
          ? bbotAvailability.details
          : "Binary not installed; passive adapters remain available",
        reasonKind: bbotAvailability.available ? "config" : "installation",
      } satisfies ToolExecution;
      toolExecutions.push(bbotExecution);
      emitToolStatus(bbotExecution);

      let httpxBatch: Awaited<ReturnType<typeof probeHostsWithHttpx>> = null;
      if (options.httpProbing !== false && !abortController.signal.aborted && sortedHosts.length > 0) {
        phase = "Preparing live HTTP probes";
        emitProgress(`Batch probing ${sortedHosts.length} tracked host(s)`);
        httpxBatch = await probeHostsWithHttpx(sortedHosts, mode, abortController.signal, runtimeConfig, emitToolStatus);
        if (httpxBatch) {
          toolExecutions.push(httpxBatch.execution);
          emitToolStatus(httpxBatch.execution);
          log(`httpx returned ${httpxBatch.results.size} live HTTP result(s) across tracked hosts`);
        } else {
          const httpxAvailability = getToolAvailability("httpx");
          const execution = {
            ...httpxAvailability,
            category: "probe",
            status: httpxAvailability.available ? "failed" : httpxAvailability.status,
            details: httpxAvailability.available
              ? "httpx did not return a usable batch result; native per-host probing remains active"
              : httpxAvailability.details,
            reasonKind: httpxAvailability.available ? "crash" : httpxAvailability.reasonKind,
          } satisfies ToolExecution;
          toolExecutions.push(execution);
          emitToolStatus(execution);
        }
      } else {
        const execution = {
          ...getToolAvailability("httpx"),
          category: "probe",
          status: "skipped",
          details: "HTTP probing disabled for this scan",
          reasonKind: "config",
        } satisfies ToolExecution;
        toolExecutions.push(execution);
        emitToolStatus(execution);
      }

      if (options.subdomainEnum !== false && !abortController.signal.aborted && sortedHosts.length > 0) {
        phase = "Checking takeover indicators";
        emitProgress(`Reviewing ${sortedHosts.length} host(s) for dangling takeover signals`);
        const takeoverBatch = await checkSubdomainTakeoverWithSubzy(sortedHosts, domain, mode, abortController.signal, runtimeConfig, emitToolStatus);
        toolExecutions.push(takeoverBatch.execution);
        emitToolStatus(takeoverBatch.execution);
        if (takeoverBatch.vulnerableHosts.length > 0) {
          for (const takeover of takeoverBatch.vulnerableHosts) {
            const record: ArchiveRecord = {
              url: `https://${takeover.hostname}`,
              source: "live",
            };
            const candidate: Finding = {
              id: randomUUID(),
              category: "Exposure",
              type: "subdomain-takeover",
              title: "Possible subdomain takeover indicator",
              asset: record.url,
              host: takeover.hostname,
              path: "/",
              source: "subzy",
              match: takeover.details,
              redactedMatch: takeover.details.slice(0, 240),
              severity: "High",
              confidence: "Needs Validation",
              summary: "Takeover tooling reported a possible dangling subdomain or takeover condition.",
              impact: "An attacker may be able to claim an external service and serve content under this host.",
              recommendation: "Review DNS, CNAME targets, and third-party service ownership for this host immediately.",
              evidence: [`subzy: ${takeover.details.slice(0, 500)}`],
              tags: ["takeover", "dangling-dns", "external-service"],
              archive: {
                seenCount: 1,
                sourceCount: 1,
                sources: ["subzy"],
                latestStatusCode: null,
                latestMimeType: null,
              },
              validation: {
                checked: false,
                live: null,
                status: "not-checked",
                notes: ["Detected by subzy during takeover review"],
              },
            };
            captureFinding(candidate, record);
          }
          log(`Subzy flagged ${takeoverBatch.vulnerableHosts.length} possible takeover target(s)`);
        }
      } else {
        const execution = {
          ...getToolAvailability("subzy"),
          category: "probe",
          status: "skipped",
          details: "Subdomain takeover review skipped because subdomain discovery is disabled",
          reasonKind: "config",
        } satisfies ToolExecution;
        toolExecutions.push(execution);
        emitToolStatus(execution);
      }

      phase = "Validating discovered hosts";
      emitProgress();
      const validationConcurrency = mode === "quick" ? 4 : mode === "live" ? 6 : mode === "full" ? 8 : 6;
      let validatedHosts = 0;
      await runTaskPool(sortedHosts, validationConcurrency, async (host, index) => {
        if (abortController.signal.aborted) return;
        const asset = ensureAsset(host);
        const sourceCount = subdomainSources.get(host)?.size || 0;
        emitProgress(`Checking ${host}`);

        if (options.dnsAnalysis !== false) {
          const dnsxResolved = dnsxResults.get(host);
          const shouldFallbackToNative = !dnsxResolved && (host === domain || host === `www.${domain}` || sourceCount > 1);
          const resolved = dnsxResolved ?? (shouldFallbackToNative ? await resolveHostname(host) : { a: [], cname: [], resolved: false });
          asset.dns = resolved;
          asset.dnsResolved = resolved.resolved;
        }

        if (options.httpProbing !== false && (options.dnsAnalysis === false || asset.dnsResolved || host === domain || host === `www.${domain}`)) {
          const batchProbe = httpxBatch?.results.get(host);
          const shouldFallbackProbe = !batchProbe && (!httpxBatch || host === domain || host === `www.${domain}` || sourceCount > 1);
          const probe = batchProbe ?? (shouldFallbackProbe ? await probeUrl(`https://${host}`) : buildSkippedProbe(host, "No HTTP response"));
          asset.probe = probe;
          asset.live = probe.alive;
          if (probe.status !== 0 && probe.status !== 404 && probe.status !== 410) {
            const liveRecord = buildLiveRecord(probe.finalUrl || `https://${host}`, probe);
            processRecord(liveRecord, probe);
          }
        } else if (options.httpProbing !== false) {
          asset.probe = buildSkippedProbe(host, asset.dnsResolved ? "Probe skipped" : "DNS unresolved");
          asset.live = false;
        }

        validatedHosts += 1;
        phase = `Validating hosts ${validatedHosts}/${sortedHosts.length}`;
        log(`[host ${index + 1}/${sortedHosts.length}] ${host} -> DNS ${asset.dnsResolved ? "resolved" : "no-answer"}, HTTP ${asset.probe?.status || 0}`);
        send({ type: "asset_update", asset });
      });

      const liveHosts = sortedHosts.filter((host) => ensureAsset(host).probe?.alive);
      const depthMultiplier = getDepthTriageMultiplier(runtimeConfig.depth);
      const triageBudget = {
        hosts: Math.max(1, Math.round(LIVE_TRIAGE_BUDGET[mode].hosts * depthMultiplier)),
        paths: Math.max(4, Math.round(LIVE_TRIAGE_BUDGET[mode].paths * depthMultiplier)),
        concurrency: LIVE_TRIAGE_BUDGET[mode].concurrency,
      };
      const triageHosts = Array.from(new Set([
        domain,
        `www.${domain}`,
        ...liveHosts,
      ]))
        .filter((host) => {
          if (host === domain) return true;
          const asset = assetMap.get(host);
          return Boolean(asset?.probe?.alive);
        })
        .slice(0, triageBudget.hosts);
      const robotsHintPaths = options.historicalRobots ? extractRobotsHintPaths(robotsLatest) : [];
      const triagePaths = Array.from(new Set([...LIVE_TRIAGE_PATHS, ...robotsHintPaths])).slice(0, triageBudget.paths);
      const triageTargets = triageHosts.flatMap((host) => triagePaths.map((triagePath) => `https://${host}${triagePath}`));

      if (triageTargets.length > 0 && !abortController.signal.aborted) {
        phase = "Checking priority live paths";
        emitProgress(`${triageTargets.length} live path check(s) queued`);
        let triagedPaths = 0;
        await runTaskPool(triageTargets, triageBudget.concurrency, async (target) => {
          if (abortController.signal.aborted) return;
          const probe = await probeUrl(target);
          triagedPaths += 1;
          phase = `Checking priority live paths ${triagedPaths}/${triageTargets.length}`;
          emitProgress(target);
          if (probe.status === 0 || probe.status === 404 || probe.status === 410) {
            return;
          }

          if (LIVE_FILE_EXPOSURE_REGEX.test(target) && (probe.status < 200 || probe.status >= 400)) {
            return;
          }

          const liveRecord = buildLiveRecord(probe.finalUrl || target, probe);
          processRecord(liveRecord, probe);
          log(`[path ${triagedPaths}/${triageTargets.length}] ${target} -> HTTP ${probe.status}`);
        });
      }

      const recursiveDirectoryTargets = options.directoryListing !== false
        ? buildDirectoryDiscoveryTargets(triageHosts, runtimeConfig, robotsHintPaths).slice(0, triageHosts.length * runtimeConfig.directoryBreadth * runtimeConfig.directoryMaxDepth)
        : [];
      if (recursiveDirectoryTargets.length > 0 && !abortController.signal.aborted) {
        emitToolStatus({
          name: "live-recursion",
          category: "probe",
          available: true,
          used: true,
          status: "running",
          details: `Recursive directory discovery depth ${runtimeConfig.directoryMaxDepth} across ${triageHosts.length} host(s)`,
          reasonKind: "info",
        });
        phase = "Recursing live directories";
        emitProgress(`${recursiveDirectoryTargets.length} recursive path probe(s) queued`);
        let recursiveHits = 0;
        let recursiveProcessed = 0;
        await runTaskPool(recursiveDirectoryTargets, Math.min(8, triageBudget.concurrency + 1), async (target) => {
          if (abortController.signal.aborted) return;
          const probe = await probeUrl(target);
          recursiveProcessed += 1;
          phase = `Recursing live directories ${recursiveProcessed}/${recursiveDirectoryTargets.length}`;
          emitProgress(target);
          if (probe.status === 0 || probe.status === 404 || probe.status === 410) {
            return;
          }
          recursiveHits += 1;
          const liveRecord = buildLiveRecord(probe.finalUrl || target, probe);
          processRecord(liveRecord, probe);
          log(`[recurse ${recursiveProcessed}/${recursiveDirectoryTargets.length}] ${target} -> HTTP ${probe.status}`);
        });
        const recursionExecution: ToolExecution = {
          name: "live-recursion",
          category: "probe",
          available: true,
          used: true,
          status: "completed",
          details: `Recursive directory discovery completed with ${recursiveHits} live hit(s)`,
          count: recursiveHits,
          reasonKind: recursiveHits > 0 ? "success" : "info",
        };
        toolExecutions.push(recursionExecution);
        emitToolStatus(recursionExecution);
      } else {
        const recursionSkipped: ToolExecution = {
          name: "live-recursion",
          category: "probe",
          available: true,
          used: false,
          status: "skipped",
          details: options.directoryListing === false ? "Directory discovery disabled for this scan" : "No live hosts qualified for recursive directory probing",
          reasonKind: "config",
        };
        toolExecutions.push(recursionSkipped);
        emitToolStatus(recursionSkipped);
      }

      if (options.parameterDiscovery !== false && !abortController.signal.aborted) {
        const parameterTargets = Array.from(new Set([
          domain,
          `www.${domain}`,
          ...triageHosts,
        ]))
          .map((host) => ensureAsset(host).probe?.finalUrl || `https://${host}`)
          .slice(0, mode === "quick" ? 3 : mode === "live" ? 6 : 10);

        if (parameterTargets.length > 0) {
          phase = "Discovering hidden parameters";
          emitProgress(`${parameterTargets.length} live endpoint(s) queued for parameter discovery`);
          const arjunBatch = await discoverParametersWithArjun(parameterTargets, mode, abortController.signal, runtimeConfig, emitToolStatus);
          toolExecutions.push(...arjunBatch.toolExecutions);
          for (const parameter of arjunBatch.parameters) {
            if (!parameterSet.has(parameter)) {
              parameterSet.add(parameter);
              send({ type: "parameter", parameter });
            }
          }
          log(`Parameter discovery added ${arjunBatch.parameters.length} distinct parameter hint(s)`);
        }
      } else {
        const execution = {
          ...getToolAvailability("arjun"),
          category: "archive",
          status: "skipped",
          details: "Parameter discovery disabled for this scan",
          reasonKind: "config",
        } satisfies ToolExecution;
        toolExecutions.push(execution);
        emitToolStatus(execution);
      }

      const rankedArchiveCandidates = sortedHosts
        .map((host) => ({
          host,
          live: Boolean(ensureAsset(host).probe?.alive),
          dnsResolved: Boolean(ensureAsset(host).dnsResolved),
          sourceCount: subdomainSources.get(host)?.size || 0,
          depth: host.split(".").length,
        }))
        .filter((candidate) => {
          const isRoot = candidate.host === domain;
          const isPrimaryWeb = candidate.host === `www.${domain}`;
          if (isRoot || isPrimaryWeb || candidate.live) return true;
          if (!candidate.dnsResolved) return false;
          if (candidate.depth > 4) return false;
          return candidate.sourceCount > 1;
        })
        .sort((left, right) => {
          if (left.live !== right.live) return left.live ? -1 : 1;
          if (left.dnsResolved !== right.dnsResolved) return left.dnsResolved ? -1 : 1;
          if (left.sourceCount !== right.sourceCount) return right.sourceCount - left.sourceCount;
          if (left.depth !== right.depth) return left.depth - right.depth;
          return left.host.localeCompare(right.host);
        })
        .map((item) => item.host);
      const archiveHostLimit = sortedHosts.length > 180
        ? Math.min(modeBudget.maxArchiveHosts, 20)
        : sortedHosts.length > 80
          ? Math.min(modeBudget.maxArchiveHosts, 30)
          : modeBudget.maxArchiveHosts;
      const archiveHosts = options.waybackUrls !== false
        ? Array.from(new Set([domain, ...liveHosts, ...rankedArchiveCandidates])).slice(0, archiveHostLimit)
        : [];
      const heavyArchiveHosts = new Set(
        Array.from(new Set([
          domain,
          `www.${domain}`,
          ...archiveHosts.filter((host) => {
            const asset = ensureAsset(host);
            const contentType = asset.probe?.contentType || "";
            return Boolean(
              asset.live
              && /html|json|xml/i.test(contentType)
              && !/^(?:autodiscover|mx\d*|smtp|imap|pop|mta-sts|mail)\./i.test(host),
            );
          }),
        ])).slice(0, mode === "quick" ? 2 : mode === "live" ? 3 : 4),
      );

      if (archiveHosts.length > 0 && !abortController.signal.aborted) {
        phase = "Collecting historical URLs";
        emitProgress(`${archiveHosts.length} host(s) queued for archive enrichment`);
        const archiveConcurrency = mode === "quick" ? 2 : mode === "live" ? 3 : mode === "full" ? 4 : 3;
        let processedArchiveHosts = 0;
        let zeroYieldArchiveHosts = 0;
        let consecutiveZeroYield = 0;
        let totalArchiveYield = 0;
        let stopArchiveExpansion = false;
        await runTaskPool(archiveHosts, archiveConcurrency, async (host, index) => {
          if (abortController.signal.aborted || stopArchiveExpansion) return;
          phase = `Collecting historical URLs ${processedArchiveHosts + 1}/${archiveHosts.length}`;
          emitProgress(`Expanding ${host}`);
          const archiveBatch = await collectArchiveRecordsForHost(
            host,
            mode,
            abortController.signal,
            runtimeConfig,
            emitToolStatus,
            {
              deepCrawl: heavyArchiveHosts.has(host),
              deepArchive: heavyArchiveHosts.has(host),
            },
          );
          toolExecutions.push(...archiveBatch.toolExecutions);
          const beforeCount = seenUrls.size;
          for (const record of archiveBatch.records) {
            processRecord(record);
          }
          const addedCount = Math.max(0, seenUrls.size - beforeCount);
          processedArchiveHosts += 1;
          totalArchiveYield += addedCount;
          if (addedCount === 0) {
            zeroYieldArchiveHosts += 1;
            consecutiveZeroYield += 1;
          } else {
            consecutiveZeroYield = 0;
          }
          log(`[archive ${index + 1}/${archiveHosts.length}] ${host} added ${addedCount} unique URL(s)`);
          emitProgress(`${host} contributed ${addedCount} URL(s)`);
          const archiveZeroThreshold = Math.min(runtimeConfig.archiveZeroYieldThreshold, archiveHosts.length);
          const nativeRateLimited = archiveBatch.toolExecutions.some((entry) => entry.name === "wayback-native" && entry.reasonKind === "rate-limit");
          if (
            (processedArchiveHosts >= archiveZeroThreshold && totalArchiveYield === 0 && zeroYieldArchiveHosts >= archiveZeroThreshold)
            || (mode === "full" && processedArchiveHosts >= Math.min(6, archiveHosts.length) && consecutiveZeroYield >= Math.min(5, archiveHosts.length))
            || (nativeRateLimited && consecutiveZeroYield >= Math.min(3, archiveHosts.length))
          ) {
            stopArchiveExpansion = true;
            log("Archive enrichment paused after repeated zero-yield hosts and provider pressure");
          }
        });
      } else {
        const archiveTools = ["waybackurls", "gau", "wayback-native", "katana", "waymore"] as const;
        archiveTools.forEach((toolName) => {
          const availability = toolName === "wayback-native"
            ? {
              name: "wayback-native",
              category: "native",
              available: true,
              used: false,
              status: "skipped",
              details: "Native archive lookup available",
              reasonKind: "info",
            } satisfies ToolExecution
            : getToolAvailability(toolName);
          const execution = {
            ...availability,
            category: toolName === "wayback-native" ? "native" : "archive",
            status: "skipped",
            details: options.waybackUrls === false
              ? "Archive expansion disabled for this scan"
              : "No hosts qualified for archive expansion",
            reasonKind: "config",
          } satisfies ToolExecution;
          toolExecutions.push(execution);
          emitToolStatus(execution);
        });
      }

      phase = "Validating live exposure candidates";
      emitProgress(`${findingsMap.size} finding(s) queued for validation`);
      const findings = Array.from(findingsMap.values());
      const findingsByAsset = new Map<string, Finding[]>();
      for (const finding of findings) {
        const list = findingsByAsset.get(finding.asset) ?? [];
        list.push(finding);
        findingsByAsset.set(finding.asset, list);
      }

      const validationTargets = Array.from(findingsByAsset.entries())
        .filter(([, groupedFindings]) => groupedFindings.some((finding) => !finding.validation.checked))
        .map(([asset]) => asset)
        .slice(0, 25);
      for (const [index, target] of validationTargets.entries()) {
        if (abortController.signal.aborted) break;
        phase = `Validating findings ${index + 1}/${validationTargets.length}`;
        emitProgress(`Re-checking ${target}`);
        const probe = await probeUrl(target);
        for (const finding of findingsByAsset.get(target) ?? []) {
          finding.validation = buildValidationFromProbe(probe);
          send({ type: "finding_update", finding });
        }
        log(`[finding ${index + 1}/${validationTargets.length}] ${target} -> HTTP ${probe.status || 0}`);
      }

      const assets = toAssets(assetMap);
      if (!sslInfo) {
        const sslFallbackHosts = Array.from(new Set([domain, `www.${domain}`, ...assets.filter((asset) => asset.live).map((asset) => asset.hostname)]));
        for (const fallbackHost of sslFallbackHosts.slice(0, 4)) {
          if (abortController.signal.aborted) break;
          sslInfo = await getTlsDetails(fallbackHost);
          if (sslInfo) {
            send({ type: "ssl", records: sslInfo });
            log(`TLS fallback certificate captured from ${fallbackHost}: issuer ${sslInfo.issuer}`);
            break;
          }
        }
      }
      const rootProbe = ensureAsset(domain).probe;
      if (rootProbe?.alive) {
        const provider = inferProviderFromSignals([
          rootProbe.server ?? "",
          rootProbe.finalUrl ?? "",
          ...(dnsInfo?.cname ?? []),
          ...(dnsInfo?.mx?.map((record: { exchange: string }) => record.exchange) ?? []),
        ]);
        if (provider && dnsInfo && !dnsInfo.hostingProvider) {
          dnsInfo.hostingProvider = provider;
        }
      }
      const finalFindings = Array.from(findingsMap.values()).sort((a, b) => {
        const severityWeight = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };
        return severityWeight[b.severity] - severityWeight[a.severity] || b.archive.seenCount - a.archive.seenCount;
      });
      const robotsHintUrls = extractRobotsHintPaths(robotsLatest).map((hintPath) => `https://${domain}${hintPath}`);
      const vpnUrls = uniqueLimited([
        ...finalFindings
          .filter((finding) => finding.type === "vpn_surface" || /\/(?:vpn|sslvpn|remote|citrix|owa|ecp|adfs|global-protect)\b/i.test(finding.path))
          .map((finding) => finding.asset),
        ...robotsHintUrls.filter((url) => /\/(?:vpn|sslvpn|remote|citrix|owa|ecp|adfs|global-protect)\b/i.test(url)),
      ], 20);
      const loginUrls = uniqueLimited([
        ...finalFindings
          .filter((finding) => (
            ["admin_panel", "live_login_surface", "vpn_surface"].includes(finding.type)
            || /\/(login|signin|auth|wp-admin|admin|portal|webmail|user\/login|vpn|sslvpn|remote|citrix|owa|ecp|adfs)\b/i.test(finding.path)
          ))
          .map((finding) => finding.asset),
        ...vpnUrls,
        ...robotsHintUrls.filter((url) => /\/(login|signin|auth|wp-admin|admin|portal|webmail|user\/login|vpn|sslvpn|remote|citrix|owa|ecp|adfs)\b/i.test(url)),
      ], 20);
      const criticalUrls = uniqueLimited([
        ...finalFindings
          .filter((finding) => (
            finding.type === "backup"
            || (finding.type === "sensitive_file" && finding.severity !== "Info" && !/\.well-known\//i.test(finding.asset))
            || (finding.severity === "Critical" && /(\.env|\.sql|\.bak|\.zip|\.pem|\.key|db\.sql|config)/i.test(finding.asset))
          ))
          .map((finding) => finding.asset),
      ], 20);
      const xssClues = uniqueLimited(finalFindings.filter((finding) => finding.type === "xss_clue").map((finding) => finding.asset), 20);
      const redirectClues = uniqueLimited(finalFindings.filter((finding) => finding.type === "open_redirect_clue").map((finding) => finding.asset), 20);
      const ssrfClues = uniqueLimited(finalFindings.filter((finding) => finding.type === "ssrf_clue").map((finding) => finding.asset), 20);
      const xmlrpcClues = uniqueLimited([
        ...finalFindings.filter((finding) => finding.type === "xmlrpc_surface").map((finding) => finding.asset),
        ...robotsHintUrls.filter((url) => /\/xmlrpc\.php(?:$|[/?#])/i.test(url)),
      ], 20);
      const graphqlClues = uniqueLimited([
        ...finalFindings.filter((finding) => finding.type === "graphql_endpoint").map((finding) => finding.asset),
        ...robotsHintUrls.filter((url) => /\/graphql(?:$|[/?#])/i.test(url)),
      ], 20);
      const apiDocClues = uniqueLimited([
        ...finalFindings.filter((finding) => finding.type === "api_docs_exposure").map((finding) => finding.asset),
        ...robotsHintUrls.filter((url) => /\/(?:swagger(?:-ui)?|openapi(?:\.(?:json|ya?ml))?|api-docs)(?:$|[/?#])/i.test(url)),
      ], 20);
      const debugClues = uniqueLimited([
        ...finalFindings.filter((finding) => finding.type === "debug_endpoint").map((finding) => finding.asset),
        ...robotsHintUrls.filter((url) => /\/(?:server-status|phpinfo\.php|actuator|debug|console)(?:$|[/?#])/i.test(url)),
      ], 20);
      const vpnClues = uniqueLimited(vpnUrls, 20);
      const riskScore = options.riskScoring !== false ? calculateRiskScore(finalFindings, assets) : undefined;
      const allIps = uniqueLimited([
        ...(dnsInfo?.a ?? []),
        ...assets.flatMap((asset) => asset.dns?.a || []),
      ], 30);
      const ipIntel = await getIpIntelligence(allIps);
      const ownerName = ipIntel.map((item) => item.owner).find(Boolean);
      const ownerEmails = uniqueLimited(ipIntel.flatMap((item) => item.emails), 10);
      const derivedHostingProvider = dnsInfo?.hostingProvider
        || ipIntel.map((item) => item.owner || item.network).find(Boolean)
        || inferProviderFromSignals([
          ...assets.map((asset) => asset.probe?.server || ""),
          ...assets.map((asset) => asset.probe?.finalUrl || ""),
          ...(dnsInfo?.cname || []),
        ]);
      const derivedFirstSeen = firstSeen || sslInfo?.validFrom || startedAt;
      const derivedLastSeen = lastSeen || new Date().toISOString();

      const summary: ScanSummary = {
        id: scanId,
        domain,
        startedAt,
        finishedAt: new Date().toISOString(),
        status: abortController.signal.aborted ? "stopped" : "finished",
        mode,
        stats: {
          urlsScanned,
          findings: finalFindings.length,
          secretFindings: finalFindings.filter((finding) => finding.category === "Secret").length,
          exposureFindings: finalFindings.filter((finding) => finding.category === "Exposure").length,
          subdomainsCount: uniqueSubdomains.size,
          validatedFindings: finalFindings.filter((finding) => finding.validation.checked).length,
          liveFindings: finalFindings.filter((finding) => finding.validation.live).length,
          uniqueSources: sourceCounts.size,
          liveHosts: assets.filter((asset) => asset.live).length,
        },
        riskScore,
      };

      const savedScan: SavedScan = {
        summary,
        findings: finalFindings,
        assets,
        dnsInfo,
        targetProfile: {
          ips: allIps,
          hostingProvider: derivedHostingProvider,
          mailProvider: dnsInfo?.mailProvider,
          ownerName,
          ownerEmails,
          firstSeen: derivedFirstSeen,
          lastSeen: derivedLastSeen,
          ssl: sslInfo,
          loginUrls,
          criticalUrls,
          vpnUrls,
          subdomains: Array.from(uniqueSubdomains).sort(),
          ipIntel,
          possibleVulns: [
            { type: "xss", label: "Possible XSS input points", urls: xssClues },
            { type: "open_redirect", label: "Possible redirect targets", urls: redirectClues },
            { type: "ssrf", label: "Possible SSRF entry points", urls: ssrfClues },
            { type: "vpn", label: "VPN and remote access surfaces", urls: vpnClues },
            { type: "xmlrpc", label: "XML-RPC surfaces", urls: xmlrpcClues },
            { type: "graphql", label: "GraphQL endpoints", urls: graphqlClues },
            { type: "api_docs", label: "API documentation exposure", urls: apiDocClues },
            { type: "debug", label: "Debug and diagnostics endpoints", urls: debugClues },
          ].filter((item) => item.urls.length > 0),
        },
        parameters: Array.from(parameterSet),
        directories: Array.from(directorySet),
        jsFiles: Array.from(jsFileSet),
        robotsLatest,
        robotsArchive: Array.from(robotsArchiveSet),
        timeline: Array.from(timelineMap.values()).sort((a, b) => a.period.localeCompare(b.period)),
        logs,
        reconMeta: {
          mode,
          depth: runtimeConfig.depth,
          config: runtimeConfig,
          sourceCounts: Object.fromEntries(Array.from(sourceCounts.entries()).sort((left, right) => right[1] - left[1])),
          liveHosts: assets.filter((asset) => asset.live).map((asset) => asset.hostname),
          toolExecutions: summarizeToolExecutions(toolExecutions),
        },
      };

      saveScan(savedScan);
      send({ type: "snapshot", scan: savedScan });
      send({ type: "done", status: summary.status, scanId, summary });
      log("Scan completed successfully");
    } catch (error) {
      if ((error as Error).name === "AbortError") {
        send({ type: "done", status: "stopped", scanId });
      } else {
        console.error(error);
        send({ type: "error", message: (error as Error).message || "Scan failed" });
      }
    } finally {
      res.end();
    }
  });

  const distPath = path.join(process.cwd(), "dist");
  const builtIndexPath = path.join(distPath, "index.html");
  const hasBuiltClient = fs.existsSync(builtIndexPath);
  const forceViteDev = process.env.USE_VITE_DEV === "true";
  const useViteMiddleware = forceViteDev || !hasBuiltClient;

  if (useViteMiddleware) {
    const { createServer: createViteServer } = await import("vite");
    const [{ default: react }, { default: tailwindcss }] = await Promise.all([
      import("@vitejs/plugin-react"),
      import("@tailwindcss/vite"),
    ]);
    const vite = await createViteServer({
      configFile: false,
      plugins: [react(), tailwindcss()],
      server: { middlewareMode: true, hmr: false },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();



