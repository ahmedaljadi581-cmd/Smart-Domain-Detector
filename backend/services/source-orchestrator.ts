import fs from "fs";
import os from "os";
import path from "path";
import { ArchiveRecord, ProbeResult, ReconMode, ScanDepth, ScanRuntimeConfig, ToolExecution, ToolTimeoutKey } from "../types";
import { normalizeDomainInput } from "./scan-runtime";
import { getToolAvailability, runLineTool } from "./tool-runner";

export type SubdomainSourceHit = {
  hostname: string;
  source: string;
};

type ModeBudget = {
  maxSubdomains: number;
  maxArchiveHosts: number;
  maxUrlsPerHost: number;
  perToolTimeoutMs: number;
  subdomainToolConcurrency: number;
};

type ToolReporter = (execution: ToolExecution) => void;

type HttpxJsonLine = {
  input?: string;
  host?: string;
  url?: string;
  final_url?: string;
  title?: string;
  status_code?: number;
  content_type?: string;
  content_length?: number;
  webserver?: string;
  hash?: Record<string, string> | string;
};

function extractHostnameCandidate(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return "";
  try {
    return new URL(trimmed).hostname;
  } catch {
    return trimmed.replace(/^https?:\/\//i, "").split("/")[0] || "";
  }
}

const MODE_BUDGETS: Record<ReconMode, ModeBudget> = {
  quick: { maxSubdomains: 60, maxArchiveHosts: 4, maxUrlsPerHost: 120, perToolTimeoutMs: 7000, subdomainToolConcurrency: 3 },
  live: { maxSubdomains: 180, maxArchiveHosts: 35, maxUrlsPerHost: 260, perToolTimeoutMs: 22000, subdomainToolConcurrency: 4 },
  full: { maxSubdomains: 420, maxArchiveHosts: 70, maxUrlsPerHost: 480, perToolTimeoutMs: 35000, subdomainToolConcurrency: 4 },
  custom: { maxSubdomains: 280, maxArchiveHosts: 50, maxUrlsPerHost: 360, perToolTimeoutMs: 28000, subdomainToolConcurrency: 4 },
};

const DEPTH_MULTIPLIER: Record<ScanDepth, { subdomains: number; archiveHosts: number; urlsPerHost: number }> = {
  standard: { subdomains: 1, archiveHosts: 1, urlsPerHost: 1 },
  aggressive: { subdomains: 1.3, archiveHosts: 1.4, urlsPerHost: 1.35 },
  deep: { subdomains: 1.6, archiveHosts: 1.8, urlsPerHost: 1.7 },
  custom: { subdomains: 1, archiveHosts: 1, urlsPerHost: 1 },
};

const DEPTH_TIMEOUT_MULTIPLIER: Record<ScanDepth, number> = {
  standard: 1,
  aggressive: 1.25,
  deep: 1.75,
  custom: 1,
};

const TOOL_TIMEOUT_OVERRIDES: Record<ReconMode, Partial<Record<string, number>>> = {
  quick: {
    subfinder: 45000,
    assetfinder: 9000,
    amass: 11000,
    findomain: 20000,
    gau: 25000,
    waybackurls: 15000,
    httpx: 20000,
    katana: 22000,
    waymore: 15000,
    arjun: 12000,
    subzy: 12000,
  },
  live: {
    amass: 38000,
    subfinder: 38000,
    findomain: 26000,
    subcat: 22000,
    gau: 30000,
    waybackurls: 25000,
    httpx: 22000,
    katana: 26000,
    waymore: 30000,
    arjun: 22000,
    subzy: 16000,
  },
  full: {
    amass: 70000,
    findomain: 45000,
    gau: 50000,
    subfinder: 65000,
    subcat: 55000,
    waybackurls: 40000,
    httpx: 45000,
    katana: 45000,
    waymore: 65000,
    arjun: 45000,
    subzy: 22000,
  },
  custom: {
    amass: 50000,
    subfinder: 50000,
    findomain: 32000,
    subcat: 32000,
    gau: 38000,
    waybackurls: 28000,
    httpx: 32000,
    katana: 32000,
    waymore: 42000,
    arjun: 30000,
    subzy: 18000,
  },
};

const SUBDOMAIN_TOOL_SPECS: Array<{
  name: string;
  args: (domain: string, timeoutMs: number, mode: ReconMode) => string[];
}> = [
  { name: "subfinder", args: (domain, timeoutMs, mode) => ["-silent", ...(mode === "quick" ? [] : ["-all"]), "-d", domain, "-timeout", String(Math.max(10, Math.min(60, Math.round(timeoutMs / 1000))))] },
  { name: "amass", args: (domain) => ["enum", "-passive", "-norecursive", "-d", domain] },
  { name: "findomain", args: (domain) => ["--quiet", "-t", domain] },
  { name: "assetfinder", args: (domain) => ["--subs-only", domain] },
  { name: "chaos", args: (domain) => ["-d", domain, "-silent"] },
  { name: "subcat", args: (domain, _timeoutMs, mode) => ["-d", domain, "-silent", "-nc", "-t", mode === "full" ? "20" : "12"] },
];

const URL_TOOL_SPECS: Array<{
  name: string;
  args: (host: string) => string[];
  stdin?: (host: string) => string | undefined;
}> = [
  { name: "waybackurls", args: () => [], stdin: (host) => `${host}\n` },
  { name: "gau", args: (host) => ["--providers", "wayback,commoncrawl,otx,urlscan", "--subs", host] },
];

function keepInScope(hostname: string, domain: string): boolean {
  const normalized = normalizeDomainInput(hostname);
  if (!(normalized === domain || normalized.endsWith(`.${domain}`))) return false;
  if (normalized.length < 3 || normalized.length > 253) return false;
  const labels = normalized.split(".");
  return labels.every((label) => (
    Boolean(label)
    && label.length <= 63
    && !label.startsWith("-")
    && !label.endsWith("-")
    && /^[a-z0-9-]+$/.test(label)
  ));
}

function normalizeUrlCandidate(input: string): string | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  try {
    return new URL(trimmed).toString();
  } catch {
    return null;
  }
}

function makeTempPath(prefix: string, suffix: string): string {
  return path.join(os.tmpdir(), `smart-domain-detector-${prefix}-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}${suffix}`);
}

function safeDelete(filePath?: string) {
  if (!filePath) return;
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch {
    // Ignore temp cleanup failures.
  }
}

function readFileLines(filePath?: string): string[] {
  if (!filePath || !fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, "utf8").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function parseHttpxProbeLine(line: string): { host: string; probe: ProbeResult } | null {
  try {
    const parsed = JSON.parse(line) as HttpxJsonLine;
    const host = normalizeDomainInput(
      extractHostnameCandidate(parsed.input || "")
      || extractHostnameCandidate(parsed.host || "")
      || extractHostnameCandidate(parsed.url || "")
      || extractHostnameCandidate(parsed.final_url || ""),
    );
    if (!host) return null;
    const finalUrl = normalizeUrlCandidate(parsed.final_url || parsed.url || "") || `https://${host}`;
    const hashValue = typeof parsed.hash === "string"
      ? parsed.hash
      : parsed.hash && typeof parsed.hash === "object"
        ? parsed.hash.sha1 || parsed.hash.sha256 || Object.values(parsed.hash)[0]
        : undefined;
    return {
      host,
      probe: {
        alive: Boolean(parsed.status_code && parsed.status_code > 0),
        status: Number(parsed.status_code || 0),
        title: parsed.title || "No Title",
        finalUrl,
        contentType: parsed.content_type,
        contentLength: parsed.content_length ?? null,
        server: parsed.webserver ?? null,
        contentHash: hashValue ?? null,
      },
    };
  } catch {
    return null;
  }
}

function parseArjunOutputLines(lines: string[]): string[] {
  const parameters = new Set<string>();
  for (const line of lines) {
    if (!line || /^https?:\/\//i.test(line)) continue;
    for (const token of line.split(/[,\s]+/)) {
      const normalized = token.replace(/[^a-zA-Z0-9_.-]/g, "").trim().toLowerCase();
      if (/^[a-z][a-z0-9_.-]{1,40}$/.test(normalized) && !["parameters", "param", "found", "endpoint", "warning"].includes(normalized)) {
        parameters.add(normalized);
      }
    }
  }
  return Array.from(parameters);
}

function extractScopedHostnames(input: string, domain: string): string[] {
  const hostnames = new Set<string>();
  for (const match of input.matchAll(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi)) {
    const hostname = normalizeDomainInput(match[0]);
    if (keepInScope(hostname, domain)) {
      hostnames.add(hostname);
    }
  }
  return Array.from(hostnames);
}

function getToolTimeout(mode: ReconMode, toolName: ToolTimeoutKey | string, fallbackMs: number, config?: ScanRuntimeConfig): number {
  const configured = config?.toolTimeouts?.[toolName as ToolTimeoutKey];
  const baseTimeout = configured ?? TOOL_TIMEOUT_OVERRIDES[mode][toolName] ?? fallbackMs;
  const multiplier = DEPTH_TIMEOUT_MULTIPLIER[config?.depth || "standard"] ?? 1;
  return Math.min(180000, Math.round(baseTimeout * multiplier));
}

function buildModeSkipExecution(
  name: string,
  category: ToolExecution["category"],
  details: string,
  host?: string,
): ToolExecution {
  const availability = getToolAvailability(name);
  return {
    ...availability,
    name,
    category,
    used: false,
    status: "skipped",
    details,
    host,
    reasonKind: "config",
  };
}

function softenSupplementaryTimeoutExecution(
  execution: ToolExecution,
  count: number,
  detail: string,
): ToolExecution {
  if (count === 0 && execution.status === "failed" && ["timeout", "network"].includes(execution.reasonKind || "")) {
    return {
      ...execution,
      status: "completed",
      reasonKind: "partial",
      details: detail,
      count,
    };
  }
  return { ...execution, count };
}

async function fetchJson<T>(url: string, abortSignal: AbortSignal, headers?: Record<string, string>, retries = 2): Promise<T | null> {
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const response = await fetch(url, {
        signal: abortSignal,
        headers: {
          "User-Agent": "Smart-Domain-Detector/1.0",
          ...(headers || {}),
        },
      });
      if (response.ok) {
        return (await response.json()) as T;
      }
      if (attempt >= retries || ![408, 425, 429, 500, 502, 503, 504].includes(response.status)) {
        return null;
      }
    } catch {
      if (attempt >= retries) {
        return null;
      }
    }
    await sleepWithAbort(800 * (attempt + 1), abortSignal);
  }
  return null;
}

async function fetchText(url: string, abortSignal: AbortSignal, retries = 1): Promise<string | null> {
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const response = await fetch(url, {
        signal: abortSignal,
        headers: { "User-Agent": "Smart-Domain-Detector/1.0" },
      });
      if (response.ok) {
        return await response.text();
      }
      if (attempt >= retries || ![408, 425, 429, 500, 502, 503, 504].includes(response.status)) {
        return null;
      }
    } catch {
      if (attempt >= retries) {
        return null;
      }
    }
    await sleepWithAbort(800 * (attempt + 1), abortSignal);
  }
  return null;
}

export async function discoverSubdomains(
  domain: string,
  mode: ReconMode,
  abortSignal: AbortSignal,
  config?: ScanRuntimeConfig,
  reportTool?: ToolReporter,
): Promise<{ hits: SubdomainSourceHit[]; toolExecutions: ToolExecution[] }> {
  const budget = getModeBudget(mode, config?.depth);
  const hits: SubdomainSourceHit[] = [];
  const toolExecutions: ToolExecution[] = [];
  const queue = [...SUBDOMAIN_TOOL_SPECS];
  const workerCount = Math.max(1, Math.min(budget.subdomainToolConcurrency, SUBDOMAIN_TOOL_SPECS.length));
  const workers = Array.from({ length: workerCount }, async () => {
    while (queue.length > 0 && !abortSignal.aborted) {
      const spec = queue.shift();
      if (!spec) break;
      if (mode === "quick" && ["amass", "subcat"].includes(spec.name)) {
        const execution = buildModeSkipExecution(
          spec.name,
          "subdomain",
          "Skipped in quick triage to keep passive discovery fast; primary passive sources remain active",
        );
        toolExecutions.push(execution);
        reportTool?.(execution);
        continue;
      }
      if (spec.name === "chaos" && !process.env.PDCP_API_KEY) {
        const availability = getToolAvailability("chaos");
        const execution = {
          ...availability,
          category: "subdomain",
          status: availability.available ? "skipped" : availability.status,
          details: availability.available ? "PDCP_API_KEY not configured; chaos source skipped" : availability.details,
          reasonKind: availability.available ? "config" : availability.reasonKind,
        } satisfies ToolExecution;
        toolExecutions.push(execution);
        reportTool?.(execution);
        continue;
      }

      reportTool?.({
        name: spec.name,
        category: "subdomain",
        available: true,
        used: true,
        status: "running",
        details: `Running ${spec.name} passive discovery`,
        reasonKind: "info",
      });
      const timeoutMs = getToolTimeout(mode, spec.name, budget.perToolTimeoutMs, config);

      const result = await runLineTool(
        spec.name,
        spec.args(domain, timeoutMs, mode),
        "subdomain",
        abortSignal,
        timeoutMs,
      );
      const scoped = result.stdoutLines
        .map((line) => normalizeDomainInput(line))
        .filter((hostname) => keepInScope(hostname, domain))
        .slice(0, budget.maxSubdomains);

      const execution = spec.name === "subcat"
        ? softenSupplementaryTimeoutExecution(
            result.execution,
            scoped.length,
            "Time budget reached before supplementary passive results were returned; primary passive sources remained active",
          )
        : { ...result.execution, count: scoped.length } satisfies ToolExecution;
      toolExecutions.push(execution);
      reportTool?.(execution);
      for (const hostname of scoped) {
        hits.push({ hostname, source: spec.name });
      }
    }
  });
  await Promise.all(workers);

  const crtsh = await fetchJson<Array<{ name_value?: string }>>(`https://crt.sh/?q=%25.${domain}&output=json`, abortSignal);
  if (crtsh) {
    const scoped = crtsh
      .flatMap((item) => (item.name_value || "").split(/\s+/))
      .map((entry) => entry.replace(/^\*\./, ""))
      .map((entry) => normalizeDomainInput(entry))
      .filter((hostname) => keepInScope(hostname, domain))
      .slice(0, budget.maxSubdomains);
    const execution = {
      name: "crtsh",
      category: "native",
      available: true,
      used: true,
      status: "completed",
      count: scoped.length,
      reasonKind: "success",
    } satisfies ToolExecution;
    toolExecutions.push(execution);
    reportTool?.(execution);
    for (const hostname of scoped) {
      hits.push({ hostname, source: "crtsh" });
    }
  } else {
    const execution = {
      name: "crtsh",
      category: "native",
      available: true,
      used: true,
      status: "failed",
      details: "Passive certificate lookup unavailable",
      reasonKind: "network",
    } satisfies ToolExecution;
    toolExecutions.push(execution);
    reportTool?.(execution);
  }

  const certspotter = await fetchJson<Array<{ dns_names?: string[] }>>(
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`,
    abortSignal,
  );
  if (certspotter) {
    const scoped = certspotter
      .flatMap((item) => item.dns_names || [])
      .map((entry) => entry.replace(/^\*\./, ""))
      .map((entry) => normalizeDomainInput(entry))
      .filter((hostname) => keepInScope(hostname, domain))
      .slice(0, budget.maxSubdomains);
    const execution = {
      name: "certspotter",
      category: "native",
      available: true,
      used: true,
      status: "completed",
      count: scoped.length,
      reasonKind: "success",
    } satisfies ToolExecution;
    toolExecutions.push(execution);
    reportTool?.(execution);
    for (const hostname of scoped) {
      hits.push({ hostname, source: "certspotter" });
    }
  } else {
    const execution = {
      name: "certspotter",
      category: "native",
      available: true,
      used: true,
      status: "failed",
      details: "Certificate API lookup unavailable",
      reasonKind: "network",
    } satisfies ToolExecution;
    toolExecutions.push(execution);
    reportTool?.(execution);
  }

  const bufferOverApiKey = process.env.BUFFEROVER_API_KEY;
  if (!bufferOverApiKey) {
    const execution = {
      name: "bufferover",
      category: "native",
      available: true,
      used: false,
      status: "skipped",
      details: "BUFFEROVER_API_KEY not configured; BufferOver source skipped",
      reasonKind: "config",
    } satisfies ToolExecution;
    toolExecutions.push(execution);
    reportTool?.(execution);
  } else {
    const bufferOver = await fetchJson<{ FDNS_A?: string[]; RDNS?: string[] }>(
      `https://tls.bufferover.run/dns?q=.${domain}`,
      abortSignal,
      { "x-api-key": bufferOverApiKey },
    );
    if (bufferOver) {
      const scoped = [...(bufferOver.FDNS_A || []), ...(bufferOver.RDNS || [])]
        .map((entry) => entry.split(",").pop() || entry)
        .map((entry) => normalizeDomainInput(entry))
        .filter((hostname) => keepInScope(hostname, domain))
        .slice(0, budget.maxSubdomains);
      const execution = {
        name: "bufferover",
        category: "native",
        available: true,
        used: true,
        status: "completed",
        count: scoped.length,
        reasonKind: "success",
      } satisfies ToolExecution;
      toolExecutions.push(execution);
      reportTool?.(execution);
      for (const hostname of scoped) {
        hits.push({ hostname, source: "bufferover" });
      }
    } else {
      const execution = {
        name: "bufferover",
        category: "native",
        available: true,
        used: true,
        status: "failed",
        details: "BufferOver query failed or API key was rejected",
        reasonKind: "network",
      } satisfies ToolExecution;
      toolExecutions.push(execution);
      reportTool?.(execution);
    }
  }

  hits.push({ hostname: domain, source: "scope-root" });

  return { hits, toolExecutions };
}

function parseWaybackText(text: string | null, source: string, limit: number): ArchiveRecord[] {
  if (!text) return [];
  const records: ArchiveRecord[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 2) continue;
    const [timestamp, original, statusCode, mimeType, digest] = parts;
    records.push({
      url: original,
      source: source as ArchiveRecord["source"],
      timestamp,
      statusCode: statusCode ? Number(statusCode) || null : null,
      mimeType: mimeType ?? null,
      digest: digest ?? null,
    });
    if (records.length >= limit) break;
  }
  return records;
}

async function fetchArchiveSnapshot(host: string, limit: number, abortSignal: AbortSignal): Promise<{ text: string | null; failureDetails?: string }> {
  const url = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(host)}/*&matchType=domain&collapse=urlkey&output=txt&limit=${limit}&fl=timestamp,original,statuscode,mimetype,digest`;
  try {
    const response = await fetch(url, {
      signal: abortSignal,
      headers: { "User-Agent": "Smart-Domain-Detector/1.0" },
    });
    if (!response.ok) {
      if (response.status === 429) {
        return { text: null, failureDetails: "Rate limited by web archive (429)" };
      }
      return { text: null, failureDetails: `Archive query returned HTTP ${response.status}` };
    }
    return { text: await response.text() };
  } catch {
    return { text: null, failureDetails: "Archive query unavailable" };
  }
}

type ArchiveCacheEntry = {
  text: string | null;
  failureDetails?: string;
  expiresAt: number;
};

const archiveCache = new Map<string, ArchiveCacheEntry>();
let nativeArchiveCooldownUntil = 0;

async function sleepWithAbort(ms: number, abortSignal: AbortSignal): Promise<void> {
  if (ms <= 0) return;
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      abortSignal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      resolve();
    };
    abortSignal.addEventListener("abort", onAbort, { once: true });
  });
}

async function fetchArchiveSnapshotWithRetry(
  host: string,
  limit: number,
  abortSignal: AbortSignal,
  config?: ScanRuntimeConfig,
): Promise<{ text: string | null; failureDetails?: string }> {
  if (nativeArchiveCooldownUntil > Date.now()) {
    return { text: null, failureDetails: "Web archive temporarily rate-limited; native archive lookup paused" };
  }
  const cacheKey = `${host}:${limit}`;
  const cached = archiveCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return { text: cached.text, failureDetails: cached.failureDetails };
  }

  const attempts = Math.max(1, (config?.archiveRetryCount ?? 2) + 1);
  let lastResult: { text: string | null; failureDetails?: string } = { text: null, failureDetails: "Archive query unavailable" };
  for (let attempt = 1; attempt <= attempts && !abortSignal.aborted; attempt += 1) {
    lastResult = await fetchArchiveSnapshot(host, limit, abortSignal);
    if (lastResult.text || !/429/.test(lastResult.failureDetails || "")) {
      break;
    }
    if (attempt < attempts) {
      await sleepWithAbort((config?.archiveRetryBackoffMs ?? 1800) * attempt, abortSignal);
    }
  }

  const ttlMs = lastResult.text
    ? 30 * 60 * 1000
    : /429/.test(lastResult.failureDetails || "")
      ? 10 * 60 * 1000
      : 5 * 60 * 1000;
  if (/429|rate-limit/i.test(lastResult.failureDetails || "")) {
    nativeArchiveCooldownUntil = Date.now() + ttlMs;
  }
  archiveCache.set(cacheKey, { ...lastResult, expiresAt: Date.now() + ttlMs });
  return lastResult;
}

export async function collectArchiveRecordsForHost(
  host: string,
  mode: ReconMode,
  abortSignal: AbortSignal,
  config?: ScanRuntimeConfig,
  reportTool?: ToolReporter,
  strategy?: {
    deepCrawl?: boolean;
    deepArchive?: boolean;
  },
): Promise<{ records: ArchiveRecord[]; toolExecutions: ToolExecution[] }> {
  const budget = getModeBudget(mode, config?.depth);
  const toolExecutions: ToolExecution[] = [];
  const records: ArchiveRecord[] = [];
  const urlToolRuns = URL_TOOL_SPECS.map(async (spec) => {
    if (abortSignal.aborted) {
      return;
    }
    reportTool?.({
      name: spec.name,
      category: "archive",
      available: true,
      used: true,
      status: "running",
      details: `Collecting archive URLs from ${spec.name} for ${host}`,
      host,
      reasonKind: "info",
    });
    const result = await runLineTool(
      spec.name,
      spec.args(host),
      "archive",
      abortSignal,
      getToolTimeout(mode, spec.name, budget.perToolTimeoutMs, config),
      spec.stdin?.(host),
    );
    const urls = result.stdoutLines
      .map((line) => normalizeUrlCandidate(line))
      .filter((value): value is string => Boolean(value))
      .slice(0, budget.maxUrlsPerHost);

    const execution = { ...result.execution, count: urls.length, host } satisfies ToolExecution;
    toolExecutions.push(execution);
    reportTool?.(execution);
    for (const url of urls) {
      records.push({
        url,
        source: spec.name === "gau" ? "commoncrawl" : "wayback",
      });
    }
  });
  await Promise.all(urlToolRuns);

  reportTool?.({
    name: "wayback-native",
    category: "native",
    available: true,
    used: true,
    status: "running",
    details: `Querying native web archive for ${host}`,
    host,
    reasonKind: "info",
  });
  const nativeArchive = await fetchArchiveSnapshotWithRetry(host, budget.maxUrlsPerHost, abortSignal, config);
  const nativeWayback = parseWaybackText(nativeArchive.text, "wayback", budget.maxUrlsPerHost);
  const nativeExecution = {
    name: "wayback-native",
    category: "native",
    available: true,
    used: true,
    status: nativeWayback.length > 0 ? "completed" : /429|rate-limit/i.test(nativeArchive.failureDetails || "") ? "skipped" : "failed",
    details: nativeWayback.length > 0 ? undefined : (nativeArchive.failureDetails || "No archive records returned"),
    count: nativeWayback.length,
    host,
    reasonKind: nativeWayback.length > 0 ? "success" : /429|rate-limit/i.test(nativeArchive.failureDetails || "") ? "rate-limit" : /unavailable/i.test(nativeArchive.failureDetails || "") ? "network" : "crash",
  } satisfies ToolExecution;
  toolExecutions.push(nativeExecution);
  reportTool?.(nativeExecution);
  records.push(...nativeWayback);

  if (!abortSignal.aborted && strategy?.deepCrawl !== false) {
    reportTool?.({
      name: "katana",
      category: "archive",
      available: true,
      used: true,
      status: "running",
      details: `Crawling live endpoints with katana for ${host}`,
      host,
      reasonKind: "info",
    });
    const katanaTimeoutMs = getToolTimeout(mode, "katana", budget.perToolTimeoutMs, config);
    const katanaResult = await runLineTool(
      "katana",
      [
        "-u",
        `https://${host}`,
        "-silent",
        "-d",
        String(Math.max(1, Math.min(4, config?.directoryMaxDepth ?? 2))),
        "-timeout",
        String(Math.max(5, Math.round(katanaTimeoutMs / 1000))),
        "-ct",
        mode === "full" ? "25s" : mode === "live" ? "18s" : "12s",
        "-kf",
        "all",
        "-jc",
        "-iqp",
      ],
      "archive",
      abortSignal,
      katanaTimeoutMs,
    );
    const katanaUrls = katanaResult.stdoutLines
      .map((line) => normalizeUrlCandidate(line))
      .filter((value): value is string => Boolean(value))
      .slice(0, budget.maxUrlsPerHost);
    const katanaExecution = { ...katanaResult.execution, count: katanaUrls.length, host } satisfies ToolExecution;
    toolExecutions.push(katanaExecution);
    reportTool?.(katanaExecution);
    for (const url of katanaUrls) {
      records.push({ url, source: "live" });
    }
  }

  if (strategy?.deepCrawl === false) {
    const execution = {
      ...getToolAvailability("katana"),
      category: "archive",
      status: "skipped",
      details: "Skipped live crawl for this host to prioritize higher-value archive targets",
      host,
      reasonKind: "config",
    } satisfies ToolExecution;
    toolExecutions.push(execution);
    reportTool?.(execution);
  }

  const allowWaymore = !abortSignal.aborted && strategy?.deepArchive !== false && mode !== "quick";
  if (allowWaymore) {
    const outputFile = makeTempPath("waymore", ".txt");
    try {
      reportTool?.({
        name: "waymore",
        category: "archive",
        available: true,
        used: true,
        status: "running",
        details: `Collecting expanded archive URLs from waymore for ${host}`,
        host,
        reasonKind: "info",
      });
      const waymoreTimeoutMs = getToolTimeout(mode, "waymore", budget.perToolTimeoutMs, config);
      const waymoreResult = await runLineTool(
        "waymore",
        [
          "-i",
          host,
          "-mode",
          "U",
          "-oU",
          outputFile,
          "--providers",
          "wayback,commoncrawl,otx,urlscan",
          "-p",
          "1",
          "-r",
          "1",
          "-t",
          String(Math.max(5, Math.round(waymoreTimeoutMs / 1000))),
        ],
        "archive",
        abortSignal,
        waymoreTimeoutMs,
      );
      const waymoreUrls = readFileLines(outputFile)
        .map((line) => normalizeUrlCandidate(line))
        .filter((value): value is string => Boolean(value))
        .slice(0, budget.maxUrlsPerHost);
      const waymoreExecution = { ...waymoreResult.execution, count: waymoreUrls.length, host } satisfies ToolExecution;
      toolExecutions.push(waymoreExecution);
      reportTool?.(waymoreExecution);
      for (const url of waymoreUrls) {
        records.push({ url, source: "commoncrawl" });
      }
    } finally {
      safeDelete(outputFile);
    }
  }

  if (strategy?.deepArchive === false || mode === "quick") {
    const execution = buildModeSkipExecution(
      "waymore",
      "archive",
      mode === "quick"
        ? "Skipped in quick triage to keep historical collection fast; native archive, gau, and waybackurls remain active"
        : "Skipped deep archive expansion for this host to keep historical collection focused",
      host,
    );
    toolExecutions.push(execution);
    reportTool?.(execution);
  }

  return { records, toolExecutions };
}

export async function probeHostsWithHttpx(
  hosts: string[],
  mode: ReconMode,
  abortSignal: AbortSignal,
  config?: ScanRuntimeConfig,
  reportTool?: ToolReporter,
): Promise<{ results: Map<string, ProbeResult>; execution: ToolExecution } | null> {
  const uniqueHosts = Array.from(new Set(hosts.map((host) => normalizeDomainInput(host)).filter(Boolean)));
  if (uniqueHosts.length === 0) return null;

  reportTool?.({
    name: "httpx",
    category: "probe",
    available: true,
    used: true,
    status: "running",
    details: `Batch probing ${uniqueHosts.length} host(s) with httpx`,
    reasonKind: "info",
  });

  const timeoutMs = getToolTimeout(mode, "httpx", MODE_BUDGETS[mode].perToolTimeoutMs, config);
  const result = await runLineTool(
    "httpx",
    [
      "-silent",
      "-json",
      "-sc",
      "-title",
      "-ct",
      "-cl",
      "-server",
      "-ip",
      "-cname",
      "-fhr",
      "-timeout",
      String(Math.max(5, Math.round(timeoutMs / 1000))),
      "-threads",
      mode === "full" ? "40" : mode === "live" ? "30" : "20",
      "-retries",
      "1",
    ],
    "probe",
    abortSignal,
    timeoutMs,
    `${uniqueHosts.join("\n")}\n`,
  );

  if (!result.execution.available || result.execution.status === "missing") {
    return null;
  }

  const probes = new Map<string, ProbeResult>();
  for (const line of result.stdoutLines) {
    const parsed = parseHttpxProbeLine(line);
    if (!parsed) continue;
    probes.set(parsed.host, parsed.probe);
  }

  return {
    results: probes,
    execution: {
      ...result.execution,
      status: result.execution.status === "failed" && probes.size === 0 && /Exited with code 1/i.test(result.execution.details || "")
        ? "completed"
        : result.execution.status,
      details: result.execution.status === "failed" && probes.size === 0 && /Exited with code 1/i.test(result.execution.details || "")
        ? "No live HTTP results returned by httpx; fallback host probing remained active"
        : result.execution.details,
      count: probes.size,
      reasonKind: probes.size > 0 && result.execution.status === "failed"
        ? "partial"
        : result.execution.status === "failed" && probes.size === 0 && /Exited with code 1/i.test(result.execution.details || "")
          ? "info"
          : result.execution.reasonKind,
    },
  };
}

export async function discoverParametersWithArjun(
  targets: string[],
  mode: ReconMode,
  abortSignal: AbortSignal,
  config?: ScanRuntimeConfig,
  reportTool?: ToolReporter,
): Promise<{ parameters: string[]; toolExecutions: ToolExecution[] }> {
  if (mode === "quick") {
    const execution = buildModeSkipExecution(
      "arjun",
      "archive",
      "Parameter discovery skipped in quick triage to prioritize core recon speed",
    );
    reportTool?.(execution);
    return { parameters: [], toolExecutions: [execution] };
  }

  const uniqueTargets = Array.from(new Set(targets.map((target) => normalizeUrlCandidate(target)).filter((value): value is string => Boolean(value))));
  const parameters = new Set<string>();
  const toolExecutions: ToolExecution[] = [];
  const queue = [...uniqueTargets];
  const workerCount = 1;
  const workers = Array.from({ length: workerCount }, async () => {
    while (queue.length > 0 && !abortSignal.aborted) {
      const target = queue.shift();
      if (!target) break;
      const outputFile = makeTempPath("arjun", ".txt");
      try {
        reportTool?.({
          name: "arjun",
          category: "archive",
          available: true,
          used: true,
          status: "running",
          details: `Discovering hidden parameters for ${target}`,
          host: new URL(target).hostname,
          reasonKind: "info",
        });
        const timeoutMs = getToolTimeout(mode, "arjun", MODE_BUDGETS[mode].perToolTimeoutMs, config);
        const result = await runLineTool(
          "arjun",
          [
            "-u",
            target,
            "-oT",
            outputFile,
            "--passive",
            "--stable",
            "-q",
            "-T",
            String(Math.max(5, Math.round(timeoutMs / 1000))),
            "-t",
            mode === "full" ? "4" : "3",
          ],
          "archive",
          abortSignal,
          timeoutMs,
        );
        const parsedParameters = parseArjunOutputLines(readFileLines(outputFile).concat(result.stdoutLines));
        parsedParameters.forEach((parameter) => parameters.add(parameter));
        const normalizedExecution = softenSupplementaryTimeoutExecution(
          result.execution,
          parsedParameters.length,
          result.execution.reasonKind === "network"
            ? "Passive parameter providers were unstable during lookup; scan continued without Arjun-only parameters"
            : "Time budget reached before passive parameter discovery returned results; scan continued without Arjun-only parameters",
        );
        const execution = {
          ...normalizedExecution,
          host: new URL(target).hostname,
        } satisfies ToolExecution;
        toolExecutions.push(execution);
        reportTool?.(execution);
      } finally {
        safeDelete(outputFile);
      }
    }
  });
  await Promise.all(workers);

  return { parameters: Array.from(parameters).sort(), toolExecutions };
}

export async function checkSubdomainTakeoverWithSubzy(
  hosts: string[],
  domain: string,
  mode: ReconMode,
  abortSignal: AbortSignal,
  config?: ScanRuntimeConfig,
  reportTool?: ToolReporter,
): Promise<{ vulnerableHosts: Array<{ hostname: string; details: string }>; execution: ToolExecution }> {
  const uniqueHosts = Array.from(new Set(hosts.map((host) => normalizeDomainInput(host)).filter((host) => keepInScope(host, domain))));
  const inputFile = makeTempPath("subzy-input", ".txt");
  const outputFile = makeTempPath("subzy-output", ".json");

  try {
    fs.writeFileSync(inputFile, `${uniqueHosts.join("\n")}\n`, "utf8");
    reportTool?.({
      name: "subzy",
      category: "probe",
      available: true,
      used: true,
      status: "running",
      details: `Checking ${uniqueHosts.length} host(s) for takeover indicators`,
      reasonKind: "info",
    });
    const timeoutMs = getToolTimeout(mode, "subzy", MODE_BUDGETS[mode].perToolTimeoutMs, config);
    const result = await runLineTool(
      "subzy",
      [
        "run",
        "--targets",
        inputFile,
        "--output",
        outputFile,
        "--https",
        "--hide_fails",
        "--vuln",
        "--timeout",
        String(Math.max(5, Math.round(timeoutMs / 1000))),
        "--concurrency",
        mode === "full" ? "25" : "15",
      ],
      "probe",
      abortSignal,
      timeoutMs,
    );

    const vulnerableHosts: Array<{ hostname: string; details: string }> = [];
    const rawOutput = fs.existsSync(outputFile) ? fs.readFileSync(outputFile, "utf8") : "";
    if (rawOutput.trim()) {
      try {
        const parsed = JSON.parse(rawOutput) as unknown;
        const entries = Array.isArray(parsed) ? parsed : [parsed];
        for (const entry of entries) {
          const serialized = JSON.stringify(entry);
          for (const hostname of extractScopedHostnames(serialized, domain)) {
            vulnerableHosts.push({ hostname, details: serialized });
          }
        }
      } catch {
        for (const hostname of extractScopedHostnames(rawOutput, domain)) {
          vulnerableHosts.push({ hostname, details: rawOutput });
        }
      }
    }

    return {
      vulnerableHosts,
      execution: {
        ...result.execution,
        count: vulnerableHosts.length,
        reasonKind: vulnerableHosts.length > 0 ? "success" : result.execution.reasonKind,
      },
    };
  } finally {
    safeDelete(inputFile);
    safeDelete(outputFile);
  }
}

export function getModeBudget(mode: ReconMode, depth: ScanDepth = "standard"): ModeBudget {
  const base = MODE_BUDGETS[mode];
  const multiplier = DEPTH_MULTIPLIER[depth];
  return {
    maxSubdomains: Math.round(base.maxSubdomains * multiplier.subdomains),
    maxArchiveHosts: Math.round(base.maxArchiveHosts * multiplier.archiveHosts),
    maxUrlsPerHost: Math.round(base.maxUrlsPerHost * multiplier.urlsPerHost),
    perToolTimeoutMs: base.perToolTimeoutMs,
    subdomainToolConcurrency: base.subdomainToolConcurrency,
  };
}
