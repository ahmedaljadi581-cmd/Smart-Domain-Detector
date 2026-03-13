
import { useEffect, useMemo, useRef, useState, type RefObject } from "react";
import ExcelJS from "exceljs";
import {
  Activity,
  AlertTriangle,
  ChevronDown,
  Database,
  Download,
  Globe,
  History,
  Key,
  Loader2,
  Play,
  Search,
  ShieldAlert,
  SlidersHorizontal,
  Square,
  Terminal,
  X,
} from "lucide-react";
import { AssetsTable } from "./components/AssetsTable";
import { FindingDrawer } from "./components/FindingDrawer";
import { FindingsTable } from "./components/FindingsTable";
import { HistorySidebar } from "./components/HistorySidebar";
import { Finding, ReconMode, SavedScan, ScanDepth, ScanOptions, ScanRuntimeConfig, ScanSummary, Severity, ToolExecution, ToolTimeoutKey } from "./types";

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

const TOOL_TIMEOUT_FIELDS: Array<{ key: ToolTimeoutKey; label: string }> = [
  { key: "subfinder", label: "subfinder" },
  { key: "amass", label: "amass" },
  { key: "findomain", label: "findomain" },
  { key: "assetfinder", label: "assetfinder" },
  { key: "chaos", label: "chaos" },
  { key: "subcat", label: "subcat" },
  { key: "gau", label: "gau" },
  { key: "waybackurls", label: "waybackurls" },
  { key: "dnsx", label: "dnsx" },
  { key: "httpx", label: "httpx" },
  { key: "katana", label: "katana" },
  { key: "waymore", label: "waymore" },
  { key: "arjun", label: "arjun" },
  { key: "subzy", label: "subzy" },
];

const TOOL_TIMEOUT_PRESETS: Record<ReconMode, Partial<Record<ToolTimeoutKey, number>>> = {
  quick: { subfinder: 45000, assetfinder: 9000, amass: 11000, findomain: 20000, gau: 25000, waybackurls: 15000, httpx: 20000, katana: 22000, waymore: 15000, arjun: 12000, subzy: 12000 },
  live: { amass: 38000, subfinder: 38000, findomain: 26000, subcat: 22000, gau: 30000, waybackurls: 25000, httpx: 22000, katana: 26000, waymore: 30000, arjun: 22000, subzy: 16000 },
  full: { amass: 70000, findomain: 45000, gau: 50000, subfinder: 65000, subcat: 55000, waybackurls: 40000, httpx: 45000, katana: 45000, waymore: 65000, arjun: 45000, subzy: 22000 },
  custom: { amass: 50000, subfinder: 50000, findomain: 32000, subcat: 32000, gau: 38000, waybackurls: 28000, httpx: 32000, katana: 32000, waymore: 42000, arjun: 30000, subzy: 18000 },
};

const DEPTH_PRESET_CONFIG: Record<Exclude<ScanDepth, "custom">, Pick<ScanRuntimeConfig, "directoryMaxDepth" | "directoryBreadth" | "archiveRetryCount" | "archiveRetryBackoffMs" | "archiveZeroYieldThreshold">> = {
  standard: { directoryMaxDepth: 1, directoryBreadth: 10, archiveRetryCount: 2, archiveRetryBackoffMs: 1200, archiveZeroYieldThreshold: 4 },
  aggressive: { directoryMaxDepth: 2, directoryBreadth: 20, archiveRetryCount: 3, archiveRetryBackoffMs: 1800, archiveZeroYieldThreshold: 6 },
  deep: { directoryMaxDepth: 4, directoryBreadth: 40, archiveRetryCount: 5, archiveRetryBackoffMs: 2600, archiveZeroYieldThreshold: 10 },
};

const GAUGE_LIMITS = {
  directoryMaxDepth: { min: 1, max: 4, step: 1, suffix: "", label: "Directory max depth" },
  directoryBreadth: { min: 4, max: 40, step: 1, suffix: "", label: "Directory breadth / host" },
  archiveRetryCount: { min: 0, max: 6, step: 1, suffix: "", label: "Archive retries" },
  archiveRetryBackoffMs: { min: 500, max: 10000, step: 100, suffix: "ms", label: "Archive backoff" },
  archiveZeroYieldThreshold: { min: 2, max: 12, step: 1, suffix: "", label: "Zero-yield stop threshold" },
} as const;

const TOOL_TIMEOUT_LIMITS = { min: 4000, max: 120000, step: 1000, suffix: "ms" } as const;
const PAGE_SIZE = 10;
const TOOL_STAGE_ORDER = [
  "subfinder",
  "assetfinder",
  "findomain",
  "amass",
  "chaos",
  "subcat",
  "crtsh",
  "certspotter",
  "bufferover",
  "dnsx",
  "puredns",
  "httpx",
  "subzy",
  "waybackurls",
  "gau",
  "katana",
  "waymore",
  "arjun",
  "wayback-native",
  "live-recursion",
  "bbot",
] as const;

const OPTION_GROUPS: Array<{ label: string; keys: Array<keyof ScanOptions> }> = [
  { label: "Collection", keys: ["waybackUrls", "historicalRobots", "subdomainEnum"] },
  { label: "Detection", keys: ["sensitiveFiles", "backups", "adminPanels", "cloudStorage", "apiKeys", "jwtTokens", "oauthTokens"] },
  { label: "Validation", keys: ["dnsAnalysis", "httpProbing", "parameterDiscovery", "jsAnalysis", "directoryListing"] },
  { label: "Scoring", keys: ["riskScoring"] },
];

function createEmptyScan(domain = "", mode: ReconMode = "full", config: ScanRuntimeConfig = DEFAULT_RUNTIME_CONFIG): SavedScan {
  return {
    summary: {
      id: "live",
      domain,
      startedAt: new Date().toISOString(),
      status: "running",
      mode,
      stats: {
        urlsScanned: 0,
        findings: 0,
        secretFindings: 0,
        exposureFindings: 0,
        subdomainsCount: 0,
        validatedFindings: 0,
        liveFindings: 0,
        uniqueSources: 0,
        liveHosts: 0,
      },
    },
    findings: [],
    assets: [],
    dnsInfo: null,
    targetProfile: {
      ips: [],
      ssl: null,
      ownerEmails: [],
      loginUrls: [],
      criticalUrls: [],
      vpnUrls: [],
      subdomains: [],
      ipIntel: [],
      possibleVulns: [],
    },
    parameters: [],
    directories: [],
    jsFiles: [],
    robotsLatest: "",
    robotsArchive: [],
    timeline: [],
    logs: [],
    reconMeta: {
      mode,
      depth: config.depth,
      config,
      sourceCounts: {},
      liveHosts: [],
      toolExecutions: [],
    },
  };
}

function upsertToolExecution(executions: ToolExecution[], next: ToolExecution): ToolExecution[] {
  const existingIndex = executions.findIndex((entry) => entry.name === next.name);
  if (existingIndex === -1) {
    return [...executions, next].sort((left, right) => left.name.localeCompare(right.name));
  }
  const current = executions[existingIndex];
  const merged: ToolExecution = {
    ...current,
    ...next,
    count: next.count ?? current.count,
    details: next.details ?? current.details,
    reasonKind: next.reasonKind ?? current.reasonKind,
  };
  const updated = [...executions];
  updated[existingIndex] = merged;
  return updated.sort((left, right) => left.name.localeCompare(right.name));
}

function replaceFinding(findings: Finding[], finding: Finding): Finding[] {
  const next = findings.filter((item) => item.id !== finding.id);
  next.push(finding);
  const severityWeight: Record<Severity, number> = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };
  return next.sort((a, b) => severityWeight[b.severity] - severityWeight[a.severity] || b.archive.seenCount - a.archive.seenCount);
}

function prettifyOption(key: keyof ScanOptions) {
  return String(key).replace(/([A-Z])/g, " $1").replace(/^./, (value) => value.toUpperCase());
}

function formatScanMode(options: ScanOptions) {
  const enabled = Object.values(options).filter(Boolean).length;
  if (enabled <= 4) return "Minimal";
  if (enabled <= 9) return "Focused";
  return "Full coverage";
}

function formatArchiveTimestamp(value?: string) {
  if (!value) return "Unknown";
  if (value.includes("T")) return new Date(value).toLocaleString();
  const parsed = new Date(value);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed.toLocaleString();
  }
  if (value.length < 14) return value;
  const iso = `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}T${value.slice(8, 10)}:${value.slice(10, 12)}:${value.slice(12, 14)}Z`;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatLocalDateTime(value?: string) {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });
}

function formatDuration(start?: string, end?: string) {
  if (!start || !end) return null;
  const startTime = new Date(start).getTime();
  const endTime = new Date(end).getTime();
  if (!Number.isFinite(startTime) || !Number.isFinite(endTime) || endTime <= startTime) return null;
  const totalSeconds = Math.round((endTime - startTime) / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

function normalizeDomainInput(input: string) {
  let value = input.trim().toLowerCase();
  if (!value) return "";
  value = value.replace(/^[a-z]+:\/\//i, "");
  value = value.split(/[/?#]/)[0] || value;
  value = value.split("@").pop() || value;
  value = value.replace(/:\d+$/, "");
  value = value.replace(/^\.+|\.+$/g, "");
  value = value.replace(/\.+/g, ".");
  value = value.replace(/[^a-z0-9.-]/g, "");
  return value;
}

function clampValue(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}

function getToolResultLabel(tool: ToolExecution) {
  if (tool.count === undefined || tool.count === null) return null;
  return `${tool.count} result${tool.count === 1 ? "" : "s"}`;
}

function getToolStatusLabel(tool: ToolExecution) {
  const resultLabel = getToolResultLabel(tool);
  if (tool.status === "completed" && resultLabel) {
    return `${tool.reasonKind === "partial" ? "partial" : "completed"} · ${resultLabel}`;
  }
  if (tool.status === "failed" && tool.count && tool.count > 0) {
    return `failed · ${resultLabel}`;
  }
  return tool.reasonKind === "partial" ? "partial" : tool.status;
}

function getToolStatusTextClass(status: ToolExecution["status"]) {
  switch (status) {
    case "completed":
      return "text-emerald-300";
    case "failed":
      return "text-rose-300";
    case "pending":
      return "text-amber-300";
    case "running":
      return "text-cyan-300";
    case "missing":
      return "text-amber-300";
    case "skipped":
    default:
      return "text-slate-400";
  }
}

function getToolDetail(tool: ToolExecution) {
  const detail = tool.details?.trim();
  const transientDetail = detail ? /^(Queued|Running)\b/i.test(detail) : false;
  const resultLabel = getToolResultLabel(tool);

  if (tool.status === "completed") {
    if (detail && !transientDetail) {
      return resultLabel && !new RegExp(`${tool.count}\\s+(?:item|result|hit)`, "i").test(detail)
        ? `${resultLabel} found. ${detail}`
        : detail;
    }
    return resultLabel ? `${resultLabel} found.` : "Completed.";
  }

  if (tool.status === "failed") {
    if (detail && !transientDetail) {
      return resultLabel ? `${detail}. ${resultLabel} recovered.` : detail;
    }
    return resultLabel ? `${resultLabel} recovered before failure.` : "Failed with no results returned.";
  }

  if (tool.status === "skipped") {
    return detail || "Skipped for this scan.";
  }

  if (tool.status === "pending") {
    return detail || "Queued to start.";
  }

  if (tool.status === "running") {
    return detail || "Running now.";
  }

  return detail || (resultLabel ? `${resultLabel} found.` : "No status detail available.");
}

function GaugeControl(props: {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  suffix?: string;
  accentClass?: string;
  onChange: (value: number) => void;
}) {
  const { label, value, min, max, step, suffix, accentClass = "stroke-cyan-300", onChange } = props;
  const clamped = clampValue(value, min, max);
  const progress = ((clamped - min) / (max - min || 1)) * 100;
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (progress / 100) * circumference;

  return (
    <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
      <div className="mb-3 text-xs uppercase tracking-[0.2em] text-slate-500">{label}</div>
      <div className="flex items-center gap-4">
        <div className="relative h-24 w-24 shrink-0">
          <svg viewBox="0 0 92 92" className="h-24 w-24 -rotate-90">
            <circle cx="46" cy="46" r={radius} className="fill-none stroke-white/10" strokeWidth="8" />
            <circle
              cx="46"
              cy="46"
              r={radius}
              className={`fill-none ${accentClass}`}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={dashOffset}
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <div className="text-xl font-semibold text-white">{clamped}</div>
              {suffix ? <div className="text-[10px] uppercase tracking-[0.16em] text-slate-400">{suffix}</div> : null}
            </div>
          </div>
        </div>
        <div className="flex-1">
          <input
            type="range"
            min={min}
            max={max}
            step={step}
            value={clamped}
            onChange={(event) => onChange(Number(event.target.value))}
            className="h-2 w-full cursor-pointer appearance-none rounded-full bg-slate-800 accent-cyan-300"
          />
          <div className="mt-2 flex items-center justify-between text-[11px] uppercase tracking-[0.16em] text-slate-500">
            <span>{min}{suffix ? suffix : ""}</span>
            <span>{max}{suffix ? suffix : ""}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function paginateItems<T>(items: T[], page: number, pageSize = PAGE_SIZE) {
  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const start = (safePage - 1) * pageSize;
  return {
    page: safePage,
    totalPages,
    items: items.slice(start, start + pageSize),
  };
}

function buildPageRows<T>(items: T[], pageSize = PAGE_SIZE): Array<T | null> {
  return Array.from({ length: pageSize }, (_, index) => items[index] ?? null);
}

function renderValueList(values: string[], emptyLabel = "Unavailable", maxHeightClass = "max-h-32") {
  if (values.length === 0) {
    return <div className="text-slate-500">{emptyLabel}</div>;
  }

  return (
    <div className={`${maxHeightClass} space-y-1 overflow-auto pr-1`}>
      {values.map((value) => (
        <div key={value} className="break-all rounded-lg bg-black/20 px-2.5 py-1.5 text-xs text-slate-100">
          {value}
        </div>
      ))}
    </div>
  );
}

function resultBadgeClass(tone: "neutral" | "cyan" | "rose" = "neutral") {
  const toneClass = tone === "cyan"
    ? "border-cyan-400/20 bg-cyan-400/10 text-cyan-100"
    : tone === "rose"
      ? "border-rose-300/20 bg-black/20 text-rose-100"
      : "border-white/10 bg-white/5 text-slate-200";
  return `rounded-full border px-3.5 py-1.5 text-sm font-semibold ${toneClass}`;
}

async function readErrorResponse(response: Response) {
  try {
    const data = await response.json();
    if (typeof data?.message === "string" && data.message.trim()) {
      return data.message.trim();
    }
  } catch {
    try {
      const text = await response.text();
      if (text.trim()) {
        return text.trim();
      }
    } catch {
      return `Request failed with HTTP ${response.status}`;
    }
  }
  return `Request failed with HTTP ${response.status}`;
}

function formatClientError(error: unknown) {
  const message = error instanceof Error ? error.message : String(error || "");
  if (/Failed to fetch|NetworkError|network error/i.test(message)) {
    return "Network error. The scan service could not be reached. Check that Docker is still running on port 3000, then refresh and try again.";
  }
  if (/No response body/i.test(message)) {
    return "The scan stream disconnected before data was returned. Check the Docker logs and try the scan again.";
  }
  return message || "Request failed.";
}

function WaitingState({ label }: { label: string }) {
  return (
    <div className="flex h-full min-h-[8rem] items-center justify-center rounded-lg border border-cyan-400/15 bg-cyan-500/[0.04] px-4 text-center">
      <div className="flex flex-col items-center gap-2 text-slate-300">
        <Loader2 className="h-5 w-5 animate-spin text-cyan-300" />
        <div className="text-xs text-slate-400">{label}</div>
      </div>
    </div>
  );
}

function sortToolExecutionsForDisplay(tools: ToolExecution[]) {
  const statusRank: Record<ToolExecution["status"], number> = {
    running: 0,
    pending: 1,
    completed: 2,
    failed: 3,
    skipped: 4,
    missing: 5,
  };
  const stageIndex = new Map<string, number>(TOOL_STAGE_ORDER.map((name, index) => [name, index]));
  return [...tools].sort((left, right) => {
    const leftStage = stageIndex.get(left.name) ?? 999;
    const rightStage = stageIndex.get(right.name) ?? 999;
    if (leftStage !== rightStage) return leftStage - rightStage;
    if (statusRank[left.status] !== statusRank[right.status]) return statusRank[left.status] - statusRank[right.status];
    return left.name.localeCompare(right.name);
  });
}

export default function App() {
  const currentYear = new Date().getFullYear();
  const [domain, setDomain] = useState("");
  const [status, setStatus] = useState<"idle" | "scanning" | "stopped" | "finished" | "error">("idle");
  const [phase, setPhase] = useState("Ready");
  const [progressDetail, setProgressDetail] = useState("");
  const [error, setError] = useState("");
  const [reconOptions, setReconOptions] = useState<ScanOptions>(DEFAULT_OPTIONS);
  const [runtimeConfig, setRuntimeConfig] = useState<ScanRuntimeConfig>(DEFAULT_RUNTIME_CONFIG);
  const [scan, setScan] = useState<SavedScan | null>(null);
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [activeTab, setActiveTab] = useState<"findings" | "assets" | "history" | "logs">("findings");
  const [selectedFindingId, setSelectedFindingId] = useState<string | undefined>();
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "All">("All");
  const [categoryFilter, setCategoryFilter] = useState<"All" | Finding["category"]>("All");
  const [validationFilter, setValidationFilter] = useState<"All" | Finding["validation"]["status"]>("All");
  const [findingsPage, setFindingsPage] = useState(1);
  const [criticalUrlsPage, setCriticalUrlsPage] = useState(1);
  const [loginUrlsPage, setLoginUrlsPage] = useState(1);
  const [vulnCluesPage, setVulnCluesPage] = useState(1);
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  const [scanPreset, setScanPreset] = useState<"quick" | "live" | "full" | "custom">("full");
  const abortRef = useRef<AbortController | null>(null);
  const intelligenceSectionRef = useRef<HTMLElement | null>(null);
  const findingsSectionRef = useRef<HTMLElement | null>(null);
  const assetsSectionRef = useRef<HTMLElement | null>(null);
  const logsSectionRef = useRef<HTMLElement | null>(null);

  const tabBackgroundClass = "bg-[radial-gradient(circle_at_12%_18%,rgba(34,211,238,0.2),transparent_32%),radial-gradient(circle_at_86%_12%,rgba(59,130,246,0.14),transparent_28%),linear-gradient(180deg,#020617,#0f172a_58%,#020617)]";

  const loadHistory = async () => {
    const response = await fetch("/api/scans");
    if (!response.ok) {
      throw new Error(await readErrorResponse(response));
    }
    const data = await response.json();
    setHistory(data.scans || []);
  };

  useEffect(() => {
    loadHistory().catch((historyError) => setError(formatClientError(historyError)));
  }, []);

  const selectedFinding = scan?.findings.find((finding) => finding.id === selectedFindingId) || null;

  const filteredFindings = useMemo(() => {
    if (!scan) return [];
    return scan.findings.filter((finding) => {
      const haystack = [finding.title, finding.asset, finding.host, finding.match, finding.summary].join(" ").toLowerCase();
      const matchesSearch = !search || haystack.includes(search.toLowerCase());
      const matchesSeverity = severityFilter === "All" || finding.severity === severityFilter;
      const matchesCategory = categoryFilter === "All" || finding.category === categoryFilter;
      const matchesValidation = validationFilter === "All" || finding.validation.status === validationFilter;
      return matchesSearch && matchesSeverity && matchesCategory && matchesValidation;
    });
  }, [scan, search, severityFilter, categoryFilter, validationFilter]);
  const findingsPageState = useMemo(() => paginateItems(filteredFindings, findingsPage), [filteredFindings, findingsPage]);
  const flatVulnClues = useMemo(() => (scan?.targetProfile.possibleVulns || []).flatMap((clue) => clue.urls.map((url) => ({ label: clue.label, url }))), [scan]);
  const criticalUrlsState = useMemo(() => paginateItems(scan?.targetProfile.criticalUrls || [], criticalUrlsPage), [scan, criticalUrlsPage]);
  const loginUrlsState = useMemo(() => paginateItems(scan?.targetProfile.loginUrls || [], loginUrlsPage), [scan, loginUrlsPage]);
  const vulnCluesState = useMemo(() => paginateItems(flatVulnClues, vulnCluesPage), [flatVulnClues, vulnCluesPage]);
  const loginUrlRows = useMemo(() => buildPageRows(loginUrlsState.items), [loginUrlsState.items]);
  const vulnClueRows = useMemo(() => buildPageRows(vulnCluesState.items), [vulnCluesState.items]);

  useEffect(() => {
    setFindingsPage(1);
  }, [scan?.summary.id, search, severityFilter, categoryFilter, validationFilter]);

  useEffect(() => {
    if (findingsPage > findingsPageState.totalPages) {
      setFindingsPage(findingsPageState.totalPages);
    }
  }, [findingsPage, findingsPageState.totalPages]);

  useEffect(() => {
    setCriticalUrlsPage(1);
    setLoginUrlsPage(1);
    setVulnCluesPage(1);
  }, [scan?.summary.id]);

  const enabledOptionCount = useMemo(() => Object.values(reconOptions).filter(Boolean).length, [reconOptions]);
  const criticalCount = scan?.findings.filter((finding) => finding.severity === "Critical").length || 0;
  const recentActivity = scan?.logs.slice(-6).reverse() || [];
  const liveToolChecklist = useMemo(() => sortToolExecutionsForDisplay(scan?.reconMeta?.toolExecutions || []), [scan]);
  const scanDuration = useMemo(() => formatDuration(scan?.summary.startedAt, scan?.summary.finishedAt), [scan?.summary.startedAt, scan?.summary.finishedAt]);
  const liveToolSummary = useMemo(() => {
    const completed = liveToolChecklist.filter((tool) => tool.status === "completed").length;
    const resolved = liveToolChecklist.filter((tool) => !["pending", "running"].includes(tool.status)).length;
    const resultCount = liveToolChecklist.reduce((sum, tool) => sum + (tool.count || 0), 0);
    return {
      completed,
      resolved,
      total: liveToolChecklist.length,
      resultCount,
    };
  }, [liveToolChecklist]);
  const getDisplayedToolTimeout = (key: ToolTimeoutKey) => runtimeConfig.toolTimeouts[key] || TOOL_TIMEOUT_PRESETS[scanPreset]?.[key] || TOOL_TIMEOUT_LIMITS.min;
  const derivedHostingProvider = scan
    ? scan.targetProfile.hostingProvider
      || scan.dnsInfo?.hostingProvider
      || scan.targetProfile.ipIntel?.map((entry) => entry.owner || entry.network).find(Boolean)
      || "Unknown"
    : "Unknown";
  const derivedFirstSeen = scan
    ? scan.targetProfile.firstSeen || scan.targetProfile.ssl?.validFrom || scan.summary.startedAt
    : undefined;

  const focusSection = (tab: "findings" | "assets" | "logs", ref: RefObject<HTMLElement | null>) => {
    setActiveTab(tab);
    window.requestAnimationFrame(() => {
      window.setTimeout(() => {
        ref.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 80);
    });
  };

  const sanitizeAndSetDomain = (value: string) => {
    setDomain(normalizeDomainInput(value));
  };

  const deleteHistoryItem = async (id: string) => {
    try {
      const response = await fetch(`/api/scans/${id}`, { method: "DELETE" });
      if (!response.ok) {
        throw new Error(await readErrorResponse(response));
      }
      if (scan?.summary.id === id) {
        setScan(null);
        setSelectedFindingId(undefined);
        setActiveTab("history");
      }
      await loadHistory();
    } catch (historyError) {
      setError(formatClientError(historyError));
    }
  };

  const clearHistory = async () => {
    const ok = window.confirm("Delete all saved reports?");
    if (!ok) return;
    try {
      const response = await fetch("/api/scans", { method: "DELETE" });
      if (!response.ok) {
        throw new Error(await readErrorResponse(response));
      }
      setScan(null);
      setSelectedFindingId(undefined);
      setActiveTab("history");
      await loadHistory();
    } catch (historyError) {
      setError(formatClientError(historyError));
    }
  };

  const runScan = async () => {
    const normalizedDomain = normalizeDomainInput(domain);
    if (!normalizedDomain) return;
    setDomain(normalizedDomain);

    setStatus("scanning");
    setPhase("Starting scan");
    setProgressDetail("Preparing scan pipeline");
    setError("");
    setActiveTab("findings");
    setSelectedFindingId(undefined);
    setScan(createEmptyScan(normalizedDomain, scanPreset, runtimeConfig));

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const response = await fetch(`/api/scan/stream?domain=${encodeURIComponent(normalizedDomain)}&mode=${encodeURIComponent(scanPreset)}&options=${encodeURIComponent(JSON.stringify(reconOptions))}&config=${encodeURIComponent(JSON.stringify(runtimeConfig))}`, {
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error(await readErrorResponse(response));
      }
      if (!response.body) throw new Error("No response body");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (!line.trim()) continue;
          const data = JSON.parse(line);

          if (data.type === "log") {
            setScan((current) => current ? { ...current, logs: [...current.logs, data.message] } : current);
          }
          if (data.type === "tool_status") {
            setScan((current) => current ? {
              ...current,
              reconMeta: {
                mode: current.reconMeta?.mode || scanPreset,
                depth: current.reconMeta?.depth || runtimeConfig.depth,
                config: current.reconMeta?.config || runtimeConfig,
                sourceCounts: current.reconMeta?.sourceCounts || {},
                liveHosts: current.reconMeta?.liveHosts || [],
                toolExecutions: upsertToolExecution(current.reconMeta?.toolExecutions || [], data.execution),
              },
            } : current);
          }
          if (data.type === "progress") {
            setPhase(data.phase || "Scanning");
            setProgressDetail(data.detail || "");
            setScan((current) => current ? {
              ...current,
              summary: {
                ...current.summary,
                stats: {
                  ...current.summary.stats,
                  urlsScanned: data.stats.urlsScanned,
                  findings: data.stats.findings,
                  subdomainsCount: data.stats.subdomainsCount,
                  validatedFindings: data.stats.validatedFindings,
                  liveFindings: data.stats.liveFindings,
                  uniqueSources: data.stats.uniqueSources,
                  liveHosts: data.stats.liveHosts,
                },
              },
            } : current);
          }
          if (data.type === "subdomain") {
            setScan((current) => {
              if (!current || current.assets.some((asset) => asset.hostname === data.subdomain)) return current;
              return {
                ...current,
                assets: [...current.assets, {
                  hostname: data.subdomain,
                  urls: 0,
                  findings: 0,
                  probe: null,
                  topIssues: [],
                  discoveredBy: [],
                  archiveUrls: 0,
                  live: null,
                  dnsResolved: false,
                  dns: { a: [], cname: [] },
                }],
              };
            });
          }
          if (data.type === "dns") setScan((current) => current ? { ...current, dnsInfo: data.records } : current);
          if (data.type === "ssl") {
            setScan((current) => current ? {
              ...current,
              targetProfile: {
                ...current.targetProfile,
                ssl: data.records,
              },
            } : current);
          }
          if (data.type === "parameter") setScan((current) => current && !current.parameters.includes(data.parameter) ? { ...current, parameters: [...current.parameters, data.parameter] } : current);
          if (data.type === "directory") setScan((current) => current && !current.directories.includes(data.url) ? { ...current, directories: [...current.directories, data.url] } : current);
          if (data.type === "js_file") setScan((current) => current && !current.jsFiles.includes(data.url) ? { ...current, jsFiles: [...current.jsFiles, data.url] } : current);
          if (data.type === "robots_latest") setScan((current) => current ? { ...current, robotsLatest: data.content } : current);
          if (data.type === "robots_archive") setScan((current) => current && !current.robotsArchive.includes(data.url) ? { ...current, robotsArchive: [...current.robotsArchive, data.url] } : current);
          if (data.type === "finding" || data.type === "finding_update") {
            setScan((current) => current ? { ...current, findings: replaceFinding(current.findings, data.finding) } : current);
            setSelectedFindingId((current) => current || data.finding.id);
          }
          if (data.type === "asset_update") {
            setScan((current) => current ? {
              ...current,
              assets: current.assets.some((asset) => asset.hostname === data.asset.hostname)
                ? current.assets.map((asset) => asset.hostname === data.asset.hostname ? data.asset : asset)
                : [...current.assets, data.asset],
            } : current);
          }
          if (data.type === "snapshot") {
            setScan(data.scan);
            setSelectedFindingId(data.scan.findings[0]?.id);
            setActiveTab("findings");
          }
          if (data.type === "done") {
            setStatus(data.status === "stopped" ? "stopped" : "finished");
            setPhase(data.status === "stopped" ? "Stopped" : "Completed");
            setProgressDetail("");
            loadHistory().catch(() => undefined);
          }
          if (data.type === "error") {
            setError(data.message || "Scan failed");
            setStatus("error");
            setPhase("Failed");
            setProgressDetail("");
          }
        }
      }
    } catch (scanError: unknown) {
      if ((scanError as Error).name === "AbortError") {
        setStatus("stopped");
        setPhase("Stopped");
        setProgressDetail("");
      } else {
        setError(formatClientError(scanError));
        setStatus("error");
        setProgressDetail("");
      }
    } finally {
      abortRef.current = null;
    }
  };
  const stopScan = () => abortRef.current?.abort();

  const presetButtonClass = (preset: "quick" | "live" | "full") => (
    scanPreset === preset
      ? "rounded-full border border-cyan-300/50 bg-cyan-300 px-4 py-2 text-sm font-medium text-slate-950"
      : "rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm text-slate-200 hover:border-cyan-400/40 hover:bg-cyan-400/10"
  );

  const loadSavedScan = async (id: string) => {
    try {
      const response = await fetch(`/api/scans/${id}`);
      if (!response.ok) {
        throw new Error(await readErrorResponse(response));
      }
      const savedScan = await response.json();
      setScan(savedScan);
      setDomain(savedScan.summary.domain);
      setRuntimeConfig(savedScan.reconMeta?.config || DEFAULT_RUNTIME_CONFIG);
      setStatus(savedScan.summary.status === "running" ? "finished" : savedScan.summary.status);
      setActiveTab("findings");
      setSelectedFindingId(savedScan.findings[0]?.id);
      setFindingsPage(1);
      setCriticalUrlsPage(1);
      setLoginUrlsPage(1);
      setVulnCluesPage(1);
      setProgressDetail("");
      setError("");
    } catch (historyError) {
      setError(formatClientError(historyError));
    }
  };

  const closeReportView = () => {
    if (status === "scanning") return;
    setScan(null);
    setSelectedFindingId(undefined);
    setStatus("idle");
    setPhase("Ready");
    setProgressDetail("");
    setError("");
    setActiveTab("history");
  };
  const metricCards = scan ? [
    {
      label: "Risk score",
      value: scan.summary.riskScore ? `${scan.summary.riskScore.score}` : "N/A",
      sub: scan.summary.riskScore?.level || "Pending",
      icon: ShieldAlert,
      onClick: () => focusSection("findings", findingsSectionRef),
    },
    {
      label: "URLs scanned",
      value: scan.summary.stats.urlsScanned.toLocaleString(),
      sub: `${scan.summary.stats.uniqueSources || 0} source streams`,
      icon: Database,
      onClick: () => focusSection("logs", logsSectionRef),
    },
    {
      label: "Critical findings",
      value: criticalCount.toLocaleString(),
      sub: `${scan.summary.stats.findings} total findings`,
      icon: AlertTriangle,
      onClick: () => focusSection("findings", findingsSectionRef),
    },
    {
      label: "Live now",
      value: scan.summary.stats.liveFindings.toLocaleString(),
      sub: `${scan.summary.stats.liveHosts || 0} live host(s)`,
      icon: Globe,
      onClick: () => focusSection("assets", assetsSectionRef),
    },
    {
      label: "Subdomains",
      value: scan.summary.stats.subdomainsCount.toLocaleString(),
      sub: `${scan.assets.length} tracked hosts`,
      icon: Key,
      onClick: () => focusSection("findings", intelligenceSectionRef),
    },
  ] : [];

  const downloadReport = async () => {
    if (!scan) return;
    const workbook = new ExcelJS.Workbook();
    workbook.creator = "Smart Domain Detector";
    workbook.created = new Date();
    const severityRank: Record<Severity, number> = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };
    const sortedFindings = [...scan.findings].sort((left, right) => (
      severityRank[right.severity] - severityRank[left.severity]
      || Number(right.validation.httpStatus || 0) - Number(left.validation.httpStatus || 0)
      || left.host.localeCompare(right.host)
      || left.asset.localeCompare(right.asset)
    ));
    const sortedAssets = [...scan.assets].sort((left, right) => (
      Number(Boolean(right.live)) - Number(Boolean(left.live))
      || right.findings - left.findings
      || right.urls - left.urls
      || left.hostname.localeCompare(right.hostname)
    ));
    const sortedSubdomains = [...scan.targetProfile.subdomains].sort((left, right) => left.localeCompare(right));
    const sortedCriticalUrls = [...scan.targetProfile.criticalUrls].sort((left, right) => left.localeCompare(right));
    const sortedLoginUrls = [...scan.targetProfile.loginUrls].sort((left, right) => left.localeCompare(right));
    const sortedVpnUrls = [...scan.targetProfile.vpnUrls].sort((left, right) => left.localeCompare(right));
    const sortedDirectories = [...scan.directories].sort((left, right) => left.localeCompare(right));
    const sortedParameters = [...scan.parameters].sort((left, right) => left.localeCompare(right));
    const sortedJsFiles = [...scan.jsFiles].sort((left, right) => left.localeCompare(right));
    const sortedRobotsArchive = [...scan.robotsArchive].sort((left, right) => left.localeCompare(right));
    const sortedIpIntel = [...(scan.targetProfile.ipIntel || [])].sort((left, right) => left.ip.localeCompare(right.ip));
    const sortedToolExecutions = sortToolExecutionsForDisplay(scan.reconMeta?.toolExecutions || []);
    const flattenedVulnClues = (scan.targetProfile.possibleVulns || [])
      .flatMap((clue) => clue.urls.map((url) => ({ type: clue.type, label: clue.label, url })))
      .sort((left, right) => left.label.localeCompare(right.label) || left.url.localeCompare(right.url));

    const header = (worksheet: ExcelJS.Worksheet, color: string) => {
      const row = worksheet.getRow(1);
      row.font = { bold: true, color: { argb: "FFFFFFFF" } };
      row.fill = { type: "pattern", pattern: "solid", fgColor: { argb: color } };
      row.alignment = { vertical: "middle", horizontal: "center", wrapText: true };
      row.height = 26;
      worksheet.views = [{ state: "frozen", ySplit: 1 }];
      worksheet.pageSetup = { fitToPage: true, fitToWidth: 1, fitToHeight: 0 };
    };
    const applyFilter = (worksheet: ExcelJS.Worksheet) => {
      const columnCount = worksheet.columns.length || 1;
      worksheet.autoFilter = {
        from: { row: 1, column: 1 },
        to: { row: 1, column: columnCount },
      };
    };
    const addDetailRows = (worksheet: ExcelJS.Worksheet, field: string, values: string[], emptyLabel = "Unavailable") => {
      if (values.length === 0) {
        worksheet.addRow({ field, value: emptyLabel, detail: "" });
        return;
      }
      values.forEach((value, index) => {
        worksheet.addRow({ field: index === 0 ? field : "", value, detail: "" });
      });
    };
    const severityColor: Record<Severity, string> = {
      Critical: "FFDC2626",
      High: "FFF97316",
      Medium: "FFEAB308",
      Low: "FF2563EB",
      Info: "FF475569",
    };

    const overview = workbook.addWorksheet("Overview");
    overview.columns = [{ header: "Metric", key: "metric", width: 24 }, { header: "Value", key: "value", width: 60 }];
    header(overview, "FF0F172A");
    overview.addRows([
      { metric: "Domain", value: scan.summary.domain },
      { metric: "Started", value: scan.summary.startedAt },
      { metric: "Finished", value: scan.summary.finishedAt || "In progress" },
      { metric: "Risk", value: scan.summary.riskScore ? `${scan.summary.riskScore.level} (${scan.summary.riskScore.score})` : "N/A" },
      { metric: "URLs scanned", value: scan.summary.stats.urlsScanned },
      { metric: "Findings", value: scan.summary.stats.findings },
      { metric: "Live findings", value: scan.summary.stats.liveFindings },
      { metric: "Subdomains", value: scan.summary.stats.subdomainsCount },
      { metric: "Live hosts", value: scan.summary.stats.liveHosts || 0 },
    ]);
    applyFilter(overview);

    const findingsSheet = workbook.addWorksheet("Findings");
    findingsSheet.columns = [
      { header: "Title", key: "title", width: 30 },
      { header: "Category", key: "category", width: 14 },
      { header: "Severity", key: "severity", width: 12 },
      { header: "Confidence", key: "confidence", width: 16 },
      { header: "Source", key: "source", width: 16 },
      { header: "Validation", key: "validation", width: 16 },
      { header: "Validated At", key: "validatedAt", width: 24 },
      { header: "Host", key: "host", width: 28 },
      { header: "Asset", key: "asset", width: 60 },
      { header: "HTTP", key: "http", width: 10 },
      { header: "Page Title", key: "pageTitle", width: 26 },
      { header: "Tags", key: "tags", width: 28 },
      { header: "Archive Sources", key: "archiveSources", width: 24 },
      { header: "Reference", key: "reference", width: 48 },
      { header: "Evidence", key: "evidence", width: 72 },
      { header: "Summary", key: "summary", width: 50 },
      { header: "Recommendation", key: "recommendation", width: 60 },
    ];
    header(findingsSheet, "FF7C3AED");
    sortedFindings.forEach((finding) => findingsSheet.addRow({
      title: finding.title,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      source: finding.source,
      validation: finding.validation.status,
      validatedAt: finding.validation.validatedAt ?? "",
      host: finding.host,
      asset: finding.asset,
      http: finding.validation.httpStatus ?? "",
      pageTitle: finding.validation.title ?? "",
      tags: finding.tags.join(", "),
      archiveSources: finding.archive.sources?.join(", ") || finding.source,
      reference: finding.asset,
      evidence: finding.evidence.join("\n"),
      summary: finding.summary,
      recommendation: finding.recommendation,
    }));
    findingsSheet.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;
      row.alignment = { vertical: "top", wrapText: true };
      const severityCell = row.getCell(3);
      const severity = String(severityCell.value || "") as Severity;
      if (severityColor[severity]) {
        severityCell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: severityColor[severity] } };
        severityCell.font = { color: { argb: "FFFFFFFF" }, bold: true };
      }
    });
    applyFilter(findingsSheet);

    const assets = workbook.addWorksheet("Assets");
    assets.columns = [
      { header: "Host", key: "host", width: 30 },
      { header: "Discovered By", key: "discoveredBy", width: 28 },
      { header: "IPs", key: "ips", width: 26 },
      { header: "CNAME", key: "cname", width: 28 },
      { header: "DNS", key: "dns", width: 18 },
      { header: "URLs", key: "urls", width: 10 },
      { header: "Findings", key: "findings", width: 12 },
      { header: "Probe", key: "probe", width: 30 },
      { header: "Reference URL", key: "referenceUrl", width: 48 },
      { header: "Top issues", key: "issues", width: 50 },
    ];
    header(assets, "FF0EA5E9");
    sortedAssets.forEach((asset) => assets.addRow({
      host: asset.hostname,
      discoveredBy: asset.discoveredBy?.join(", ") || "scope-root",
      ips: asset.dns?.a?.join(", ") || "",
      cname: asset.dns?.cname?.join(", ") || "",
      dns: asset.dnsResolved ? "resolved" : "unresolved",
      urls: asset.urls,
      findings: asset.findings,
      probe: asset.probe ? `${asset.probe.status} ${asset.probe.title}` : "Pending",
      referenceUrl: asset.probe?.finalUrl || `https://${asset.hostname}`,
      issues: asset.topIssues.join(", "),
    }));
    assets.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;
      row.alignment = { vertical: "top", wrapText: true };
    });
    applyFilter(assets);

    const intelligence = workbook.addWorksheet("Target Intel");
    intelligence.columns = [
      { header: "Field", key: "field", width: 24 },
      { header: "Value", key: "value", width: 56 },
      { header: "Detail", key: "detail", width: 36 },
    ];
    header(intelligence, "FF14532D");
    intelligence.addRow({ field: "Domain", value: scan.summary.domain, detail: "" });
    intelligence.addRow({ field: "Hosting provider", value: derivedHostingProvider, detail: "" });
    intelligence.addRow({ field: "Mail provider", value: scan.targetProfile.mailProvider || "Unknown", detail: "" });
    intelligence.addRow({ field: "Owner", value: scan.targetProfile.ownerName || "Unknown", detail: "" });
    intelligence.addRow({ field: "First seen", value: derivedFirstSeen ? formatArchiveTimestamp(derivedFirstSeen) : "Unknown", detail: "" });
    intelligence.addRow({ field: "Last seen", value: scan.targetProfile.lastSeen ? formatArchiveTimestamp(scan.targetProfile.lastSeen) : "Unknown", detail: "" });
    intelligence.addRow({ field: "SSL issuer", value: scan.targetProfile.ssl?.issuer || "Unavailable", detail: "" });
    intelligence.addRow({ field: "SSL valid from", value: scan.targetProfile.ssl?.validFrom || "Unavailable", detail: "" });
    intelligence.addRow({ field: "SSL valid to", value: scan.targetProfile.ssl?.validTo || "Unavailable", detail: "" });
    intelligence.addRow({ field: "SSL status", value: scan.targetProfile.ssl ? (scan.targetProfile.ssl.expired ? "Expired" : "Active") : "Unknown", detail: "" });
    addDetailRows(intelligence, "IPs", scan.targetProfile.ips);
    addDetailRows(intelligence, "Owner emails", scan.targetProfile.ownerEmails || []);
    addDetailRows(intelligence, "Mail servers", scan.dnsInfo?.mx.map((record) => record.exchange) || []);
    addDetailRows(intelligence, "Name servers", scan.dnsInfo?.ns || []);
    addDetailRows(intelligence, "Subdomains", sortedSubdomains, "None detected");
    addDetailRows(intelligence, "VPN / remote access", sortedVpnUrls, "None detected");
    addDetailRows(intelligence, "Critical URLs", sortedCriticalUrls, "None detected");
    addDetailRows(intelligence, "Login URLs", sortedLoginUrls, "None detected");
    intelligence.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;
      row.alignment = { vertical: "top", wrapText: true };
    });
    applyFilter(intelligence);

    const vulnCluesSheet = workbook.addWorksheet("Vuln Clues");
    vulnCluesSheet.columns = [
      { header: "Label", key: "label", width: 30 },
      { header: "Type", key: "type", width: 18 },
      { header: "URL", key: "url", width: 88 },
    ];
    header(vulnCluesSheet, "FF334155");
    flattenedVulnClues.forEach((clue) => vulnCluesSheet.addRow(clue));
    vulnCluesSheet.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;
      row.alignment = { vertical: "top", wrapText: true };
    });
    applyFilter(vulnCluesSheet);

    const ipIntelSheet = workbook.addWorksheet("IP Intel");
    ipIntelSheet.columns = [
      { header: "IP", key: "ip", width: 20 },
      { header: "Network", key: "network", width: 24 },
      { header: "Country", key: "country", width: 12 },
      { header: "Owner", key: "owner", width: 30 },
      { header: "Emails", key: "emails", width: 56 },
    ];
    header(ipIntelSheet, "FF0F766E");
    sortedIpIntel.forEach((entry) => ipIntelSheet.addRow({
      ip: entry.ip,
      network: entry.network || "",
      country: entry.country || "",
      owner: entry.owner || "",
      emails: entry.emails.join("\n"),
    }));
    ipIntelSheet.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;
      row.alignment = { vertical: "top", wrapText: true };
    });
    applyFilter(ipIntelSheet);

    const toolHealth = workbook.addWorksheet("Tool Health");
    toolHealth.columns = [
      { header: "Tool", key: "tool", width: 22 },
      { header: "Category", key: "category", width: 14 },
      { header: "Status", key: "status", width: 14 },
      { header: "Results", key: "count", width: 12 },
      { header: "Reason", key: "reason", width: 16 },
      { header: "Host", key: "host", width: 28 },
      { header: "Details", key: "details", width: 72 },
    ];
    header(toolHealth, "FF155E75");
    sortedToolExecutions.forEach((tool) => toolHealth.addRow({
      tool: tool.name,
      category: tool.category,
      status: tool.status,
      count: tool.count ?? 0,
      reason: tool.reasonKind || "",
      host: tool.host || "",
      details: tool.details || "",
    }));
    toolHealth.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;
      row.alignment = { vertical: "top", wrapText: true };
    });
    applyFilter(toolHealth);

    const artifactSheet = workbook.addWorksheet("Artifacts");
    artifactSheet.columns = [
      { header: "Type", key: "type", width: 18 },
      { header: "Value", key: "value", width: 90 },
      { header: "Notes", key: "notes", width: 36 },
    ];
    header(artifactSheet, "FF7C2D12");
    if (scan.robotsLatest) {
      artifactSheet.addRow({ type: "robots-live", value: "https://" + scan.summary.domain + "/robots.txt", notes: scan.robotsLatest.slice(0, 4000) });
    }
    sortedParameters.forEach((parameter) => artifactSheet.addRow({ type: "parameter", value: parameter, notes: "Input parameter" }));
    sortedDirectories.forEach((directory) => artifactSheet.addRow({ type: "directory", value: directory, notes: "Directory/path clue" }));
    sortedJsFiles.forEach((url) => artifactSheet.addRow({ type: "javascript", value: url, notes: "Linked JS asset" }));
    sortedRobotsArchive.forEach((url) => artifactSheet.addRow({ type: "robots-archive", value: url, notes: "Archived robots.txt" }));
    artifactSheet.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;
      row.alignment = { vertical: "top", wrapText: true };
    });
    applyFilter(artifactSheet);

    const followUp = workbook.addWorksheet("Follow-up Targets");
    followUp.columns = [
      { header: "URL", key: "url", width: 84 },
      { header: "Kind", key: "kind", width: 22 },
      { header: "Host", key: "host", width: 28 },
      { header: "HTTP", key: "http", width: 10 },
      { header: "Reason", key: "reason", width: 44 },
    ];
    header(followUp, "FF1D4ED8");
    const excludedMedia = /\.(?:jpg|jpeg|png|gif|svg|webp|pdf|woff2?|ttf)(?:$|[?#])/i;
    const followUpRows = sortedFindings
      .filter((finding) => !excludedMedia.test(finding.asset))
      .map((finding) => ({
        url: finding.asset,
        kind: finding.type,
        host: finding.host,
        http: finding.validation.httpStatus ?? "",
        reason: `${finding.severity} - ${finding.title}`,
      }));
    sortedCriticalUrls
      .filter((url) => !excludedMedia.test(url))
      .forEach((url) => followUpRows.push({ url, kind: "critical-url", host: new URL(url).hostname, http: "", reason: "Critical exposure follow-up" }));
    sortedVpnUrls
      .filter((url) => !excludedMedia.test(url))
      .forEach((url) => followUpRows.push({ url, kind: "vpn-surface", host: new URL(url).hostname, http: "", reason: "Remote access review" }));
    Array.from(new Map(followUpRows.map((row) => [row.url, row])).values()).forEach((row) => followUp.addRow(row));
    followUp.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;
      row.alignment = { vertical: "top", wrapText: true };
    });
    applyFilter(followUp);

    const buffer = await workbook.xlsx.writeBuffer();
    const blob = new Blob([buffer], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${scan.summary.domain.replace(/[^a-z0-9.-]/gi, "_")}_assessment.xlsx`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const setAllOptions = (value: boolean) => {
    const next = { ...reconOptions };
    (Object.keys(next) as Array<keyof ScanOptions>).forEach((key) => {
      next[key] = value;
    });
    setReconOptions(next);
    setScanPreset(value ? "full" : "custom");
  };

  const setQuickTriage = () => {
    setScanPreset("quick");
    setReconOptions({
      ...DEFAULT_OPTIONS,
      parameterDiscovery: false,
      historicalRobots: false,
      jsAnalysis: false,
      directoryListing: false,
      cloudStorage: false,
      jwtTokens: false,
      oauthTokens: false,
    });
  };

  const setLiveFocused = () => {
    setScanPreset("live");
    setReconOptions({
      ...DEFAULT_OPTIONS,
      historicalRobots: false,
      parameterDiscovery: false,
      jsAnalysis: false,
    });
  };

  const setDepthPreset = (depth: ScanDepth) => {
    if (depth === "custom") return;
    const preset = DEPTH_PRESET_CONFIG[depth];
    const presetConfig = {
      ...runtimeConfig,
      depth,
      ...preset,
    };
    setRuntimeConfig(presetConfig);
  };

  const updateRuntimeNumber = (key: keyof Omit<ScanRuntimeConfig, "depth" | "toolTimeouts">, value: string) => {
    const limit = GAUGE_LIMITS[key as keyof typeof GAUGE_LIMITS];
    const nextValue = clampValue(Number(value) || limit.min, limit.min, limit.max);
    setRuntimeConfig((current) => ({
      ...current,
      depth: "custom",
      [key]: nextValue,
    }));
  };

  const setToolTimeout = (key: ToolTimeoutKey, value: string) => {
    const numeric = clampValue(Number(value) || TOOL_TIMEOUT_LIMITS.min, TOOL_TIMEOUT_LIMITS.min, TOOL_TIMEOUT_LIMITS.max);
    setRuntimeConfig((current) => ({
      ...current,
      depth: "custom",
      toolTimeouts: {
        ...current.toolTimeouts,
        [key]: Number.isFinite(numeric) && numeric > 0 ? numeric : undefined,
      },
    }));
  };

  const depthButtonClass = (depth: ScanDepth) => (
    runtimeConfig.depth === depth
      ? "rounded-full border border-emerald-300/50 bg-emerald-300 px-4 py-2 text-sm font-medium text-slate-950"
      : "rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm text-slate-200 hover:border-emerald-400/40 hover:bg-emerald-400/10"
  );

  return (
    <div className={`flex min-h-screen flex-col text-slate-100 transition-[background] duration-500 ${tabBackgroundClass}`}>
      <header className="sticky top-0 z-20 border-b border-white/10 bg-slate-950/80 backdrop-blur-xl">
        <div className="mx-auto flex w-full max-w-[2200px] items-center justify-between px-4 py-2.5 sm:px-6 lg:px-8 2xl:px-12">
          <div className="flex items-center gap-3">
            <img
              src="/logo.png"
              alt="Smart Domain Detector"
              className="h-22 w-auto max-w-[480px] object-contain drop-shadow-[0_0_18px_rgba(34,211,238,0.18)] sm:h-[104px] sm:max-w-[560px]"
            />
          </div>
          <div className="flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm text-slate-300">
            <Activity className={`h-4 w-4 ${status === "scanning" ? "animate-pulse text-cyan-300" : "text-slate-500"}`} />
            {phase}
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-[2200px] flex-1 space-y-6 px-4 py-8 sm:px-6 lg:px-8 2xl:px-12">
        <section className="rounded-[28px] border border-white/10 bg-slate-950/75 p-6 shadow-2xl shadow-cyan-950/20">
          <div className="space-y-5">
            <div>
                <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs uppercase tracking-[0.25em] text-cyan-200">
                  Smart Domain Detector
                </div>
              </div>

              <div className="flex flex-col gap-3 lg:flex-row">
                <div className="relative flex-1">
                  <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                  <input
                    value={domain}
                    onChange={(event) => setDomain(event.target.value)}
                    onBlur={(event) => sanitizeAndSetDomain(event.target.value)}
                    onPaste={(event) => {
                      event.preventDefault();
                      sanitizeAndSetDomain(event.clipboardData.getData("text"));
                    }}
                    onKeyDown={(event) => event.key === "Enter" && status !== "scanning" && runScan()}
                    className="w-full rounded-2xl border border-white/10 bg-black/30 py-3 pl-10 pr-4 text-white outline-none transition focus:border-cyan-400/50"
                    placeholder="Enter target domain"
                    disabled={status === "scanning"}
                  />
                </div>
                {status === "scanning" ? (
                  <button onClick={stopScan} className="inline-flex items-center justify-center gap-2 rounded-2xl bg-rose-500 px-5 py-3 font-medium text-white transition hover:bg-rose-400">
                    <Square className="h-4 w-4 fill-current" /> Stop scan
                  </button>
                ) : (
                  <button onClick={runScan} disabled={!domain.trim()} className="inline-flex items-center justify-center gap-2 rounded-2xl bg-cyan-400 px-5 py-3 font-medium text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50">
                    {status === "scanning" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Run scan
                  </button>
                )}
              </div>

              <div className="flex flex-wrap gap-3">
                <button onClick={setQuickTriage} className={presetButtonClass("quick")}>Quick triage</button>
                <button onClick={setLiveFocused} className={presetButtonClass("live")}>Live focused</button>
                <button onClick={() => setAllOptions(true)} className={presetButtonClass("full")}>Full coverage</button>
                <button onClick={() => setActiveTab("history")} className={`inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm ${activeTab === "history" ? "border-cyan-300/50 bg-cyan-300 text-slate-950" : "border-white/10 bg-white/5 text-slate-200 hover:bg-white/10"}`}>
                  <History className="h-4 w-4" /> Report history
                </button>
                <button onClick={() => setShowAdvancedOptions((current) => !current)} className="inline-flex items-center gap-2 rounded-full border border-cyan-400/30 bg-cyan-400/10 px-4 py-2 text-sm text-cyan-200 hover:bg-cyan-400/20">
                  <SlidersHorizontal className="h-4 w-4" /> Advanced options
                  <ChevronDown className={`h-4 w-4 transition ${showAdvancedOptions ? "rotate-180" : ""}`} />
                </button>
              </div>

              <div className="flex flex-wrap gap-3">
                <button onClick={() => setDepthPreset("standard")} className={depthButtonClass("standard")}>Standard</button>
                <button onClick={() => setDepthPreset("aggressive")} className={depthButtonClass("aggressive")}>Aggressive</button>
                <button onClick={() => setDepthPreset("deep")} className={depthButtonClass("deep")}>Deep</button>
                {runtimeConfig.depth === "custom" ? <span className="rounded-full border border-amber-300/40 bg-amber-400/10 px-4 py-2 text-sm text-amber-100">Custom tuned</span> : null}
              </div>

                <div className="flex flex-wrap items-center gap-3 text-sm text-slate-400">
                  <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5">
                    Mode: {scanPreset === "quick" ? "Quick triage" : scanPreset === "live" ? "Live focused" : scanPreset === "full" ? "Full coverage" : "Custom"}
                  </span>
                  <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5">
                    Depth: {runtimeConfig.depth === "custom" ? "Custom" : runtimeConfig.depth}
                  </span>
                  <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5">
                    Standard &lt; Aggressive &lt; Deep
                  </span>
                  <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5">
                    {enabledOptionCount} checks enabled
                  </span>
                  <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5">
                    {history.length} saved report{history.length === 1 ? "" : "s"}
                  </span>
                </div>

              {showAdvancedOptions && (
                <div className="grid gap-4 xl:grid-cols-[1.1fr,1fr]">
                  <div className="grid gap-4 lg:grid-cols-2">
                    {OPTION_GROUPS.map((group) => (
                      <div key={group.label} className="rounded-2xl border border-white/10 bg-white/5 p-4">
                        <div className="mb-3 text-xs uppercase tracking-[0.2em] text-slate-400">{group.label}</div>
                        <div className="space-y-2">
                          {group.keys.map((key) => (
                            <label key={String(key)} className="flex items-center justify-between gap-3 rounded-xl bg-black/20 px-3 py-2 text-sm text-slate-300">
                              <span>{prettifyOption(key)}</span>
                              <input type="checkbox" checked={reconOptions[key]} onChange={(event) => { setReconOptions({ ...reconOptions, [key]: event.target.checked }); setScanPreset("custom"); }} />
                            </label>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="space-y-4">
                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                      <div className="mb-3 text-xs uppercase tracking-[0.2em] text-slate-400">Discovery depth</div>
                      <div className="grid gap-3 md:grid-cols-3">
                        <GaugeControl label="Directory max depth" value={runtimeConfig.directoryMaxDepth} min={GAUGE_LIMITS.directoryMaxDepth.min} max={GAUGE_LIMITS.directoryMaxDepth.max} step={GAUGE_LIMITS.directoryMaxDepth.step} onChange={(value) => updateRuntimeNumber("directoryMaxDepth", String(value))} />
                        <GaugeControl label="Directory breadth / host" value={runtimeConfig.directoryBreadth} min={GAUGE_LIMITS.directoryBreadth.min} max={GAUGE_LIMITS.directoryBreadth.max} step={GAUGE_LIMITS.directoryBreadth.step} onChange={(value) => updateRuntimeNumber("directoryBreadth", String(value))} />
                        <GaugeControl label="Archive retries" value={runtimeConfig.archiveRetryCount} min={GAUGE_LIMITS.archiveRetryCount.min} max={GAUGE_LIMITS.archiveRetryCount.max} step={GAUGE_LIMITS.archiveRetryCount.step} onChange={(value) => updateRuntimeNumber("archiveRetryCount", String(value))} accentClass="stroke-emerald-300" />
                        <GaugeControl label="Archive backoff" value={runtimeConfig.archiveRetryBackoffMs} min={GAUGE_LIMITS.archiveRetryBackoffMs.min} max={GAUGE_LIMITS.archiveRetryBackoffMs.max} step={GAUGE_LIMITS.archiveRetryBackoffMs.step} suffix="ms" onChange={(value) => updateRuntimeNumber("archiveRetryBackoffMs", String(value))} accentClass="stroke-amber-300" />
                        <div className="md:col-span-2 xl:col-span-1">
                          <GaugeControl label="Archive zero-yield stop threshold" value={runtimeConfig.archiveZeroYieldThreshold} min={GAUGE_LIMITS.archiveZeroYieldThreshold.min} max={GAUGE_LIMITS.archiveZeroYieldThreshold.max} step={GAUGE_LIMITS.archiveZeroYieldThreshold.step} onChange={(value) => updateRuntimeNumber("archiveZeroYieldThreshold", String(value))} accentClass="stroke-fuchsia-300" />
                        </div>
                      </div>
                    </div>

                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                      <div className="mb-3 text-xs uppercase tracking-[0.2em] text-slate-400">Per-tool timeouts (ms)</div>
                      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                        {TOOL_TIMEOUT_FIELDS.map((tool) => (
                          <div key={tool.key}>
                            <GaugeControl
                              label={tool.label}
                              value={getDisplayedToolTimeout(tool.key)}
                              min={TOOL_TIMEOUT_LIMITS.min}
                              max={TOOL_TIMEOUT_LIMITS.max}
                              step={TOOL_TIMEOUT_LIMITS.step}
                              suffix="ms"
                              accentClass="stroke-cyan-200"
                              onChange={(value) => setToolTimeout(tool.key, String(value))}
                            />
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {error && <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{error}</div>}
          </div>
        </section>

        {status === "scanning" && scan && (
          <section className="rounded-[28px] border border-cyan-400/20 bg-slate-950/70 p-5 shadow-[0_0_60px_rgba(34,211,238,0.08)]">
            <div className="grid gap-4 xl:grid-cols-[0.92fr,1.08fr]">
              <div className="space-y-4">
                <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                  <div className="text-xs uppercase tracking-[0.2em] text-cyan-200">Live scan activity</div>
                  <div className="mt-3 flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2 text-lg font-semibold text-white">
                        <Loader2 className="h-4 w-4 animate-spin text-cyan-300" />
                        <span>{phase}</span>
                      </div>
                      <div className="mt-1 flex items-center gap-2 text-sm text-slate-300">
                        <span className="inline-flex h-2 w-2 rounded-full bg-cyan-300 animate-pulse" />
                        <span>{progressDetail || "The engine is still processing. New signals will appear here as soon as they land."}</span>
                      </div>
                    </div>
                    <div className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs uppercase tracking-[0.18em] text-cyan-100">
                      {liveToolSummary.resultCount} results tracked
                    </div>
                  </div>
                  <div className="mt-4 grid gap-3 sm:grid-cols-3">
                    <div className="rounded-xl bg-black/20 p-3">
                      <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Tracked hosts</div>
                      <div className="mt-2 text-2xl font-semibold text-white">{scan.assets.length}</div>
                    </div>
                    <div className="rounded-xl bg-black/20 p-3">
                      <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Sources seen</div>
                      <div className="mt-2 text-2xl font-semibold text-white">{scan.summary.stats.uniqueSources || 0}</div>
                    </div>
                    <div className="rounded-xl bg-black/20 p-3">
                      <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Live hosts</div>
                      <div className="mt-2 text-2xl font-semibold text-white">{scan.summary.stats.liveHosts || 0}</div>
                    </div>
                  </div>
                </div>

                <div className="rounded-2xl border border-emerald-300/30 bg-[linear-gradient(180deg,rgba(6,14,20,0.94),rgba(3,10,15,0.98))] p-4 shadow-[inset_0_1px_0_rgba(74,222,128,0.16),0_0_50px_rgba(16,185,129,0.16)]">
                  <div className="flex items-center justify-between gap-3">
                    <div className="inline-flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-emerald-200">
                      <Terminal className="h-4 w-4 text-emerald-300" /> Recent engine output
                    </div>
                    <div className="inline-flex items-center gap-2 rounded-full border border-emerald-300/35 bg-emerald-400/10 px-2 py-0.5 text-[10px] uppercase tracking-[0.16em] text-emerald-200">
                      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-300" /> Live
                    </div>
                  </div>
                  <div className="mt-3 max-h-52 space-y-2 overflow-y-auto rounded-xl border border-emerald-400/15 bg-black/45 p-3 font-mono">
                    {recentActivity.length > 0 ? recentActivity.map((entry, index) => {
                      const isError = /failed|error|timed out|unavailable|no records/i.test(entry);
                      const isSuccess = /completed|added|captured|resolved|contributed|discovered|finished/i.test(entry);
                      const rowClass = isError
                        ? "border-rose-400/35 bg-rose-500/10 text-rose-100 shadow-[0_0_18px_rgba(244,63,94,0.16)]"
                        : isSuccess
                          ? "border-emerald-400/35 bg-emerald-500/10 text-emerald-100 shadow-[0_0_18px_rgba(16,185,129,0.18)]"
                          : "border-cyan-400/30 bg-cyan-500/10 text-cyan-100";

                      return (
                        <div key={`${entry}-${index}`} className={`rounded-lg border px-3 py-2 text-xs ${rowClass}`}>
                          <span className="mr-2 text-emerald-300">$</span>{entry}
                        </div>
                      );
                    }) : (
                      <div className="rounded-lg border border-emerald-400/20 bg-emerald-500/8 px-3 py-3 text-xs text-emerald-100">
                        <div className="inline-flex items-center gap-2">
                          <Loader2 className="h-4 w-4 animate-spin text-emerald-300" />
                          <span>Waiting for the first scan events.</span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div className="rounded-2xl border border-cyan-300/20 bg-slate-950/80 p-4 shadow-[inset_0_1px_0_rgba(34,211,238,0.1)]">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-xs uppercase tracking-[0.2em] text-cyan-200">Tool checklist</div>
                  <div className="text-[11px] uppercase tracking-[0.16em] text-slate-400">{liveToolSummary.resolved}/{liveToolSummary.total} resolved</div>
                </div>
                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  <div className="rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-xs text-slate-300">
                    <div className="uppercase tracking-[0.16em] text-slate-500">Completed</div>
                    <div className="mt-1 text-lg font-semibold text-white">{liveToolSummary.completed}</div>
                  </div>
                  <div className="rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-xs text-slate-300">
                    <div className="uppercase tracking-[0.16em] text-slate-500">Results found</div>
                    <div className="mt-1 text-lg font-semibold text-white">{liveToolSummary.resultCount}</div>
                  </div>
                </div>
                <div className="mt-3 grid max-h-[25rem] gap-2 overflow-y-auto pr-1 sm:grid-cols-2">
                  {liveToolChecklist.length > 0 ? liveToolChecklist.map((tool) => {
                    const statusStyles: Record<ToolExecution["status"], string> = {
                      pending: "border-amber-400/30 bg-amber-500/10 text-amber-100",
                      running: "border-cyan-400/30 bg-cyan-500/10 text-cyan-100",
                      completed: "border-emerald-400/30 bg-emerald-500/10 text-emerald-100",
                      failed: "border-rose-400/35 bg-rose-500/10 text-rose-100",
                      missing: "border-amber-400/35 bg-amber-500/10 text-amber-100",
                      skipped: "border-slate-500/30 bg-slate-700/20 text-slate-300",
                    };
                    const dotStyles: Record<ToolExecution["status"], string> = {
                      pending: "bg-amber-300 animate-pulse",
                      running: "bg-cyan-300 animate-pulse",
                      completed: "bg-emerald-300",
                      failed: "bg-rose-300",
                      missing: "bg-amber-300",
                      skipped: "bg-slate-400",
                    };

                    return (
                      <div key={tool.name} className={`rounded-xl border px-3 py-2 text-xs ${statusStyles[tool.status]}`}>
                        <div className="flex items-center justify-between gap-3">
                          <div className="inline-flex items-center gap-2 font-medium">
                            <span className={`h-2 w-2 rounded-full ${dotStyles[tool.status]}`} />
                            {tool.name}
                          </div>
                          <div className="text-right uppercase tracking-[0.16em]">{getToolStatusLabel(tool)}</div>
                        </div>
                        <div className="mt-1 text-[11px] opacity-80">{getToolDetail(tool)}</div>
                      </div>
                    );
                  }) : (
                    <div className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-400">Tool progress will appear here as the scan starts.</div>
                  )}
                </div>
              </div>
            </div>
          </section>
        )}

        {(!scan || activeTab === "history") && (
          <section className="grid gap-6 xl:grid-cols-[0.8fr,1.2fr]">
            <HistorySidebar scans={history} activeId={scan?.summary.id} onLoad={loadSavedScan} onDelete={deleteHistoryItem} onClearAll={clearHistory} />
            <div className="rounded-2xl border border-white/10 bg-slate-950/80 p-5">
              <div className="mb-4 flex items-center gap-2 text-sm font-medium text-slate-300"><History className="h-4 w-4 text-cyan-300" /></div>
              {scan ? (
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Loaded report</div>
                      <button
                        onClick={closeReportView}
                        className="inline-flex items-center gap-1 rounded-full border border-white/15 bg-white/5 px-3 py-1 text-xs text-slate-300 transition hover:border-cyan-300/40 hover:text-cyan-200"
                      >
                        <X className="h-3.5 w-3.5" /> Close
                      </button>
                    </div>
                    <div className="mt-3 space-y-2 text-sm text-slate-300">
                      <div>Domain: {scan.summary.domain}</div>
                      <div>Mode: {scan.summary.mode || scan.reconMeta?.mode || "full"}</div>
                      <div>Status: {scan.summary.status}</div>
                      <div>Started: {formatLocalDateTime(scan.summary.startedAt)}</div>
                      <div>Finished: {scan.summary.finishedAt ? formatLocalDateTime(scan.summary.finishedAt) : "In progress"}</div>
                      <div>Duration: {scanDuration || "Running"}</div>
                    </div>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                    <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Risk drivers</div>
                    <ul className="mt-3 space-y-2 text-sm text-slate-300">
                      {(scan.summary.riskScore?.reasons || ["Run a scan to compute risk drivers."]).map((reason) => <li key={reason}>- {reason}</li>)}
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="rounded-2xl border border-dashed border-white/10 bg-white/5 p-5 text-sm text-slate-400">
                  Select any saved report on the left, or run a new scan.
                </div>
              )}
            </div>
          </section>
        )}
        {scan && (
          <>
            <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
              {metricCards.map((card) => (
                <button
                  key={card.label}
                  type="button"
                  onClick={card.onClick}
                  className="rounded-2xl border border-white/10 bg-slate-950/80 p-4 text-left transition hover:border-cyan-300/35 hover:bg-slate-900/90"
                >
                  <div className="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-slate-400"><card.icon className="h-4 w-4 text-cyan-300" /> {card.label}</div>
                  <div className="mt-3 text-3xl font-semibold text-white">{card.value}</div>
                  <div className="mt-1 text-sm text-slate-400">{card.sub}</div>
                </button>
              ))}
            </section>

            <section className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap gap-2">
                {(["findings", "assets", "logs"] as const).map((tab) => (
                  <button key={tab === "logs" ? "artifacts" : tab} onClick={() => setActiveTab(tab)} className={`rounded-full px-4 py-2 text-sm transition ${activeTab === tab ? "bg-cyan-400 text-slate-950" : "border border-white/10 bg-white/5 text-slate-300 hover:bg-white/10"}`}>
                    {tab === "logs" ? "artifacts" : tab}
                  </button>
                ))}
              </div>
              <div className="flex flex-wrap gap-2">
                <button onClick={() => setActiveTab("history")} className={`inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm ${activeTab === "history" ? "border border-cyan-300/50 bg-cyan-300 text-slate-950" : "border border-white/10 bg-white/5 text-slate-200 hover:bg-white/10"}`}>
                  <History className="h-4 w-4" /> Report history
                </button>
                <button onClick={closeReportView} className="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/5 px-4 py-2 text-sm text-slate-200 hover:border-cyan-300/40 hover:text-cyan-200">
                  <X className="h-4 w-4" /> Close report
                </button>
                <button onClick={downloadReport} className="inline-flex items-center gap-2 rounded-full border border-cyan-400/30 bg-cyan-400/10 px-4 py-2 text-sm text-cyan-200 hover:bg-cyan-400/20">
                  <Download className="h-4 w-4" /> Download Report
                </button>
              </div>
            </section>

            {activeTab === "findings" && (
              <section className="space-y-6">
                <div ref={intelligenceSectionRef} className="space-y-4">
                  <div className="rounded-2xl border border-white/10 bg-slate-950/80 p-4">
                    <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Target intelligence</div>
                    <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                      <div className="rounded-xl bg-white/5 p-3 text-sm text-slate-300">
                        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Hosting</div>
                        <div className="mt-2 line-clamp-3 text-slate-100">{derivedHostingProvider}</div>
                      </div>
                      <div className="rounded-xl bg-white/5 p-3 text-sm text-slate-300">
                        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Owner</div>
                        <div className="mt-2 line-clamp-3 text-slate-100">{scan.targetProfile.ownerName || "Unavailable"}</div>
                      </div>
                      <div className="rounded-xl bg-white/5 p-3 text-sm text-slate-300">
                        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">First seen</div>
                        <div className="mt-2 text-slate-100">{formatArchiveTimestamp(derivedFirstSeen)}</div>
                      </div>
                      <div className="rounded-xl bg-white/5 p-3 text-sm text-slate-300">
                        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">SSL status</div>
                        <div className="mt-2 text-slate-100">{scan.targetProfile.ssl ? (scan.targetProfile.ssl.expired ? "Expired" : "Active") : "Unavailable"}</div>
                      </div>
                    </div>
                    <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                      <div className="rounded-xl bg-white/5 p-3 text-sm text-slate-300">
                        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">IP addresses</div>
                        <div className="mt-2">{renderValueList(scan.targetProfile.ips, "Unavailable", "max-h-36")}</div>
                      </div>
                      <div className="rounded-xl bg-white/5 p-3 text-sm text-slate-300">
                        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Mail servers</div>
                        <div className="mt-2">{renderValueList(scan.dnsInfo?.mx.map((record) => record.exchange) || [], "Unavailable", "max-h-36")}</div>
                      </div>
                      <div className="rounded-xl bg-white/5 p-3 text-sm text-slate-300">
                        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Contact emails</div>
                        <div className="mt-2">{renderValueList(scan.targetProfile.ownerEmails || [], "Unavailable", "max-h-36")}</div>
                      </div>
                      <div className="rounded-xl bg-white/5 p-3 text-sm text-slate-300">
                        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Name servers</div>
                        <div className="mt-2">{renderValueList(scan.dnsInfo?.ns || [], "Unavailable", "max-h-36")}</div>
                      </div>
                    </div>
                  </div>

                  <div className="grid gap-4 xl:grid-cols-[0.8fr,1.2fr]">
                    <div className="rounded-2xl border border-white/10 bg-slate-950/80 p-4">
                      <div className="flex items-center justify-between gap-2">
                        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">SSL</div>
                        <div className={resultBadgeClass("cyan")}>{scan.targetProfile.ssl ? "Certificate loaded" : "No certificate"}</div>
                      </div>
                      {!scan.targetProfile.ssl && status === "scanning" ? (
                        <div className="mt-3">
                          <WaitingState label="Waiting for TLS details to be captured from the root or fallback live hosts." />
                        </div>
                      ) : (
                      <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-1">
                        <div className="rounded-xl bg-white/5 px-3 py-2 text-sm text-slate-300">
                          <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">Issuer</div>
                          <div className="mt-1 break-words text-slate-100">{scan.targetProfile.ssl?.issuer || "Unavailable"}</div>
                        </div>
                        <div className="rounded-xl bg-white/5 px-3 py-2 text-sm text-slate-300">
                          <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">Valid from</div>
                          <div className="mt-1 text-slate-100">{scan.targetProfile.ssl?.validFrom || "Unavailable"}</div>
                        </div>
                        <div className="rounded-xl bg-white/5 px-3 py-2 text-sm text-slate-300">
                          <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">Valid to</div>
                          <div className="mt-1 text-slate-100">{scan.targetProfile.ssl?.validTo || "Unavailable"}</div>
                        </div>
                        <div className="rounded-xl bg-white/5 px-3 py-2 text-sm text-slate-300">
                          <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">Protocol</div>
                          <div className="mt-1 text-slate-100">{scan.targetProfile.ssl?.protocol || "Unavailable"}</div>
                        </div>
                        <div className="rounded-xl bg-white/5 px-3 py-2 text-sm text-slate-300 md:col-span-2 xl:col-span-1">
                          <div className="text-[11px] uppercase tracking-[0.16em] text-slate-500">Fingerprint</div>
                          <div className="mt-1 break-all font-mono text-xs text-slate-100">{scan.targetProfile.ssl?.fingerprint256 || "Unavailable"}</div>
                        </div>
                      </div>
                      )}
                    </div>

                    <div className="rounded-2xl border border-white/10 bg-slate-950/80 p-4">
                      <div className="flex items-center justify-between gap-2">
                        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Subdomains</div>
                        <div className={resultBadgeClass()}>{scan.targetProfile.subdomains.length} result{scan.targetProfile.subdomains.length === 1 ? "" : "s"}</div>
                      </div>
                      <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
                        {scan.targetProfile.subdomains.length > 0 ? scan.targetProfile.subdomains.slice(0, 18).map((subdomain) => (
                          <div key={subdomain} className="truncate rounded-lg bg-black/20 px-2.5 py-1.5 font-mono text-xs text-slate-200">
                            {subdomain}
                          </div>
                        )) : status === "scanning" ? <div className="md:col-span-2 xl:col-span-3"><WaitingState label="Waiting for passive discovery and DNS validation to finish." /></div> : <div className="text-slate-500">No subdomains collected.</div>}
                      </div>
                    </div>
                  </div>
                </div>

                {scan.targetProfile.ipIntel?.length ? (
                  <div className="rounded-2xl border border-white/10 bg-slate-950/80 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Resolved IP ownership</div>
                        <div className="mt-1 text-xs text-slate-400">Owner and contact records for IPs resolved from the root domain and discovered live subdomains.</div>
                      </div>
                      <div className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-slate-300">
                        {scan.targetProfile.ipIntel.length} IP records
                      </div>
                    </div>
                    <div className="mt-3 grid gap-2 lg:grid-cols-2">
                        {scan.targetProfile.ipIntel.slice(0, 6).map((entry) => (
                          <div key={entry.ip} className="rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-xs text-slate-300">
                            <div className="font-mono text-slate-100">{entry.ip}</div>
                            <div className="mt-1 text-slate-400">{entry.network || "Unknown network"}{entry.country ? ` · ${entry.country}` : ""}</div>
                            <div className="mt-1 text-slate-400">{entry.owner || "Unknown owner"}</div>
                            {entry.emails.length ? <div className="mt-1 break-all text-cyan-200">{entry.emails.join(", ")}</div> : null}
                          </div>
                        ))}
                    </div>
                  </div>
                ) : null}

                <div className="rounded-2xl border border-rose-400/25 bg-rose-500/[0.08] p-4 shadow-[0_0_60px_rgba(244,63,94,0.08)]">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <div className="text-xs uppercase tracking-[0.2em] text-rose-200">Potentially sensitive file exposure</div>
                      <div className="mt-1 text-xs text-rose-100/80">High-priority file, backup, and dump paths confirmed during the scan.</div>
                    </div>
                    <div className={resultBadgeClass("rose")}>
                      {scan.targetProfile.criticalUrls.length} result{scan.targetProfile.criticalUrls.length === 1 ? "" : "s"}
                    </div>
                  </div>
                  <div className="mt-3 min-h-[12rem] space-y-2 text-xs text-slate-200">
                    {criticalUrlsState.items.length > 0 ? criticalUrlsState.items.map((url) => <div key={url} className="truncate font-mono">{url}</div>) : status === "scanning" ? <WaitingState label="Waiting for confirmed high-risk file, dump, or backup paths." /> : <div className="text-slate-500">No potentially sensitive files confirmed yet.</div>}
                  </div>
                  {scan.targetProfile.criticalUrls.length > PAGE_SIZE ? (
                    <div className="mt-3 flex items-center justify-between text-xs text-slate-400">
                      <span>Page {criticalUrlsState.page} of {criticalUrlsState.totalPages}</span>
                      <div className="flex gap-2">
                        <button onClick={() => setCriticalUrlsPage((page) => Math.max(1, page - 1))} disabled={criticalUrlsPage === 1} className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 disabled:opacity-40">Prev</button>
                        <button onClick={() => setCriticalUrlsPage((page) => Math.min(criticalUrlsState.totalPages, page + 1))} disabled={criticalUrlsPage === criticalUrlsState.totalPages} className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 disabled:opacity-40">Next</button>
                      </div>
                    </div>
                  ) : null}
                </div>

                <div className="grid gap-4 xl:grid-cols-2">
                  <div className="rounded-2xl border border-white/10 bg-slate-950/80 p-4">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Login URLs</div>
                      <div className={resultBadgeClass()}>
                        {scan.targetProfile.loginUrls.length} result{scan.targetProfile.loginUrls.length === 1 ? "" : "s"}
                      </div>
                    </div>
                    <div className="mt-3 grid h-[25rem] grid-rows-10 gap-2 text-xs text-slate-200">
                      {scan.targetProfile.loginUrls.length === 0 ? (
                        <div className="row-span-10">
                          {status === "scanning" ? <WaitingState label="Waiting for live login, SSO, and admin surfaces to be confirmed." /> : <div className="flex h-full items-center justify-center rounded-lg border border-white/5 bg-white/[0.02] text-slate-500">No login or auth surfaces identified.</div>}
                        </div>
                      ) : loginUrlRows.map((url, index) => url ? (
                        <div key={url} className="truncate rounded-lg bg-black/20 px-2.5 py-2 font-mono">{url}</div>
                      ) : (
                        <div key={`login-empty-${index}`} className="rounded-lg border border-white/5 bg-white/[0.02]" />
                      ))}
                    </div>
                    {scan.targetProfile.loginUrls.length > PAGE_SIZE ? (
                      <div className="mt-3 flex items-center justify-between text-xs text-slate-400">
                        <span>Page {loginUrlsState.page} of {loginUrlsState.totalPages}</span>
                        <div className="flex gap-2">
                          <button onClick={() => setLoginUrlsPage((page) => Math.max(1, page - 1))} disabled={loginUrlsPage === 1} className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 disabled:opacity-40">Prev</button>
                          <button onClick={() => setLoginUrlsPage((page) => Math.min(loginUrlsState.totalPages, page + 1))} disabled={loginUrlsPage === loginUrlsState.totalPages} className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 disabled:opacity-40">Next</button>
                        </div>
                      </div>
                    ) : null}
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-slate-950/80 p-4">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Possible vuln clues</div>
                      <div className={resultBadgeClass()}>
                        {flatVulnClues.length} result{flatVulnClues.length === 1 ? "" : "s"}
                      </div>
                    </div>
                    <div className="mt-3 grid h-[25rem] grid-rows-10 gap-2 text-xs text-slate-200">
                      {flatVulnClues.length === 0 ? (
                        <div className="row-span-10">
                          {status === "scanning" ? <WaitingState label="Waiting for probe and archive clues such as redirect, SSRF, XSS, XML-RPC, GraphQL, and debug endpoints." /> : <div className="flex h-full items-center justify-center rounded-lg border border-white/5 bg-white/[0.02] text-slate-500">No live or historical vulnerability clues identified yet.</div>}
                        </div>
                      ) : vulnClueRows.map((clue, index) => clue ? (
                        <div key={`${clue.label}-${clue.url}-${index}`} className="rounded-lg bg-black/20 px-2.5 py-2">
                          <div className="truncate text-[11px] text-slate-400">{clue.label}</div>
                          <div className="truncate font-mono">{clue.url}</div>
                        </div>
                      ) : (
                        <div key={`clue-empty-${index}`} className="rounded-lg border border-white/5 bg-white/[0.02]" />
                      ))}
                    </div>
                    {flatVulnClues.length > PAGE_SIZE ? (
                      <div className="mt-3 flex items-center justify-between text-xs text-slate-400">
                        <span>Page {vulnCluesState.page} of {vulnCluesState.totalPages}</span>
                        <div className="flex gap-2">
                          <button onClick={() => setVulnCluesPage((page) => Math.max(1, page - 1))} disabled={vulnCluesPage === 1} className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 disabled:opacity-40">Prev</button>
                          <button onClick={() => setVulnCluesPage((page) => Math.min(vulnCluesState.totalPages, page + 1))} disabled={vulnCluesPage === vulnCluesState.totalPages} className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 disabled:opacity-40">Next</button>
                        </div>
                      </div>
                    ) : null}
                  </div>
                </div>

                {scan.targetProfile.vpnUrls.length > 0 ? (
                  <div className="rounded-2xl border border-cyan-400/20 bg-cyan-500/5 p-4">
                    <div className="text-xs uppercase tracking-[0.2em] text-cyan-200">VPN and remote access</div>
                    <div className="mt-3 max-h-40 space-y-2 overflow-auto text-xs text-slate-200">
                      {scan.targetProfile.vpnUrls.map((url) => <div key={url} className="truncate font-mono">{url}</div>)}
                    </div>
                  </div>
                ) : null}

                <div ref={findingsSectionRef} className="grid gap-6 xl:grid-cols-[1.35fr,0.65fr]">
                <div className="space-y-4">
                  <div className="grid gap-3 md:grid-cols-4">
                    <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search title, URL, host..." className="rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm outline-none focus:border-cyan-400/40 md:col-span-2" />
                    <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as Severity | "All")} className="rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm outline-none">
                      <option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option>
                    </select>
                    <select value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value as typeof categoryFilter)} className="rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm outline-none">
                      <option>All</option><option>Exposure</option><option>Secret</option><option>Historical</option><option>Asset</option>
                    </select>
                  </div>
                  <div className="grid gap-3 md:grid-cols-4">
                    <select value={validationFilter} onChange={(event) => setValidationFilter(event.target.value as typeof validationFilter)} className="rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm outline-none">
                      <option>All</option><option value="live">live</option><option value="unreachable">unreachable</option><option value="archived-only">archived-only</option><option value="not-checked">not-checked</option>
                    </select>
                    <div className="rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm text-slate-400 md:col-span-3">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <span>{filteredFindings.length} of {scan.findings.length} findings shown. 10 per page.</span>
                        <span className={resultBadgeClass("cyan")}>{filteredFindings.length} results</span>
                      </div>
                    </div>
                  </div>
                  <FindingsTable findings={findingsPageState.items} selectedId={selectedFindingId} onSelect={(finding) => setSelectedFindingId(finding.id)} />
                  <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm text-slate-300">
                    <div>
                      Page {findingsPageState.page} of {findingsPageState.totalPages}
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={() => setFindingsPage((page) => Math.max(1, page - 1))} disabled={findingsPage === 1} className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5 text-xs disabled:opacity-40">
                        Previous
                      </button>
                      <button onClick={() => setFindingsPage((page) => Math.min(findingsPageState.totalPages, page + 1))} disabled={findingsPage === findingsPageState.totalPages} className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5 text-xs disabled:opacity-40">
                        Next
                      </button>
                    </div>
                  </div>
                </div>
                <FindingDrawer finding={selectedFinding} />
                </div>
              </section>
            )}
            {activeTab === "assets" && (
              <section ref={assetsSectionRef} className="rounded-3xl border border-white/10 bg-slate-950/80 p-4">
                <AssetsTable assets={scan.assets} />
              </section>
            )}

            {activeTab === "logs" && (
              <section ref={logsSectionRef} className="grid gap-6 rounded-3xl border border-white/10 bg-slate-950/80 p-4 xl:grid-cols-[0.82fr,1.18fr]">
                <div className="rounded-2xl border border-white/10 bg-slate-950/80 p-5">
                  <div className="mb-4 flex items-center gap-2 text-sm font-medium text-slate-300"><Terminal className="h-4 w-4 text-cyan-300" /> Execution log</div>
                  <div className="max-h-[520px] space-y-2 overflow-y-auto rounded-2xl bg-black/40 p-4 font-mono text-xs text-slate-300">
                    {scan.logs.map((entry, index) => <div key={`${entry}-${index}`}>{entry}</div>)}
                  </div>
                </div>
                <div className="rounded-2xl border border-white/10 bg-slate-950/80 p-5">
                  <div className="mb-4 text-sm font-medium text-slate-300">Historical recon artifacts</div>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4 md:col-span-2">
                      <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Tool health</div>
                      <div className="mt-3 grid gap-2 xl:grid-cols-2 2xl:grid-cols-3">
                        {sortToolExecutionsForDisplay(scan.reconMeta?.toolExecutions || []).map((tool, index) => (
                          <div key={`${tool.name}-${index}`} className="rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-xs text-slate-300">
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-medium text-slate-100">{tool.name}</span>
                              <span className={getToolStatusTextClass(tool.status)}>{getToolStatusLabel(tool)}</span>
                            </div>
                            <div className="mt-1 text-slate-400">{getToolDetail(tool)}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4 md:col-span-2">
                      <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Source coverage</div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {Object.entries(scan.reconMeta?.sourceCounts || {}).map(([source, count]) => (
                          <span key={source} className="rounded-full bg-black/30 px-2.5 py-1 text-xs text-slate-300">{source}: {count}</span>
                        ))}
                      </div>
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4"><div className="text-xs uppercase tracking-[0.2em] text-slate-500">Parameters</div><div className="mt-3 flex flex-wrap gap-2">{scan.parameters.map((parameter) => <span key={parameter} className="rounded-full bg-black/30 px-2.5 py-1 text-xs text-slate-300">{parameter}</span>)}</div></div>
                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4"><div className="text-xs uppercase tracking-[0.2em] text-slate-500">JavaScript files</div><div className="mt-3 space-y-2 text-xs text-slate-300">{scan.jsFiles.slice(0, 50).map((url) => <div key={url} className="truncate font-mono">{url}</div>)}</div></div>
                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4"><div className="text-xs uppercase tracking-[0.2em] text-slate-500">Current robots.txt</div><pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap text-xs text-slate-300">{scan.robotsLatest || "Unavailable"}</pre></div>
                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4"><div className="text-xs uppercase tracking-[0.2em] text-slate-500">Archived robots URLs</div><div className="mt-3 space-y-2 text-xs text-slate-300">{scan.robotsArchive.map((url) => <div key={url} className="truncate font-mono">{url}</div>)}</div></div>
                  </div>
                </div>
              </section>
            )}
          </>
        )}
      </main>
      <footer className="border-t border-white/10 bg-slate-950/70">
        <div className="mx-auto flex w-full max-w-[2200px] flex-col gap-2 px-4 py-4 text-xs text-slate-400 sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8 2xl:px-12">
          <p>Smart Domain Detector v1.0</p>
          <p>
            © {currentYear} Professional project by{" "}
            <a
              href="https://github.com/smartboy223"
              target="_blank"
              rel="noreferrer"
              className="text-cyan-300 transition hover:text-cyan-200"
            >
              github.com/smartboy223
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
}
