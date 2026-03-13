import { Confidence, Severity } from "../types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const colors: Record<Severity, string> = {
    Critical: "border-red-500/40 bg-red-500/15 text-red-300",
    High: "border-orange-500/40 bg-orange-500/15 text-orange-300",
    Medium: "border-amber-500/40 bg-amber-500/15 text-amber-300",
    Low: "border-sky-500/40 bg-sky-500/15 text-sky-300",
    Info: "border-slate-500/40 bg-slate-500/15 text-slate-300",
  };

  return <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${colors[severity]}`}>{severity}</span>;
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  const colors: Record<Confidence, string> = {
    Confirmed: "text-emerald-300",
    Likely: "text-sky-300",
    "Needs Validation": "text-slate-300",
  };

  return <span className={`text-xs font-medium ${colors[confidence]}`}>{confidence}</span>;
}

export function ValidationBadge({ status }: { status: "live" | "archived-only" | "unreachable" | "not-checked" }) {
  const labels = {
    live: "Live",
    "archived-only": "Archived Only",
    unreachable: "Unreachable",
    "not-checked": "Not Checked",
  };
  const colors = {
    live: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
    "archived-only": "border-blue-500/40 bg-blue-500/15 text-blue-300",
    unreachable: "border-red-500/40 bg-red-500/15 text-red-300",
    "not-checked": "border-slate-500/40 bg-slate-500/15 text-slate-300",
  };

  return <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${colors[status]}`}>{labels[status]}</span>;
}

export function SourceBadge({ source }: { source: string }) {
  const label = source === "wayback"
    ? "Wayback"
    : source === "commoncrawl"
      ? "CommonCrawl"
      : source === "live"
        ? "Live"
        : source;
  const colors: Record<string, string> = {
    Wayback: "border-blue-400/40 bg-blue-500/15 text-blue-200",
    CommonCrawl: "border-indigo-400/40 bg-indigo-500/15 text-indigo-200",
    Live: "border-emerald-400/40 bg-emerald-500/15 text-emerald-200",
    crtsh: "border-cyan-400/40 bg-cyan-500/15 text-cyan-200",
    bufferover: "border-teal-400/40 bg-teal-500/15 text-teal-200",
  };
  const key = Object.keys(colors).find((item) => item.toLowerCase() === label.toLowerCase()) ?? "Wayback";
  return <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${colors[key] || colors.Wayback}`}>{label}</span>;
}
