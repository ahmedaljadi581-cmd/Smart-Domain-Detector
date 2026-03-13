import { ChevronDown, Trash2, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { ScanSummary } from "../types";

export function HistorySidebar({
  scans,
  activeId,
  onLoad,
  onDelete,
  onClearAll,
}: {
  scans: ScanSummary[];
  activeId?: string;
  onLoad: (id: string) => void;
  onDelete: (id: string) => void;
  onClearAll: () => void;
}) {
  const [collapsed, setCollapsed] = useState(true);
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const term = query.trim().toLowerCase();
    if (!term) return scans;
    return scans.filter((scan) => scan.domain.toLowerCase().includes(term) || (scan.riskScore?.level || "").toLowerCase().includes(term));
  }, [scans, query]);

  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/80 p-4">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold uppercase tracking-[0.2em] text-slate-400">Saved Reports</h3>
            <span className="rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-[11px] text-slate-200">{scans.length}</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {scans.length > 0 && !collapsed && (
            <button onClick={onClearAll} className="rounded-full border border-rose-400/20 bg-rose-500/10 px-3 py-1.5 text-xs text-rose-200 hover:bg-rose-500/20">
              Clear all
            </button>
          )}
          <button onClick={() => setCollapsed((current) => !current)} className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1.5 text-xs text-slate-300 hover:bg-white/10">
            {collapsed ? "Show" : "Hide"}
            <ChevronDown className={`h-4 w-4 transition ${collapsed ? "" : "rotate-180"}`} />
          </button>
        </div>
      </div>
      {!collapsed && <div className="space-y-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search saved reports..."
            className="w-full rounded-xl border border-white/10 bg-black/30 py-2 pl-9 pr-3 text-sm text-slate-100 outline-none focus:border-cyan-400/40"
          />
        </div>
        {scans.length === 0 ? (
          <div className="rounded-xl border border-dashed border-white/10 p-4 text-sm text-slate-500">No saved scans yet.</div>
        ) : (
          filtered.length === 0 ? (
            <div className="rounded-xl border border-dashed border-white/10 p-4 text-sm text-slate-500">No reports match that search.</div>
          ) : filtered.map((scan) => (
            <div key={scan.id} className={`rounded-xl border p-3 transition ${activeId === scan.id ? "border-cyan-400/40 bg-cyan-500/10" : "border-white/10 bg-white/5 hover:bg-white/10"}`}>
              <div className="flex items-start justify-between gap-3">
                <button onClick={() => onLoad(scan.id)} className="flex-1 text-left">
                  <div className="font-medium text-slate-100">{scan.domain}</div>
                  <div className="mt-1 text-xs text-slate-400">{new Date(scan.startedAt).toLocaleString()}</div>
                  <div className="mt-2 flex gap-3 text-xs text-slate-300">
                    <span>{scan.stats.findings} findings</span>
                    <span>{scan.stats.liveFindings} live</span>
                    <span>{scan.riskScore?.level || "N/A"}</span>
                  </div>
                </button>
                <div className="flex flex-col items-end gap-2">
                  <div className="text-xs text-slate-400">{scan.status}</div>
                  <button
                    onClick={() => onDelete(scan.id)}
                    className="rounded-full border border-white/10 bg-black/20 p-1.5 text-slate-400 hover:border-rose-400/30 hover:bg-rose-500/10 hover:text-rose-200"
                    aria-label={`Delete report for ${scan.domain}`}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>}
    </div>
  );
}
