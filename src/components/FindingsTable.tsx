import { ConfidenceBadge, SeverityBadge, ValidationBadge, SourceBadge } from "./Badges";
import { Finding } from "../types";

type Props = {
  findings: Finding[];
  selectedId?: string;
  onSelect: (finding: Finding) => void;
};

export function FindingsTable({ findings, selectedId, onSelect }: Props) {
  return (
    <div className="overflow-hidden rounded-2xl border border-white/10 bg-slate-950/80">
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="bg-slate-900/90 text-xs uppercase tracking-[0.2em] text-slate-400">
            <tr>
              <th className="px-4 py-3">Finding</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Confidence</th>
              <th className="px-4 py-3">Live</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Host</th>
              <th className="px-4 py-3">Archive</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {findings.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-slate-500">
                  No findings match the current filters.
                </td>
              </tr>
            ) : (
              findings.map((finding) => (
                <tr
                  key={finding.id}
                  onClick={() => onSelect(finding)}
                  className={`cursor-pointer transition hover:bg-white/5 ${selectedId === finding.id ? "bg-cyan-500/10" : ""}`}
                >
                  <td className="px-4 py-4 align-top">
                    <div className="font-medium text-slate-100">{finding.title}</div>
                    <div className="mt-1 text-xs text-slate-400">{finding.summary}</div>
                    <div className="mt-2 font-mono text-xs text-cyan-300">{finding.redactedMatch || finding.match}</div>
                  </td>
                  <td className="px-4 py-4 align-top"><SeverityBadge severity={finding.severity} /></td>
                  <td className="px-4 py-4 align-top"><ConfidenceBadge confidence={finding.confidence} /></td>
                  <td className="px-4 py-4 align-top"><ValidationBadge status={finding.validation.status} /></td>
                  <td className="px-4 py-4 align-top"><SourceBadge source={finding.source} /></td>
                  <td className="px-4 py-4 align-top font-mono text-xs text-slate-300">{finding.host}</td>
                  <td className="px-4 py-4 align-top text-xs text-slate-400">
                    <div>{finding.archive.firstSeen ? `First ${finding.archive.firstSeen}` : "No archive date"}</div>
                    <div>{finding.archive.lastSeen ? `Last ${finding.archive.lastSeen}` : ""}</div>
                    <div>{finding.archive.seenCount} capture(s)</div>
                    <div>{finding.archive.sources?.join(", ") || finding.source}</div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
