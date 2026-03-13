import { Asset } from "../types";

export function AssetsTable({ assets }: { assets: Asset[] }) {
  const formatProbe = (asset: Asset) => {
    if (asset.probe) {
      if (asset.probe.status > 0) {
        return `HTTP ${asset.probe.status} ${asset.probe.title || ""}`.trim();
      }
      if (asset.dnsResolved) {
        return `HTTP 0 ${asset.probe.title || "unreachable"}`.trim();
      }
      return asset.probe.title || "DNS unresolved";
    }
    return asset.dnsResolved ? "DNS resolved, probe not run" : "DNS unresolved";
  };

  return (
    <div className="overflow-hidden rounded-2xl border border-white/10 bg-slate-950/80">
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="bg-slate-900/90 text-xs uppercase tracking-[0.2em] text-slate-400">
            <tr>
              <th className="px-4 py-3">Host</th>
              <th className="px-4 py-3">Sources</th>
              <th className="px-4 py-3">URLs</th>
              <th className="px-4 py-3">Archive</th>
              <th className="px-4 py-3">Findings</th>
              <th className="px-4 py-3">Probe</th>
              <th className="px-4 py-3">Top Issues</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {assets.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-slate-500">No assets discovered yet.</td>
              </tr>
            ) : (
              assets.map((asset) => (
                <tr key={asset.hostname}>
                  <td className="px-4 py-4 font-mono text-xs text-slate-200">{asset.hostname}</td>
                  <td className="px-4 py-4 text-xs text-slate-400">{asset.discoveredBy?.join(", ") || "scope-root"}</td>
                  <td className="px-4 py-4 text-slate-300">{asset.urls}</td>
                  <td className="px-4 py-4 text-slate-300">{asset.archiveUrls || 0}</td>
                  <td className="px-4 py-4 text-slate-300">{asset.findings}</td>
                  <td className="px-4 py-4 text-slate-300">
                    {formatProbe(asset)}
                  </td>
                  <td className="px-4 py-4 text-xs text-slate-400">{asset.topIssues.join(", ") || "None"}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
