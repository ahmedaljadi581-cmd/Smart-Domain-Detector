import { ConfidenceBadge, SeverityBadge, ValidationBadge } from "./Badges";
import { Finding } from "../types";

export function FindingDrawer({ finding }: { finding: Finding | null }) {
  if (!finding) {
    return (
      <div className="rounded-2xl border border-dashed border-white/10 bg-slate-950/50 p-6 text-sm text-slate-400">
        Select a finding to inspect evidence, validation, and remediation guidance.
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/80 p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold text-white">{finding.title}</h3>
          <p className="mt-1 text-sm text-slate-400">{finding.summary}</p>
        </div>
        <div className="flex gap-2">
          <SeverityBadge severity={finding.severity} />
          <ConfidenceBadge confidence={finding.confidence} />
        </div>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        <ValidationBadge status={finding.validation.status} />
        <span className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-slate-300">Source: {finding.source}</span>
        {finding.tags.map((tag) => (
          <span key={tag} className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-slate-300">
            {tag}
          </span>
        ))}
      </div>

      <div className="mt-5 space-y-4 text-sm">
        <div>
          <div className="mb-1 text-xs uppercase tracking-[0.2em] text-slate-500">Asset</div>
          <a href={finding.asset} target="_blank" rel="noreferrer" className="break-all font-mono text-cyan-300 hover:text-cyan-200">
            {finding.asset}
          </a>
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <div className="rounded-xl border border-white/10 bg-black/20 p-3 text-xs text-slate-300">
            <div className="text-slate-500">First seen</div>
            <div className="mt-1">{finding.archive.firstSeen || "Unknown"}</div>
          </div>
          <div className="rounded-xl border border-white/10 bg-black/20 p-3 text-xs text-slate-300">
            <div className="text-slate-500">Last seen</div>
            <div className="mt-1">{finding.archive.lastSeen || "Unknown"}</div>
          </div>
          <div className="rounded-xl border border-white/10 bg-black/20 p-3 text-xs text-slate-300 md:col-span-2">
            <div className="text-slate-500">Archive sources</div>
            <div className="mt-1">{finding.archive.sources?.join(", ") || finding.source}</div>
          </div>
        </div>
        <div>
          <div className="mb-1 text-xs uppercase tracking-[0.2em] text-slate-500">Impact</div>
          <p className="text-slate-300">{finding.impact}</p>
        </div>
        <div>
          <div className="mb-1 text-xs uppercase tracking-[0.2em] text-slate-500">Recommended Action</div>
          <p className="text-slate-300">{finding.recommendation}</p>
        </div>
        <div>
          <div className="mb-1 text-xs uppercase tracking-[0.2em] text-slate-500">Validation Notes</div>
          <ul className="space-y-1 text-slate-300">
            {finding.validation.notes.map((note) => (
              <li key={note}>- {note}</li>
            ))}
            {finding.validation.validatedAt && <li>- Validated at {finding.validation.validatedAt}</li>}
            {finding.validation.contentHash && <li>- Content hash {finding.validation.contentHash}</li>}
          </ul>
        </div>
        <div>
          <div className="mb-1 text-xs uppercase tracking-[0.2em] text-slate-500">Evidence</div>
          <ul className="space-y-1 text-slate-300">
            {finding.evidence.map((evidence) => (
              <li key={evidence}>- {evidence}</li>
            ))}
          </ul>
        </div>
        {finding.jwt && (
          <div>
            <div className="mb-1 text-xs uppercase tracking-[0.2em] text-slate-500">JWT Intelligence</div>
            <div className="rounded-xl border border-white/10 bg-black/30 p-3 text-xs text-slate-300">
              <div>User: {finding.jwt.user}</div>
              <div>Email: {finding.jwt.email}</div>
              <div>Roles: {finding.jwt.roles.join(", ") || "None"}</div>
              <div>Issuer: {finding.jwt.issuer || "Unknown"}</div>
              <div>Algorithm: {finding.jwt.algorithm || "Unknown"}</div>
              <div>Flags: {finding.jwt.riskFlags.join(", ") || "None"}</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
