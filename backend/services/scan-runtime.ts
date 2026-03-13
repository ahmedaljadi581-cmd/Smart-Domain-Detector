import { ArchiveRecord, Finding, ProbeResult } from "../types";

export function normalizeDomainInput(input: string): string {
  let value = input.trim().toLowerCase();
  if (!value) return "";
  value = value.replace(/^[a-z]+:\/\//i, "");
  value = value.replace(/^\/+|\/+$/g, "");
  value = value.split(/[/?#]/)[0] || value;
  value = value.split("@").pop() || value;
  value = value.replace(/:\d+$/, "");
  value = value.replace(/^\.+|\.+$/g, "");
  value = value.replace(/\.+/g, ".");
  value = value.replace(/[^a-z0-9.-]/g, "");
  return value;
}

export function canonicalizeUrl(input: string): string {
  try {
    const parsed = new URL(input);
    parsed.hash = "";
    parsed.hostname = parsed.hostname.toLowerCase();
    if ((parsed.protocol === "https:" && parsed.port === "443") || (parsed.protocol === "http:" && parsed.port === "80")) {
      parsed.port = "";
    }

    const params = Array.from(parsed.searchParams.entries()).sort(([leftKey, leftValue], [rightKey, rightValue]) => {
      if (leftKey === rightKey) return leftValue.localeCompare(rightValue);
      return leftKey.localeCompare(rightKey);
    });
    parsed.search = "";
    for (const [key, value] of params) {
      parsed.searchParams.append(key, value);
    }
    return parsed.toString();
  } catch {
    return input.trim();
  }
}

function isArchivedOnlyStatus(status: number): boolean {
  return status === 404 || status === 410;
}

function isLiveStatus(status: number): boolean {
  return status > 0 && !isArchivedOnlyStatus(status);
}

export function buildValidationFromProbe(probe: ProbeResult): Finding["validation"] {
  if (probe.status === 0) {
    return {
      checked: true,
      live: false,
      status: "unreachable",
      httpStatus: probe.status,
      title: probe.title,
      contentType: probe.contentType,
      contentHash: probe.contentHash ?? null,
      validatedAt: new Date().toISOString(),
      notes: ["Validation request failed or timed out"],
    };
  }

  if (isArchivedOnlyStatus(probe.status)) {
    return {
      checked: true,
      live: false,
      status: "archived-only",
      httpStatus: probe.status,
      title: probe.title,
      contentType: probe.contentType,
      contentHash: probe.contentHash ?? null,
      validatedAt: new Date().toISOString(),
      notes: [`Live host responded with HTTP ${probe.status}`, "The archived path no longer appears to exist on the live target"],
    };
  }

  return {
    checked: true,
    live: isLiveStatus(probe.status),
    status: "live",
    httpStatus: probe.status,
    title: probe.title,
    contentType: probe.contentType,
    contentHash: probe.contentHash ?? null,
    validatedAt: new Date().toISOString(),
    notes: [
      `Asset responded with HTTP ${probe.status}`,
      probe.contentType ? `Content-Type: ${probe.contentType}` : "Content type unavailable",
    ],
  };
}

export function upsertFindingCapture(store: Map<string, Finding>, finding: Finding, record: ArchiveRecord): { finding: Finding; inserted: boolean } {
  const existing = store.get(finding.id);
  if (!existing) {
    store.set(finding.id, finding);
    return { finding, inserted: true };
  }

  existing.archive.seenCount += 1;
  if (record.timestamp) {
    if (!existing.archive.firstSeen || record.timestamp < existing.archive.firstSeen) {
      existing.archive.firstSeen = record.timestamp;
    }
    if (!existing.archive.lastSeen || record.timestamp > existing.archive.lastSeen) {
      existing.archive.lastSeen = record.timestamp;
    }
  }
  existing.archive.latestStatusCode = record.statusCode ?? existing.archive.latestStatusCode ?? null;
  existing.archive.latestMimeType = record.mimeType ?? existing.archive.latestMimeType ?? null;
  const sources = new Set(existing.archive.sources ?? [existing.source]);
  sources.add(record.source);
  existing.archive.sources = Array.from(sources);
  existing.archive.sourceCount = existing.archive.sources.length;
  const repeatEvidence = record.source === "live"
    ? `Observed live at: ${finding.asset}`
    : `Archived URL: ${finding.asset}`;
  if (!existing.evidence.includes(repeatEvidence)) {
    existing.evidence.push(repeatEvidence);
  }

  return { finding: existing, inserted: false };
}
