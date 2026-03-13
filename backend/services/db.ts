import fs from "fs";
import path from "path";
import Database from "better-sqlite3";
import { SavedScan, ScanSummary } from "../types";

const dataDir = path.join(process.cwd(), "backend", "data");
fs.mkdirSync(dataDir, { recursive: true });
const dbPath = path.join(dataDir, "scans.db");
const db = new Database(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    payload_json TEXT NOT NULL
  );
`);

const insertScan = db.prepare(`
  INSERT OR REPLACE INTO scans (id, domain, started_at, finished_at, status, summary_json, payload_json)
  VALUES (@id, @domain, @started_at, @finished_at, @status, @summary_json, @payload_json)
`);

const selectSummaries = db.prepare(`
  SELECT summary_json
  FROM scans
  ORDER BY started_at DESC
  LIMIT ?
`);

const selectPayload = db.prepare(`
  SELECT payload_json
  FROM scans
  WHERE id = ?
`);

const deleteScanStatement = db.prepare(`
  DELETE FROM scans
  WHERE id = ?
`);

const clearScansStatement = db.prepare(`
  DELETE FROM scans
`);

export function saveScan(scan: SavedScan): void {
  insertScan.run({
    id: scan.summary.id,
    domain: scan.summary.domain,
    started_at: scan.summary.startedAt,
    finished_at: scan.summary.finishedAt ?? null,
    status: scan.summary.status,
    summary_json: JSON.stringify(scan.summary),
    payload_json: JSON.stringify(scan),
  });
}

export function listScanSummaries(limit = 20): ScanSummary[] {
  return (selectSummaries.all(limit) as Array<{ summary_json: string }>).map((row) => JSON.parse(row.summary_json) as ScanSummary);
}

export function getSavedScan(id: string): SavedScan | null {
  const row = selectPayload.get(id) as { payload_json: string } | undefined;
  return row ? (JSON.parse(row.payload_json) as SavedScan) : null;
}

export function deleteSavedScan(id: string): boolean {
  return deleteScanStatement.run(id).changes > 0;
}

export function clearSavedScans(): number {
  return clearScansStatement.run().changes;
}
