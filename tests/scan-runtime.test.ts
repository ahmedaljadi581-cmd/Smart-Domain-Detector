import test from "node:test";
import assert from "node:assert/strict";
import { buildValidationFromProbe, canonicalizeUrl, normalizeDomainInput, upsertFindingCapture } from "../backend/services/scan-runtime";
import { ArchiveRecord, Finding } from "../backend/types";

function createFinding(): Finding {
  return {
    id: "finding-1",
    category: "Exposure",
    type: "admin_panel",
    title: "Administrative interface discovered",
    asset: "https://admin.example.com/login",
    host: "admin.example.com",
    path: "/login",
    source: "wayback",
    match: "/login",
    severity: "High",
    confidence: "Confirmed",
    summary: "Archived path suggests an admin interface.",
    impact: "Can increase brute-force and misconfiguration risk.",
    recommendation: "Review and restrict access.",
    evidence: ["Archived URL: https://admin.example.com/login"],
    tags: ["admin"],
    archive: {
      firstSeen: "20240101000000",
      lastSeen: "20240101000000",
      seenCount: 1,
      sourceCount: 1,
      latestStatusCode: 200,
      latestMimeType: "text/html",
    },
    validation: {
      checked: false,
      live: null,
      status: "not-checked",
      notes: ["Live validation not run yet."],
    },
  };
}

test("normalizeDomainInput strips protocols, paths, and ports", () => {
  assert.equal(normalizeDomainInput("https://Admin.Example.com:8443/path?q=1"), "admin.example.com");
  assert.equal(normalizeDomainInput(" user@example.com "), "example.com");
});

test("canonicalizeUrl sorts query parameters for stable dedupe", () => {
  assert.equal(
    canonicalizeUrl("https://example.com/path?b=2&a=1"),
    "https://example.com/path?a=1&b=2",
  );
});

test("buildValidationFromProbe returns archived-only for missing live paths", () => {
  const validation = buildValidationFromProbe({
    alive: false,
    status: 404,
    title: "Not Found",
    contentType: "text/html",
    contentHash: "abc123",
  });

  assert.equal(validation.status, "archived-only");
  assert.equal(validation.live, false);
  assert.equal(validation.httpStatus, 404);
});

test("buildValidationFromProbe keeps 403 assets as live", () => {
  const validation = buildValidationFromProbe({
    alive: true,
    status: 403,
    title: "Forbidden",
    contentType: "text/html",
    contentHash: "def456",
  });

  assert.equal(validation.status, "live");
  assert.equal(validation.live, true);
});

test("upsertFindingCapture preserves capture history for duplicate URLs", () => {
  const store = new Map<string, Finding>();
  const original = createFinding();
  const laterRecord: ArchiveRecord = {
    url: "https://admin.example.com/login",
    source: "wayback",
    timestamp: "20240501000000",
    statusCode: 302,
    mimeType: "text/html",
  };

  upsertFindingCapture(store, original, {
    url: original.asset,
    source: "wayback",
    timestamp: "20240101000000",
    statusCode: 200,
    mimeType: "text/html",
  });
  const merged = upsertFindingCapture(store, createFinding(), laterRecord).finding;

  assert.equal(merged.archive.seenCount, 2);
  assert.equal(merged.archive.firstSeen, "20240101000000");
  assert.equal(merged.archive.lastSeen, "20240501000000");
  assert.equal(merged.archive.latestStatusCode, 302);
});
