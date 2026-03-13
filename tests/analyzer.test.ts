import test from "node:test";
import assert from "node:assert/strict";
import { detectFindings, extractSubdomain } from "../backend/services/analyzer";
import { ArchiveRecord, ScanOptions } from "../backend/types";

const options: ScanOptions = {
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

function getTypes(record: ArchiveRecord): string[] {
  return detectFindings(record, options).map((finding) => finding.type);
}

test("detectFindings flags sensitive file exposures", () => {
  const types = getTypes({
    url: "https://dev.example.com/.env",
    source: "wayback",
    timestamp: "20240101000000",
    statusCode: 200,
    mimeType: "text/plain",
  });

  assert.ok(types.includes("sensitive_file"));
});

test("detectFindings flags reflected-input and redirect clues from params", () => {
  const types = getTypes({
    url: "https://app.example.com/search?q=test&redirect=https://evil.test",
    source: "wayback",
    timestamp: "20240101000000",
    statusCode: 200,
    mimeType: "text/html",
  });

  assert.ok(types.includes("xss_clue"));
  assert.ok(types.includes("open_redirect_clue"));
});

test("detectFindings flags SSRF-like fetch parameters", () => {
  const types = getTypes({
    url: "https://app.example.com/proxy?url=http://169.254.169.254/latest/meta-data/",
    source: "wayback",
    timestamp: "20240101000000",
    statusCode: 200,
    mimeType: "text/html",
  });

  assert.ok(types.includes("ssrf_clue"));
});

test("extractSubdomain does not treat lookalike domains as in-scope", () => {
  assert.equal(extractSubdomain("https://portal.example.com/login", "example.com"), "portal.example.com");
  assert.equal(extractSubdomain("https://notexample.com/login", "example.com"), null);
});
