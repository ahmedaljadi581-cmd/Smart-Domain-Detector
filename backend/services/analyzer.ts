import { createHash } from "crypto";
import { ArchiveRecord, Confidence, Finding, JwtAnalysis, ProbeResult, Severity } from "../types";

const SENSITIVE_FILE_REGEX = /(?:^|\/)(?:\.env(?:\.[^/?#]+)?|\.git\/config|id_rsa(?:\.pub)?|authorized_keys|known_hosts|wp-config\.php|web\.config|local\.settings\.json|docker-compose\.(?:ya?ml)|settings\.(?:php|ini|conf|ya?ml|json|bak)|config\.(?:php|ini|conf|ya?ml|json|bak|old)|backup\.(?:zip|tar|gz|tgz|rar|7z|sql)|dump\.(?:sql|zip|gz)|db(?:ase)?\.(?:sql|bak)|database\.(?:sql|bak)|[^/?#]+\.(?:sql|bak|pem|key|pfx|p12))(?:$|[?#])/i;
const ADMIN_REGEX = /\/(admin|wp-admin|dashboard|manager|setup|phpinfo\.php|server-status|login|signin|controlpanel)/i;
const BACKUP_REGEX = /\.(bak|sql|tar\.gz|tgz|zip|rar|7z|swp|~)$/i;
const API_KEY_REGEX = /(?:api_key|apikey|access_token|secret|token|key)=([a-zA-Z0-9_\-.]{16,})/i;
const OAUTH_REGEX = /(?:oauth_token|bearer_token|refresh_token)=([a-zA-Z0-9_\-.]{20,})/i;
const JWT_REGEX = /(?:eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,})/;
const CLOUD_REGEX = /(?:s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|digitaloceanspaces\.com|cloudfront\.net)/i;
const XMLRPC_REGEX = /\/xmlrpc\.php(?:$|[/?#])/i;
const GRAPHQL_REGEX = /\/graphql(?:$|[/?#])/i;
const API_DOCS_REGEX = /\/(?:swagger(?:-ui)?(?:\/index\.html)?|openapi(?:\.(?:json|ya?ml))?|api-docs)(?:$|[/?#])/i;
const DEBUG_ENDPOINT_REGEX = /\/(?:server-status|phpinfo\.php|actuator(?:\/(?:env|heapdump|configprops|beans|mappings|threaddump|health))?|debug(?:\/|$)|console)(?:$|[/?#])/i;
const LOGIN_PATH_REGEX = /\/(login|signin|auth|wp-login\.php|wp-admin|admin|administrator|user\/login|portal|webmail|owa)(?:$|[/?#])/i;
const LOGIN_TITLE_REGEX = /(login|sign in|single sign-on|authentication|required|webmail|roundcube|cpanel|plesk|outlook web access|vmware horizon|citrix|okta|adfs)/i;
const VPN_PATH_REGEX = /\/(?:vpn|sslvpn|remote(?:\/login)?|citrix|netscaler|adfs|rdweb|global-protect(?:\/login\.esp)?)(?:$|[/?#])/i;
const VPN_TITLE_REGEX = /(remote access vpn|globalprotect|citrix gateway|pulse secure|fortinet|fortigate|sonicwall|netscaler|juniper secure connect|f5 big-ip|secure gateway|adfs)/i;
const XSS_PARAM_NAMES = new Set(["q", "query", "search", "s", "keyword", "term", "message", "comment", "name", "input"]);
const REDIRECT_PARAM_NAMES = new Set(["next", "url", "target", "return", "returnto", "return_url", "redirect", "redirect_uri", "dest", "destination", "continue", "callback"]);
const SSRF_PARAM_NAMES = new Set(["url", "uri", "dest", "destination", "target", "feed", "img", "image", "file", "path", "proxy", "callback", "redirect"]);

function makeId(seed: string): string {
  return createHash("sha1").update(seed).digest("hex");
}

function parseUrl(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

function b64UrlDecode(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
  return Buffer.from(padded, "base64").toString("utf8");
}

function redactSecret(value: string): string {
  if (value.length <= 10) return "[redacted]";
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

function buildArchive(record: ArchiveRecord) {
  return {
    firstSeen: record.timestamp,
    lastSeen: record.timestamp,
    seenCount: 1,
    sourceCount: 1,
    sources: [record.source],
    latestStatusCode: record.statusCode ?? null,
    latestMimeType: record.mimeType ?? null,
  };
}

function buildLiveRecord(url: string, probe: ProbeResult): ArchiveRecord {
  return {
    url,
    source: "live",
    statusCode: probe.status || null,
    mimeType: probe.contentType ?? null,
  };
}

function baseFinding(args: {
  type: string;
  category: Finding["category"];
  title: string;
  url: string;
  source: string;
  match: string;
  severity: Severity;
  confidence: Confidence;
  summary: string;
  impact: string;
  recommendation: string;
  evidence: string[];
  tags: string[];
  archive: ArchiveRecord;
  redactedMatch?: string;
  jwt?: JwtAnalysis;
}): Finding {
  const parsed = parseUrl(args.url);
  return {
    id: makeId(`${args.type}:${args.url}:${args.match}`),
    category: args.category,
    type: args.type,
    title: args.title,
    asset: args.url,
    host: parsed?.hostname ?? "unknown",
    path: parsed?.pathname ?? "/",
    source: args.source,
    match: args.match,
    redactedMatch: args.redactedMatch,
    severity: args.severity,
    confidence: args.confidence,
    summary: args.summary,
    impact: args.impact,
    recommendation: args.recommendation,
    evidence: args.evidence,
    tags: args.tags,
    archive: buildArchive(args.archive),
    validation: {
      checked: false,
      live: null,
      status: "not-checked",
      notes: ["Live validation not run yet."],
    },
    jwt: args.jwt,
  };
}

export function extractSubdomain(url: string, targetDomain: string): string | null {
  const parsed = parseUrl(url);
  if (!parsed) return null;
  const hostname = parsed.hostname.toLowerCase();
  const domain = targetDomain.toLowerCase();
  return hostname === domain || hostname.endsWith(`.${domain}`) ? hostname : null;
}

export function extractParameters(url: string): string[] {
  const parsed = parseUrl(url);
  if (!parsed) return [];
  return Array.from(parsed.searchParams.keys()).filter(Boolean);
}

export function checkDirectoryListing(url: string): boolean {
  const parsed = parseUrl(url);
  if (!parsed) return false;
  return parsed.pathname.endsWith("/") && parsed.pathname.length > 1;
}

export function checkJsFile(url: string): boolean {
  const parsed = parseUrl(url);
  if (!parsed) return false;
  return parsed.pathname.endsWith(".js");
}

export function analyzeJwt(token: string): JwtAnalysis {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return {
        user: "Unknown",
        email: "N/A",
        roles: [],
        riskFlags: ["Malformed token"],
        error: "Invalid JWT format",
      };
    }

    const header = JSON.parse(b64UrlDecode(parts[0])) as Record<string, unknown>;
    const payload = JSON.parse(b64UrlDecode(parts[1])) as Record<string, unknown>;
    const now = Math.floor(Date.now() / 1000);
    const exp = typeof payload.exp === "number" ? payload.exp : undefined;
    const alg = typeof header.alg === "string" ? header.alg : undefined;
    const riskFlags: string[] = [];

    if (!alg || alg.toLowerCase() === "none") {
      riskFlags.push("Unsigned or weak JWT algorithm");
    }
    if (exp && exp < now) {
      riskFlags.push("Token appears expired");
    }
    if (payload.scope) {
      riskFlags.push("Scoped access claims present");
    }
    if (payload.roles || payload.role || payload.admin === true) {
      riskFlags.push("Privilege-related claims present");
    }

    const roles = Array.isArray(payload.roles)
      ? payload.roles.map(String)
      : payload.role
        ? [String(payload.role)]
        : [];

    return {
      header,
      payload,
      user: String(payload.sub ?? payload.username ?? payload.user ?? "Unknown"),
      email: String(payload.email ?? payload.upn ?? payload.preferred_username ?? "N/A"),
      roles,
      issuer: typeof payload.iss === "string" ? payload.iss : undefined,
      audience: (payload.aud as string | string[] | undefined) ?? undefined,
      expiry: exp,
      algorithm: alg,
      riskFlags,
    };
  } catch {
    return {
      user: "Unknown",
      email: "N/A",
      roles: [],
      riskFlags: ["Payload decode failed"],
      error: "Invalid JWT format",
    };
  }
}

export function detectFindings(record: ArchiveRecord, options: Record<string, boolean>): Finding[] {
  const findings: Finding[] = [];
  const url = record.url;
  const parsed = parseUrl(url);
  if (!parsed) return findings;

  const fileMatch = url.match(SENSITIVE_FILE_REGEX)?.[0];
  if (options.sensitiveFiles !== false && fileMatch) {
    const isWellKnown = parsed.pathname.includes(".well-known");
    findings.push(baseFinding({
      type: "sensitive_file",
      category: "Exposure",
      title: isWellKnown ? "Exposed well-known JSON/config file" : "Potentially sensitive file exposed",
      url,
      source: record.source,
      match: fileMatch,
      severity: isWellKnown ? "Info" : /\.(env|sql|key|pem|db)$/i.test(fileMatch) ? "Critical" : "High",
      confidence: isWellKnown ? "Confirmed" : /\.(env|sql|key|pem|db)$/i.test(fileMatch) ? "Confirmed" : "Likely",
      summary: isWellKnown
        ? "A standard discovery file was archived. This is usually benign but still useful for recon context."
        : `Archived path suggests a sensitive file exposure (${fileMatch}).`,
      impact: isWellKnown
        ? "May reveal product or integration metadata."
        : "Could expose source code, credentials, database content, or internal configuration.",
      recommendation: isWellKnown
        ? "Review contents for unintentional metadata leakage and ensure only expected values are published."
        : "Validate whether the file is still reachable, rotate any exposed secrets, and remove public access where not intended.",
      evidence: [`Archived URL: ${url}`, `Archive mime type: ${record.mimeType ?? "unknown"}`],
      tags: ["archive", "file-exposure", fileMatch.replace(".", "")],
      archive: record,
    }));
  }

  const xmlrpcMatch = url.match(XMLRPC_REGEX)?.[0];
  if (xmlrpcMatch) {
    findings.push(baseFinding({
      type: "xmlrpc_surface",
      category: "Exposure",
      title: "XML-RPC endpoint discovered",
      url,
      source: record.source,
      match: xmlrpcMatch,
      severity: "High",
      confidence: "Likely",
      summary: "XML-RPC was observed on this host.",
      impact: "XML-RPC can expand brute-force, pingback, and legacy WordPress attack surface.",
      recommendation: "Confirm whether XML-RPC is intentionally enabled, rate limit requests, and disable it if unused.",
      evidence: [`Matched endpoint: ${xmlrpcMatch}`, `Status code: ${record.statusCode ?? "unknown"}`],
      tags: ["xmlrpc", "wordpress", "attack-surface"],
      archive: record,
    }));
  }

  const graphqlMatch = url.match(GRAPHQL_REGEX)?.[0];
  if (graphqlMatch) {
    findings.push(baseFinding({
      type: "graphql_endpoint",
      category: "Exposure",
      title: "GraphQL endpoint discovered",
      url,
      source: record.source,
      match: graphqlMatch,
      severity: "Medium",
      confidence: "Likely",
      summary: "A GraphQL endpoint was discovered on this host.",
      impact: "GraphQL endpoints can expose schema data, introspection, and complex query abuse if not hardened.",
      recommendation: "Check auth requirements, disable public introspection when unnecessary, and enforce query complexity limits.",
      evidence: [`Matched endpoint: ${graphqlMatch}`],
      tags: ["graphql", "api", "attack-surface"],
      archive: record,
    }));
  }

  const apiDocsMatch = url.match(API_DOCS_REGEX)?.[0];
  if (apiDocsMatch) {
    findings.push(baseFinding({
      type: "api_docs_exposure",
      category: "Exposure",
      title: "API documentation surface discovered",
      url,
      source: record.source,
      match: apiDocsMatch,
      severity: "Medium",
      confidence: "Likely",
      summary: "An API documentation or schema endpoint was observed.",
      impact: "Live API documentation can reveal routes, parameters, and auth flows useful for attackers and defenders alike.",
      recommendation: "Restrict access if documentation is not meant to be public and review sensitive route exposure.",
      evidence: [`Matched endpoint: ${apiDocsMatch}`],
      tags: ["api-docs", "swagger", "openapi"],
      archive: record,
    }));
  }

  const debugEndpointMatch = url.match(DEBUG_ENDPOINT_REGEX)?.[0];
  if (debugEndpointMatch) {
    findings.push(baseFinding({
      type: "debug_endpoint",
      category: "Exposure",
      title: "Debug or introspection endpoint discovered",
      url,
      source: record.source,
      match: debugEndpointMatch,
      severity: /env|heapdump|phpinfo|server-status/i.test(debugEndpointMatch) ? "High" : "Medium",
      confidence: "Likely",
      summary: "A debugging, health, or introspection endpoint was identified.",
      impact: "These endpoints can reveal runtime state, environment data, internal mappings, or privileged diagnostic access.",
      recommendation: "Restrict to trusted networks, require authentication, and remove nonessential diagnostic endpoints from public exposure.",
      evidence: [`Matched endpoint: ${debugEndpointMatch}`],
      tags: ["debug", "diagnostics", "exposure"],
      archive: record,
    }));
  }

  const adminMatch = url.match(ADMIN_REGEX)?.[0];
  if (options.adminPanels !== false && adminMatch && !xmlrpcMatch && !graphqlMatch && !apiDocsMatch && !debugEndpointMatch) {
    findings.push(baseFinding({
      type: "admin_panel",
      category: "Exposure",
      title: "Administrative interface discovered",
      url,
      source: record.source,
      match: adminMatch,
      severity: "High",
      confidence: "Confirmed",
      summary: "An archived URL suggests an admin or privileged control path.",
      impact: "Increases attack surface for brute force, auth bypass, or misconfiguration exploitation.",
      recommendation: "Verify exposure with live probing, enforce MFA/IP restrictions, and remove obsolete admin paths.",
      evidence: [`Matched path fragment: ${adminMatch}`, `Host: ${parsed.hostname}`],
      tags: ["admin", "auth-surface", "archive"],
      archive: record,
    }));
  }

  const backupMatch = url.match(BACKUP_REGEX)?.[0];
  if (options.backups !== false && backupMatch) {
    findings.push(baseFinding({
      type: "backup",
      category: "Exposure",
      title: "Backup or archive artifact exposed",
      url,
      source: record.source,
      match: backupMatch,
      severity: "Critical",
      confidence: "Likely",
      summary: "Backup-like naming pattern found in archived URL history.",
      impact: "Archived backups often contain source code, credentials, or full database dumps.",
      recommendation: "Check whether the asset is still live, inspect content safely, and remove public access immediately if confirmed.",
      evidence: [`Matched extension: ${backupMatch}`, `Archive status code: ${record.statusCode ?? "unknown"}`],
      tags: ["backup", "archive", "high-value"],
      archive: record,
    }));
  }

  if (options.cloudStorage !== false) {
    const cloudMatch = url.match(CLOUD_REGEX)?.[0];
    if (cloudMatch) {
      findings.push(baseFinding({
        type: "cloud_storage",
        category: "Exposure",
        title: "Cloud storage reference discovered",
        url,
        source: record.source,
        match: cloudMatch,
        severity: "Medium",
        confidence: "Confirmed",
        summary: "Archived content references external cloud storage infrastructure.",
        impact: "Buckets or object stores may hold backups, static assets, or unintended public data.",
        recommendation: "Validate bucket permissions, inventory exposed objects, and restrict anonymous access if not intended.",
        evidence: [`Storage provider marker: ${cloudMatch}`],
        tags: ["cloud", "storage", "third-party"],
        archive: record,
      }));
    }
  }

  const params = Array.from(parsed.searchParams.keys()).map((param) => param.toLowerCase());
  const xssParam = params.find((param) => XSS_PARAM_NAMES.has(param));
  if (xssParam) {
    findings.push(baseFinding({
      type: "xss_clue",
      category: "Historical",
      title: "Possible reflected input point",
      url,
      source: record.source,
      match: xssParam,
      severity: "Medium",
      confidence: "Needs Validation",
      summary: `Archived URL includes the parameter "${xssParam}", which is commonly reflected in search or user input flows.`,
      impact: "If the parameter is reflected unsafely in responses, it could indicate XSS or HTML injection risk.",
      recommendation: "Probe the live endpoint with safe test payloads and verify output encoding for reflected input.",
      evidence: [`Parameter observed: ${xssParam}`, `Archived URL: ${url}`],
      tags: ["xss-clue", "input-reflection", "historical"],
      archive: record,
    }));
  }

  const redirectParam = params.find((param) => REDIRECT_PARAM_NAMES.has(param));
  if (redirectParam) {
    findings.push(baseFinding({
      type: "open_redirect_clue",
      category: "Historical",
      title: "Possible redirect or callback parameter",
      url,
      source: record.source,
      match: redirectParam,
      severity: "Medium",
      confidence: "Needs Validation",
      summary: `Archived URL includes the parameter "${redirectParam}", a common redirect or callback sink.`,
      impact: "Poor validation of redirect targets can lead to open redirect, OAuth abuse, or phishing chains.",
      recommendation: "Check whether the endpoint restricts redirect destinations and validates callback targets against an allowlist.",
      evidence: [`Parameter observed: ${redirectParam}`, `Archived URL: ${url}`],
      tags: ["redirect-clue", "oauth-flow", "historical"],
      archive: record,
    }));
  }

  const ssrfParam = params.find((param) => SSRF_PARAM_NAMES.has(param));
  if (ssrfParam) {
    const value = parsed.searchParams.get(ssrfParam) || "";
    const hintsInternal = /(?:169\.254\.169\.254|\.internal\b|\.local\b|0\.0\.0\.0|127\.|10\.)/i.test(value);
    const looksLikeUrl = /^https?:\/\//i.test(value);
    if (hintsInternal || looksLikeUrl) {
      findings.push(baseFinding({
        type: "ssrf_clue",
        category: "Exposure",
        title: "Possible SSRF / server-side fetch parameter",
        url,
        source: record.source,
        match: ssrfParam,
        severity: hintsInternal ? "High" : "Medium",
        confidence: "Needs Validation",
        summary: `Parameter "${ssrfParam}" is commonly used for outbound fetch/proxy logic.`,
        impact: "If unvalidated, it may allow internal network access, metadata service access, or arbitrary HTTP calls.",
        recommendation: "Validate destinations against an allowlist, block internal IP ranges, and enforce protocol/hostname checks.",
        evidence: [`Parameter observed: ${ssrfParam}`, value ? `Value sample: ${value.slice(0, 140)}` : "No sample value in archive"],
        tags: ["ssrf-clue", "server-side-request", "archive"],
        archive: record,
      }));
    }
  }

  if (options.apiKeys !== false) {
    const keyMatch = url.match(API_KEY_REGEX)?.[1];
    if (keyMatch) {
      findings.push(baseFinding({
        type: "api_key",
        category: "Secret",
        title: "API key-like value in archived URL",
        url,
        source: record.source,
        match: keyMatch,
        redactedMatch: redactSecret(keyMatch),
        severity: "Critical",
        confidence: "Needs Validation",
        summary: "A key-shaped value is present in a query string or path.",
        impact: "If still valid, the key could allow API calls, data access, or billing abuse.",
        recommendation: "Validate safely, rotate if active, and prevent secrets from being embedded in URLs.",
        evidence: [`Redacted value: ${redactSecret(keyMatch)}`],
        tags: ["secret", "api-key", "url-leak"],
        archive: record,
      }));
    }
  }

  if (options.oauthTokens !== false) {
    const oauthMatch = url.match(OAUTH_REGEX)?.[1];
    if (oauthMatch) {
      findings.push(baseFinding({
        type: "oauth_token",
        category: "Secret",
        title: "OAuth token-like value in archived URL",
        url,
        source: record.source,
        match: oauthMatch,
        redactedMatch: redactSecret(oauthMatch),
        severity: "High",
        confidence: "Needs Validation",
        summary: "A bearer or refresh token pattern was found in an archived URL.",
        impact: "Active tokens could permit session reuse or unauthorized API access.",
        recommendation: "Invalidate active tokens, review token transport patterns, and keep tokens out of URLs.",
        evidence: [`Redacted token: ${redactSecret(oauthMatch)}`],
        tags: ["secret", "oauth", "session-risk"],
        archive: record,
      }));
    }
  }

  if (options.jwtTokens !== false) {
    const jwtToken = url.match(JWT_REGEX)?.[0];
    if (jwtToken) {
      const jwt = analyzeJwt(jwtToken);
      findings.push(baseFinding({
        type: "jwt",
        category: "Secret",
        title: "JWT exposed in archived URL",
        url,
        source: record.source,
        match: jwtToken,
        redactedMatch: redactSecret(jwtToken),
        severity: "High",
        confidence: jwt.error ? "Needs Validation" : "Confirmed",
        summary: "A JSON Web Token was embedded in a URL captured by an archive.",
        impact: "JWT claims may reveal identity, privileges, issuers, and potentially allow replay if the token remains valid.",
        recommendation: "Treat the token as compromised, review claim sensitivity, rotate secrets if needed, and stop transporting JWTs in URLs.",
        evidence: [
          `Redacted token: ${redactSecret(jwtToken)}`,
          `JWT algorithm: ${jwt.algorithm ?? "unknown"}`,
          `JWT risk flags: ${jwt.riskFlags.join(", ") || "none"}`,
        ],
        tags: ["secret", "jwt", "identity"],
        archive: record,
        jwt,
      }));
    }
  }

  if (options.directoryListing !== false && checkDirectoryListing(url)) {
    findings.push(baseFinding({
      type: "directory_listing_candidate",
      category: "Historical",
      title: "Interesting directory path discovered",
      url,
      source: record.source,
      match: parsed.pathname,
      severity: "Low",
      confidence: "Needs Validation",
      summary: "Directory-style URL may reveal browseable content or hidden structure.",
      impact: "Useful for attack-surface enumeration and may expose indexes if still enabled.",
      recommendation: "Validate with a live request and compare returned content for index signatures.",
      evidence: [`Path: ${parsed.pathname}`],
      tags: ["directory", "enumeration"],
      archive: record,
    }));
  }

  return findings;
}

export function detectLiveFindings(
  url: string,
  probe: ProbeResult,
  options: Record<string, boolean>,
): Finding[] {
  const findings: Finding[] = [];
  if (probe.status === 0) return findings;

  const parsed = parseUrl(probe.finalUrl || url);
  if (!parsed) return findings;
  const liveRecord = buildLiveRecord(parsed.toString(), probe);
  const signalText = [probe.title, probe.server ?? "", parsed.pathname].join(" ").trim();

  const loginPathMatch = parsed.pathname.match(LOGIN_PATH_REGEX)?.[0];
  const loginTitleMatch = signalText.match(LOGIN_TITLE_REGEX)?.[0];
  const vpnPathMatch = parsed.pathname.match(VPN_PATH_REGEX)?.[0];
  const vpnTitleMatch = signalText.match(VPN_TITLE_REGEX)?.[0];
  if (options.adminPanels !== false && !loginPathMatch && loginTitleMatch) {
    const lowerSignal = loginTitleMatch.toLowerCase();
    const isStrongPortal = /vmware horizon|roundcube|cpanel|plesk|citrix|okta|adfs|outlook web access/.test(lowerSignal);
    findings.push(baseFinding({
      type: "live_login_surface",
      category: "Exposure",
      title: isStrongPortal ? "Named login portal exposed" : "Live authentication surface discovered",
      url: parsed.toString(),
      source: liveRecord.source,
      match: loginTitleMatch,
      severity: isStrongPortal ? "High" : "Medium",
      confidence: "Confirmed",
      summary: "Live probing identified a login or authentication portal.",
      impact: "These surfaces are high-priority for SOC review because they frequently represent externally reachable user or admin access.",
      recommendation: "Confirm intended exposure, enforce MFA and rate limiting, and inventory ownership of this login surface.",
      evidence: [
        `Title: ${probe.title || "Unavailable"}`,
        `HTTP status: ${probe.status}`,
        `Final URL: ${parsed.toString()}`,
      ],
      tags: ["login", "auth-surface", "live"],
      archive: liveRecord,
    }));
  }

  if (options.adminPanels !== false && (vpnPathMatch || vpnTitleMatch)) {
    const matchedSignal = vpnPathMatch || vpnTitleMatch || parsed.pathname;
    findings.push(baseFinding({
      type: "vpn_surface",
      category: "Exposure",
      title: "VPN or remote access surface discovered",
      url: parsed.toString(),
      source: liveRecord.source,
      match: matchedSignal,
      severity: "High",
      confidence: "Confirmed",
      summary: "Live probing identified a VPN, gateway, or remote-access surface.",
      impact: "Remote access portals are high-priority external entry points and should be reviewed for MFA, ownership, and exposure policy.",
      recommendation: "Validate intended exposure, enforce MFA and conditional access, and confirm the service owner and hardening baseline.",
      evidence: [
        `Matched signal: ${matchedSignal}`,
        `Title: ${probe.title || "Unavailable"}`,
        `HTTP status: ${probe.status}`,
      ],
      tags: ["vpn", "remote-access", "auth-surface", "live"],
      archive: liveRecord,
    }));
  }

  if (options.cloudStorage !== false && probe.status !== 404 && probe.status !== 410) {
    const cloudSignal = `${probe.server ?? ""} ${probe.title} ${parsed.toString()}`.match(CLOUD_REGEX)?.[0];
    if (cloudSignal) {
      findings.push(baseFinding({
        type: "cloud_storage_live",
        category: "Exposure",
        title: "Live cloud storage surface detected",
        url: parsed.toString(),
        source: liveRecord.source,
        match: cloudSignal,
        severity: probe.status === 200 ? "High" : "Medium",
        confidence: "Confirmed",
        summary: "Live probing indicates the host is backed by a cloud storage surface.",
        impact: "Object storage endpoints can expose buckets, static assets, or misconfigured protected files.",
        recommendation: "Review the backing bucket or object store permissions and confirm that access controls match intended exposure.",
        evidence: [
          `Matched provider marker: ${cloudSignal}`,
          `HTTP status: ${probe.status}`,
        ],
        tags: ["cloud", "storage", "live"],
        archive: liveRecord,
      }));
    }
  }

  if (options.directoryListing !== false && probe.status === 200 && /^index of\b/i.test(probe.title || "")) {
    findings.push(baseFinding({
      type: "directory_listing_live",
      category: "Exposure",
      title: "Live directory listing detected",
      url: parsed.toString(),
      source: liveRecord.source,
      match: probe.title,
      severity: "High",
      confidence: "Confirmed",
      summary: "The live page title indicates an exposed directory index.",
      impact: "Directory listings can leak internal files, source bundles, and deployment structure.",
      recommendation: "Disable auto-indexing and restrict direct access to the exposed directory.",
      evidence: [
        `Title: ${probe.title}`,
        `HTTP status: ${probe.status}`,
      ],
      tags: ["directory-listing", "live", "exposure"],
      archive: liveRecord,
    }));
  }

  return findings;
}


