import dns from "dns/promises";
import tls from "tls";
import { createHash } from "crypto";
import { IpIntel, ProbeResult, ToolExecution } from "../types";
import { runLineTool } from "./tool-runner";

function inferProviderFromSignals(signals: string[]): string | undefined {
  const joined = signals.join(" ").toLowerCase();
  if (!joined) return undefined;
  if (joined.includes("cloudflare")) return "Cloudflare";
  if (joined.includes("amazonaws") || joined.includes("cloudfront") || joined.includes("elb.amazonaws")) return "Amazon Web Services";
  if (joined.includes("azure") || joined.includes("azurewebsites") || joined.includes("trafficmanager") || joined.includes("outlook")) return "Microsoft Azure";
  if (joined.includes("google") || joined.includes("googleapis") || joined.includes("appspot")) return "Google Cloud";
  if (joined.includes("vercel")) return "Vercel";
  if (joined.includes("netlify")) return "Netlify";
  if (joined.includes("fastly")) return "Fastly";
  if (joined.includes("akamai")) return "Akamai";
  if (joined.includes("digitalocean")) return "DigitalOcean";
  if (joined.includes("oraclecloud")) return "Oracle Cloud";
  if (joined.includes("herokudns")) return "Heroku";
  return undefined;
}

function isReachableStatus(status: number): boolean {
  return status > 0 && status !== 404 && status !== 410;
}

export async function getDnsRecords(domain: string) {
  const records: {
    a: string[];
    cname: string[];
    mx: { exchange: string; priority: number }[];
    ns: string[];
    hostingProvider?: string;
    mailProvider?: string;
  } = { a: [], cname: [], mx: [], ns: [] };
  try {
    records.a = await dns.resolve4(domain);
  } catch {
    // Ignore when no A records are available.
  }
  try {
    records.cname = await dns.resolveCname(domain);
  } catch {
    // Ignore when no CNAME records are available.
  }
  try {
    records.mx = await dns.resolveMx(domain);
  } catch {
    // Ignore when no MX records are available.
  }
  try {
    records.ns = await dns.resolveNs(domain);
  } catch {
    // Ignore when no NS records are available.
  }
  records.hostingProvider = inferProviderFromSignals([...records.cname, ...records.a]);
  records.mailProvider = inferProviderFromSignals(records.mx.map((record) => record.exchange));
  return records;
}

export async function resolveHostname(hostname: string): Promise<{ a: string[]; cname: string[]; resolved: boolean }> {
  const result = { a: [] as string[], cname: [] as string[], resolved: false };
  try {
    result.a = await dns.resolve4(hostname);
  } catch {
    // Ignore when no A records are available.
  }
  try {
    result.cname = await dns.resolveCname(hostname);
  } catch {
    // Ignore when no CNAME records are available.
  }
  result.resolved = result.a.length > 0 || result.cname.length > 0;
  return result;
}

export async function resolveHostnamesWithDnsx(
  hostnames: string[],
  abortSignal: AbortSignal,
): Promise<{
  results: Map<string, { a: string[]; cname: string[]; resolved: boolean }>;
  execution: ToolExecution;
} | null> {
  const uniqueHosts = Array.from(new Set(hostnames.map((host) => host.trim()).filter(Boolean)));
  if (uniqueHosts.length === 0) return null;

  const result = await runLineTool(
    "dnsx",
    ["-silent", "-j", "-a", "-cname", "-retry", "1", "-timeout", "2"],
    "dns",
    abortSignal,
    15000,
    `${uniqueHosts.join("\n")}\n`,
  );

  if (!result.execution.available || result.execution.status === "missing") {
    return null;
  }

  const output = new Map<string, { a: string[]; cname: string[]; resolved: boolean }>();
  for (const line of result.stdoutLines) {
    try {
      const parsed = JSON.parse(line) as {
        host?: string;
        a?: string[];
        cname?: string[];
      };
      const host = parsed.host?.toLowerCase().trim();
      if (!host) continue;
      const a = Array.isArray(parsed.a) ? parsed.a : [];
      const cname = Array.isArray(parsed.cname) ? parsed.cname : [];
      output.set(host, { a, cname, resolved: a.length > 0 || cname.length > 0 });
    } catch {
      // Ignore malformed lines from the tool output.
    }
  }

  return {
    results: output,
    execution: {
      ...result.execution,
      count: output.size,
      details: result.execution.details,
    },
  };
}

export async function getTlsDetails(domain: string): Promise<{
  subject: string;
  issuer: string;
  validFrom?: string;
  validTo?: string;
  san: string[];
  fingerprint256?: string;
  protocol?: string;
  expired: boolean;
  daysRemaining?: number | null;
} | null> {
  return new Promise((resolve) => {
    type TlsResult = {
      subject: string;
      issuer: string;
      validFrom?: string;
      validTo?: string;
      san: string[];
      fingerprint256?: string;
      protocol?: string;
      expired: boolean;
      daysRemaining?: number | null;
    } | null;

    const socket = tls.connect({
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false,
      timeout: 5000,
    });

    const finish = (result: TlsResult) => {
      if (!socket.destroyed) {
        socket.destroy();
      }
      resolve(result);
    };

    socket.once("secureConnect", () => {
      try {
        const certificate = socket.getPeerCertificate();
        if (!certificate || !certificate.subject) {
          finish(null);
          return;
        }

        const validTo = certificate.valid_to ? new Date(certificate.valid_to) : null;
        const now = Date.now();
        const daysRemaining = validTo ? Math.round((validTo.getTime() - now) / 86400000) : null;
        const subject = typeof certificate.subject === "object"
          ? Object.values(certificate.subject).filter(Boolean).join(", ")
          : String(certificate.subject);
        const issuer = typeof certificate.issuer === "object"
          ? Object.values(certificate.issuer).filter(Boolean).join(", ")
          : String(certificate.issuer ?? "Unknown");
        const san = typeof certificate.subjectaltname === "string"
          ? certificate.subjectaltname.split(",").map((item) => item.replace(/^DNS:/, "").trim())
          : [];

        finish({
          subject,
          issuer,
          validFrom: certificate.valid_from,
          validTo: certificate.valid_to,
          san,
          fingerprint256: certificate.fingerprint256,
          protocol: socket.getProtocol() || undefined,
          expired: daysRemaining !== null ? daysRemaining < 0 : false,
          daysRemaining,
        });
      } catch {
        finish(null);
      }
    });

    socket.once("error", () => finish(null));
    socket.once("timeout", () => finish(null));
  });
}

export { inferProviderFromSignals };

type RdapEntity = {
  entities?: RdapEntity[];
  vcardArray?: [string, Array<[string, Record<string, unknown>, string, string | string[]]>];
};

function collectRdapContacts(entities: RdapEntity[] | undefined, names: Set<string>, emails: Set<string>) {
  for (const entity of entities || []) {
    const vcardEntries = Array.isArray(entity.vcardArray?.[1]) ? entity.vcardArray[1] : [];
    for (const entry of vcardEntries) {
      const [field, , , value] = entry;
      if ((field === "fn" || field === "org") && typeof value === "string" && value.trim()) {
        names.add(value.trim());
      }
      if (field === "email") {
        const values = Array.isArray(value) ? value : [value];
        values
          .filter((item): item is string => typeof item === "string" && item.includes("@"))
          .forEach((email) => emails.add(email.trim().toLowerCase()));
      }
    }
    if (entity.entities?.length) {
      collectRdapContacts(entity.entities, names, emails);
    }
  }
}

export async function getIpIntelligence(ips: string[]): Promise<IpIntel[]> {
  const uniqueIps = Array.from(new Set(ips.filter(Boolean)));
  const intel: IpIntel[] = [];

  for (const ip of uniqueIps) {
    try {
      const response = await fetch(`https://rdap.arin.net/registry/ip/${encodeURIComponent(ip)}`, {
        headers: {
          Accept: "application/rdap+json",
          "User-Agent": "Smart-Domain-Detector/1.0",
        },
      });
      if (!response.ok) {
        continue;
      }
      const payload = await response.json() as {
        name?: string;
        country?: string;
        entities?: RdapEntity[];
      };
      const names = new Set<string>();
      const emails = new Set<string>();
      collectRdapContacts(payload.entities, names, emails);
      intel.push({
        ip,
        network: payload.name,
        country: payload.country,
        owner: names.values().next().value || payload.name,
        emails: Array.from(emails).slice(0, 5),
      });
    } catch {
      // Ignore RDAP lookup failures and keep scanning.
    }
  }

  return intel;
}

async function readResponseSample(response: Response, byteLimit = 65536): Promise<string> {
  if (!response.body) {
    return await response.text();
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let received = 0;
  let text = "";

  try {
    while (received < byteLimit) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      received += value.byteLength;
      text += decoder.decode(value, { stream: true });
      if (received >= byteLimit) break;
    }
    text += decoder.decode();
  } finally {
    reader.cancel().catch(() => undefined);
  }

  return text;
}

function unreachableProbe(url: string): ProbeResult {
  return {
    alive: false,
    status: 0,
    title: "",
    finalUrl: url,
    contentLength: null,
    server: null,
    contentHash: null,
  };
}

async function probeOnce(url: string): Promise<ProbeResult> {
  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, {
      method: "GET",
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "Wayback-Smart-Scanner/2.0 (+validation)",
      },
    });
    clearTimeout(id);

    const text = await readResponseSample(response);
    const hash = createHash("sha1").update(text).digest("hex");
    const titleMatch = text.match(/<title[^>]*>([^<]+)<\/title>/i);
    const contentType = response.headers.get("content-type") ?? undefined;
    const contentLengthHeader = response.headers.get("content-length");
    const server = response.headers.get("server");

    return {
      alive: isReachableStatus(response.status),
      status: response.status,
      title: titleMatch ? titleMatch[1].trim() : "No Title",
      finalUrl: response.url,
      contentType,
      contentLength: contentLengthHeader ? Number(contentLengthHeader) || null : text.length,
      server,
      contentHash: hash,
    };
  } catch {
    return unreachableProbe(url);
  }
}

export async function probeUrl(url: string): Promise<ProbeResult> {
  const first = await probeOnce(url);
  if (first.status !== 0) {
    return first;
  }

  try {
    const parsed = new URL(url);
    if (parsed.protocol === "https:") {
      parsed.protocol = "http:";
      const fallback = await probeOnce(parsed.toString());
      if (fallback.status !== 0) {
        return fallback;
      }
    }
  } catch {
    return first;
  }

  return first;
}
