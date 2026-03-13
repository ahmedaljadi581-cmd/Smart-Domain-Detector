import fs from "fs";
import path from "path";
import { spawn } from "child_process";
import { ToolExecution } from "../types";

type ToolResult = {
  execution: ToolExecution;
  stdoutLines: string[];
};

const ANSI_ESCAPE_PATTERN = /\x1b\[[0-9;]*m/g;

function stripAnsi(input: string): string {
  return input.replace(ANSI_ESCAPE_PATTERN, "");
}

function summarizeToolDetail(name: string, raw?: string): string | undefined {
  const detail = raw?.trim();
  if (!detail) return undefined;
  const lowered = detail.toLowerCase();

  if (name === "arjun") {
    if (lowered.includes("remotedisconnected") || lowered.includes("connection aborted")) {
      return "Passive parameter providers disconnected during lookup";
    }
    if (lowered.includes("insecurerequestwarning")) {
      return "Passive parameter lookup returned provider warnings or network instability";
    }
  }

  if (name === "waymore" && lowered.includes("timed out")) {
    return detail.split(/\r?\n/)[0];
  }

  if (name === "subcat" && lowered.includes("timed out")) {
    return detail.split(/\r?\n/)[0];
  }

  const firstMeaningfulLine = detail
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line && !/^traceback/i.test(line) && !/^at line:/i.test(line));

  const compact = firstMeaningfulLine || detail.split(/\r?\n/)[0] || detail;
  return compact.length > 280 ? `${compact.slice(0, 277)}...` : compact;
}

function classifyReason(status: ToolExecution["status"], details?: string): ToolExecution["reasonKind"] {
  const lowered = (details || "").toLowerCase();
  if (status === "missing") return "installation";
  if (status === "completed" && lowered.includes("partial")) return "partial";
  if (lowered.includes("429") || lowered.includes("rate limit")) return "rate-limit";
  if (lowered.includes("timed out")) return "timeout";
  if (lowered.includes("api_key") || lowered.includes("not configured") || lowered.includes("use wsl")) return "config";
  if (lowered.includes("binary not installed")) return "installation";
  if (
    lowered.includes("unavailable")
    || lowered.includes("econn")
    || lowered.includes("network")
    || lowered.includes("refused")
    || lowered.includes("disconnected")
    || lowered.includes("connection aborted")
    || lowered.includes("remote end closed connection")
  ) return "network";
  if (status === "completed") return "success";
  if (status === "skipped") return "info";
  return "crash";
}

const PROJECT_ROOT = process.cwd();
const LOCAL_TOOL_PATHS = [
  path.join(PROJECT_ROOT, "tools", "bin"),
  path.join(PROJECT_ROOT, "tools", "runtime", "go", "bin"),
  path.join(PROJECT_ROOT, "tools", "runtime", "pytools", "Scripts"),
  path.join(PROJECT_ROOT, "tools", "runtime", "pytools", "bin"),
].filter((candidate) => fs.existsSync(candidate));

function normalizePathEntries(rawPath: string | undefined): string[] {
  return (rawPath || "")
    .split(path.delimiter)
    .map((entry) => entry.trim().replace(/^"(.*)"$/, "$1"))
    .filter(Boolean)
    .filter((entry, index, all) => all.indexOf(entry) === index)
    .filter((entry) => fs.existsSync(entry));
}

const PATH_DIRECTORIES = normalizePathEntries(process.env.PATH);

const SEARCH_PATHS = [
  ...LOCAL_TOOL_PATHS,
  ...PATH_DIRECTORIES,
].filter((entry, index, all) => all.indexOf(entry) === index);

const LOCAL_PATH_ENV = [
  ...LOCAL_TOOL_PATHS,
  process.env.PATH || "",
].filter(Boolean).join(path.delimiter);

const WINDOWS_EXECUTABLE_SUFFIXES = process.platform === "win32"
  ? [".exe", ".cmd", ".bat", ""]
  : [""];

function getToolCategory(name: string): ToolExecution["category"] {
  if (["dnsx", "puredns"].includes(name)) return "dns";
  if (["httpx", "subzy"].includes(name)) return "probe";
  if (["gau", "waybackurls", "katana", "waymore", "arjun"].includes(name)) return "archive";
  return "subdomain";
}

function hasLocalBinary(name: string): boolean {
  return SEARCH_PATHS.some((basePath) => WINDOWS_EXECUTABLE_SUFFIXES.some((suffix) => {
    const candidate = path.join(basePath, suffix ? `${name}${suffix}` : name);
    return fs.existsSync(candidate);
  }));
}

export function getToolAvailability(name: string): ToolExecution {
  const available = hasLocalBinary(name);

  if (name === "bbot" && process.platform === "win32" && available) {
    return {
      name,
      category: getToolCategory(name),
      available: true,
      used: false,
      status: "skipped",
      details: "Installed locally, but BBOT is not usable on native Windows here; use WSL for active BBOT scans",
    };
  }

  return {
    name,
    category: getToolCategory(name),
    available,
    used: false,
    status: available ? "skipped" : "missing",
    details: available ? "Installed locally and ready" : "Binary not installed",
    reasonKind: available ? "info" : "installation",
  };
}

export async function runLineTool(
  name: string,
  args: string[],
  category: ToolExecution["category"],
  abortSignal: AbortSignal,
  timeoutMs = 30000,
  stdinText?: string,
): Promise<ToolResult> {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let finished = false;

    const child = spawn(name, args, {
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      env: {
        ...process.env,
        PATH: LOCAL_PATH_ENV,
      },
    });

    if (stdinText) {
      child.stdin.write(stdinText);
    }
    child.stdin.end();

    const finish = (execution: ToolExecution) => {
      if (finished) return;
      finished = true;
      resolve({
        execution,
        stdoutLines: stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
      });
    };

    const timeout = setTimeout(() => {
      child.kill();
      const hasPartialOutput = stdout.trim().length > 0;
      finish({
        name,
        category,
        available: true,
        used: true,
        status: hasPartialOutput ? "completed" : "failed",
        details: hasPartialOutput
          ? `Timed out after ${timeoutMs}ms (partial results captured)`
          : `Timed out after ${timeoutMs}ms`,
        reasonKind: hasPartialOutput ? "partial" : "timeout",
      });
    }, timeoutMs);

    const abort = () => {
      child.kill();
      clearTimeout(timeout);
      finish({
        name,
        category,
        available: true,
        used: true,
        status: "skipped",
        details: "Cancelled",
        reasonKind: "info",
      });
    };

    abortSignal.addEventListener("abort", abort, { once: true });

    child.stdout.on("data", (chunk) => {
      stdout += stripAnsi(String(chunk));
    });

    child.stderr.on("data", (chunk) => {
      stderr += stripAnsi(String(chunk));
    });

    child.on("error", (error: NodeJS.ErrnoException) => {
      clearTimeout(timeout);
      abortSignal.removeEventListener("abort", abort);
      if (error.code === "ENOENT") {
        finish({
          name,
          category,
          available: false,
          used: false,
          status: "missing",
          details: "Binary not installed",
          reasonKind: "installation",
        });
        return;
      }
      finish({
        name,
        category,
        available: true,
        used: true,
        status: "failed",
        details: error.message,
        reasonKind: classifyReason("failed", error.message),
      });
    });

    child.on("close", (code) => {
      clearTimeout(timeout);
      abortSignal.removeEventListener("abort", abort);
      if (finished) return;
      finish({
        name,
        category,
        available: true,
        used: true,
        status: code === 0 ? "completed" : "failed",
        details: code === 0 ? undefined : summarizeToolDetail(name, stderr.trim() || `Exited with code ${code}`),
        reasonKind: classifyReason(code === 0 ? "completed" : "failed", summarizeToolDetail(name, stderr.trim() || `Exited with code ${code}`)),
      });
    });
  });
}
