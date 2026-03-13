import { ArchiveRecord } from "../types";

function parseRecordLine(line: string): ArchiveRecord | null {
  const trimmed = line.trim();
  if (!trimmed) return null;

  const parts = trimmed.split(" ");
  if (parts.length < 2) return null;

  const [timestamp, original, statusCode, mimeType, digest] = parts;
  return {
    url: original,
    source: "wayback",
    timestamp,
    statusCode: statusCode ? Number(statusCode) || null : null,
    mimeType: mimeType ?? null,
    digest: digest ?? null,
  };
}

export async function streamWaybackRecords(
  domain: string,
  limit: number,
  abortSignal: AbortSignal,
  onRecord: (record: ArchiveRecord) => void,
): Promise<void> {
  const url = `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&collapse=urlkey&output=txt&limit=${limit}&fl=timestamp,original,statuscode,mimetype,digest`;

  try {
    const response = await fetch(url, { signal: abortSignal });

    if (!response.ok) {
      throw new Error(`Wayback Machine API error: ${response.status} ${response.statusText}`);
    }
    if (!response.body) {
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        const record = parseRecordLine(line);
        if (record) {
          onRecord(record);
        }
      }
    }

    if (buffer.trim()) {
      const record = parseRecordLine(buffer);
      if (record) {
        onRecord(record);
      }
    }
  } catch (error) {
    if ((error as Error).name === "AbortError") {
      throw error;
    }
    console.warn(`Wayback fetch skipped: ${((error as Error).message || "unknown error")}`);
    return;
  }
}

