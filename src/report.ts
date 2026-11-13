/**
 * The timing report, as the page reads and writes it.
 *
 * The Go runtime owns the measurement and emits one JSON document; this module
 * is the only place that knows that document's shape. It validates the answer
 * instead of trusting it, turns the raw marks into timeline phases, and writes
 * the plain-text report the copy action sends back through the host.
 */

export interface Timings {
  dns: number;
  connect: number;
  tls: number;
  server: number;
  transfer: number;
  total: number;
  namelookup: number;
  pretransfer: number;
  starttransfer: number;
}

export interface HeaderPair {
  name: string;
  value: string;
}

export interface TlsInfo {
  version: string;
  cipher: string;
  serverName?: string;
  protocol?: string;
}

export interface Report {
  url: string;
  method: string;
  status: number;
  statusText: string;
  statusLine: string;
  proto: string;
  remoteAddr?: string;
  remoteIp?: string;
  remotePort?: string;
  tls?: TlsInfo;
  contentType?: string;
  /** Declared length; -1 when the response did not name one. */
  contentLength: number;
  /** Bytes actually read. */
  size: number;
  bodyTruncated: boolean;
  headers: HeaderPair[];
  timings: Timings;
}

export type PhaseKey = "dns" | "connect" | "tls" | "server" | "transfer";

export interface Phase {
  key: PhaseKey;
  label: string;
  /** Offset from the start of the request, in milliseconds. */
  start: number;
  /** Duration in milliseconds. */
  duration: number;
  /** Fraction of the track this phase occupies. */
  offset: number;
  width: number;
  /** Fraction of the total this phase accounts for. */
  share: number;
}

export interface Mark {
  key: PhaseKey;
  label: string;
  value: number;
  /** Where the checkpoint falls on the track, 0–1. */
  ratio: number;
}

const PHASE_LABELS: Record<PhaseKey, string> = {
  dns: "DNS 查询",
  connect: "TCP 连接",
  tls: "TLS 握手",
  server: "等待响应",
  transfer: "内容传输",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function stringField(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

/** A non-negative finite number; anything else becomes 0. */
function amount(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return 0;
  return value;
}

function parseTls(value: unknown): TlsInfo | undefined {
  if (!isRecord(value)) return undefined;
  const version = stringField(value.version);
  const cipher = stringField(value.cipher);
  if (version === "" || cipher === "") return undefined;
  const info: TlsInfo = { version, cipher };
  const serverName = stringField(value.serverName);
  const protocol = stringField(value.protocol);
  if (serverName !== "") info.serverName = serverName;
  if (protocol !== "") info.protocol = protocol;
  return info;
}

function parseHeaders(value: unknown): HeaderPair[] {
  if (!Array.isArray(value)) return [];
  const headers: HeaderPair[] = [];
  for (const entry of value) {
    if (!isRecord(entry)) continue;
    const name = stringField(entry.name);
    const headerValue = stringField(entry.value);
    if (name === "") continue;
    headers.push({ name, value: headerValue });
    if (headers.length >= 128) break;
  }
  return headers;
}

function parseTimings(value: unknown): Timings {
  if (!isRecord(value)) throw new Error("计时结果缺少分段时间");
  const total = amount(value.total);
  if (total <= 0) throw new Error("计时结果的总耗时无效");
  return {
    dns: amount(value.dns),
    connect: amount(value.connect),
    tls: amount(value.tls),
    server: amount(value.server),
    transfer: amount(value.transfer),
    total,
    namelookup: amount(value.namelookup),
    pretransfer: amount(value.pretransfer),
    starttransfer: amount(value.starttransfer),
  };
}

/** parseReport validates the runtime's JSON. A malformed answer is an error,
 * never a page that renders zeroes as if the request had been instant. */
export function parseReport(output: string): Report {
  let parsed: unknown;
  try {
    parsed = JSON.parse(output);
  } catch {
    throw new Error("计时结果的格式不正确");
  }
  if (!isRecord(parsed)) throw new Error("计时结果的格式不正确");
  const status = parsed.status;
  if (typeof status !== "number" || !Number.isInteger(status) || status < 100 || status > 599) {
    throw new Error("计时结果缺少有效的状态码");
  }
  const report: Report = {
    url: stringField(parsed.url),
    method: stringField(parsed.method, "GET"),
    status,
    statusText: stringField(parsed.statusText),
    statusLine: stringField(parsed.statusLine),
    proto: stringField(parsed.proto),
    contentLength: typeof parsed.contentLength === "number" ? parsed.contentLength : -1,
    size: amount(parsed.size),
    bodyTruncated: parsed.bodyTruncated === true,
    headers: parseHeaders(parsed.headers),
    timings: parseTimings(parsed.timings),
  };
  const remoteAddr = stringField(parsed.remoteAddr);
  const remoteIp = stringField(parsed.remoteIp);
  const remotePort = stringField(parsed.remotePort);
  const contentType = stringField(parsed.contentType);
  const tls = parseTls(parsed.tls);
  if (remoteAddr !== "") report.remoteAddr = remoteAddr;
  if (remoteIp !== "") report.remoteIp = remoteIp;
  if (remotePort !== "") report.remotePort = remotePort;
  if (contentType !== "") report.contentType = contentType;
  if (tls) report.tls = tls;
  return report;
}

/** phases lays the measured spans on one track. The TLS row exists only when
 * the handshake did; every other span is always there, even at zero. */
export function phases(report: Report): Phase[] {
  const timings = report.timings;
  const spans: Array<{ key: PhaseKey; start: number; duration: number }> = [
    { key: "dns", start: timings.namelookup - timings.dns, duration: timings.dns },
    { key: "connect", start: timings.namelookup, duration: timings.connect },
  ];
  if (report.tls) {
    spans.push({ key: "tls", start: timings.pretransfer - timings.tls, duration: timings.tls });
  }
  spans.push(
    { key: "server", start: timings.starttransfer - timings.server, duration: timings.server },
    { key: "transfer", start: timings.starttransfer, duration: timings.transfer },
  );
  const total = timings.total;
  return spans.map((span) => {
    const start = Math.max(0, span.start);
    const duration = Math.max(0, span.duration);
    return {
      key: span.key,
      label: PHASE_LABELS[span.key],
      start,
      duration,
      offset: clamp(start / total),
      width: clamp(duration / total),
      share: clamp(duration / total),
    };
  });
}

/** marks are the cumulative checkpoints curl names; the page hangs them under
 * the waterfall at the boundary each one closes, so a phase's end is readable
 * without adding numbers up. */
export function marks(report: Report): Mark[] {
  const timings = report.timings;
  const list: Array<Omit<Mark, "ratio">> = [
    { key: "dns", label: "解析完成", value: timings.namelookup },
  ];
  if (report.tls) {
    list.push({ key: "tls", label: "握手完成", value: timings.pretransfer });
  } else {
    list.push({ key: "connect", label: "连接完成", value: timings.pretransfer });
  }
  list.push({ key: "server", label: "开始响应", value: timings.starttransfer });
  list.push({ key: "transfer", label: "总计", value: timings.total });
  const total = timings.total;
  return list.map((mark) => ({ ...mark, ratio: clamp(mark.value / total) }));
}

function clamp(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return Math.min(1, value);
}

/** A duration the table and chips share; sub-second values keep one decimal,
 * longer ones switch to seconds so a 30-second response stays readable. */
export function formatDuration(milliseconds: number): string {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "0.0 ms";
  if (milliseconds >= 1000) {
    const seconds = milliseconds / 1000;
    return `${seconds >= 10 ? seconds.toFixed(1) : seconds.toFixed(2)} s`;
  }
  return `${milliseconds.toFixed(1)} ms`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/** Transfer speed over the transfer phase only; an unmeasurable phase says
 * nothing rather than dividing by zero. */
export function formatSpeed(bytes: number, milliseconds: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0 || !Number.isFinite(milliseconds) || milliseconds <= 0) {
    return "";
  }
  const perSecond = bytes / (milliseconds / 1000);
  return `${formatBytes(perSecond)}/s`;
}

export function formatPercent(share: number): string {
  if (!Number.isFinite(share) || share <= 0) return "—";
  if (share < 0.005) return "<1%";
  return `${Math.round(share * 100)}%`;
}

/** formatReport is the copy action's text: the same facts the page shows. */
export function formatReport(report: Report): string {
  const lines: string[] = [];
  lines.push(report.statusLine !== "" ? report.statusLine : `${report.proto} ${report.status}`);
  lines.push(`地址: ${report.url}`);
  if (report.remoteIp) {
    lines.push(`IP: ${report.remoteIp}${report.remotePort ? `:${report.remotePort}` : ""}`);
  }
  if (report.proto) lines.push(`协议: ${report.proto}`);
  if (report.tls) {
    const alpn = report.tls.protocol ? ` (${report.tls.protocol})` : "";
    lines.push(`TLS: ${report.tls.version} · ${report.tls.cipher}${alpn}`);
  }
  lines.push(`大小: ${formatBytes(report.size)}${report.bodyTruncated ? "（已截断）" : ""}`);
  if (report.contentType) lines.push(`类型: ${report.contentType}`);
  lines.push("");
  for (const phase of phases(report)) {
    lines.push(`${phase.label}: ${formatDuration(phase.duration)}`);
  }
  lines.push(`总计: ${formatDuration(report.timings.total)}`);
  const chips = marks(report)
    .map((mark) => `${mark.label} ${formatDuration(mark.value)}`)
    .join(" · ");
  if (chips !== "") {
    lines.push("");
    lines.push(chips);
  }
  return lines.join("\n");
}
