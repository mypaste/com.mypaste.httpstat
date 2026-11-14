/**
 * The HTTP timing page.
 *
 * The page owns the whole card (PLUGINS.md §5.1, `chrome: "page"`): the URL
 * field, the waterfall, the phase table and the response headers are drawn
 * here. The measurement happens in this package's Go runtime, reached through
 * the host's internal-command channel; the page itself opens no socket and
 * holds no host object beyond the surface bridge.
 *
 * Untrusted values (the URL, header names and values) are written with
 * textContent only: a response header must never become markup.
 */

import { connectSurface } from "./bridge";
import {
  formatBytes,
  formatDuration,
  formatPercent,
  formatReport,
  formatSpeed,
  marks,
  parseReport,
  phases,
  type Report,
} from "./report";

const OWN_PLUGIN_ID = "com.mypaste.httpstat";
const PROBE_COMMAND = "probe";
/** Matches the runtime's own bound; the input refuses to carry more. */
const MAX_INPUT = 4096;
/** How long the first arrival of a report takes to draw itself in. */
const REVEAL_MS = 620;

function one<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (element === null) throw new Error(`缺少元素 ${selector}`);
  return element;
}

const form = one<HTMLFormElement>("#probe-form");
const urlInput = one<HTMLInputElement>("#url");
const runButton = one<HTMLButtonElement>("#run");
const statusElement = one<HTMLParagraphElement>("#status");
const errorPanel = one<HTMLElement>("#error");
const errorMessage = one<HTMLParagraphElement>("#error-message");
const retryButton = one<HTMLButtonElement>("#retry");
const resultSection = one<HTMLElement>("#result");
const statusCode = one<HTMLSpanElement>("#status-code");
const statusText = one<HTMLSpanElement>("#status-text");
const totalValue = one<HTMLSpanElement>("#total");
const facts = one<HTMLParagraphElement>("#facts");
const phaseStrip = one<HTMLDivElement>("#phase-strip");
const track = one<HTMLDivElement>("#track");
const ladder = one<HTMLDivElement>("#marks");
const phasesBody = one<HTMLTableSectionElement>("#phases");
const headersBlock = one<HTMLDetailsElement>("#headers-block");
const headersCount = one<HTMLSpanElement>("#headers-count");
const headersBody = one<HTMLTableSectionElement>("#headers");
const truncatedNote = one<HTMLParagraphElement>("#truncated");
const copyButton = one<HTMLButtonElement>("#copy");
const closeButton = one<HTMLButtonElement>("#doc-close");

const bridge = connectSurface();

let running = false;
let lastReport: Report | null = null;
let runToken = 0;

function setStatus(text: string, tone: "info" | "error" = "info"): void {
  statusElement.textContent = text;
  statusElement.dataset.tone = tone;
}

function setBusy(busy: boolean): void {
  running = busy;
  runButton.disabled = busy;
  runButton.textContent = busy ? "计时中…" : "计时";
}

function hideError(): void {
  errorPanel.hidden = true;
  errorMessage.textContent = "";
}

function showError(message: string): void {
  lastReport = null;
  resultSection.hidden = true;
  copyButton.disabled = true;
  errorMessage.textContent = message;
  errorPanel.hidden = false;
  setStatus("计时没有完成。", "error");
}

function hostOf(value: string): string {
  try {
    return new URL(value.includes("://") ? value : `https://${value}`).host;
  } catch {
    return value;
  }
}

async function runProbe(raw: string): Promise<void> {
  const value = raw.trim();
  if (running) return;
  if (value === "") {
    showError("请先输入一条 http 或 https 链接。");
    return;
  }
  runToken += 1;
  const token = runToken;
  setBusy(true);
  hideError();
  resultSection.hidden = true;
  copyButton.disabled = true;
  setStatus(`正在请求 ${hostOf(value)}…`);

  try {
    const result = await bridge.invoke(OWN_PLUGIN_ID, PROBE_COMMAND, value);
    if (token !== runToken) return;
    if (!result.ok) {
      showError(result.message ?? "计时失败，运行时没有给出原因。");
      return;
    }
    const report = parseReport(result.output ?? "");
    if (token !== runToken) return;
    lastReport = report;
    urlInput.value = report.url;
    render(report);
  } catch (error) {
    if (token !== runToken) return;
    showError(error instanceof Error ? error.message : "计时失败。");
  } finally {
    if (token === runToken) setBusy(false);
  }
}

function render(report: Report): void {
  hideError();
  resultSection.hidden = false;
  setStatus(`计时完成：HTTP ${report.status}，总计 ${formatDuration(report.timings.total)}。`);

  statusCode.textContent = String(report.status);
  statusCode.dataset.tone = statusTone(report.status);
  statusText.textContent = report.statusText;
  totalValue.textContent = formatDuration(report.timings.total);

  const chips: string[] = [];
  if (report.proto !== "") chips.push(report.proto);
  chips.push(`${formatBytes(report.size)}${report.bodyTruncated ? "+" : ""}`);
  const speed = formatSpeed(report.size, report.timings.transfer);
  if (speed !== "") chips.push(speed);
  const remote = report.remoteIp !== undefined
    ? `${report.remoteIp}${report.remotePort ? `:${report.remotePort}` : ""}`
    : report.remoteAddr;
  if (remote) chips.push(remote);
  if (report.tls) {
    chips.push(report.tls.protocol ? `${report.tls.version} · ${report.tls.protocol}` : report.tls.version);
  }
  if (report.contentType) chips.push(report.contentType);
  facts.textContent = chips.join("  ·  ");

  drawPhaseStrip(report, true);
  drawTrack(report, true);
  drawMarks(report, true);
  drawPhases(report, true);
  drawHeaders(report);
  truncatedNote.hidden = !report.bodyTruncated;
  copyButton.disabled = false;
}

function statusTone(status: number): "ok" | "warn" | "bad" {
  if (status < 300) return "ok";
  if (status < 400) return "warn";
  return "bad";
}

function drawTrack(report: Report, animate: boolean): void {
  track.replaceChildren();
  const total = report.timings.total;
  if (total <= 0) return;
  for (const phase of phases(report)) {
    if (phase.width <= 0) continue;
    const segment = document.createElement("span");
    segment.className = `segment phase-${phase.key}`;
    segment.style.left = `${phase.offset * 100}%`;
    const width = `${phase.width * 100}%`;
    segment.style.width = animate ? "0%" : width;
    if (animate) {
      // Each span grows on the clock's own proportions: it starts where it
      // starts in the report and takes as long as it took.
      segment.style.transitionDelay = `${Math.round(phase.offset * REVEAL_MS)}ms`;
      segment.style.transitionDuration = `${Math.round(Math.max(140, phase.width * REVEAL_MS))}ms`;
      requestAnimationFrame(() => {
        segment.style.width = width;
      });
    }
    segment.title = `${phase.label} ${formatDuration(phase.duration)}`;
    segment.setAttribute("aria-hidden", "true");
    track.append(segment);
    const end = phase.offset + phase.width;
    if (end < 0.999) {
      const tick = document.createElement("span");
      tick.className = "tick";
      tick.style.left = `${end * 100}%`;
      if (animate) {
        tick.classList.add("enter");
        tick.style.animationDelay = `${Math.round(end * REVEAL_MS)}ms`;
      }
      tick.setAttribute("aria-hidden", "true");
      track.append(tick);
    }
  }
}

/** One cell per measured span, its width following the span's share. */
function drawPhaseStrip(report: Report, animate: boolean): void {
  phaseStrip.replaceChildren();
  const cells: Array<{ cell: HTMLDivElement; parts: HTMLElement[] }> = [];
  for (const phase of phases(report)) {
    if (phase.width <= 0) continue;
    const cell = document.createElement("div");
    cell.className = `phase-cell phase-${phase.key}`;
    cell.style.flex = `0 0 ${phase.width * 100}%`;
    if (animate) {
      cell.classList.add("enter");
      cell.style.animationDelay = `${Math.round(phase.offset * REVEAL_MS)}ms`;
    }
    cell.title = `${phase.label} · ${formatDuration(phase.duration)}`;
    const head = document.createElement("span");
    head.className = "phase-head";
    const dot = document.createElement("i");
    dot.setAttribute("aria-hidden", "true");
    const name = document.createElement("span");
    name.className = "phase-name";
    name.textContent = phase.label;
    head.append(dot, name);
    const value = document.createElement("b");
    value.textContent = formatDuration(phase.duration);
    cell.append(head, value);
    phaseStrip.append(cell);
    cells.push({ cell, parts: [head, value] });
  }
  // A span too narrow to say anything keeps its place but stays blank; the
  // table below still carries its name and duration.
  for (const { cell, parts } of cells) {
    if (cell.clientWidth >= 44) continue;
    for (const part of parts) part.remove();
  }
}

/**
 * The cumulative marks hang under the bar at the boundary each one closes.
 * Lane assignment needs the labels' widths, so it happens after they are in
 * the document: each label is placed beside its guide, then stacked into the
 * first lane whose last label it does not touch.
 */
function drawMarks(report: Report, animate: boolean): void {
  ladder.replaceChildren();
  const width = track.clientWidth;
  if (width <= 0) {
    ladder.style.height = "0px";
    return;
  }
  const anchors: Array<{ label: HTMLSpanElement; x: number }> = [];
  for (const mark of marks(report)) {
    const x = mark.ratio * width;
    const anchor = document.createElement("div");
    anchor.className = `anchor phase-${mark.key}`;
    anchor.style.left = `${x}px`;
    const guide = document.createElement("span");
    guide.className = "guide";
    guide.setAttribute("aria-hidden", "true");
    const label = document.createElement("span");
    label.className = "ladder-label";
    if (animate) {
      // The guide appears once the growing bar has reached its boundary.
      const at = Math.round(60 + mark.ratio * REVEAL_MS);
      guide.classList.add("enter");
      guide.style.animationDelay = `${at}ms`;
      label.classList.add("enter");
      label.style.animationDelay = `${at}ms`;
    }
    const dot = document.createElement("i");
    dot.className = "dot";
    dot.setAttribute("aria-hidden", "true");
    const name = document.createElement("span");
    name.textContent = mark.label;
    const value = document.createElement("b");
    value.textContent = formatDuration(mark.value);
    label.append(dot, name, value);
    anchor.append(guide, label);
    ladder.append(anchor);
    anchors.push({ label, x });
  }
  const measured = anchors.map((item) => ({
    ...item,
    labelWidth: item.label.offsetWidth,
    labelHeight: item.label.offsetHeight,
  }));
  const step = Math.max(...measured.map((item) => item.labelHeight)) + 3;
  const laneEnds = [0, 0, 0];
  let lanes = 1;
  for (const item of measured) {
    const left = Math.min(
      Math.max(0, item.x - item.labelWidth / 2),
      Math.max(0, width - item.labelWidth),
    );
    let lane = laneEnds.findIndex((end) => left >= end);
    if (lane === -1) lane = laneEnds.length - 1;
    laneEnds[lane] = left + item.labelWidth + 8;
    lanes = Math.max(lanes, lane + 1);
    item.label.style.left = `${left - item.x}px`;
    item.label.style.top = `${6 + lane * step}px`;
    const guide = item.label.previousElementSibling;
    if (guide instanceof HTMLElement) guide.style.height = `${6 + lane * step}px`;
  }
  ladder.style.height = `${6 + (lanes - 1) * step + (measured[0]?.labelHeight ?? 0)}px`;
}

function cell(text: string): HTMLTableCellElement {
  const cellElement = document.createElement("td");
  cellElement.textContent = text;
  return cellElement;
}

function drawPhases(report: Report, animate: boolean): void {
  phasesBody.replaceChildren();
  for (const [index, phase] of phases(report).entries()) {
    const row = document.createElement("tr");
    row.className = `phase-${phase.key}`;
    if (animate) {
      row.classList.add("enter");
      row.style.animationDelay = `${Math.round(220 + index * 45)}ms`;
    }
    const name = document.createElement("th");
    name.scope = "row";
    const swatch = document.createElement("i");
    swatch.className = "swatch";
    swatch.setAttribute("aria-hidden", "true");
    const label = document.createElement("span");
    label.textContent = phase.label;
    name.append(swatch, label);
    row.append(name, cell(formatDuration(phase.start)), cell(formatDuration(phase.duration)), cell(formatPercent(phase.share)));
    phasesBody.append(row);
  }
}

function drawHeaders(report: Report): void {
  headersBody.replaceChildren();
  headersCount.textContent = String(report.headers.length);
  headersBlock.hidden = report.headers.length === 0;
  for (const header of report.headers) {
    const row = document.createElement("tr");
    const name = document.createElement("td");
    name.className = "header-name";
    name.textContent = header.name;
    const value = document.createElement("td");
    value.className = "header-value";
    value.textContent = header.value;
    row.append(name, value);
    headersBody.append(row);
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  void runProbe(urlInput.value);
});

retryButton.addEventListener("click", () => {
  void runProbe(urlInput.value);
});

copyButton.addEventListener("click", async () => {
  if (lastReport === null) return;
  try {
    const result = await bridge.copy(formatReport(lastReport));
    setStatus(result.ok ? "已复制计时报告。" : result.message ?? "复制失败。", result.ok ? "info" : "error");
  } catch {
    setStatus("复制失败。", "error");
  }
});

closeButton.addEventListener("click", () => bridge.close());

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape" || event.isComposing) return;
  bridge.close();
});

bridge.onItem(({ item }) => {
  const text = item.text.trim();
  urlInput.value = text.length > MAX_INPUT ? text.slice(0, MAX_INPUT) : text;
  void runProbe(urlInput.value);
});

// The ladder and the strip are measured in pixels, so a narrower card needs
// them laid out again.
let resizeFrame = 0;
window.addEventListener("resize", () => {
  if (lastReport === null) return;
  cancelAnimationFrame(resizeFrame);
  resizeFrame = requestAnimationFrame(() => {
    if (lastReport === null) return;
    drawPhaseStrip(lastReport, false);
    drawMarks(lastReport, false);
  });
});

setStatus("打开一条链接，或输入地址后按回车。");
