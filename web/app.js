"use strict";

const state = {
  csrf: "",
  bootstrap: null,
  activeJob: null,
  currentJobId: null,
  report: null,
  filter: "actionable",
  selected: new Set(),
  preparedPatch: null,
};

const elements = {
  version: document.querySelector("#versionLabel"),
  machineMap: document.querySelector("#machineMap"),
  scoreValue: document.querySelector("#scoreValue"),
  scoreDescription: document.querySelector("#scoreDescription"),
  scanState: document.querySelector("#scanState"),
  reportContext: document.querySelector("#reportContext"),
  criticalCount: document.querySelector("#criticalCount"),
  highCount: document.querySelector("#highCount"),
  mediumCount: document.querySelector("#mediumCount"),
  passedCount: document.querySelector("#passedCount"),
  findingList: document.querySelector("#findingList"),
  patchCount: document.querySelector("#patchCount"),
  buildPatch: document.querySelector("#buildPatchButton"),
  selectPatches: document.querySelector("#selectPatchesButton"),
  patchHelp: document.querySelector("#patchHelp"),
  patchDialog: document.querySelector("#patchDialog"),
  patchChanges: document.querySelector("#patchChanges"),
  patchScript: document.querySelector("#patchScript"),
  downloadReport: document.querySelector("#downloadReport"),
  malwareState: document.querySelector("#malwareState"),
  malwareDescription: document.querySelector("#malwareDescription"),
  malwarebytesButton: document.querySelector("#malwarebytesButton"),
  intelStatus: document.querySelector("#intelStatus"),
  intelResults: document.querySelector("#intelResults"),
  detailDialog: document.querySelector("#detailDialog"),
  detailCategory: document.querySelector("#detailCategory"),
  detailTitle: document.querySelector("#detailTitle"),
  detailEvidence: document.querySelector("#detailEvidence"),
  detailRemediation: document.querySelector("#detailRemediation"),
  detailPatch: document.querySelector("#detailPatch"),
  detailPatchSection: document.querySelector("#detailPatchSection"),
  toast: document.querySelector("#toast"),
};

async function request(path, options = {}) {
  const settings = { method: options.method || "GET", headers: { Accept: "application/json" } };
  if (options.body !== undefined) {
    settings.headers["Content-Type"] = "application/json";
    settings.headers["X-CSRF-Token"] = state.csrf;
    settings.body = JSON.stringify(options.body);
  }
  const response = await fetch(path, settings);
  const data = await response.json().catch(() => ({ error: "The server returned an unreadable response." }));
  if (!response.ok) {
    throw new Error(data.error || `Request failed with HTTP ${response.status}.`);
  }
  return data;
}

function setBusy(active, label = "") {
  state.activeJob = active ? state.activeJob : null;
  document.body.classList.toggle("is-scanning", active);
  document.querySelectorAll("[data-job]").forEach((button) => {
    button.disabled = active;
  });
  if (active) {
    elements.scanState.textContent = label;
  }
}

function notify(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("is-visible");
  window.clearTimeout(notify.timer);
  notify.timer = window.setTimeout(() => elements.toast.classList.remove("is-visible"), 3600);
}

function delay(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

async function startJob(path, body, label, onComplete) {
  if (state.activeJob) {
    notify("Another scan is already running in this session.");
    return;
  }
  setBusy(true, label);
  try {
    const job = await request(path, { method: "POST", body });
    state.activeJob = job.id;
    while (state.activeJob === job.id) {
      await delay(750);
      const current = await request(`/api/jobs/${encodeURIComponent(job.id)}`);
      if (current.status === "completed") {
        state.activeJob = null;
        setBusy(false);
        await onComplete(current);
        return;
      }
      if (current.status === "failed") {
        throw new Error(current.error || "The scan failed.");
      }
      elements.scanState.textContent = current.status === "queued" ? `${label} (queued)` : label;
    }
  } catch (error) {
    state.activeJob = null;
    setBusy(false);
    elements.scanState.textContent = "Scan stopped";
    notify(error.message);
  }
}

function reportRows(report) {
  return Array.isArray(report.checks) ? report.checks : Array.isArray(report.findings) ? report.findings : [];
}

function renderReport(report, jobId) {
  state.report = report;
  state.currentJobId = jobId;
  state.selected.clear();
  const score = Number.isFinite(report.score) ? Math.max(0, Math.min(100, report.score)) : null;
  elements.scoreValue.textContent = score === null ? "--" : String(score);
  elements.machineMap.style.setProperty("--score-offset", score === null ? "327" : String(327 - (327 * score) / 100));
  elements.machineMap.classList.toggle("score-risk", score !== null && score < 60);
  elements.machineMap.classList.toggle("score-watch", score !== null && score >= 60 && score < 82);
  elements.scoreDescription.textContent = score === null ? "No score was calculated." : `Security posture score ${score} out of 100.`;

  const summary = report.summary || {};
  elements.criticalCount.textContent = String(summary.critical || 0);
  elements.highCount.textContent = String(summary.high || 0);
  elements.mediumCount.textContent = String(summary.medium || 0);
  elements.passedCount.textContent = String(summary.pass || 0);
  elements.scanState.textContent = "Scan complete";

  if (report.scan_type === "system_posture") {
    const machine = report.machine || {};
    elements.reportContext.textContent = `${machine.name || "This PC"} - ${machine.os || "Windows"} build ${machine.build || "unknown"}. ${summary.actionable || 0} actionable finding(s) in ${report.duration_seconds || 0}s.`;
  } else if (report.scan_type === "website_passive") {
    elements.reportContext.textContent = `${report.final_url || report.url} returned HTTP ${report.http_status}. Passive header and TLS checks completed in ${report.duration_seconds || 0}s.`;
  } else if (report.scan_type === "network_exposure") {
    elements.reportContext.textContent = `${report.scanned_hosts || 0} private host(s), ${report.scanned_ports_per_host || 0} ports per host, ${report.open_ports?.length || 0} open TCP service(s).`;
  }

  elements.downloadReport.href = `/api/reports/${encodeURIComponent(jobId)}`;
  elements.downloadReport.classList.remove("is-disabled");
  elements.downloadReport.setAttribute("aria-disabled", "false");
  renderFindings();
  updatePatchQueue();
  document.querySelector("#ledgerHeading").scrollIntoView({ behavior: "smooth", block: "start" });
}

function filteredRows() {
  const rows = state.report ? reportRows(state.report) : [];
  if (state.filter === "passed") {
    return rows.filter((row) => row.status === "pass");
  }
  if (state.filter === "actionable") {
    return rows.filter((row) => !["pass", "info"].includes(row.status));
  }
  return rows;
}

function renderFindings() {
  elements.findingList.textContent = "";
  const rows = filteredRows();
  if (!state.report || rows.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    const mark = document.createElement("span");
    mark.className = "empty-mark";
    mark.setAttribute("aria-hidden", "true");
    const title = document.createElement("h3");
    title.textContent = state.report ? "No checks match this filter" : "The ledger is empty";
    const detail = document.createElement("p");
    detail.textContent = state.report ? "Choose another filter to review the rest of the report." : "Run a scan to collect evidence.";
    empty.append(mark, title, detail);
    elements.findingList.append(empty);
    return;
  }

  rows.forEach((finding) => {
    const row = document.createElement("article");
    row.className = "finding-row";
    row.dataset.severity = finding.severity || "INFO";
    row.dataset.status = finding.status || "info";
    row.setAttribute("role", "listitem");

    const control = document.createElement("div");
    control.className = "finding-control";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.disabled = !finding.patch_id;
    checkbox.checked = state.selected.has(finding.id);
    checkbox.setAttribute("aria-label", `Add ${finding.title} to the patch bundle`);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) state.selected.add(finding.id);
      else state.selected.delete(finding.id);
      updatePatchQueue();
    });
    const label = document.createElement("div");
    const title = document.createElement("h3");
    title.className = "finding-title";
    title.textContent = finding.title || "Unnamed check";
    const category = document.createElement("span");
    category.className = "finding-category";
    category.textContent = finding.category || "security check";
    label.append(title, category);
    control.append(checkbox, label);

    const evidence = document.createElement("div");
    evidence.className = "finding-evidence";
    const evidenceText = document.createElement("p");
    evidenceText.textContent = finding.evidence || finding.description || "No evidence was recorded.";
    const inspect = document.createElement("button");
    inspect.type = "button";
    inspect.textContent = "Inspect response";
    inspect.addEventListener("click", () => showFinding(finding));
    evidence.append(evidenceText, inspect);

    const findingState = document.createElement("div");
    findingState.className = "finding-state";
    const tag = document.createElement("span");
    tag.className = "severity-tag";
    tag.textContent = finding.status === "pass" ? "VERIFIED" : finding.status === "error" ? "UNCHECKED" : finding.severity || "INFO";
    const patchNote = document.createElement("span");
    patchNote.className = "patch-note";
    patchNote.textContent = finding.patch_id ? "Patch available" : finding.status === "pass" ? "No action" : "Review manually";
    findingState.append(tag, patchNote);
    row.append(control, evidence, findingState);
    elements.findingList.append(row);
  });
}

function showFinding(finding) {
  elements.detailCategory.textContent = `${finding.category || "Security check"} - ${finding.severity || "INFO"}`;
  elements.detailTitle.textContent = finding.title || "Finding details";
  elements.detailEvidence.textContent = finding.evidence || finding.description || "No evidence was recorded.";
  elements.detailRemediation.textContent = finding.remediation || "Review this item manually.";
  elements.detailPatchSection.hidden = !finding.patch;
  if (finding.patch) {
    const restart = finding.patch.restart ? " A Windows restart is required." : " No restart is expected.";
    elements.detailPatch.textContent = `${finding.patch.title}. The generated script requires administrator rights.${restart}`;
  }
  elements.detailDialog.showModal();
}

function updatePatchQueue() {
  const count = state.selected.size;
  const supported = state.report ? reportRows(state.report).filter((row) => row.patch_id) : [];
  elements.patchCount.textContent = `${count} selected`;
  elements.selectPatches.disabled = supported.length === 0;
  elements.buildPatch.disabled = count === 0 || !state.currentJobId;
  elements.patchHelp.textContent = !state.report
    ? "Run a PC scan to find supported fixes."
    : supported.length ? `${supported.length} supported fix(es). Review the changes before downloading.`
      : "This report has no automatic PC patches. Inspect each finding for manual steps.";
}

async function reviewPatchBundle() {
  if (!state.currentJobId || state.selected.size === 0) return;
  const findings = reportRows(state.report).filter((row) => state.selected.has(row.id));
  elements.buildPatch.disabled = true;
  try {
    const response = await fetch("/api/patches/build", {
      method: "POST",
      headers: {
        Accept: "text/plain",
        "Content-Type": "application/json",
        "X-CSRF-Token": state.csrf,
      },
      body: JSON.stringify({ jobId: state.currentJobId, findingIds: Array.from(state.selected) }),
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: "Patch generation failed." }));
      throw new Error(error.error || "Patch generation failed.");
    }
    state.preparedPatch = await response.text();
    elements.patchScript.textContent = state.preparedPatch;
    elements.patchChanges.replaceChildren();
    for (const finding of findings) {
      const item = document.createElement("li");
      item.textContent = `${finding.patch?.title || finding.title}. Evidence: ${finding.evidence}. ${finding.patch?.restart ? "Restart required after applying." : "No restart expected."}`;
      elements.patchChanges.append(item);
    }
    elements.patchDialog.showModal();
  } catch (error) {
    notify(error.message);
  } finally {
    updatePatchQueue();
  }
}

function downloadPatchBundle() {
  if (!state.preparedPatch) return;
  const blob = new Blob([state.preparedPatch], { type: "text/plain;charset=utf-8" });
  const link = document.createElement("a");
  const objectUrl = URL.createObjectURL(blob);
  link.href = objectUrl;
  link.download = "security-suite-patches.ps1";
  document.body.append(link);
  link.click();
  link.remove();
  // Let the browser finish consuming the download before releasing its URL.
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
  notify("Patch download requested. The file previews changes until you run it with -Apply.");
}

function updateMalwareIntegration(bootstrap) {
  const product = bootstrap.malware.malwarebytes;
  if (product.installed) {
    elements.malwareState.textContent = "Ready";
    elements.malwareDescription.textContent = `${product.name} detected. Security Suite uses the existing licensed installation.`;
    elements.malwarebytesButton.textContent = product.scan_cli_available ? "Run Malwarebytes scan" : "Open Malwarebytes";
  } else {
    elements.malwareState.textContent = "Not installed";
    elements.malwareDescription.textContent = "Microsoft Defender is available. Malwarebytes can be added with your own license.";
    elements.malwarebytesButton.textContent = "Get Malwarebytes";
  }
}

async function handleMalwarebytes() {
  const product = state.bootstrap.malware.malwarebytes;
  if (!product.installed) {
    window.open(state.bootstrap.malware.official_download, "_blank", "noopener,noreferrer");
    return;
  }
  try {
    const scan = Boolean(product.scan_cli_available);
    const result = await request("/api/malwarebytes/open", { method: "POST", body: { scan } });
    notify(`${result.product} launched.`);
  } catch (error) {
    notify(error.message);
  }
}

async function loadIntel(query = "") {
  try {
    const payload = await request(`/api/intel?q=${encodeURIComponent(query)}`);
    renderIntelRows(payload.results || []);
    const kev = payload.kev || {};
    elements.intelStatus.textContent = kev.loaded
      ? `${kev.count} CISA Known Exploited Vulnerability records loaded. Search a CVE ID for live NVD detail.`
      : "Five curated records are available offline. Refresh KEV to load the current CISA catalog.";
  } catch (error) {
    notify(error.message);
  }
}

function renderIntelRows(rows) {
  elements.intelResults.textContent = "";
  if (rows.length === 0) {
    const empty = document.createElement("div");
    empty.className = "intel-detail";
    empty.textContent = "No matching local or cached records. Enter an exact CVE ID to query NVD.";
    elements.intelResults.append(empty);
    return;
  }
  rows.slice(0, 50).forEach((record) => {
    const row = document.createElement("div");
    row.className = "intel-row";
    const id = document.createElement("strong");
    id.textContent = record.cve || "CVE";
    const title = document.createElement("span");
    title.textContent = record.title || "No title";
    const severity = document.createElement("small");
    severity.textContent = record.known_exploited ? "Known exploited" : `${record.severity || "Unknown"}${record.cvss ? ` / ${record.cvss}` : ""}`;
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "NVD detail";
    button.addEventListener("click", () => lookupCve(record.cve));
    row.append(id, title, severity, button);
    elements.intelResults.append(row);
  });
}

async function lookupCve(cve) {
  elements.intelStatus.textContent = `Looking up ${cve} in NVD...`;
  try {
    const record = await request("/api/intel/lookup", { method: "POST", body: { cve, live: true } });
    renderIntelDetail(record);
    elements.intelStatus.textContent = record.live_error
      ? `Live NVD lookup was unavailable; showing cached detail for ${cve}.`
      : `Detail loaded for ${cve}.`;
  } catch (error) {
    elements.intelStatus.textContent = "Lookup failed.";
    notify(error.message);
  }
}

function renderIntelDetail(record) {
  elements.intelResults.textContent = "";
  const panel = document.createElement("article");
  panel.className = "intel-detail";
  const severity = document.createElement("span");
  severity.textContent = `${record.severity || "UNKNOWN"}${record.cvss ? ` / CVSS ${record.cvss}` : ""}${record.known_exploited ? " / CISA KEV" : ""}`;
  const title = document.createElement("h3");
  title.textContent = `${record.cve} - ${record.title || "Vulnerability record"}`;
  const description = document.createElement("p");
  description.textContent = record.description || record.plain || record.note || "No description was returned.";
  panel.append(severity, title, description);
  if (record.required_action) {
    const action = document.createElement("p");
    action.textContent = `Required action: ${record.required_action}`;
    panel.append(action);
  }
  if (Array.isArray(record.cwe) && record.cwe.length) {
    const cwe = document.createElement("p");
    cwe.textContent = `Weakness: ${record.cwe.join(", ")}`;
    panel.append(cwe);
  }
  if (Array.isArray(record.references)) {
    record.references.slice(0, 6).forEach((url) => {
      if (typeof url !== "string" || !url.startsWith("https://")) return;
      const link = document.createElement("a");
      link.href = url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "Vendor or source reference";
      panel.append(link);
    });
  }
  if (record.found !== false) {
    const briefButton = document.createElement("button");
    briefButton.type = "button";
    briefButton.className = "primary-button brief-open";
    briefButton.textContent = "Build client brief";
    briefButton.addEventListener("click", () => buildBrief(record.cve, briefButton));
    panel.append(briefButton);
  }
  elements.intelResults.append(panel);
}

async function buildBrief(cve, trigger) {
  trigger.disabled = true;
  elements.intelStatus.textContent = `Building the client brief for ${cve}...`;
  try {
    const brief = await request("/api/intel/brief", { method: "POST", body: { cve, live: true } });
    renderBrief(brief);
    trigger.remove();
    elements.intelStatus.textContent = brief.missingSections.length
      ? `Brief for ${cve} is missing: ${brief.missingSections.join(", ")}. Fill those in before sending.`
      : `Brief for ${cve} has all four sections. Confirm affected versions against the vendor advisory before sending.`;
  } catch (error) {
    trigger.disabled = false;
    elements.intelStatus.textContent = "Brief failed.";
    notify(error.message);
  }
}

function renderBrief(brief) {
  document.querySelector(".brief-panel")?.remove();
  const panel = document.createElement("section");
  panel.className = "brief-panel";
  panel.setAttribute("aria-label", `Client brief for ${brief.cve}`);

  const header = document.createElement("header");
  const heading = document.createElement("h4");
  heading.textContent = "Client brief";
  const check = document.createElement("span");
  check.className = brief.missingSections.length ? "brief-check is-missing" : "brief-check";
  check.textContent = brief.missingSections.length
    ? `Missing: ${brief.missingSections.join(", ")}`
    : "4 of 4 sections";
  header.append(heading, check);

  const preview = document.createElement("pre");
  preview.className = "brief-preview";
  preview.textContent = brief.markdown;

  const actions = document.createElement("div");
  actions.className = "brief-actions";

  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "quiet-button";
  copy.textContent = "Copy markdown";
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(brief.markdown);
      notify("Brief copied.");
    } catch {
      notify("Copy failed. Select the text and copy it instead.");
    }
  });

  const download = document.createElement("button");
  download.type = "button";
  download.className = "quiet-button";
  download.textContent = "Download .md";
  download.addEventListener("click", () => {
    const url = URL.createObjectURL(new Blob([brief.markdown], { type: "text/markdown" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `${brief.cve}.md`;
    link.click();
    URL.revokeObjectURL(url);
  });

  actions.append(copy, download);

  const clients = state.bootstrap?.clients || [];
  if (clients.length) {
    const label = document.createElement("label");
    label.className = "brief-client";
    label.textContent = "Save to client folder";
    const select = document.createElement("select");
    clients.forEach((slug) => select.append(new Option(slug, slug)));
    label.append(select);
    const save = document.createElement("button");
    save.type = "button";
    save.className = "primary-button";
    save.textContent = "Save";
    save.addEventListener("click", () => saveBrief(brief.cve, select.value, save));
    actions.append(label, save);
  }

  panel.append(header, preview, actions);
  if (brief.liveError) {
    const note = document.createElement("p");
    note.className = "brief-note";
    note.textContent = "Live NVD lookup failed, so this brief uses offline data.";
    panel.append(note);
  }
  const reminder = document.createElement("p");
  reminder.className = "brief-note";
  reminder.textContent = "A named client must already be in leads.md. Confirm versions with NVD and the vendor advisory before sending.";
  panel.append(reminder);
  elements.intelResults.querySelector(".intel-detail")?.append(panel);
}

async function saveBrief(cve, client, trigger, overwrite = false) {
  trigger.disabled = true;
  try {
    const result = await request("/api/intel/brief/save", { method: "POST", body: { cve, client, live: true, overwrite } });
    notify(`Saved to clients/${result.client}/${result.cve}.md`);
    elements.intelStatus.textContent = `Saved ${result.path}`;
  } catch (error) {
    if (!overwrite && /already exists/.test(error.message) && window.confirm(`${error.message} Replace it?`)) {
      trigger.disabled = false;
      await saveBrief(cve, client, trigger, true);
      return;
    }
    notify(error.message);
  } finally {
    trigger.disabled = false;
  }
}

async function bootstrap() {
  try {
    const payload = await request("/api/bootstrap");
    state.bootstrap = payload;
    state.csrf = payload.csrfToken;
    elements.version.textContent = `v${payload.version}`;
    updateMalwareIntegration(payload);
    if (payload.latestReport) renderReport(payload.latestReport.result, payload.latestReport.id);
    await loadIntel("");
  } catch (error) {
    elements.scanState.textContent = "Dashboard connection failed";
    notify(error.message);
  }
}

document.querySelector("#quickSystemButton").addEventListener("click", () => {
  startJob("/api/scans/system", { profile: "quick" }, "Inspecting Windows posture", (job) => renderReport(job.result, job.id));
});

document.querySelector("#fullSystemButton").addEventListener("click", () => {
  startJob("/api/scans/system", { profile: "full" }, "Inspecting posture and Windows Update", (job) => renderReport(job.result, job.id));
});

document.querySelector("#defenderQuickButton").addEventListener("click", () => {
  startJob("/api/scans/defender", { scanType: "quick" }, "Microsoft Defender quick scan running", () => {
    elements.scanState.textContent = "Defender quick scan complete";
    notify("Microsoft Defender quick scan completed.");
  });
});

document.querySelector("#defenderFullButton").addEventListener("click", () => {
  const proceed = window.confirm("A Defender full scan can take several hours. Start it now?");
  if (!proceed) return;
  startJob("/api/scans/defender", { scanType: "full" }, "Microsoft Defender full scan running", () => {
    elements.scanState.textContent = "Defender full scan complete";
    notify("Microsoft Defender full scan completed.");
  });
});

elements.malwarebytesButton.addEventListener("click", handleMalwarebytes);

document.querySelector("#websiteForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const url = document.querySelector("#websiteUrl").value;
  startJob("/api/scans/website", { url }, "Inspecting website headers and TLS", (job) => renderReport(job.result, job.id));
});

document.querySelector("#networkForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const target = document.querySelector("#networkTarget").value;
  const ports = document.querySelector("#networkPorts").value;
  const quick = document.querySelector("#networkQuick").checked;
  startJob("/api/scans/network", { target, ports, quick }, "Checking private-network exposure", (job) => renderReport(job.result, job.id));
});

document.querySelectorAll("[data-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    state.filter = button.dataset.filter;
    document.querySelectorAll("[data-filter]").forEach((item) => item.classList.toggle("is-active", item === button));
    renderFindings();
  });
});

elements.downloadReport.addEventListener("click", (event) => {
  if (elements.downloadReport.classList.contains("is-disabled")) event.preventDefault();
});

elements.selectPatches.addEventListener("click", () => {
  for (const row of reportRows(state.report)) {
    if (row.patch_id) state.selected.add(row.id);
  }
  renderFindings();
  updatePatchQueue();
});
elements.buildPatch.addEventListener("click", reviewPatchBundle);
document.querySelector("#downloadPatchButton").addEventListener("click", downloadPatchBundle);

document.querySelector("#intelForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const query = document.querySelector("#intelQuery").value.trim();
  if (/^CVE-\d{4}-\d{4,}$/i.test(query)) lookupCve(query.toUpperCase());
  else loadIntel(query);
});

document.querySelector("#syncKevButton").addEventListener("click", () => {
  startJob("/api/intel/sync", {}, "Refreshing the CISA KEV catalog", async (job) => {
    elements.scanState.textContent = "CISA KEV catalog refreshed";
    elements.intelStatus.textContent = `${job.result.count} known exploited vulnerabilities loaded from CISA.`;
    await loadIntel(document.querySelector("#intelQuery").value.trim());
    notify("CISA KEV catalog refreshed.");
  });
});

bootstrap();
