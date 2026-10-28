(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const state = {
    boot: null, nodes: new Map(), rows: new Map(), activeJobs: [], jobs: [], queues: [],
    page: "overview", sort: { key: "name", descending: false },
    processSort: "cpu", selectedNode: null, selectedJob: null,
    viewId: sessionStorage.getItem("macluster-view") || crypto.randomUUID(),
    events: null, jobOffsetStack: [0], nextJobOffset: null,
    history: new Map(), log: { stdout: { offset: null, content: "", fileIdentity: null }, stderr: { offset: null, content: "", fileIdentity: null } },
    logTimer: null, connected: false, lastUpdated: 0
  };
  sessionStorage.setItem("macluster-view", state.viewId);

  function text(node, value) { node.textContent = value == null ? "" : String(value); }
  function stripTerminalControls(value) {
    const input = String(value ?? "");
    const output = [];
    let keepFrom = 0;
    for (let i = 0; i < input.length; i++) {
      const code = input.charCodeAt(i);
      let skipThrough = -1;
      if (code === 0x1b || code === 0x9b) {
        const csi = code === 0x9b || input[i + 1] === "[";
        const osc = code === 0x1b && input[i + 1] === "]";
        const stringControl = code === 0x1b && "PX^_".includes(input[i + 1] || "");
        if (csi) {
          let end = i + (code === 0x9b ? 1 : 2);
          while (end < input.length && !(input.charCodeAt(end) >= 0x40 && input.charCodeAt(end) <= 0x7e)) end++;
          if (end === input.length) {
            output.push(input.slice(keepFrom, i));
            return output.join("");
          }
          skipThrough = end;
        } else if (osc || stringControl) {
          let end = i + 2;
          let terminated = false;
          while (end < input.length) {
            if (osc && input.charCodeAt(end) === 0x07) { terminated = true; break; }
            if (input.charCodeAt(end) === 0x1b && input[end + 1] === "\\") { terminated = true; end++; break; }
            end++;
          }
          if (!terminated) {
            output.push(input.slice(keepFrom, i));
            return output.join("");
          }
          skipThrough = end;
        } else {
          skipThrough = Math.min(i + 1, input.length - 1);
        }
      } else if ((code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) || code === 0x7f) {
        skipThrough = i;
      }
      if (skipThrough >= 0) {
        output.push(input.slice(keepFrom, i));
        keepFrom = skipThrough + 1;
        i = skipThrough;
      }
    }
    output.push(input.slice(keepFrom));
    return output.join("");
  }
  function element(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value != null) node.textContent = value;
    return node;
  }
  function setBanner(message, kind = "info") {
    const banner = $("#banner");
    if (!message) { banner.className = "banner hidden"; text(banner, ""); return; }
    banner.className = `banner ${kind}`;
    text(banner, message);
  }
  async function api(path, options = {}) {
    const response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options });
    const type = response.headers.get("content-type") || "";
    const body = type.includes("application/json") ? await response.json() : null;
    if (!response.ok) throw new Error(body?.error || `Request failed (${response.status})`);
    return body;
  }
  function redeemEntryToken() {
    const token = location.hash.startsWith("#") ? location.hash.slice(1) : "";
    if (!token) return Promise.resolve(false);
    history.replaceState(null, "", `${location.pathname}${location.search}`);
    return api("/api/v1/session", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token })
    }).then(() => true);
  }
  const num = (value, digits = 0) => Number.isFinite(value) ? value.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits }) : "N/A";
  const gib = bytes => Number.isFinite(bytes) ? `${(bytes / 1073741824).toFixed(1)}` : "N/A";
  const rate = value => {
    if (!Number.isFinite(value)) return "N/A";
    const units = ["B/s", "KiB/s", "MiB/s", "GiB/s"];
    let amount = value, index = 0;
    while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index++; }
    return `${amount.toFixed(index ? 1 : 0)} ${units[index]}`;
  };
  const stateLabel = value => String(value || "UNKNOWN").replaceAll("_", " ").toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
  const localTime = value => value ? new Date(value).toLocaleString() : "—";
  const sampleAge = value => {
    if (!Number.isFinite(value)) return "No sample yet";
    if (value < 1000) return "just now";
    return `${Math.floor(value / 1000)}s ago`;
  };
  const nodeRole = id => state.nodes.get(id)?.role || "compute";

  async function initialize() {
    try {
      await redeemEntryToken();
      state.boot = await api("/api/v1/bootstrap");
      text($("#cluster-name"), state.boot.cluster_name);
      state.nodes = new Map(state.boot.configured_nodes.map(node => [node.id, node]));
      for (const row of state.boot.monitor.nodes) state.rows.set(row.node_id, row);
      state.activeJobs = state.boot.jobs.jobs;
      state.jobs = state.boot.jobs.jobs;
      state.queues = state.boot.queues;
      if (state.boot.truncated_nodes) setBanner(`This view shows the first ${state.boot.node_limit} configured nodes.`, "info");
      renderQueueFilter(); renderOverview(); renderJobs(); renderQueues();
      await updateView();
      connectEvents();
      setConnection("ready", "Connected to controller");
      $("#refresh-button").addEventListener("click", refreshBootstrap);
      $("#jobs-refresh").addEventListener("click", () => loadJobs(true));
      $("#node-search").addEventListener("input", renderOverview);
      $("#queue-filter").addEventListener("change", renderOverview);
      $("#job-state-filter").addEventListener("change", () => { state.jobOffsetStack = [0]; loadJobs(true); });
      $("#jobs-prev").addEventListener("click", previousJobs);
      $("#jobs-next").addEventListener("click", nextJobs);
      $("#job-detail-close").addEventListener("click", closeJob);
      $("#detail-close").addEventListener("click", closeNode);
      $("#node-dialog").addEventListener("click", event => { if (event.target === $("#node-dialog")) closeNode(); });
      $$(".nav-item").forEach(button => button.addEventListener("click", () => switchPage(button.dataset.page)));
      $$(".sort-button").forEach(button => button.addEventListener("click", () => sortNodes(button.dataset.sort)));
      $$("[data-process-sort]").forEach(button => button.addEventListener("click", () => setProcessSort(button.dataset.processSort)));
      document.addEventListener("visibilitychange", handleVisibility);
      document.addEventListener("keydown", handleKeys);
      setInterval(() => {
        if (state.connected) text($("#last-updated"), new Date(state.lastUpdated).toLocaleTimeString());
      }, 1000);
    } catch (error) {
      setConnection("error", "Monitor unavailable");
      setBanner(error.message || "Could not connect to the local controller.", "error");
      $("#cluster-name").textContent = "Connection required";
      $("#connection-state").textContent = "Run macluster controller run --web in Terminal for a fresh link";
    }
  }

  function setConnection(kind, label) {
    const pill = $("#controller-status");
    pill.className = `status-pill ${kind}`;
    pill.lastChild.textContent = label;
    text($("#connection-state"), label);
  }
  async function refreshBootstrap() {
    try {
      const boot = await api("/api/v1/bootstrap");
      state.boot = boot;
      state.nodes = new Map(boot.configured_nodes.map(node => [node.id, node]));
      state.rows = new Map(boot.monitor.nodes.map(row => [row.node_id, row]));
      state.activeJobs = boot.jobs.jobs;
      state.queues = boot.queues;
      renderQueueFilter(); renderOverview(); renderQueues();
      if (state.page === "jobs") loadJobs(true);
      await updateView();
      setBanner(boot.truncated_nodes ? `Showing at most ${boot.node_limit} configured nodes.` : "", boot.truncated_nodes ? "info" : "");
    } catch (error) { setBanner(error.message, "error"); }
  }
  function renderQueueFilter() {
    const filter = $("#queue-filter");
    const selected = filter.value;
    filter.replaceChildren(element("option", "", "All queues"));
    filter.firstElementChild.value = "";
    for (const queue of state.queues) {
      const option = element("option", "", queue.name);
      option.value = queue.name;
      filter.append(option);
    }
    if ([...filter.options].some(option => option.value === selected)) filter.value = selected;
  }
  function currentNodeRows() {
    const query = $("#node-search").value.trim().toLowerCase();
    const queue = $("#queue-filter").value;
    return [...state.nodes.values()].filter(node => {
      const matchesText = !query || node.id.toLowerCase().includes(query);
      const matchesQueue = !queue || node.queues.includes(queue);
      return matchesText && matchesQueue;
    }).sort((a, b) => compareNodes(a, b, state.sort.key, state.sort.descending));
  }
  function compareNodes(a, b, key, descending) {
    const left = state.rows.get(a.id), right = state.rows.get(b.id);
    let order = 0;
    if (key === "name") order = a.id.localeCompare(b.id);
    else if (key === "cpu") order = metricSortValue(left?.metrics?.cpu_percent, right?.metrics?.cpu_percent);
    else if (key === "memory") order = metricSortValue(left?.metrics?.memory_used_bytes, right?.metrics?.memory_used_bytes);
    else if (key === "tasks") order = metricSortValue((left?.running_tasks || 0) + (left?.waiting_tasks || 0), (right?.running_tasks || 0) + (right?.waiting_tasks || 0));
    return descending ? -order : order;
  }
  function metricSortValue(a, b) {
    if (a == null && b == null) return 0;
    if (a == null) return 1;
    if (b == null) return -1;
    return a - b;
  }
  function sortNodes(key) {
    if (state.sort.key === key) state.sort.descending = !state.sort.descending;
    else { state.sort.key = key; state.sort.descending = key !== "name"; }
    $$(".sort-button").forEach(button => button.setAttribute("aria-sort", button.dataset.sort === state.sort.key ? (state.sort.descending ? "descending" : "ascending") : "none"));
    renderOverview();
  }
  function renderOverview() {
    const body = $("#node-rows");
    const existingCards = new Map([...body.querySelectorAll(".node-card[data-node-id]")].map(card => [card.dataset.nodeId, card]));
    const nodes = currentNodeRows();
    $("#node-empty").classList.toggle("hidden", nodes.length > 0);
    $("#node-count-label").textContent = `${nodes.length} ${nodes.length === 1 ? "node" : "nodes"}`;
    $("#nav-node-count").textContent = nodes.length;
    const allRows = [...state.rows.values()].filter(row => state.nodes.has(row.node_id));
    const fresh = allRows.filter(row => !row.stale && !row.sample_error);
    text($("#kpi-nodes"), fresh.length);
    text($("#kpi-nodes-note"), `of ${state.nodes.size} configured`);
    const active = state.activeJobs.filter(job => ["RUNNING", "STARTING", "CANCELLING"].includes(job.state));
    const pending = state.activeJobs.filter(job => job.state === "PENDING");
    text($("#kpi-running"), active.length);
    text($("#kpi-waiting"), pending.length);
    const cpu = fresh.reduce((sum, row) => sum + (row.metrics.cpu_percent || 0), 0);
    const cpuMax = fresh.reduce((sum, row) => sum + (row.metrics.cpu_max_percent || 0), 0);
    text($("#kpi-cpu"), cpuMax ? `${num(cpu / cpuMax * 100)}%` : "N/A");
    setRing($("#cluster-cpu-ring"), cpu, cpuMax);
    text($("#kpi-cpu-note"), cpuMax ? `${num(cpuMax ? cpu / cpuMax * 100 : 0, 1)}% of available CPU` : "across available nodes");
    const used = fresh.reduce((sum, row) => sum + (row.metrics.memory_used_bytes || 0), 0);
    const total = fresh.reduce((sum, row) => sum + (row.metrics.memory_total_bytes || 0), 0);
    text($("#kpi-memory"), total ? `${num(used / total * 100)}%` : "N/A");
    setRing($("#cluster-memory-ring"), used, total);
    const latestAge = fresh.reduce((age, row) => Math.max(age, row.age_ms || 0), 0);
    text($("#sample-age"), fresh.length ? `Sample age ${sampleAge(latestAge)}` : "Waiting for first sample");
    let cursor = body.firstElementChild;
    const visible = new Set();
    for (const node of nodes) {
      visible.add(node.id);
      let card = existingCards.get(node.id);
      if (card) updateNodeRow(card, node, state.rows.get(node.id));
      else card = renderNodeRow(node, state.rows.get(node.id));
      if (card !== cursor) body.insertBefore(card, cursor);
      cursor = card.nextElementSibling;
    }
    for (const card of [...body.children]) {
      if (!visible.has(card.dataset.nodeId)) card.remove();
    }
  }
  function setRing(node, used, capacity) {
    const known = Number.isFinite(used) && Number.isFinite(capacity) && capacity > 0;
    node.style.setProperty("--fill", known ? `${Math.max(0, Math.min(100, used / capacity * 100))}%` : "0%");
    node.classList.toggle("unavailable", !known);
  }
  function resourceGauge(label, used, capacity, kind, caption) {
    const gauge = element("div", "resource-gauge");
    gauge.dataset.resource = kind;
    const ring = element("div", `resource-ring ${kind}`);
    setRing(ring, used, capacity);
    const valid = Number.isFinite(used) && Number.isFinite(capacity) && capacity > 0;
    ring.append(element("strong", "", valid ? `${num(used / capacity * 100)}%` : "N/A"));
    gauge.append(ring, element("b", "", label), element("small", "", caption));
    return gauge;
  }
  function sparkline(id) {
    const root = element("div", "node-trend");
    const samples = (state.history.get(id) || []).slice(-60);
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 300 60"); svg.setAttribute("preserveAspectRatio", "none");
    svg.setAttribute("role", "img"); svg.setAttribute("aria-label", "Recent CPU and memory activity");
    for (const [kind, value] of [["cpu", m => m.cpu_max_percent > 0 && m.cpu_percent != null ? m.cpu_percent / m.cpu_max_percent : null], ["memory", m => m.memory_total_bytes > 0 && m.memory_used_bytes != null ? m.memory_used_bytes / m.memory_total_bytes : null]]) {
      let path = "", connected = false;
      samples.forEach((m, i) => {
        const v = value(m);
        if (v == null) { connected = false; return; }
        const x = samples.length > 1 ? i / (samples.length - 1) * 300 : 0;
        const y = 56 - Math.max(0, Math.min(1, v)) * 50;
        path += `${connected ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)} `; connected = true;
      });
      const line = document.createElementNS(ns, "path");
      line.setAttribute("d", path); line.setAttribute("class", `trend-${kind}`); svg.append(line);
    }
    root.append(svg);
    if (samples.length < 2) root.append(element("span", "trend-placeholder", "Collecting activity…"));
    return root;
  }
  function renderNodeRow(node, row) {
    const card = element("article", "node-card");
    card.dataset.nodeId = node.id;
    card.tabIndex = 0; card.setAttribute("role", "button"); card.setAttribute("aria-label", `Open details for ${node.id}`);
    card.addEventListener("click", () => openNode(node.id));
    card.addEventListener("keydown", event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openNode(node.id); } });
    updateNodeRow(card, node, row);
    return card;
  }
  function updateNodeRow(card, node, row) {
    const m = row?.metrics || {}, online = Boolean(row && !row.stale && !row.sample_error);
    card.classList.toggle("is-stale", !online);
    if (!card.querySelector(".node-card-heading")) {
      const head = element("div", "node-card-heading"), identity = element("div", "node-identity");
      const icon = element("span", "mac-icon"); icon.setAttribute("aria-hidden", "true");
      const label = element("div"); label.append(element("h3", "", node.id), element("span", "muted small", `${nodeRole(node.id)} · ${(node.queues || []).join(", ") || "login"}`));
      identity.append(icon, label);
      head.append(identity, element("span", "node-health"));
      const gauges = element("div", "node-gauges");
      gauges.append(resourceGauge("CPU", null, null, "cpu", "No reading"), resourceGauge("Memory", null, null, "memory", "No reading"), resourceGauge("GPU", null, 100, "gpu", "GPU activity"));
      const trend = element("div", "node-trend");
      const foot = element("div", "node-card-footer");
      for (const labelText of ["Power", "Temperature", "Jobs"]) {
        const item = element("div"); item.append(element("small", "", labelText), element("strong", "")); foot.append(item);
      }
      card.append(head, gauges, trend, foot);
    }
    const status = card.querySelector(".node-health");
    status.className = `node-health ${online ? "online" : "offline"}`;
    status.textContent = online ? `Online · ${sampleAge(row?.age_ms || 0)}` : row?.stale ? "Stale" : "Unavailable";
    const gauges = card.querySelector(".node-gauges");
    const gaugeValues = [
      ["cpu", "CPU", m.cpu_percent, m.cpu_max_percent, m.cpu_percent == null ? "No reading" : `${num(m.cpu_percent)} / ${num(m.cpu_max_percent)} CPU%`],
      ["memory", "Memory", m.memory_used_bytes, m.memory_total_bytes, m.memory_used_bytes == null ? "No reading" : `${gib(m.memory_used_bytes)} / ${gib(m.memory_total_bytes)} GiB`],
      ["gpu", "GPU", m.gpu_percent, 100, "GPU activity"],
    ];
    for (const [kind, label, used, capacity, caption] of gaugeValues) {
      const gauge = gauges.querySelector(`[data-resource="${kind}"]`);
      const ring = gauge.querySelector(".resource-ring");
      const valid = Number.isFinite(used) && Number.isFinite(capacity) && capacity > 0;
      setRing(ring, used, capacity);
      text(ring.querySelector("strong"), valid ? `${num(used / capacity * 100)}%` : "N/A");
      text(gauge.querySelector("b"), label);
      text(gauge.querySelector("small"), caption);
    }
    const trend = card.querySelector(".node-trend"), nextTrend = sparkline(node.id);
    trend.replaceChildren(...nextTrend.childNodes);
    const footValues = [m.power_watts == null ? "N/A" : `${num(m.power_watts, 1)} W`, m.cpu_temp_celsius == null ? "N/A" : `${num(m.cpu_temp_celsius)}°C`, `${row?.running_tasks || 0} running · ${row?.waiting_tasks || 0} waiting`];
    [...card.querySelectorAll(".node-card-footer strong")].forEach((item, index) => text(item, footValues[index]));
    let warning = card.querySelector(".node-warning");
    if (!online) {
      if (!warning) { warning = element("div", "node-warning"); card.append(warning); }
      text(warning, row?.sample_error || "Waiting for a fresh resource sample");
    } else if (warning) warning.remove();
  }
  function cell(value, className = "") { const td = element("td", className); text(td, value); return td; }
  function metricCell(value, used, capacity) {
    const td = element("td");
    const span = element("span", "metric-value", value);
    if (Number.isFinite(used) && Number.isFinite(capacity) && capacity > 0) {
      const ratio = used / capacity;
      if (ratio >= .9) span.classList.add("metric-critical"); else if (ratio >= .7) span.classList.add("metric-high");
    }
    if (value === "N/A") span.classList.add("muted-value");
    td.append(span); return td;
  }

  async function updateView() {
    if (!state.boot) return;
    if (document.hidden) { closeEvents(); return; }
    const visible = state.page === "overview" ? [...state.nodes.keys()] : [];
    const detail = $("#node-dialog").open ? state.selectedNode : null;
    try {
      await api("/api/v1/view", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ view_id: state.viewId, visible_nodes: visible.slice(0, 128), detail_node: detail }) });
    } catch (error) { setBanner(error.message, "error"); }
    if (state.events) state.events.close();
    if (visible.length || detail) connectEvents();
  }
  function connectEvents() {
    if (document.hidden || !state.boot || state.events) return;
    state.events = new EventSource(`/api/v1/events?view=${encodeURIComponent(state.viewId)}`);
    state.events.onopen = () => { state.connected = true; setConnection("ready", "Connected to controller"); setBanner(""); };
    state.events.onerror = () => { state.connected = false; setConnection("pending", "Reconnecting to controller"); };
    state.events.addEventListener("update", event => {
      let update;
      try { update = JSON.parse(event.data); } catch { return; }
      if (update.error) setBanner(update.error, "error");
      else if (update.monitor) setBanner(state.boot.truncated_nodes || update.truncated_nodes ? `This view shows at most ${state.boot.node_limit} nodes.` : "");
      if (update.controller) updateController(update.controller);
      if (update.monitor) {
        for (const row of update.monitor.nodes) {
          state.rows.set(row.node_id, row);
          const samples = state.history.get(row.node_id) || [];
          const sample = row.metrics;
          if (sample?.sampled_unix_ms && samples.at(-1)?.sampled_unix_ms < sample.sampled_unix_ms) {
            samples.push(sample);
            const cutoff = Date.now() - 5 * 60 * 1000;
            while (samples.length > 150 || samples[0]?.sampled_unix_ms < cutoff) samples.shift();
            state.history.set(row.node_id, samples);
          } else if (sample?.sampled_unix_ms && samples.length === 0) {
            samples.push(sample);
            state.history.set(row.node_id, samples);
          }
        }
        state.lastUpdated = Date.now();
        text($("#last-updated"), new Date(state.lastUpdated).toLocaleTimeString());
        renderOverview();
        if (state.selectedNode) renderNodeDetail();
      }
      if (update.jobs) { state.activeJobs = update.jobs.jobs; renderOverview(); }
      if (update.queues) { state.queues = update.queues; renderQueueFilter(); renderQueues(); renderOverview(); }
    });
  }
  function closeEvents() { if (state.events) state.events.close(); state.events = null; state.connected = false; }
  function updateController(controller) {
    const label = controller.lifecycle === "ready" ? "Controller ready" : `Controller ${stateLabel(controller.lifecycle).toLowerCase()}`;
    setConnection(controller.lifecycle === "ready" ? "ready" : "pending", label);
  }
  function handleVisibility() {
    if (document.hidden) closeEvents();
    else updateView();
  }
  function switchPage(page) {
    state.page = page;
    $$(".nav-item").forEach(button => button.classList.toggle("active", button.dataset.page === page));
    $$(".page").forEach(section => section.classList.toggle("active", section.id === `page-${page}`));
    updateView();
    if (page === "jobs") loadJobs();
    if (page === "queues") loadQueues();
  }
  async function loadQueues() {
    try { state.queues = await api("/api/v1/queues"); renderQueues(); }
    catch (error) { setBanner(error.message, "error"); }
  }
  function renderQueues() {
    const root = $("#queue-cards"); root.replaceChildren();
    $("#queues-empty").classList.toggle("hidden", state.queues.length > 0);
    for (const queue of state.queues) {
      const card = element("article", "queue-card");
      const heading = element("div", "queue-title"); heading.append(element("strong", "", queue.name), element("span", "", `${queue.nodes.length} ${queue.nodes.length === 1 ? "node" : "nodes"}`)); card.append(heading);
      const counts = element("div", "queue-counts");
      for (const [label, value] of [["Pending", queue.pending], ["Running", queue.running], ["Done", queue.completed], ["Failed", queue.failed]]) {
        const item = element("div", "queue-count"); item.append(element("b", "", value), element("span", "", label)); counts.append(item);
      }
      const distribution = element("div", "queue-distribution");
      const values = [["pending", queue.pending], ["running", queue.running], ["completed", queue.completed], ["failed", queue.failed]];
      for (const [kind, value] of values) {
        if (!value) continue;
        const segment = element("span", kind); segment.style.flex = String(value);
        segment.title = stateLabel(kind) + ": " + value; distribution.append(segment);
      }
      if (!distribution.children.length) distribution.classList.add("empty");
      card.append(distribution, counts);
      const nodeList = element("div", "queue-nodes", "Nodes");
      for (const node of queue.nodes) nodeList.append(element("span", "queue-node", node));
      card.append(nodeList); root.append(card);
    }
  }
  function openNode(id) {
    state.selectedNode = id;
    text($("#detail-title"), id);
    text($("#detail-subtitle"), `${nodeRole(id)} node · ${(state.nodes.get(id)?.queues || []).join(", ") || "not assigned to a queue"}`);
    $("#node-dialog").showModal();
    renderNodeDetail(); updateView(); loadHistory(id);
  }
  function closeNode() {
    const dialog = $("#node-dialog"); if (dialog.open) dialog.close();
    state.selectedNode = null; updateView();
  }
  function renderNodeDetail() {
    const row = state.rows.get(state.selectedNode);
    const metrics = row?.metrics || {};
    const status = $("#detail-status"); status.replaceChildren();
    status.append(element("span", "", row && !row.stale ? `Metrics ${sampleAge(row.age_ms)}` : `Metrics stale · ${sampleAge(row?.age_ms)}`));
    if (row?.request_latency_ms != null) status.append(element("span", "", `Request ${row.request_latency_ms} ms`));
    if (row?.process_age_ms != null) {
      status.append(element("span", "", `${row.process_stale ? "Process data stale" : "Processes updated"} · ${sampleAge(row.process_age_ms)}`));
    }
    if (row?.sample_error) status.append(element("span", "", row.sample_error));
    const items = [
      ["CPU%", metrics.cpu_percent == null ? "N/A" : `${num(metrics.cpu_percent, 0)} / ${num(metrics.cpu_max_percent, 0)}`],
      ["MEM(GiB)", metrics.memory_used_bytes == null ? "N/A" : `${gib(metrics.memory_used_bytes)} / ${gib(metrics.memory_total_bytes)}`],
      ["GPU%", metrics.gpu_percent == null ? "N/A" : num(metrics.gpu_percent, 0)],
      ["POWER", metrics.power_watts == null ? "N/A" : `${num(metrics.power_watts, 1)} W`],
      ["TEMP", metrics.cpu_temp_celsius == null ? "N/A" : `${num(metrics.cpu_temp_celsius, 1)}°C`],
      ["FAN", metrics.fan_speed_rpm == null ? "N/A" : `${num(metrics.fan_speed_rpm, 0)} RPM`],
      ["DISK(R/W)", `${rate(metrics.disk_read_bytes_per_sec)} / ${rate(metrics.disk_write_bytes_per_sec)}`],
      ["NET(down/up)", `${rate(metrics.network_rx_bytes_per_sec)} / ${rate(metrics.network_tx_bytes_per_sec)}`],
      ["SWAP", metrics.swap_used_bytes == null ? "N/A" : `${gib(metrics.swap_used_bytes)} GiB`],
      ["POWER SCOPE", metrics.power_scope || "N/A"]
    ];
    const root = $("#detail-metrics"); root.replaceChildren();
    root.append(
      resourceGauge("CPU", metrics.cpu_percent, metrics.cpu_max_percent, "cpu", items[0][1]),
      resourceGauge("Memory", metrics.memory_used_bytes, metrics.memory_total_bytes, "memory", `${items[1][1]} GiB`),
      resourceGauge("GPU", metrics.gpu_percent, 100, "gpu", "GPU activity")
    );
    for (const [label, value] of items.slice(3)) { const tile = element("div", "detail-tile"); tile.append(element("span", "", label), element("strong", "", value)); root.append(tile); }
    const processRows = [...(row?.processes || [])].sort((a, b) => state.processSort === "cpu" ? b.cpu_percent - a.cpu_percent : ((b.memory_bytes ?? -1) - (a.memory_bytes ?? -1)));
    const body = $("#process-rows"); body.replaceChildren();
    $("#process-empty").classList.toggle("hidden", processRows.length > 0);
    text($("#process-note"), row?.process_error ? `Process sampling failed · ${row.process_error}` : `Sampled process list · ${processRows.length} rows · ${state.processSort === "cpu" ? "CPU" : "memory"} descending`);
    for (const process of processRows) {
      const tr = element("tr");
      tr.append(cell(process.pid), cell(num(process.cpu_percent, 1)), cell(process.memory || "N/A"), cell(process.cpu_time || "N/A"));
      const command = cell(process.command || "unknown", "command-cell"); command.title = process.command || "unknown"; tr.append(command); body.append(tr);
    }
    drawHistory();
  }
  function setProcessSort(sort) {
    state.processSort = sort;
    $$("[data-process-sort]").forEach(button => button.classList.toggle("active", button.dataset.processSort === sort));
    renderNodeDetail();
  }
  function handleKeys(event) {
    if (!$("#node-dialog").open || ["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement?.tagName)) return;
    if (event.key.toLowerCase() === "c") setProcessSort("cpu");
    if (event.key.toLowerCase() === "m") setProcessSort("memory");
    if (event.key === "Escape") closeNode();
  }
  async function loadHistory(id) {
    try {
      const fetched = await api(`/api/v1/nodes/${encodeURIComponent(id)}/history?minutes=5`);
      const byTime = new Map([...(state.history.get(id) || []), ...fetched].map(sample => [sample.sampled_unix_ms, sample]));
      state.history.set(id, [...byTime.values()].sort((a, b) => a.sampled_unix_ms - b.sampled_unix_ms).slice(-150));
      drawHistory();
    }
    catch { /* The live stream will fill this history after samples arrive. */ }
  }
  function drawHistory() {
    const canvas = $("#history-chart"), ctx = canvas.getContext("2d");
    const dpr = Math.max(1, window.devicePixelRatio || 1);
    const width = Math.max(320, canvas.clientWidth), height = canvas.clientHeight || 180;
    canvas.width = Math.floor(width * dpr); canvas.height = Math.floor(height * dpr); ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);
    const pad = { left: 38, right: 12, top: 12, bottom: 22 }, plotW = width - pad.left - pad.right, plotH = height - pad.top - pad.bottom;
    ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue("--line"); ctx.lineWidth = 1;
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--faint"); ctx.font = "10px -apple-system, sans-serif";
    for (let i = 0; i <= 4; i++) { const y = pad.top + plotH * i / 4; ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(width - pad.right, y); ctx.stroke(); ctx.fillText(`${100 - i * 25}%`, 2, y + 3); }
    const samples = state.history.get(state.selectedNode) || [];
    if (samples.length < 2) { ctx.fillText("Waiting for history samples…", pad.left + 8, pad.top + plotH / 2); return; }
    const now = Date.now(), start = now - 5 * 60 * 1000;
    const draw = (color, value) => {
      ctx.beginPath(); ctx.strokeStyle = color; ctx.lineWidth = 1.8; let count = 0;
      for (const sample of samples) {
        const pct = value(sample); if (pct == null) continue;
        const x = pad.left + Math.max(0, Math.min(1, (sample.sampled_unix_ms - start) / (now - start))) * plotW;
        const y = pad.top + (1 - Math.max(0, Math.min(100, pct)) / 100) * plotH;
        if (!count++) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      if (count) ctx.stroke();
    };
    draw("#238467", sample => sample.cpu_percent == null || !sample.cpu_max_percent ? null : sample.cpu_percent / sample.cpu_max_percent * 100);
    draw("#6488d6", sample => sample.memory_used_bytes == null || !sample.memory_total_bytes ? null : sample.memory_used_bytes / sample.memory_total_bytes * 100);
  }

  async function loadJobs(reset = false) {
    if (reset) state.jobOffsetStack = [0];
    const offset = state.jobOffsetStack[state.jobOffsetStack.length - 1] || 0;
    const params = new URLSearchParams({ offset: String(offset), limit: "50", active_only: "false" });
    const filter = $("#job-state-filter").value; if (filter) params.set("state", filter);
    try {
      const page = await api(`/api/v1/jobs?${params}`);
      state.jobs = page.jobs; state.nextJobOffset = page.next_offset;
      renderJobs();
    } catch (error) { setBanner(error.message, "error"); }
  }
  function renderJobs() {
    const body = $("#job-rows"); body.replaceChildren();
    $("#jobs-empty").classList.toggle("hidden", state.jobs.length > 0);
    for (const job of state.jobs) {

      const card = element("article", "job-card"); card.tabIndex = 0; card.setAttribute("role", "button");
      const heading = element("div", "job-card-heading");
      const badge = element("span", "job-state " + String(job.state).toLowerCase(), stateLabel(job.state));
      heading.append(element("span", "muted small", "JOB " + job.id), badge);
      card.append(heading, element("h3", "", job.name));
      const track = element("div", "job-progress");
      const position = ["PENDING", "STARTING", "RUNNING", "COMPLETED"].indexOf(job.state);
      for (let i = 0; i < 4; i++) track.append(element("i", i <= position ? "filled" : ""));
      track.setAttribute("aria-label", stateLabel(job.state)); card.append(track);
      card.append(element("p", "muted small", job.queue + " → " + (job.node || "Waiting for a node")), element("small", "muted", localTime(job.created_unix_ms)));
      if (job.waiting_reason) card.append(element("p", "job-wait-reason", job.waiting_reason));
      card.addEventListener("click", () => openJob(job.id));
      card.addEventListener("keydown", event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openJob(job.id); } });
      body.append(card);
    }
    $("#jobs-prev").disabled = state.jobOffsetStack.length <= 1;
    $("#jobs-next").disabled = state.nextJobOffset == null;
    const start = state.jobOffsetStack[state.jobOffsetStack.length - 1] || 0;
    text($("#jobs-page-label"), state.jobs.length ? `Jobs ${start + 1}–${start + state.jobs.length}` : "No jobs");
  }
  function stateCell(value) {
    const td = element("td"); const badge = element("span", `job-state ${String(value).toLowerCase()}`, stateLabel(value)); td.append(badge); return td;
  }
  function previousJobs() { if (state.jobOffsetStack.length > 1) { state.jobOffsetStack.pop(); loadJobs(); } }
  function nextJobs() { if (state.nextJobOffset != null) { state.jobOffsetStack.push(state.nextJobOffset); loadJobs(); } }
  async function openJob(id) {
    state.selectedJob = id;
    state.log = { stdout: { offset: null, content: "", fileIdentity: null }, stderr: { offset: null, content: "", fileIdentity: null } };
    clearInterval(state.logTimer);
    $("#job-detail").classList.remove("hidden");
    text($("#job-detail-title"), `Job ${id}`);
    $("#job-detail-content").replaceChildren(element("span", "muted", "Loading job details…"));
    try {
      const job = await api(`/api/v1/jobs/${id}`);
      if (state.selectedJob !== id) return;
      renderJobDetail(job); await refreshLogs(id);
      state.logTimer = setInterval(() => refreshLogs(id), 5000);
      $("#job-detail").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) { setBanner(error.message, "error"); }
  }
  function renderJobDetail(job) {
    text($("#job-detail-title"), `Job ${job.id} · ${job.name}`);
    const root = $("#job-detail-content"); root.replaceChildren();
    const fields = [["State", stateLabel(job.state)], ["Queue", job.queue], ["Node", job.node || "—"], ["Exit code", job.exit_code ?? "—"], ["Submitted", localTime(job.created_unix_ms)], ["Started", localTime(job.started_unix_ms)], ["Working directory", job.cwd], ["Waiting reason", job.waiting_reason || job.end_reason || "—"], ["stdout path", job.stdout_path], ["stderr path", job.stderr_path]];
    for (const [label, value] of fields) { const item = element("div", "meta-field"); item.append(element("span", "", label), element("strong", "", value)); item.title = String(value); root.append(item); }
  }
  async function refreshLogs(id) {
    if (state.selectedJob !== id) return;
    await Promise.all(["stdout", "stderr"].map(async streamName => {
      const logState = state.log[streamName];
      const params = new URLSearchParams({ stream: streamName, limit: "65536" });
      if (logState.offset != null) params.set("offset", String(logState.offset));
      try {
        const result = await api(`/api/v1/jobs/${id}/logs?${params}`);
        if (state.selectedJob !== id) return;
        if (result.reset || (logState.fileIdentity && logState.fileIdentity !== result.file_identity)) logState.content = result.content;
        else if (logState.offset == null) logState.content = result.content;
        else logState.content += result.content;
        if (logState.content.length > 1024 * 1024) logState.content = logState.content.slice(-1024 * 1024);
        logState.offset = result.end_offset;
        logState.fileIdentity = result.file_identity;
        const output = $(`#${streamName}-log`);
        text(output, stripTerminalControls(logState.content) || "(empty)");
        output.scrollTop = output.scrollHeight;
        text($(`#${streamName}-status`), `${num(result.total_bytes)} bytes${result.truncated ? " · tail" : ""}`);
      } catch (error) {
        const output = $(`#${streamName}-log`);
        if (logState.content) text(output, stripTerminalControls(logState.content));
        else text(output, error.message);
        text($(`#${streamName}-status`), "Unavailable");
      }
    }));
  }
  function closeJob() { clearInterval(state.logTimer); state.logTimer = null; state.selectedJob = null; $("#job-detail").classList.add("hidden"); }

  window.addEventListener("resize", () => { if (state.selectedNode) drawHistory(); });
  initialize();
})();
