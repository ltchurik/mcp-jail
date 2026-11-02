// mcp-jail dashboard. Plain DOM, no build step. Talks to /api/* on the same
// origin; the cookie set on first visit authenticates every request.
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const fmtTime = (iso) => { const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0"); };
  const fmtDate = (iso) => { const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleString([], { hour12: false }); };
  const dur = (ms) => { if (ms < 0) ms = 0; const s = Math.floor(ms / 1000), m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24); return d ? `${d}d ${h % 24}h` : h ? `${h}h ${m % 60}m` : m ? `${m}m ${s % 60}s` : `${s}s`; };

  const state = { events: [], servers: [], filters: {}, follow: true, es: null, maxRows: 2000 };
  const filtersForm = $("#filters");
  const tbody = $("#events");

  function readFilters() {
    const fd = new FormData(filtersForm);
    const f = {};
    for (const [k, v] of fd.entries()) if (v) f[k] = v;
    state.filters = f;
    state.follow = $("#follow").checked;
    return f;
  }

  function matches(e) {
    const f = state.filters;
    if (f.server && e.server !== f.server) return false;
    if (f.kind && e.kind !== f.kind) return false;
    if (f.decision && e.decision !== f.decision) return false;
    if (f.q) {
      const q = f.q.toLowerCase();
      const hay = [e.tool, e.host, e.reason, e.error, e.server].filter(Boolean).join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  async function api(path) {
    const r = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (r.status === 401) { setLive(false, "session expired: reopen the URL printed by mcp-jail ui"); throw new Error("unauthorized"); }
    if (!r.ok) throw new Error(`${path}: ${r.status}`);
    return r.json();
  }

  function setLive(on, text) {
    $("#live-dot").className = "dot " + (on ? "on" : "off");
    $("#live-text").textContent = text || (on ? "live" : "disconnected");
  }

  // ---- servers -----------------------------------------------------------
  function renderServers(st) {
    state.servers = st.servers || [];
    $("#version").textContent = st.version ? "v" + st.version.replace(/^v/, "") : "";
    $("#server-count").textContent = state.servers.length ? `(${state.servers.filter(s => s.running).length} running / ${state.servers.length})` : "";
    const sel = filtersForm.elements.server;
    const cur = sel.value;
    sel.replaceChildren(new Option("all servers", ""));
    for (const s of state.servers) sel.append(new Option(s.name, s.name));
    sel.value = state.servers.some(s => s.name === cur) ? cur : "";

    const wrap = $("#servers");
    wrap.replaceChildren();
    if (!state.servers.length) {
      wrap.append(el("p", "muted small", "No servers yet. Start one with `mcp-jail run --policy policy.yml -- <command>` and it shows up here."));
      return;
    }
    const tpl = $("#tpl-card").content;
    const now = new Date(st.now);
    for (const s of state.servers) {
      const c = tpl.cloneNode(true);
      const f = (k) => c.querySelector(`[data-f="${k}"]`);
      f("name").textContent = s.name;
      f("name").title = s.name;
      f("state").className = "state" + (s.running ? " running" : "");
      f("state").title = s.running ? `running, pid ${s.pid}` : "not running";
      f("how").textContent = s.running ? (s.how || "running") : "stopped";
      f("network").textContent = s.network || "—";
      f("default").textContent = s.tools_default ? `default ${s.tools_default}` : "—";
      f("lock").textContent = s.lock && s.lock.length ? s.lock.map(x => `${x.count} ${x.kind.replace(/_/g, " ")}`).join(", ") : (s.lock_enabled ? "on, nothing recorded" : "off");
      f("uptime").textContent = s.running && s.started_at ? dur(now - new Date(s.started_at)) : (s.last_seen ? "last run " + fmtDate(s.last_seen) : "—");
      const counts = f("counts");
      for (const k of ["allow", "ask_allow", "deny", "ask_deny", "blocked"]) {
        if (s.counts && s.counts[k]) counts.append(el("span", "pill " + k, `${s.counts[k]} ${k.replace("_", " ")}`));
      }
      if (s.counts === undefined) counts.append(el("span", "muted small", "no events in the last 24h"));
      if (s.pending) {
        const p = f("pending");
        p.hidden = false;
        p.append(el("strong", null, "Pending change"), el("span", "muted small", ` seen ${fmtDate(s.pending.seen_at)}`));
        const ul = el("ul");
        for (const [kind, d] of Object.entries(s.pending.sections)) {
          const parts = [];
          if (d.added.length) parts.push(`+${d.added.length} added`);
          if (d.removed.length) parts.push(`−${d.removed.length} removed`);
          if (d.changed.length) parts.push(`~${d.changed.length} changed`);
          const li = el("li", null, `${kind.replace(/_/g, " ")}: ${parts.join(", ")}`);
          li.title = [...d.added.map(x => "+ " + x), ...d.removed.map(x => "- " + x), ...d.changed.map(x => "~ " + x)].join("\n");
          ul.append(li);
        }
        p.append(ul);
        const cmd = el("div", "small");
        cmd.append("review the server, then ", el("code", null, `mcp-jail approve ${s.name}`));
        p.append(cmd);
      }
      const paths = f("paths");
      if (s.policy) { const d = el("div"); d.title = s.policy; d.textContent = "policy " + s.policy; paths.append(d); }
      if (s.audit) { const d = el("div"); d.title = s.audit; d.textContent = "audit " + s.audit; paths.append(d); }
      if (s.command && s.command.length) { const d = el("div", "mono"); d.title = s.command.join(" "); d.textContent = s.command.join(" "); paths.append(d); }
      if (s.error) paths.append(el("div", "pill deny", s.error));
      wrap.append(c);
    }
  }

  // ---- events ------------------------------------------------------------
  function target(e) {
    if (e.tool) return e.tool;
    if (e.host) return e.host;
    return "";
  }
  function row(e, fresh) {
    const tr = el("tr", fresh ? "fresh" : null);
    tr.append(el("td", "time", fmtTime(e.ts)));
    tr.children[0].title = e.ts;
    tr.append(el("td", null, e.server || ""));
    tr.append(el("td", "kind " + (e.kind || ""), e.kind || ""));
    const dec = el("td");
    if (e.decision) dec.append(el("span", "dec " + e.decision, e.decision.replace("_", " ")));
    tr.append(dec);
    const t = el("td", "mono", target(e));
    tr.append(t);
    const reason = el("td", "reason", [e.reason, e.error].filter(Boolean).join(" · "));
    tr.append(reason);
    tr.append(el("td", "num muted", e.duration_ms ? String(e.duration_ms) : ""));
    tr.addEventListener("click", () => openDrawer(e));
    return tr;
  }
  function renderEvents() {
    tbody.replaceChildren();
    const shown = state.events.filter(matches);
    for (const e of shown) tbody.append(row(e, false));
    $("#events-empty").hidden = shown.length > 0;
  }
  function prepend(e) {
    if (!matches(e)) return;
    tbody.prepend(row(e, true));
    while (tbody.children.length > state.maxRows) tbody.lastChild.remove();
    $("#events-empty").hidden = true;
    if (state.follow) $(".table-wrap").scrollTop = 0;
  }
  async function loadEvents() {
    const f = readFilters();
    const qs = new URLSearchParams();
    for (const k of ["server", "kind", "decision", "since", "q"]) if (f[k]) qs.set(k, f[k]);
    qs.set("limit", "1000");
    const r = await api("/api/events?" + qs);
    state.events = r.events || [];
    renderEvents();
    $("#events-meta").textContent = `${state.events.length} of up to ${r.limit} events from ${r.files.length} file${r.files.length === 1 ? "" : "s"}` + (r.skipped_lines ? ` · ${r.skipped_lines} unparsable line${r.skipped_lines === 1 ? "" : "s"} skipped` : "");
  }

  // ---- drawer ------------------------------------------------------------
  function openDrawer(e) {
    $("#drawer-title").textContent = `${e.kind || "event"} ${target(e)} ${e.decision || ""}`.trim();
    $("#drawer-body").textContent = JSON.stringify(e, null, 2);
    $("#drawer").hidden = false;
  }
  $("#drawer-close").addEventListener("click", () => { $("#drawer").hidden = true; });
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") $("#drawer").hidden = true; });

  // ---- toasts ------------------------------------------------------------
  function toast(text, cls) {
    const t = el("div", "toast " + (cls || ""), text);
    $("#toasts").append(t);
    setTimeout(() => t.remove(), 6000);
  }

  // ---- live stream -------------------------------------------------------
  function connect() {
    if (state.es) state.es.close();
    const es = new EventSource("/api/stream");
    state.es = es;
    es.onopen = () => setLive(true);
    es.onerror = () => { setLive(false, "reconnecting…"); };
    es.addEventListener("audit", (m) => {
      let e;
      try { e = JSON.parse(m.data); } catch { return; }
      state.events.unshift(e);
      if (state.events.length > state.maxRows) state.events.length = state.maxRows;
      prepend(e);
      if (e.kind === "lock") { toast(`${e.server}: lock ${e.decision} ${e.reason || ""}`, "lock"); refreshState(); }
      else if (e.decision === "deny" || e.decision === "blocked" || e.decision === "ask_deny") toast(`${e.server}: ${e.kind} ${target(e)} ${e.decision}`, "deny");
      if (e.kind === "start" || e.kind === "exit") refreshState();
      $("#events-meta").textContent = `${state.events.length} events (live)`;
    });
  }

  async function refreshState() {
    try { renderServers(await api("/api/state")); } catch (err) { console.warn(err); }
  }

  // ---- wiring ------------------------------------------------------------
  let debounce;
  filtersForm.addEventListener("input", () => { clearTimeout(debounce); debounce = setTimeout(() => loadEvents().catch(console.warn), 150); });
  filtersForm.addEventListener("submit", (ev) => ev.preventDefault());
  setInterval(() => { $("#clock").textContent = new Date().toLocaleTimeString([], { hour12: false }); }, 1000);
  setInterval(refreshState, 10000);
  refreshState().then(loadEvents).catch(console.warn).finally(connect);
})();
