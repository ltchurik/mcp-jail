// mcp-jail dashboard. Plain DOM, no build step. Talks to /api/* on the same
// origin; the cookie set on first visit authenticates every request.
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const fmtTime = (iso) => { const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0"); };
  const fmtDate = (iso) => { const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleString([], { hour12: false }); };
  const dur = (ms) => { if (ms < 0) ms = 0; const s = Math.floor(ms / 1000), m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24); return d ? `${d}d ${h % 24}h` : h ? `${h}h ${m % 60}m` : m ? `${m}m ${s % 60}s` : `${s}s`; };

  const state = { events: [], servers: [], filters: {}, follow: true, es: null, maxRows: 2000, home: "" };
  // tilde shortens absolute paths under the home directory for display only
  const tilde = (p) => (state.home && typeof p === "string" && (p === state.home || p.startsWith(state.home + "/"))) ? "~" + p.slice(state.home.length) : p;
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

  // mutate POSTs to a state-changing endpoint. The custom header is the
  // same-origin proof the server insists on.
  async function mutate(path, body) {
    const r = await fetch(path, { method: "POST", credentials: "same-origin", headers: { "X-Mcp-Jail": "1", "Content-Type": "application/json", Accept: "application/json" }, body: body ? JSON.stringify(body) : undefined });
    if (r.status === 401) { setLive(false, "session expired: reopen the URL printed by mcp-jail ui"); throw new Error("unauthorized"); }
    if (!r.ok) throw new Error((await r.text()).trim() || `${r.status}`);
    return r.json();
  }

  function setLive(on, text) {
    $("#live-dot").className = "dot " + (on ? "on" : "off");
    $("#live-text").textContent = text || (on ? "live" : "disconnected");
  }

  // ---- servers -----------------------------------------------------------
  // promote writes tools.rules[tool] = decision into the server's policy
  // file and reports whether the running jail took it live.
  async function promote(server, tool, decision) {
    const r = await mutate(`/api/servers/${encodeURIComponent(server)}/rules`, { tool, decision });
    const where = tilde(r.policy);
    if (r.live) toast(`${server}: ${tool} → ${decision} saved to ${where}, in force now`, decision === "deny" ? "deny" : "");
    else toast(`${server}: ${tool} → ${decision} saved to ${where} · ${r.warning || "applies on the next start"}`, "ask");
    return r;
  }
  // arm turns a button into a two-click action: the first click asks for
  // confirmation in place, the second runs it; a click elsewhere resets.
  function arm(btn, confirmText, run) {
    const label = btn.textContent;
    let armed = false;
    const reset = () => { armed = false; btn.textContent = label; btn.classList.remove("armed"); document.removeEventListener("click", away, true); };
    const away = (ev) => { if (!btn.contains(ev.target)) reset(); };
    btn.addEventListener("click", async () => {
      if (!armed) { armed = true; btn.textContent = confirmText; btn.classList.add("armed"); setTimeout(() => document.addEventListener("click", away, true), 0); return; }
      reset();
      btn.disabled = true;
      try { await run(); } finally { btn.disabled = false; }
    });
    return btn;
  }

  function renderServers(st) {
    if (state.confirming) return; // an inline confirmation is open: do not pull the card from under the user
    state.servers = st.servers || [];
    state.home = st.home || "";
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
      if (s.asks) counts.append(el("span", "pill ask", `${s.asks} waiting`));
      if (s.pending) {
        const p = f("pending");
        p.hidden = false;
        const sections = Object.values(s.pending.sections);
        const firstOnly = sections.length > 0 && sections.every(d => d.first);
        p.append(el("strong", null, firstOnly ? "First contact: review before use" : "Pending change"), el("span", "muted small", ` seen ${fmtDate(s.pending.seen_at)}`));
        const ul = el("ul");
        for (const [kind, d] of Object.entries(s.pending.sections)) {
          const parts = [];
          if (d.first) parts.push(`${d.added.length} seen for the first time`);
          else if (d.added.length) parts.push(`+${d.added.length} added`);
          if (d.removed.length) parts.push(`−${d.removed.length} removed`);
          if (d.changed.length) parts.push(`~${d.changed.length} changed`);
          const li = el("li", null, `${kind.replace(/_/g, " ")}: ${parts.join(", ")}`);
          li.title = [...d.added.map(x => "+ " + x), ...d.removed.map(x => "- " + x), ...d.changed.map(x => "~ " + x)].join("\n");
          if (d.lint && d.lint.length) {
            // the content findings: what to look at before approving
            li.append(" ", el("span", "pill blocked", `${d.lint.length} lint finding${d.lint.length === 1 ? "" : "s"}`));
            const lul = el("ul", "lint");
            for (const x of d.lint) lul.append(el("li", null, x));
            li.append(lul);
          }
          ul.append(li);
        }
        p.append(ul);
        const act = el("div", "actions");
        const btn = el("button", "btn primary", "Approve");
        btn.type = "button";
        const cmd = el("span", "muted small");
        cmd.append("or ", el("code", null, `mcp-jail approve ${s.name}`));
        act.append(btn, cmd);
        p.append(act);
        btn.addEventListener("click", () => {
          // inline confirmation: no browser dialogs
          state.confirming = true;
          act.replaceChildren();
          const yes = el("button", "btn danger", "Yes, accept the new definitions");
          const no = el("button", "btn", "Cancel");
          yes.type = no.type = "button";
          act.append(el("span", "small", "Trust what the server now serves?"), yes, no);
          no.addEventListener("click", () => { state.confirming = false; refreshState(); });
          yes.addEventListener("click", async () => {
            yes.disabled = no.disabled = true;
            state.confirming = false;
            try {
              const r = await mutate(`/api/servers/${encodeURIComponent(s.name)}/approve`);
              toast(`${s.name}: approved · ${r.lock.map(x => `${x.count} ${x.kind.replace(/_/g, " ")}`).join(", ")}`, "lock");
            } catch (err) {
              toast(`${s.name}: approve failed · ${err.message}`, "deny");
            }
            refreshState();
          });
        });
      }
      if (s.running && s.control) {
        const act = el("div", "actions");
        const stop = el("button", "btn", "Stop");
        stop.type = "button";
        stop.title = `ask the jail to exit: the server gets SIGTERM (pid ${s.pid})`;
        arm(stop, `Confirm: stop ${s.name}`, async () => {
          try {
            await mutate(`/api/servers/${encodeURIComponent(s.name)}/stop`);
            toast(`${s.name}: stop requested (pid ${s.pid})`, "ask");
          } catch (err) {
            toast(`${s.name}: stop failed · ${err.message}`, "deny");
          }
          setTimeout(refreshState, 1500);
        });
        act.append(stop);
        f("paths").before(act);
      }
      const paths = f("paths");
      if (s.policy) { const d = el("div"); d.title = s.policy; d.textContent = "policy " + tilde(s.policy); paths.append(d); }
      if (s.audit) { const d = el("div"); d.title = s.audit; d.textContent = "audit " + tilde(s.audit); paths.append(d); }
      if (s.command && s.command.length) { const d = el("div", "mono"); d.title = s.command.join(" "); d.textContent = s.command.map(tilde).join(" "); paths.append(d); }
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

  // ---- report ------------------------------------------------------------
  const SVGNS = "http://www.w3.org/2000/svg";
  const svgEl = (tag, attrs, text) => { const e = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); if (text != null) e.textContent = text; return e; };
  const fmtN = (n) => n.toLocaleString();
  const SERIES = [["allow", "allow"], ["deny", "deny"], ["blocked", "blocked"], ["ask", "ask"]];

  function tile(cls, value, label) {
    const t = el("div", "tile " + cls);
    t.append(el("div", "v", fmtN(value)), el("div", "l", label));
    return t;
  }
  function legend(target, items) {
    const box = $(target);
    box.replaceChildren();
    for (const [cls, name] of items) { const s = el("span", null, name); s.style.setProperty("--c", `var(--${cls === "blocked" ? "deny" : cls})`); if (cls === "blocked") s.style.opacity = ".75"; box.append(s); }
  }
  // bucketMinutes parses a Go duration string such as "1h0m0s" or "168h0m0s".
  function bucketMinutes(b) {
    const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:[\d.]+s)?$/.exec(b || "");
    return m ? (Number(m[1] || 0) * 60 + Number(m[2] || 0)) : 60;
  }
  function timelineChart(rep) {
    const svg = $("#timeline");
    svg.replaceChildren();
    const data = rep.timeline || [];
    const W = Math.max(svg.clientWidth || 400, 200), H = 140, padL = 32, padB = 18, padT = 6;
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.setAttribute("height", H);
    const max = Math.max(1, ...data.map(b => b.allow + b.deny + b.blocked + b.ask));
    const plotW = W - padL - 4, plotH = H - padB - padT;
    const slot = plotW / Math.max(data.length, 1);
    const bw = Math.min(24, Math.max(2, slot - 2));
    // gridlines: 0 and max, rounded
    for (const v of [0, max]) {
      const y = padT + plotH - (v / max) * plotH;
      svg.append(svgEl("line", { x1: padL, x2: W - 4, y1: y, y2: y, class: "grid" }));
      svg.append(svgEl("text", { x: padL - 6, y: y + 4, "text-anchor": "end" }, fmtN(v)));
    }
    data.forEach((b, i) => {
      const x = padL + i * slot + (slot - bw) / 2;
      let y = padT + plotH;
      const total = b.allow + b.deny + b.blocked + b.ask;
      for (const [k] of SERIES) {
        const v = b[k];
        if (!v) continue;
        const h = (v / max) * plotH;
        y -= h;
        const r = svgEl("rect", { x, y, width: bw, height: Math.max(h - (y > padT + plotH - h ? 0 : 0), 1), class: k, rx: 0 });
        svg.append(r);
        y -= 2; // 2px surface gap between segments
      }
      const hit = svgEl("rect", { x: padL + i * slot, y: padT, width: slot, height: plotH, class: "hit" });
      const when = new Date(b.start);
      hit.append(svgEl("title", {}, `${when.toLocaleString([], { hour12: false })}\n${total} decisions: ${b.allow} allow, ${b.deny} deny, ${b.blocked} blocked, ${b.ask} ask`));
      svg.append(hit);
    });
    if (data.length) {
      const first = new Date(data[0].start), last = new Date(data[data.length - 1].start);
      const mins = bucketMinutes(rep.bucket);
      const f = (d) => mins < 60 ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })
        : mins < 1440 ? d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false })
        : d.toLocaleDateString([], { month: "short", day: "numeric" });
      svg.append(svgEl("text", { x: padL, y: H - 4 }, f(first)));
      svg.append(svgEl("text", { x: W - 4, y: H - 4, "text-anchor": "end" }, f(last)));
    }
  }
  function toolsChart(rep) {
    const svg = $("#tools-chart");
    svg.replaceChildren();
    const rows = (rep.tools || []).slice(0, 8);
    const W = Math.max(svg.clientWidth || 400, 200), rowH = 26, labelW = Math.min(160, W * 0.38), padR = 44;
    const H = Math.max(rows.length * rowH, 20);
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.setAttribute("height", H);
    const max = Math.max(1, ...rows.map(t => t.total));
    const plotW = W - labelW - padR;
    rows.forEach((t, i) => {
      const y = i * rowH + 4, bh = 16;
      const name = svgEl("text", { x: labelW - 8, y: y + 12, "text-anchor": "end" }, t.tool.length > 22 ? t.tool.slice(0, 21) + "…" : t.tool);
      name.append(svgEl("title", {}, `${t.tool} (${t.server})`));
      svg.append(name);
      let x = labelW;
      const parts = [["allow", t.allow], ["deny", t.deny], ["ask", t.ask_allow + t.ask_deny]];
      for (const [k, v] of parts) {
        if (!v) continue;
        const w = (v / max) * plotW;
        const r = svgEl("rect", { x, y, width: Math.max(w, 1), height: bh, class: k });
        r.append(svgEl("title", {}, `${t.tool}: ${v} ${k}`));
        svg.append(r);
        x += w + 2;
      }
      const val = svgEl("text", { x: Math.min(x + 4, W - 2), y: y + 12, class: "val" }, fmtN(t.total));
      svg.append(val);
      const hit = svgEl("rect", { x: 0, y: y - 4, width: W, height: rowH, class: "hit" });
      hit.append(svgEl("title", {}, `${t.tool} on ${t.server}\n${t.total} calls: ${t.allow} allow, ${t.deny} deny, ${t.ask_allow} asked+allowed, ${t.ask_deny} asked+denied` + (t.avg_ms ? `\navg ${t.avg_ms.toFixed(1)} ms` : "") + (t.errors ? `\n${t.errors} errors` : "")));
      svg.insertBefore(hit, svg.firstChild);
    });
    $("#tools-more").textContent = (rep.tools || []).length > 8 ? `${rep.tools.length - 8} more tools in the CSV export` : (rows.length ? "" : "no tool calls in this range");
  }
  function renderReport(rep) {
    const d = rep.decisions || {};
    const tiles = $("#tiles");
    tiles.replaceChildren(
      tile("", rep.total, "events"),
      tile("allow", d.allow || 0, "allowed"),
      tile("deny", d.deny || 0, "denied by policy"),
      tile("ask", (d.ask_allow || 0) + (d.ask_deny || 0), `asked · ${d.ask_allow || 0} yes / ${d.ask_deny || 0} no`),
      tile("blocked", d.blocked || 0, "blocked (net, lock)"),
      tile("lock", (rep.locks || []).length, "lock events"),
    );
    $("#report-range").textContent = `${fmtDate(rep.since)} → ${fmtDate(rep.until)}` + (rep.truncated ? " · truncated" : "");
    const bm = bucketMinutes(rep.bucket);
    $("#timeline-bucket").textContent = rep.bucket ? `per ${bm >= 1440 ? (bm / 1440) + "d" : bm >= 60 ? (bm / 60) + "h" : bm + "m"}` : "";
    legend("#timeline-legend", SERIES);
    legend("#tools-legend", [["allow", "allow"], ["deny", "deny"], ["ask", "ask"]]);
    timelineChart(rep);
    toolsChart(rep);
    const hosts = $("#hosts");
    hosts.replaceChildren();
    for (const h of (rep.hosts || []).slice(0, 12)) {
      const tr = el("tr");
      const td = el("td", "host", h.host); td.title = `${h.host} · ${h.servers.join(", ")}`;
      tr.append(td, el("td", "num", fmtN(h.allowed)), el("td", "num", fmtN(h.blocked)));
      if (h.blocked) tr.children[2].append(" ", el("span", "pill blocked", "blocked"));
      hosts.append(tr);
    }
    $("#hosts-empty").hidden = (rep.hosts || []).length > 0;
    const reasons = $("#reasons");
    reasons.replaceChildren();
    for (const r of (rep.reasons || []).slice(0, 8)) {
      const tr = el("tr");
      const td = el("td", "reason", r.reason); td.title = r.reason;
      tr.append(el("td", "num", fmtN(r.count)), td);
      reasons.append(tr);
    }
    $("#reasons-empty").hidden = (rep.reasons || []).length > 0;
  }
  async function loadReport() {
    const since = $("#report-since").value;
    const qs = new URLSearchParams({ since });
    const server = state.filters.server;
    if (server) qs.set("server", server);
    $("#report-csv").href = "/api/report?format=csv&" + qs;
    $("#report-json").href = "/api/report?" + qs;
    state.report = await api("/api/report?" + qs);
    if (!$("#view-overview").hidden) renderReport(state.report);
  }
  $("#report-since").addEventListener("change", () => loadReport().catch(console.warn));
  window.addEventListener("resize", () => { clearTimeout(window.__rr); window.__rr = setTimeout(() => loadReport().catch(console.warn), 200); });

  // ---- drawer ------------------------------------------------------------
  function openDrawer(e) {
    $("#drawer-title").textContent = `${e.kind || "event"} ${target(e)} ${e.decision || ""}`.trim();
    $("#drawer-body").textContent = JSON.stringify(e, null, 2);
    const act = $("#drawer-actions");
    act.replaceChildren();
    if (e.kind === "tool_call" && e.tool && e.server) {
      // promote this tool's decision into the policy; glob tools stay as logged
      const mk = (decision, cls) => {
        const b = el("button", "btn " + cls, `Always ${decision} ${e.tool}`);
        b.type = "button";
        b.title = `write "${e.tool}: ${decision}" into ${e.server}'s policy file`;
        return arm(b, `Confirm: ${e.tool} → ${decision} in the policy`, async () => {
          try { await promote(e.server, e.tool, decision); } catch (err) { toast(`${e.server}: rule failed · ${err.message}`, "deny"); }
        });
      };
      act.append(el("span", "muted small", "From now on:"), mk("allow", "allow"), mk("deny", "danger"));
    }
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
      if ($("#view-events").hidden && (e.decision === "deny" || e.decision === "blocked" || e.decision === "ask_deny")) { unseen++; badge(); }
      if (e.kind === "lock") { toast(`${e.server}: lock ${e.decision} ${e.reason || ""}`, "lock"); refreshState(); }
      else if (e.decision === "deny" || e.decision === "blocked" || e.decision === "ask_deny") toast(`${e.server}: ${e.kind} ${target(e)} ${e.decision}`, "deny");
      if (e.kind === "start" || e.kind === "exit") refreshState();
      $("#events-meta").textContent = `${state.events.length} events (live)`;
      clearTimeout(state.reportTimer);
      state.reportTimer = setTimeout(() => loadReport().catch(console.warn), 1500);
    });
  }

  async function refreshState() {
    try { renderServers(await api("/api/state")); } catch (err) { console.warn(err); }
  }

  // ---- pending asks ------------------------------------------------------
  // Polled every second while the page is visible. The poll itself matters:
  // a jail waits for the dashboard only while someone is polling it.
  const asks = { known: new Map(), timer: null };
  function renderAsks(list, now) {
    const box = $("#asks"), wrap = $("#ask-list");
    const ids = new Set(list.map(a => `${a.server}/${a.id}`));
    for (const [key, node] of asks.known) if (!ids.has(key)) { node.remove(); asks.known.delete(key); }
    for (const a of list) {
      const key = `${a.server}/${a.id}`;
      let node = asks.known.get(key);
      if (!node) {
        node = el("div", "ask");
        const what = el("div", "what");
        what.append(el("span", "srv", a.server), "wants to call", el("span", "tool", a.tool), el("span", "muted small left"));
        const buttons = el("div", "buttons");
        const allow = el("button", "btn allow", "Allow"), deny = el("button", "btn danger", "Deny");
        const always = el("button", "btn", "Always allow"), never = el("button", "btn", "Always deny");
        always.title = `write "${a.tool}: allow" into the policy file, then allow this call`;
        never.title = `write "${a.tool}: deny" into the policy file, then deny this call`;
        const all = [allow, deny, always, never];
        for (const b of all) b.type = "button";
        const answer = async (decision, remember) => {
          for (const b of all) b.disabled = true;
          try {
            if (remember) await promote(a.server, a.tool, decision); // the rule first: if it fails, the ask stays open
            await mutate(`/api/servers/${encodeURIComponent(a.server)}/asks/${encodeURIComponent(a.id)}`, { decision });
            toast(`${a.server}: ${a.tool} ${decision === "allow" ? "allowed" : "denied"}`, decision === "allow" ? "" : "deny");
          } catch (err) {
            toast(`${a.server}: ${remember ? "rule" : "answer"} failed · ${err.message}`, "deny");
            for (const b of all) b.disabled = false;
          }
          loadAsks().catch(() => {});
        };
        allow.addEventListener("click", () => answer("allow", false));
        deny.addEventListener("click", () => answer("deny", false));
        always.addEventListener("click", () => answer("allow", true));
        never.addEventListener("click", () => answer("deny", true));
        buttons.append(allow, always, deny, never);
        node.append(what, buttons);
        if (a.arguments !== undefined && a.arguments !== null) { const pre = el("pre", "args"); pre.textContent = typeof a.arguments === "string" ? a.arguments : JSON.stringify(a.arguments, null, 1); node.append(pre); }
        wrap.append(node);
        asks.known.set(key, node);
        if (document.hidden) { try { new Notification("mcp-jail", { body: `${a.server} wants to call ${a.tool}` }); } catch { /* no permission */ } }
      }
      const left = Math.max(0, Math.round((new Date(a.deadline) - new Date(now)) / 1000));
      node.querySelector(".left").textContent = a.deadline && left ? `${left}s left` : "";
    }
    box.hidden = list.length === 0;
    if (list.length) document.title = `(${list.length}) mcp-jail`; else if (document.title.startsWith("(")) document.title = "mcp-jail";
  }
  async function loadAsks() {
    const r = await api("/api/asks");
    renderAsks(r.asks || [], r.now);
  }
  function scheduleAsks() {
    clearTimeout(asks.timer);
    asks.timer = setTimeout(async () => { try { await loadAsks(); } catch { /* retried next tick */ } scheduleAsks(); }, document.hidden ? 5000 : 1000);
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden) loadAsks().catch(() => {}); });

  // ---- tabs --------------------------------------------------------------
  const TAB_KEY = "mcp-jail.tab";
  let unseen = 0;
  function showTab(name) {
    for (const b of document.querySelectorAll(".tab")) b.setAttribute("aria-selected", String(b.dataset.tab === name));
    for (const m of document.querySelectorAll("main[data-view]")) m.hidden = m.dataset.view !== name;
    if (name === "events") { unseen = 0; badge(); }
    if (name === "overview" && state.report) renderReport(state.report); // charts size to their panel; redraw when visible
    try { localStorage.setItem(TAB_KEY, name); } catch { /* private mode */ }
  }
  function badge() {
    const b = $("#events-badge");
    b.hidden = unseen === 0;
    b.textContent = unseen > 99 ? "99+" : String(unseen);
  }
  for (const b of document.querySelectorAll(".tab")) b.addEventListener("click", () => showTab(b.dataset.tab));
  let initialTab = "overview";
  try { initialTab = localStorage.getItem(TAB_KEY) || "overview"; } catch { /* ignore */ }

  // ---- wiring ------------------------------------------------------------
  let debounce;
  filtersForm.addEventListener("input", () => { clearTimeout(debounce); debounce = setTimeout(() => { loadEvents().catch(console.warn); loadReport().catch(console.warn); }, 150); });
  filtersForm.addEventListener("submit", (ev) => ev.preventDefault());
  setInterval(() => { $("#clock").textContent = new Date().toLocaleTimeString([], { hour12: false }); }, 1000);
  setInterval(refreshState, 10000);
  showTab(initialTab);
  refreshState().then(loadEvents).then(loadReport).catch(console.warn).finally(() => { connect(); loadAsks().catch(() => {}); scheduleAsks(); });
})();
