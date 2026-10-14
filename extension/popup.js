/* Watchman popup — read + act against the local registry. v0.1 */
const $ = (id) => document.getElementById(id);

async function cfg() {
  const s = await chrome.storage.sync.get({ apiUrl: "http://127.0.0.1:8471", token: "" });
  return s;
}

async function api(path, opts = {}) {
  const c = await cfg();
  if (!c.token) throw new Error("no token — set it in options");
  const r = await fetch(c.apiUrl + path, {
    ...opts,
    headers: { "X-Watchman-Token": c.token, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  if (!r.ok) throw new Error("api " + r.status);
  return r.json();
}

function tierColor(score) {
  if (score >= 850) return "#3fd68c";
  if (score >= 600) return "#9db4d0";
  if (score >= 300) return "#e8b33f";
  return "#ff5d5d";
}

async function load() {
  try {
    const health = await api("/health");
    $("healthDot").className = "dot " + (health.chain_ok ? "ok" : "bad");
    $("chainState").textContent = health.chain_ok ? "chain ok · " + health.head : "CHAIN BROKEN";

    const { agents } = await api("/agents");
    const q = agents.filter((a) => a.tier === "quarantine").length;
    $("qCount").textContent = q ? "· " + q + " quarantined" : "";
    $("agents").innerHTML = agents.map((a) => `
      <div class="agent">
        <div class="name">${esc(a.name)}<small>${esc(a.kind)} · ${esc(a.location)} · ${esc(a.status)}</small></div>
        <div class="bar"><i style="width:${a.score / 10}%;background:${tierColor(a.score)}"></i></div>
        <span class="tier ${a.tier}">${a.tier}</span>
      </div>`).join("") || '<p class="muted">no agents</p>';

    const { tasks } = await api("/tasks");
    const open = tasks.filter((t) => !["done", "failed"].includes(t.status)).slice(0, 12);
    $("tasks").innerHTML = open.map((t) => `
      <div class="task"><div class="row">
        <div style="flex:1;min-width:0">${esc(t.title)}<br><small>${t.id} · ${esc(t.agent_id)}</small></div>
        <span class="status ${t.status}">${t.status}</span>
        ${t.status === "submitted" ? `<button class="verify" data-verify="${t.id}">verify</button>` : ""}
      </div></div>`).join("") || '<p class="muted">no open tasks</p>';

    document.querySelectorAll("[data-verify]").forEach((b) =>
      b.addEventListener("click", async () => {
        b.disabled = true; b.textContent = "…";
        try {
          const approver = prompt("Approver name for manual-approval steps (blank if none):", "") || "";
          const res = await api("/tasks/" + b.dataset.verify + "/verify",
            { method: "POST", body: JSON.stringify({ approver }) });
          alert(res.verified ? "VERIFIED → done" : "FAILED: " + (res.info.fails || []).join("; "));
        } catch (e) { alert("error: " + e.message); }
        load();
      }));
  } catch (e) {
    $("healthDot").className = "dot bad";
    $("agents").innerHTML = `<p class="muted">can't reach registry: ${esc(e.message)}. Is <code>watchman.py serve</code> running?</p>`;
    $("tasks").innerHTML = "";
  }
}

function esc(s) { return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

$("refresh").addEventListener("click", load);
$("openOptions").addEventListener("click", (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });
load();
