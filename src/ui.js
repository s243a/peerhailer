/**
 * A page for looking at what this machine believes.
 *
 * One file, no build step, no dependencies — served by the daemon on the same
 * loopback address as the local API. The value of a GUI here is not
 * convenience: it is that the answers to "who can reach me", "why is that peer
 * refused" and "what did I actually grant" are hard to hold in your head and
 * trivial to read from a table.
 *
 * Deliberately read-mostly. The actions it offers are the ones that are safe to
 * take quickly — admit a candidate, change a profile, block, unblock — and each
 * is the same call the CLI makes. Anything whose consequences deserve thought
 * stays where thought is easier.
 *
 * @module ui
 */

/** @param {{name: string, fingerprint: string}} self */
export function renderPage(self) {
  // String.raw, not a cooked template: the inline browser script below is the
  // real payload, and a cooked literal eats its backslash escapes before they
  // reach the browser — `\/` in a regex collapses to `/` (turning `/\/+$/` into
  // the comment `//+$/`) and a string's `\n` becomes a raw newline, both of
  // which are syntax errors in the served <script>. String.raw passes every
  // escape through untouched while still interpolating ${...}. (See the
  // renderPage parse test — the served script must parse.)
  return String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>peerhailer — ${escapeHtml(self.name)}</title>
<style>
  :root { color-scheme: light dark; --line: color-mix(in oklab, currentColor 15%, transparent); }
  body { font: 15px/1.5 ui-sans-serif, system-ui, sans-serif; margin: 0; padding: 2rem 1.5rem 4rem; max-width: 60rem; }
  h1 { font-size: 1.15rem; margin: 0; font-weight: 600; }
  h2 { font-size: .95rem; margin: 2.2rem 0 .6rem; font-weight: 600; }
  header { display: flex; align-items: baseline; gap: .75rem; flex-wrap: wrap; border-bottom: 1px solid var(--line); padding-bottom: .8rem; }
  code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85em; }
  .muted { opacity: .62; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: .45rem .6rem .45rem 0; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; opacity: .6; }
  .tag { display: inline-block; padding: .05rem .4rem; border: 1px solid var(--line); border-radius: .5rem; font-size: .78rem; }
  button { font: inherit; font-size: .82rem; padding: .18rem .5rem; border: 1px solid var(--line); border-radius: .4rem; background: transparent; color: inherit; cursor: pointer; }
  button:hover { border-color: currentColor; }
  select { font: inherit; font-size: .82rem; background: transparent; color: inherit; border: 1px solid var(--line); border-radius: .4rem; padding: .15rem; }
  .empty { opacity: .55; font-style: italic; padding: .5rem 0; }
  .row-actions { display: flex; gap: .35rem; flex-wrap: wrap; }
  /* The only colour on the page that does not derive from currentColor, so
     the only one that can end up dark red on a dark background. */
  #error { color: #b00; color: light-dark(#b00, #ff9b9b); margin-top: 1rem; }
  details.node { border-left: 1px solid var(--line); margin: .15rem 0 .15rem .35rem; padding-left: .7rem; }
  details.node > summary { cursor: pointer; padding: .15rem 0; font-size: .88rem; }
  details.node > summary::marker { color: color-mix(in oklab, currentColor 45%, transparent); }
  .leaf { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8rem; padding: .1rem 0 .1rem .2rem; }
  .leaf .k { opacity: .6; }
  .gate { display: inline-block; margin-left: .4rem; font-size: .72rem; padding: 0 .35rem; border: 1px solid var(--line); border-radius: .5rem; }
  .gate.no { opacity: .5; text-decoration: line-through; }
  .warn { color: #b00; color: light-dark(#b00, #ff9b9b); }
  input[type=text], input:not([type]) { font: inherit; font-size: .82rem; background: transparent; color: inherit; border: 1px solid var(--line); border-radius: .4rem; padding: .15rem .35rem; }
  #composer { border: 1px solid var(--line); border-radius: .55rem; padding: .75rem .85rem; }
  .cx-row { display: flex; gap: .9rem; align-items: center; flex-wrap: wrap; margin-bottom: .55rem; }
  .cx-row label { display: flex; gap: .35rem; align-items: center; }
  #cx-status { margin-top: .5rem; line-height: 1.8; }
  #chat { border: 1px solid var(--line); border-radius: .55rem; padding: .75rem .85rem; }
  .ch-thread { height: 220px; overflow-y: auto; border: 1px solid var(--line); border-radius: .4rem; padding: .5rem; display: flex; flex-direction: column; gap: .3rem; }
  .ch-msg { max-width: 78%; padding: .3rem .55rem; border-radius: .5rem; line-height: 1.35; white-space: pre-wrap; overflow-wrap: anywhere; }
  .ch-mine { align-self: flex-end; background: #2f6f4f; color: #fff; }
  .ch-theirs { align-self: flex-start; background: var(--line); }
  .ch-meta { font-size: .72rem; opacity: .6; margin-top: .12rem; }
  #files { border: 1px solid var(--line); border-radius: .55rem; padding: .75rem .85rem; }
  .fx-list { max-height: 260px; overflow-y: auto; border: 1px solid var(--line); border-radius: .4rem; padding: .3rem; }
  .fx-row { display: flex; gap: .6rem; align-items: center; padding: .2rem .35rem; border-radius: .3rem; }
  .fx-row:hover { background: var(--line); }
  .fx-name { flex: 1; overflow-wrap: anywhere; }
  .fx-name.dir { cursor: pointer; font-weight: 600; }
  .fx-size { opacity: .6; font-size: .8rem; }
</style>
</head>
<body>
<header>
  <h1>${escapeHtml(self.name)}</h1>
  <span class="mono muted" id="fingerprint-value">${escapeHtml(self.fingerprint)}</span>
  <span class="muted" id="clock"></span>
</header>

<h2>Compose a session</h2>
<p class="muted" style="margin:.2rem 0 .6rem">
  Launch a local T3 instance whose model is a bridged coding agent. Optionally
  supervise its tool calls from your own Claude Code over MCP, and gate the T3 web
  app behind a password.
</p>
<section id="composer">
  <div class="cx-row">
    <label>Node <select id="cx-node"></select></label>
    <label>Agent <select id="cx-agent"></select></label>
    <label>Supervision
      <select id="cx-sup">
        <option value="none">None</option>
        <option value="mcp">MCP seat (my Claude Code)</option>
      </select>
    </label>
    <label>Pacing
      <select id="cx-pace" title="human-like response latency on the supervisor's verdicts">
        <option value="none">None</option>
        <option value="human">Human-like</option>
      </select>
    </label>
    <label><input type="checkbox" id="cx-gate"> Password bastion</label>
  </div>
  <div class="cx-row">
    <label>Workspace <input type="text" id="cx-cwd" size="34" placeholder="(a throwaway dir if empty)"></label>
    <button id="cx-launch">Launch</button>
    <button id="cx-stop" disabled>Stop</button>
  </div>
  <div id="cx-status" class="muted"></div>
  <div class="cx-row" style="margin-top:.6rem;border-top:1px solid var(--line);padding-top:.6rem">
    <label>Drive a remote T3 <select id="cx-rc-node"></select></label>
    <label>Local T3
      <select id="cx-rc-local">
        <option value="existing">Use the one already running</option>
        <option value="new">Launch a new one</option>
      </select>
    </label>
    <button id="cx-rc-connect">Connect</button>
    <button id="cx-rc-stop" disabled>Stop</button>
  </div>
  <div id="cx-rc-status" class="muted"></div>
</section>

<h2>Chat</h2>
<section id="chat">
  <div class="cx-row">
    <label>Peer <select id="ch-peer"></select></label>
    <span id="ch-seal" class="muted"></span>
    <button id="ch-accept" style="display:none" title="accept the sealing key this peer now presents">Accept new key</button>
    <button id="ch-clear" title="forget this conversation (memory only)">Clear</button>
  </div>
  <div id="ch-thread" class="ch-thread"></div>
  <div class="cx-row" style="margin-top:.5rem">
    <input type="text" id="ch-text" size="44" maxlength="4096" placeholder="a short message…">
    <button id="ch-send">Send</button>
  </div>
  <div id="ch-status" class="muted"></div>
</section>

<h2>Files</h2>
<section id="files">
  <div class="cx-row">
    <label>Peer <select id="fx-peer"></select></label>
    <label>Share <input type="text" id="fx-share" size="14" placeholder="e.g. docs"></label>
    <button id="fx-open">Open</button>
  </div>
  <div id="fx-path" class="muted"></div>
  <div id="fx-list" class="fx-list"></div>
  <div class="cx-row" style="margin-top:.5rem">
    <input type="file" id="fx-file">
    <button id="fx-upload" disabled>Upload here</button>
  </div>
  <div class="cx-row" style="margin-top:.5rem">
    <button id="fx-mount" title="expose this share over loopback WebDAV so external tools can use it">Mount for external tools</button>
    <span class="muted" style="font-size:.8rem">permissive — a mount is reachable by any local process</span>
  </div>
  <div id="fx-mounts" class="muted"></div>
  <div id="fx-status" class="muted"></div>
</section>

<h2>Peers</h2>
<div id="peers"></div>

<h2>Heard of, not admitted</h2>
<p class="muted" style="margin:.2rem 0 .6rem">
  A peer naming another tells you it exists, not that you should talk to it.
</p>
<div id="candidates"></div>

<h2>What this machine holds and shares
  <button id="reload" style="margin-left:.6rem">reload config</button>
</h2>
<p class="muted" style="margin:.2rem 0 .6rem">
  Opening a branch fetches it; closing one discards what was fetched, so nothing
  read stays behind. Re-opening asks again.
</p>
<div id="tree"></div>

<div id="error"></div>

<script type="module">
const $ = (id) => document.getElementById(id);
// Escapes ampersand, angle brackets and the double quote. Every attribute this
// page builds is double-quoted, so a peer name — which arrives in a signed
// record, travels by gossip, and is therefore text an attacker chose — cannot
// close one. Single quotes are deliberately not escaped, which means a
// single-quoted attribute must never be introduced here.
// (No backticks in this comment: it lives inside the page template.)
const esc = (value) => String(value ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function api(path, options) {
  const response = await fetch(path, options);
  // Read the body either way: the server puts a human reason in the error field
  // (a 409 sealing explanation, "a name is required"), and throwing a bare status
  // code threw that away — the operator saw "HTTP 409" for a message meant for them.
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error ?? (path + " -> HTTP " + response.status));
  return data;
}

function addressesOf(peer) {
  if (!peer.addresses?.length) return '<span class="muted">no address</span>';
  return peer.addresses
    .map((a) => '<code>' + esc(a.transport) + ':' + esc(a.value) + '</code>')
    .join("<br>");
}

async function refresh() {
  try {
    const [state, profiles] = await Promise.all([api("/api/peers"), api("/api/profiles")]);
    $("clock").textContent = new Date().toLocaleTimeString();

    const options = profiles.map((p) => p.name);
    // Don't repaint the peer table out from under an open profile <select>: the
    // 5s refresh replacing innerHTML would snap it shut mid-choice and drop the
    // half-made selection. The focus check runs right before the write, so focus
    // cannot slip into the table between the check and the replacement.
    const peersEl = $("peers");
    if (!peersEl.contains(document.activeElement))
      peersEl.innerHTML = state.admitted.length
      ? '<table><tr><th>Peer</th><th>Profile</th><th>Why</th><th>Reachable at</th><th></th></tr>' +
        state.admitted.map((peer) => {
          const chosen = options
            .map((name) => '<option' + (name === peer.effective?.profile ? " selected" : "") + '>' + esc(name) + '</option>')
            .join("");
          return '<tr><td><strong>' + esc(peer.name) + '</strong>' +
            (peer.publicKey ? "" : ' <span class="tag">no key</span>') +
            // Parked: an assigned profile that no longer resolves — granted
            // nothing until reassigned. Shown so the demotion is not silent.
            (peer.parked ? ' <span class="tag" title="assigned \'' + esc(peer.parked) + '\' no longer exists — granted nothing until reassigned">⚠ parked</span>' : "") +
            '</td><td><select data-peer="' + esc(peer.name) + '">' + chosen + '</select></td>' +
            '<td class="muted">' + esc(peer.parked ? "assigned '" + peer.parked + "' no longer exists" : (peer.effective?.reason ?? "")) + '</td>' +
            '<td>' + addressesOf(peer) + '</td>' +
            '<td class="row-actions">' +
              '<button data-block="' + esc(peer.name) + '" data-blocked="' + (peer.effective?.profile === "blocked") + '">' +
                (peer.effective?.profile === "blocked" ? "unblock" : "block") + '</button>' +
              '<button data-forget="' + esc(peer.name) + '">forget</button>' +
            '</td></tr>';
        }).join("") + '</table>'
      : '<p class="empty">No peers yet. Add one with <code>hail add &lt;name&gt; &lt;address&gt;</code>.</p>';

    $("candidates").innerHTML = state.candidates.length
      ? '<table><tr><th>Name</th><th>Heard from</th><th></th></tr>' +
        state.candidates.map((peer) =>
          '<tr><td>' + esc(peer.name) + '</td><td class="muted">' + esc((peer.heardFrom ?? []).join(", ")) + '</td>' +
          '<td><button data-admit="' + esc(peer.name) + '">admit</button></td></tr>').join("") + '</table>'
      : '<p class="empty">Nothing heard of. Run <code>hail walk</code>.</p>';

    $("error").textContent = "";
  } catch (cause) {
    $("error").textContent = String(cause.message ?? cause);
  }
}

document.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLButtonElement)) return;

  if (target.id === "reload") {
    // Declaring a tunnel or a command at a terminal reaches disk and not this
    // process. This is the door for that, without ending the process and losing
    // what it is holding.
    try {
      const result = await api("/api/reload", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      $("error").textContent = "reloaded: " + result.routes + " routes, " + result.profiles + " profiles";
    } catch (cause) {
      $("error").textContent = String(cause.message ?? cause);
    }
    return;
  }
  const { admit, block, forget } = target.dataset;
  try {
    if (admit) await api("/api/peers", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: admit }) });
    if (forget) await api("/api/peers?name=" + encodeURIComponent(forget), { method: "DELETE" });
    // What to send comes from the row's data, not the button's own label: a
    // refresh landing between render and click would otherwise invert the
    // action, and the row would look unchanged because it did the opposite.
    if (block) await api("/api/block", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: block, blocked: target.dataset.blocked !== "true" }) });
    await refresh();
  } catch (cause) {
    $("error").textContent = String(cause.message ?? cause);
  }
});

document.addEventListener("change", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLSelectElement) || !target.dataset.peer) return;
  try {
    await api("/api/peers", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: target.dataset.peer, profile: target.value }),
    });
    await refresh();
  } catch (cause) {
    $("error").textContent = String(cause.message ?? cause);
  }
});


/*
 * The tree.
 *
 * Closing a branch throws away what was fetched rather than hiding it. Hiding
 * leaves the value in the DOM and in memory, where a heap snapshot still finds
 * it and re-opening shows it again without asking anyone's permission a second
 * time. Discarding makes the gate run every time a branch opens, which is what
 * you want a gate to do.
 */
const nodes = new Map();

function leaf(key, value) {
  return '<div class="leaf"><span class="k">' + esc(key) + ':</span> ' + esc(value) + '</div>';
}

function gateChip(name, open) {
  return '<span class="gate' + (open ? '' : ' no') + '">' + esc(name) + '</span>';
}

function node(id, label, extra) {
  return '<details class="node" data-node="' + esc(id) + '"><summary>' + label +
    (extra ?? '') + '</summary><div class="body"></div></details>';
}

const RENDER = {
  async self() {
    const state = await api("/api/peers");
    const plugins = await api("/api/plugins");
    return [
      leaf("name", state.self.name),
      leaf("fingerprint", $("fingerprint-value")?.textContent ?? ""),
      state.self.addresses?.length
        ? state.self.addresses.map((a) => leaf(a.transport, a.value)).join("")
        : leaf("addresses", "none recorded"),
      '<div class="leaf k" style="margin-top:.3rem">offers</div>',
      plugins.plugins.map((p) =>
        leaf(p.name, (p.capabilities.join(", ") || "no capability") + " — " + p.description)).join(""),
    ].join("");
  },

  async peers() {
    const state = await api("/api/peers");
    if (!state.admitted.length) return '<div class="leaf">none admitted</div>';
    return state.admitted.map((peer) => node("peer:" + peer.name, esc(peer.name),
      gateChip(peer.effective?.profile ?? "?", peer.effective?.profile !== "blocked"))).join("");
  },

  async ran() {
    const { entries } = await api("/api/command-history");
    if (!entries.length) return '<div class="leaf">nothing has been run here</div>';
    return entries.map((entry) =>
      leaf(new Date(entry.at).toISOString(),
        entry.capability + " — " + entry.peer + " — " + entry.outcome)).join("");
  },

  async shared() {
    const profiles = await api("/api/profiles");
    return profiles.map((p) => node("shared:" + p.name, esc(p.name))).join("");
  },
};

async function renderNode(id) {
  if (RENDER[id]) return RENDER[id]();

  if (id.startsWith("peer:")) {
    const name = id.slice(5);
    const state = await api("/api/peers");
    const peer = state.admitted.find((entry) => entry.name === name);
    if (!peer) return '<div class="leaf">gone</div>';
    const lapses = peer.profileUntil && peer.profileUntil > Date.now()
      ? leaf("until", new Date(peer.profileUntil).toISOString() + " then " + (peer.profileAfter ?? "default"))
      : "";
    const conflicts = (peer.conflicts ?? []).map((c) =>
      '<div class="leaf warn">! another key answered as ' + esc(name) + ', seen ' + c.count +
      'x since ' + esc(new Date(c.firstSeen).toISOString()) + ' — the key held still applies</div>').join("");
    return [
      leaf("profile", peer.effective?.profile ?? "?"),
      leaf("why", peer.effective?.reason ?? ""),
      lapses,
      leaf("key", peer.publicKey ? "held" : "none — trust on first use"),
      peer.addresses?.length
        ? peer.addresses.map((a) => leaf(a.transport, a.value)).join("")
        : leaf("addresses", "none"),
      leaf("last seen", peer.lastSeen ? new Date(peer.lastSeen).toISOString() : "never"),
      conflicts,
    ].join("");
  }

  if (id.startsWith("shared:")) {
    const view = await api("/api/shared?profile=" + encodeURIComponent(id.slice(7)));
    const gates =
      '<div class="leaf">' + gateChip("hail", view.gates.hail) + gateChip("directory", view.gates.directory) + '</div>';
    if (!view.receives) return gates + '<div class="leaf">receives nothing — not answered at all</div>';
    return gates +
      leaf("self", view.receives.self?.name ?? "") +
      (view.gates.directory
        ? (view.receives.peers.length
            ? view.receives.peers.map((peer) => leaf("peer", peer.name)).join("")
            : leaf("peers", "none to pass on"))
        : leaf("peers", "withheld — no directory capability"));
  }

  return "";
}

document.addEventListener("toggle", async (event) => {
  const details = event.target;
  if (!(details instanceof HTMLDetailsElement) || !details.dataset.node) return;
  const body = details.querySelector(".body");
  const id = details.dataset.node;

  if (!details.open) {
    // Discard, do not hide. Any nested branch goes with it.
    body.innerHTML = "";
    for (const key of [...nodes.keys()]) if (key === id || key.startsWith(id + "/")) nodes.delete(key);
    return;
  }

  try {
    body.innerHTML = '<div class="leaf muted">…</div>';
    body.innerHTML = await renderNode(id);
    nodes.set(id, true);
  } catch (cause) {
    body.innerHTML = "";
    $("error").textContent = String(cause.message ?? cause);
  }
}, true);

$("tree").innerHTML = [
  node("self", "self"),
  node("peers", "peers"),
  node("shared", "what a caller receives"),
  node("ran", "what peers have run here"),
].join("");

// --- session composer ---
let cxRes = null, cxSeatTimer = null, cxNodes = null, cxLocalAgents = [];
async function cxLoadAll() {
  try {
    const info = await api("/api/compose/agents");
    cxLocalAgents = info.agents;
    const gate = $("cx-gate");
    gate.disabled = !info.gateConfigured;
    gate.title = info.gateConfigured ? "" : "run: hail gate set-password";
    let opts = '<option value="local">This machine (local)</option>';
    if (info.remote) {
      try {
        cxNodes = await api("/api/compose/nodes");
        for (const n of (cxNodes.nodes || [])) {
          const workers = (n.offers || []).filter((o) => o.role === "worker");
          if (workers.length) opts += '<option value="' + esc(n.peer) + '">' + esc(n.peer) + " (" + workers.length + " offered)</option>";
        }
      } catch (ignore) {}
    }
    $("cx-node").innerHTML = opts;
    cxRcRefreshNodes();
    cxRefreshAgents();
  } catch (cause) { $("cx-status").textContent = "could not load: " + (cause.message ?? cause); }
}
function cxRefreshAgents() {
  const remote = $("cx-node").value !== "local";
  if (!remote) {
    $("cx-agent").innerHTML = cxLocalAgents.map((a) => "<option>" + esc(a) + "</option>").join("");
  } else {
    const n = (cxNodes && cxNodes.nodes || []).find((x) => x.peer === $("cx-node").value);
    const workers = ((n && n.offers) || []).filter((o) => o.role === "worker");
    $("cx-agent").innerHTML = workers.length
      ? workers.map((o) => '<option value="' + esc(o.service) + '" data-tunnel="' + esc(o.tunnel) + '" data-seat="' + esc(o.supervisorTunnel || "") + '">' + esc(o.label) + (o.agent ? " — " + esc(o.agent) : "") + "</option>").join("")
      : '<option value="">(no worker offers)</option>';
  }
  $("cx-pace").disabled = remote; // pacing stays a local option for now
  cxUpdateSupervision();
}
function cxUpdateSupervision() {
  const remote = $("cx-node").value !== "local";
  if (!remote) { $("cx-sup").disabled = false; return; }
  // A remote offer can be MCP-supervised only if it advertised a seat tunnel.
  const opt = $("cx-agent").selectedOptions[0];
  const canSupervise = !!(opt && opt.dataset.seat);
  $("cx-sup").disabled = !canSupervise;
  if (!canSupervise) $("cx-sup").value = "none";
}
async function cxPost(path, body) {
  const response = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body ?? {}) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error ?? (path + " -> HTTP " + response.status));
  return data;
}
function cxRender(seat) {
  if (!cxRes) { $("cx-status").textContent = ""; return; }
  const rows = ['T3: <a href="' + esc(cxRes.t3Url) + '" target="_blank">' + esc(cxRes.t3Url) + "</a>"];
  if (cxRes.gateUrl) rows.push('Gated: <a href="' + esc(cxRes.gateUrl) + '" target="_blank">' + esc(cxRes.gateUrl) + "</a>");
  if (cxRes.pairingUrl) rows.push("Pairing: <code>" + esc(cxRes.pairingUrl) + "</code>");
  const seatUrl = cxRes.seatUrl || (seat && seat.seatUrl);
  if (seatUrl) rows.push("Supervisor seat (point Claude Code here): <code>" + esc(seatUrl) + "</code>");
  else if (cxRes.supervision === "mcp") rows.push('<span class="muted">' + esc((seat && seat.hint) || "waiting for the supervisor seat…") + "</span>");
  $("cx-status").innerHTML = rows.join("<br>");
}
function cxPollSeat() {
  if (cxSeatTimer) clearInterval(cxSeatTimer);
  if (!cxRes || cxRes.supervision !== "mcp" || cxRes.seatUrl) return;
  const lid = cxRes.launchId;
  cxSeatTimer = setInterval(async () => {
    if (!cxRes || cxRes.launchId !== lid) { clearInterval(cxSeatTimer); return; }
    try {
      const seat = await api("/api/compose/seat?launchId=" + encodeURIComponent(lid));
      // The launch may have been stopped or replaced during the await; if so this
      // reply is for a session that is gone, and must not repaint its status.
      if (!cxRes || cxRes.launchId !== lid) { clearInterval(cxSeatTimer); return; }
      cxRender(seat);
      if (seat.seatUrl) clearInterval(cxSeatTimer);
    } catch (ignore) {}
  }, 2000);
}
async function cxLaunchNow() {
  $("cx-status").textContent = "launching… (starting a T3 server can take a few seconds)";
  $("cx-launch").disabled = true;
  try {
    const node = $("cx-node").value;
    let body;
    if (node === "local") {
      body = {
        agent: $("cx-agent").value,
        supervision: $("cx-sup").value,
        gate: $("cx-gate").checked,
        cwd: $("cx-cwd").value.trim() || undefined,
        timing: $("cx-pace").value === "human" ? { min: 2000, max: 30000, dist: "gamma", shape: 2 } : undefined,
      };
    } else {
      const opt = $("cx-agent").selectedOptions[0];
      if (!opt || !opt.value) throw new Error("that node offers no worker");
      body = {
        node,
        service: opt.value,
        tunnel: opt.dataset.tunnel,
        supervisorTunnel: opt.dataset.seat || undefined,
        supervision: $("cx-sup").disabled ? "none" : $("cx-sup").value,
        gate: $("cx-gate").checked,
      };
    }
    cxRes = await cxPost("/api/compose/launch", body);
    $("cx-stop").disabled = false;
    cxRender(null);
    cxPollSeat();
  } catch (cause) {
    $("cx-status").textContent = "launch failed: " + (cause.message ?? cause);
    $("cx-launch").disabled = false;
  }
}
async function cxStopNow() {
  const lid = cxRes && cxRes.launchId;
  if (!lid) { cxRes = null; if (cxSeatTimer) clearInterval(cxSeatTimer); $("cx-launch").disabled = false; $("cx-stop").disabled = true; return; }
  // Keep the session and hold both actions while the stop is in flight: the
  // launch id is only discarded once the teardown actually succeeds, so a failed
  // stop leaves a live seat that Stop can still retry, not an orphan with no
  // handle. The seat poll keeps running until then.
  // Pause seat polling while the stop is in flight, so a seat reply cannot repaint
  // over "stopping…". It resumes if the stop fails (the session is still live).
  if (cxSeatTimer) clearInterval(cxSeatTimer);
  $("cx-launch").disabled = true; $("cx-stop").disabled = true;
  $("cx-status").textContent = "stopping…";
  try {
    await cxPost("/api/compose/stop", { launchId: lid });
    cxRes = null;
    $("cx-status").textContent = "stopped";
    $("cx-launch").disabled = false; $("cx-stop").disabled = true;
  } catch (e) {
    // Still running — keep the session, re-enable Stop to retry, leave Launch off,
    // and resume watching for the seat.
    $("cx-status").textContent = "stop failed: " + (e.message ?? e);
    $("cx-stop").disabled = false;
    cxPollSeat();
  }
}
// --- remote control: drive a remote T3 from a local T3 client ---
let cxRc = null;
function cxRcRefreshNodes() {
  // Only peers advertising a T3 controller offer (a 'pair' command + a 't3'
  // tunnel) can be driven; the offer carries the names so we don't guess them.
  const options = [];
  for (const n of ((cxNodes && cxNodes.nodes) || []).filter((x) => x.reachable)) {
    const ctrl = (n.offers || []).find((o) => o.role === "controller");
    if (ctrl) options.push('<option value="' + esc(n.peer) + '" data-command="' + esc(ctrl.command) + '" data-tunnel="' + esc(ctrl.tunnel) + '">' + esc(n.peer) + "</option>");
  }
  $("cx-rc-node").innerHTML = options.length ? options.join("") : '<option value="">(no control-capable peers)</option>';
}
async function cxRcConnect() {
  $("cx-rc-status").textContent = "minting a grant on the remote and forwarding its T3…";
  $("cx-rc-connect").disabled = true;
  try {
    const opt = $("cx-rc-node").selectedOptions[0];
    const node = opt && opt.value;
    if (!node) throw new Error("no control-capable peer to drive");
    cxRc = await cxPost("/api/compose/control", {
      node,
      localT3: $("cx-rc-local").value,
      pairCommand: opt.dataset.command,
      tunnel: opt.dataset.tunnel,
    });
    $("cx-rc-stop").disabled = false;
    const rows = ['Open in your browser: <a href="' + esc(cxRc.deepLink) + '" target="_blank">register ' + esc(node) + " as a saved connection</a>"];
    if (cxRc.localPairingUrl) rows.push("Local T3 pairing: <code>" + esc(cxRc.localPairingUrl) + "</code>");
    rows.push('<span class="muted">via ' + esc(cxRc.remoteOrigin) + (cxRc.expiresAt ? " · grant expires " + esc(cxRc.expiresAt) : "") + "</span>");
    $("cx-rc-status").innerHTML = rows.join("<br>");
  } catch (cause) {
    $("cx-rc-status").textContent = "connect failed: " + (cause.message ?? cause);
    $("cx-rc-connect").disabled = false;
  }
}
async function cxRcStop() {
  const cid = cxRc && cxRc.controlId;
  cxRc = null;
  $("cx-rc-connect").disabled = false; $("cx-rc-stop").disabled = true;
  $("cx-rc-status").textContent = "stopped";
  try { if (cid) await cxPost("/api/compose/control/stop", { controlId: cid }); } catch (ignore) {}
}
$("cx-launch").addEventListener("click", cxLaunchNow);
$("cx-stop").addEventListener("click", cxStopNow);
$("cx-rc-connect").addEventListener("click", cxRcConnect);
$("cx-rc-stop").addEventListener("click", cxRcStop);
$("cx-node").addEventListener("change", cxRefreshAgents);
$("cx-agent").addEventListener("change", cxUpdateSupervision);
// --- files explorer: browse and transfer with a peer's share ---
let fxPath = "", fxGen = 0;
async function fxLoadPeers() {
  try {
    const p = await api("/api/peers");
    const names = (p.admitted || []).map((x) => x.name);
    $("fx-peer").innerHTML = names.length ? names.map((n) => "<option>" + esc(n) + "</option>").join("") : '<option value="">(no peers)</option>';
  } catch (ignore) {}
}
// The peer+share+path an operation was started against. Every browse binds to
// one, so a request that lands after the user has switched peer, share, or
// directory is neither rendered nor acted on under the wrong target.
function fxCtx() { return { peer: $("fx-peer").value, share: $("fx-share").value.trim(), path: fxPath }; }
function fxBrowse(op, extra, ctx) {
  const c = ctx || fxCtx();
  return cxPost("/api/files/browse", Object.assign({ peer: c.peer, share: c.share, op: op, path: c.path }, extra || {}));
}
function fxJoin(a, b) { return a ? (a.replace(/\/+$/, "") + "/" + b) : b; }
function fxParent(p) { const i = p.replace(/\/+$/, "").lastIndexOf("/"); return i < 0 ? "" : p.slice(0, i); }
async function fxOpen(path) {
  const share = $("fx-share").value.trim();
  if (!$("fx-peer").value || !share) { $("fx-status").textContent = "pick a peer and a share"; return; }
  if (path !== undefined) fxPath = path;
  const ctx = fxCtx();
  const gen = ++fxGen;
  $("fx-status").textContent = "loading…";
  try {
    const r = await fxBrowse("list", null, ctx);
    // A newer browse (or a target change, which bumps the generation via fxClear)
    // has superseded this one — its listing and status are stale, so drop them.
    if (gen !== fxGen) return;
    if (r.error) { $("fx-status").textContent = r.error; return; }
    fxRender(r.entries || [], r.truncated, ctx);
    $("fx-path").textContent = ctx.share + ":/" + ctx.path;
    $("fx-status").textContent = "";
    $("fx-upload").disabled = false;
  } catch (e) { if (gen === fxGen) $("fx-status").textContent = "open failed: " + (e.message ?? e); }
}
function fxClear() {
  fxGen++; // invalidate any browse in flight, so its late listing is dropped
  $("fx-list").innerHTML = ""; $("fx-path").textContent = ""; $("fx-status").textContent = "";
  $("fx-upload").disabled = true; fxPath = "";
}
function fxRender(entries, truncated, ctx) {
  // Rows are built from the path the listing was for (ctx.path), not the global
  // fxPath, which a newer browse may already have moved — so a navigate or a
  // download from a row always targets the directory the row actually came from.
  const rows = [];
  if (ctx.path) rows.push('<div class="fx-row"><span class="fx-name dir" data-nav="' + esc(fxParent(ctx.path)) + '">../</span></div>');
  for (const e of entries) {
    if (e.type === "dir") rows.push('<div class="fx-row"><span class="fx-name dir" data-nav="' + esc(fxJoin(ctx.path, e.name)) + '">' + esc(e.name) + "/</span></div>");
    else rows.push('<div class="fx-row"><span class="fx-name">' + esc(e.name) + '</span><span class="fx-size">' + esc(String(e.size == null ? "" : e.size)) + '</span><button data-get="' + esc(fxJoin(ctx.path, e.name)) + '">download</button></div>');
  }
  if (truncated) rows.push('<div class="muted" style="padding:.3rem">… (list truncated)</div>');
  const box = $("fx-list");
  box.innerHTML = rows.join("") || '<div class="muted" style="padding:.3rem">(empty)</div>';
  box.querySelectorAll("[data-nav]").forEach((el) => el.addEventListener("click", () => fxOpen(el.dataset.nav)));
  // Download against the target the row was rendered for, not whatever the peer
  // and share boxes happen to say now.
  box.querySelectorAll("[data-get]").forEach((el) => el.addEventListener("click", () => fxDownload(el.dataset.get, ctx)));
}
async function fxDownload(path, ctx) {
  // The generation the click happened at. The file itself is an explicit request
  // fetched from its own ctx, so it is still delivered if it lands after the view
  // moved on — but the status line belongs to the current view, so only write it
  // (success or error) while this download is still the current one.
  const gen = fxGen;
  const fresh = () => gen === fxGen;
  $("fx-status").textContent = "downloading " + path + "…";
  try {
    const r = await fxBrowse("get", { path: path }, ctx);
    if (r.error || !r.data) { if (fresh()) $("fx-status").textContent = r.error || "no data"; return; }
    const bytes = Uint8Array.from(atob(r.data), (c) => c.charCodeAt(0));
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([bytes]));
    a.download = path.split("/").pop();
    a.click();
    URL.revokeObjectURL(a.href);
    if (fresh()) $("fx-status").textContent = "downloaded " + a.download + " (" + (r.size == null ? bytes.length : r.size) + " bytes)";
  } catch (e) { if (fresh()) $("fx-status").textContent = "download failed: " + (e.message ?? e); }
}
async function fxUpload() {
  const f = $("fx-file").files[0];
  if (!f) { $("fx-status").textContent = "choose a file first"; return; }
  const ctx = fxCtx();
  // The generation the upload started at. A generation check, not a peer/share
  // value check, so an A→(clear)→A bounce into a different directory does not read
  // as "unchanged": any intervening open or clear bumps fxGen and marks this
  // upload's result stale — it targeted the directory it captured, not this one.
  const gen = fxGen;
  const fresh = () => gen === fxGen;
  $("fx-upload").disabled = true;
  $("fx-status").textContent = "uploading " + f.name + "…";
  try {
    const buf = new Uint8Array(await f.arrayBuffer());
    let bin = "";
    for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
    const r = await fxBrowse("put", { path: fxJoin(ctx.path, f.name), data: btoa(bin) }, ctx);
    if (!fresh()) {
      // The view moved on, but this upload had a definite outcome for its own
      // target — report it honestly (a refusal is not a success), attributed to
      // the target it was for, not the one on screen now.
      $("fx-status").textContent = r.error
        ? "upload to " + ctx.peer + ":" + ctx.share + " refused: " + r.error
        : "uploaded to " + ctx.peer + ":" + ctx.share + " (view since changed)";
      return;
    }
    if (r.error) $("fx-status").textContent = "upload refused: " + r.error;
    else { $("fx-status").textContent = "uploaded " + f.name + " (" + (r.written == null ? "?" : r.written) + " bytes)"; await fxOpen(); }
  } catch (e) { if (fresh()) $("fx-status").textContent = "upload failed: " + (e.message ?? e); }
  // Re-enable Upload only if the view is still the one uploaded to; if it changed
  // mid-flight, fxClear disabled it deliberately and it must stay off. (On the
  // success path fxOpen has already re-enabled it and bumped the generation.)
  finally { if (fresh()) $("fx-upload").disabled = false; }
}
async function fxMount() {
  const peer = $("fx-peer").value, share = $("fx-share").value.trim();
  if (!peer || !share) { $("fx-status").textContent = "pick a peer and a share to mount"; return; }
  $("fx-mount").disabled = true;
  try {
    const m = await cxPost("/api/files/mount", { peer: peer, share: share });
    $("fx-status").textContent = "mounted at " + m.url;
    fxLoadMounts();
  } catch (e) { $("fx-status").textContent = "mount failed: " + (e.message ?? e); }
  finally { $("fx-mount").disabled = false; }
}
async function fxLoadMounts() {
  try {
    const r = await api("/api/files/mounts");
    if (!r.mounts || !r.mounts.length) { $("fx-mounts").innerHTML = ""; return; }
    $("fx-mounts").innerHTML = "Active mounts:<br>" + r.mounts.map((m) =>
      esc(m.peer) + ":" + esc(m.share) + ' → <code>' + esc(m.url) + "</code> " +
      '<button data-stop="' + esc(m.mountId) + '">unmount</button>' +
      '<div class="muted" style="font-size:.78rem">macOS: Finder → Go → Connect to Server · Windows: Map network drive · Linux: rclone/davfs2 — use ' + esc(m.url) + "</div>"
    ).join("<br>");
    $("fx-mounts").querySelectorAll("[data-stop]").forEach((el) => el.addEventListener("click", async () => {
      try { await cxPost("/api/files/mount/stop", { mountId: el.dataset.stop }); fxLoadMounts(); } catch (ignore) {}
    }));
  } catch (ignore) {}
}
$("fx-open").addEventListener("click", () => fxOpen(""));
$("fx-upload").addEventListener("click", fxUpload);
$("fx-mount").addEventListener("click", fxMount);
// Changing the target abandons the current listing, so no stale row can be
// clicked to act on a peer/share it was never from.
$("fx-peer").addEventListener("change", fxClear);
$("fx-share").addEventListener("input", fxClear);
fxLoadPeers();
fxLoadMounts();
// --- chat: short messages to/from admitted peers (memory only) ---
let chPeer = null, chTimer = null, chEnabled = false, chSeal = {}, chGen = 0;
// How each sealing state reads to the operator. conflict/reverify block a
// send (fail closed, never cleartext); the accept button shows only for a conflict.
const SEAL_LABEL = {
  verified: "🔒 sealed",
  conflict: "⚠ sealing conflict",
  reverify: "⚠ needs re-verify — walk this peer before sending",
  unverified: "",
};
async function chLoad() {
  try {
    const st = await api("/api/chat/state");
    chEnabled = st.enabled;
    if (!chEnabled) { $("ch-status").textContent = "chat is off — start the daemon with --chat"; $("ch-peer").innerHTML = '<option value="">(chat off)</option>'; return; }
    const named = new Set();
    const opts = [];
    chSeal = {};
    for (const c of (st.conversations || [])) if (c.name) { named.add(c.name); chSeal[c.name] = c; opts.push('<option value="' + esc(c.name) + '">' + esc(c.name) + " (" + c.count + ")</option>"); }
    for (const p of (st.peers || [])) if (!named.has(p.name)) { chSeal[p.name] = p; opts.push('<option value="' + esc(p.name) + '">' + esc(p.name) + "</option>"); }
    $("ch-peer").innerHTML = opts.length ? opts.join("") : '<option value="">(no admitted peers)</option>';
    if (chPeer && [...$("ch-peer").options].some((o) => o.value === chPeer)) $("ch-peer").value = chPeer;
    await chOpen();
  } catch (e) { $("ch-status").textContent = "could not load chat: " + (e.message ?? e); }
}
function chSealBadge() {
  const info = chSeal[$("ch-peer").value] || {};
  const state = info.seal || "unverified";
  let label = SEAL_LABEL[state] || "";
  // A conflict is a decision between two keys — show both fingerprints, never a
  // bare "there's a conflict". The held key is the one still in use.
  if (state === "conflict" && info.sealFp && info.sealPendingFp) {
    label += " — held " + info.sealFp.slice(0, 12) + " vs presented " + info.sealPendingFp.slice(0, 12);
  }
  $("ch-seal").textContent = label;
  $("ch-accept").style.display = state === "conflict" ? "" : "none";
}
function chRender(messages) {
  const box = $("ch-thread");
  // Text is attacker-chosen — esc() is mandatory here (see chatPlugin.js).
  box.innerHTML = (messages || []).map((m) =>
    '<div class="ch-msg ' + (m.mine ? "ch-mine" : "ch-theirs") + '">' + esc(m.text) +
    '<div class="ch-meta">' + (m.sealed ? "🔒 " : "") + esc(m.mine ? "me" : (m.from || "them")) + " · " + esc(new Date(m.at).toLocaleTimeString()) + "</div></div>"
  ).join("");
  box.scrollTop = box.scrollHeight;
}
// switched is a real peer change (clear the old thread at once); the 4s poll
// calls it without, so a refresh does not flash empty. chGen orders responses:
// only the newest open paints, so a slow one, a reordered poll, or an A→B→A
// bounce cannot roll the display back or paint one peer's thread under another.
async function chOpen(switched) {
  const peer = $("ch-peer").value;
  chPeer = peer || null;
  chSealBadge();
  if (switched) { chRender([]); $("ch-status").textContent = ""; }
  if (!peer) { chRender([]); return; }
  const gen = ++chGen;
  try {
    const t = await api("/api/chat/thread?peer=" + encodeURIComponent(peer));
    if (gen !== chGen || $("ch-peer").value !== peer) return; // superseded, or peer changed
    chRender(t.messages);
    $("ch-status").textContent = "";
  } catch (e) { if (gen === chGen && $("ch-peer").value === peer) $("ch-status").textContent = "could not open thread: " + (e.message ?? e); }
}
async function chSend() {
  const peer = $("ch-peer").value, text = $("ch-text").value;
  if (!peer || !text.trim()) return;
  // Clear the composer up front, before any await. This is what makes a later
  // draft safe: a value-equality check after the send would erase an A→B→A draft
  // that happened to retype the same text. On failure the message is restored
  // only if the box is still empty (no new draft was started) and still on peer.
  $("ch-text").value = "";
  $("ch-send").disabled = true;
  try {
    await cxPost("/api/chat/send", { peer: peer, text: text });
    await chLoad();
  } catch (e) {
    if ($("ch-peer").value === peer && $("ch-text").value === "") $("ch-text").value = text;
    if ($("ch-peer").value === peer) $("ch-status").textContent = "send failed: " + (e.message ?? e);
  } finally { $("ch-send").disabled = false; }
}
async function chAccept() {
  const peer = $("ch-peer").value;
  if (!peer) return;
  const info = chSeal[peer] || {};
  // Confirm the exact key change, fingerprints shown — a signed record is
  // replayable, so accepting the presented key is a deliberate trust decision.
  const held = info.sealFp ? info.sealFp.slice(0, 20) : "(none)";
  const pending = info.sealPendingFp ? info.sealPendingFp.slice(0, 20) : "(none)";
  if (!window.confirm("Seal to " + peer + "'s new key?\n\nheld:      " + held + "\npresented: " + pending + "\n\nOnly accept if you recognise the presented key.")) return;
  $("ch-accept").disabled = true;
  try { await cxPost("/api/seal/accept", { peer: peer }); await chLoad(); }
  catch (e) { $("ch-status").textContent = "could not accept key: " + (e.message ?? e); }
  finally { $("ch-accept").disabled = false; }
}
async function chClear() {
  const peer = $("ch-peer").value;
  if (!peer) return;
  try { await cxPost("/api/chat/clear", { peer: peer }); await chLoad(); } catch (ignore) {}
}
$("ch-peer").addEventListener("change", () => chOpen(true));
$("ch-accept").addEventListener("click", chAccept);
$("ch-send").addEventListener("click", chSend);
$("ch-text").addEventListener("keydown", (e) => { if (e.key === "Enter") chSend(); });
$("ch-clear").addEventListener("click", chClear);
chLoad();
if (chTimer) clearInterval(chTimer);
chTimer = setInterval(() => { if (chEnabled && chPeer) chOpen(); }, 4000);
cxLoadAll();

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`;
}

/** @param {unknown} value */
function escapeHtml(value) {
  return String(value ?? "").replace(
    /[&<>"]/g,
    (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[character] ?? character,
  );
}
