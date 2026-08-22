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
  return `<!doctype html>
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
</style>
</head>
<body>
<header>
  <h1>${escapeHtml(self.name)}</h1>
  <span class="mono muted" id="fingerprint-value">${escapeHtml(self.fingerprint)}</span>
  <span class="muted" id="clock"></span>
</header>

<h2>Peers</h2>
<div id="peers"></div>

<h2>Heard of, not admitted</h2>
<p class="muted" style="margin:.2rem 0 .6rem">
  A peer naming another tells you it exists, not that you should talk to it.
</p>
<div id="candidates"></div>

<h2>What this machine holds and shares</h2>
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
  if (!response.ok) throw new Error(path + " -> HTTP " + response.status);
  return response.json();
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
    $("peers").innerHTML = state.admitted.length
      ? '<table><tr><th>Peer</th><th>Profile</th><th>Why</th><th>Reachable at</th><th></th></tr>' +
        state.admitted.map((peer) => {
          const chosen = options
            .map((name) => '<option' + (name === peer.effective?.profile ? " selected" : "") + '>' + esc(name) + '</option>')
            .join("");
          return '<tr><td><strong>' + esc(peer.name) + '</strong>' +
            (peer.publicKey ? "" : ' <span class="tag">no key</span>') +
            '</td><td><select data-peer="' + esc(peer.name) + '">' + chosen + '</select></td>' +
            '<td class="muted">' + esc(peer.effective?.reason ?? "") + '</td>' +
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
].join("");

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
