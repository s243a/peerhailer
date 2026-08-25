/**
 * The caller side of the tunnel plugin: driving a byte pipe to an endpoint a
 * peer declared.
 *
 * The plugin is the server half — it connects to a locally-declared address and
 * shuttles bytes. This is what a peer holding `tunnel:<name>` uses to reach one:
 * `open` a pipe, `send` bytes into it, `poll` for bytes coming back, `close`.
 * Like `shellClient`, it is deliberately thin over a `call(path, body)` function
 * (a `callPeer` bound to a peer), so it carries no transport of its own and is
 * testable without a network.
 *
 * The `pipe` function is the point for a real workload: it pumps a live stream
 * (a socket, or a process's stdio) through the tunnel, so a program on this side
 * talks to the endpoint on the far side as if it were local. That is exactly
 * what a relay wants — spawn `hail tunnel <peer> <name> pipe` as the command a
 * tool runs, and the tool reaches the remote endpoint over the fabric without
 * knowing the fabric is there. The transport underneath is request/poll (the
 * same shape the whole plugin family uses), so it adds a poll of latency per
 * round trip and asks nothing of the network but ordinary requests.
 *
 * @module tunnelClient
 */

/** @typedef {(path: string, body?: Record<string, any>) => Promise<{ok: boolean, response?: any, error?: string}>} Call */

/** @param {Call} call @param {string} name */
export const openTunnel = (call, name) => call(`/tunnel/${name}/open`, {});

/**
 * Send bytes into the tunnel — they reach the endpoint's socket unchanged.
 * @param {Call} call @param {string} name @param {string} id
 * @param {Buffer | Uint8Array | string} data
 */
export const sendTunnel = (call, name, id, data) =>
  call(`/tunnel/${name}/send`, { id, data: Buffer.from(data).toString("base64") });

/** @param {Call} call @param {string} name @param {string} id */
export const pollTunnel = (call, name, id) => call(`/tunnel/${name}/poll`, { id });

/** @param {Call} call @param {string} name @param {string} id */
export const closeTunnel = (call, name, id) => call(`/tunnel/${name}/close`, { id });

/** @param {number} ms */
function defaultWait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Pump a stream through the tunnel until either side ends.
 *
 * Two loops share a `done` flag:
 *   - the **reader** consumes `input` one chunk at a time and `send`s each on —
 *     `for await` serialises it, so bytes reach the endpoint in order and a slow
 *     send applies backpressure rather than racing;
 *   - the **poller** `poll`s the endpoint and writes whatever came back to
 *     `output`.
 * When either the local stream ends or the endpoint closes, the tunnel is closed
 * once and both loops stop.
 *
 * `input`/`output` are separate on purpose: a process has a readable stdin and a
 * writable stdout, not one duplex, and a socket satisfies both.
 *
 * @param {Call} call
 * @param {string} name
 * @param {{ input: NodeJS.ReadableStream, output: NodeJS.WritableStream }} streams
 * @param {{ wait?: (ms: number) => Promise<void>, pollMs?: number, log?: (m: string) => void }} [options]
 * @returns {Promise<{ok: true, closed: string} | {ok: false, error: string}>}
 */
export async function pipeTunnel(call, name, { input, output }, { wait = defaultWait, pollMs = 25, log = () => {} } = {}) {
  const opened = await openTunnel(call, name);
  if (!opened.ok) return { ok: false, error: opened.error ?? "could not open the tunnel" };
  const id = opened.response?.id;
  if (!id) return { ok: false, error: "the tunnel opened without an id" };

  let done = false;
  let why = "";
  const finish = async (/** @type {string} */ reason) => {
    if (done) return;
    done = true;
    why = reason;
    await closeTunnel(call, name, id).catch(() => {});
    log(`[tunnel] ${name} closed: ${reason}`);
  };

  // Local → endpoint. `for await` awaits each send before pulling the next
  // chunk, which keeps order and backpressure both correct.
  const reader = (async () => {
    try {
      for await (const chunk of input) {
        if (done) break;
        const sent = await sendTunnel(call, name, id, chunk);
        if (!sent.ok) return finish(sent.error ?? "send failed");
        if (sent.response?.closed) return finish(sent.response?.error ?? "endpoint closed");
      }
    } catch (error) {
      return finish(`input error: ${error instanceof Error ? error.message : error}`);
    }
    return finish("input ended");
  })();

  // Endpoint → local. Poll, write what came back, stop when it closes.
  const poller = (async () => {
    while (!done) {
      const polled = await pollTunnel(call, name, id);
      if (!polled.ok) return finish(polled.error ?? "poll failed");
      if (polled.response?.data) output.write(Buffer.from(polled.response.data, "base64"));
      if (polled.response?.closed) return finish(polled.response?.error ?? "endpoint closed");
      await wait(pollMs);
    }
  })();

  await Promise.race([reader, poller]);
  await finish("pump ended");
  await Promise.allSettled([reader, poller]);
  return { ok: true, closed: why };
}
