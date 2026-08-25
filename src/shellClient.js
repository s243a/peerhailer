/**
 * The caller side of the shell plugin: driving a shell on another machine.
 *
 * The plugin is the server half — it declares the routes and spawns the shell.
 * This is what a peer holding `shell:<name>` uses to actually reach one: open a
 * session, send keystrokes, poll for output, close. It is deliberately thin over
 * a `call(path, body)` function (a `callPeer` bound to a peer), so it carries no
 * transport of its own and is testable without a network.
 *
 * Two ways to drive it, and the low-level one is the point for an agent. An
 * automation whose every step is a separate, stateless invocation cannot hold an
 * interactive terminal — but it *can* hold a session id and drive it a call at a
 * time: `open` once, then `send`/`poll` across as many later invocations as the
 * work takes, `close` at the end. State (a working directory, an environment)
 * survives between steps because the remote shell does. `exec` is the
 * convenience wrapper over that, for a single command whose output you want back
 * in one go.
 *
 * @module shellClient
 */

/** @typedef {(path: string, body?: Record<string, any>) => Promise<{ok: boolean, response?: any, error?: string}>} Call */

/** @param {Call} call @param {string} name */
export const openShell = (call, name) => call(`/shell/${name}/open`, {});

/**
 * Send bytes to the shell's stdin. The text is sent exactly as given — the
 * caller owns the newlines, because whether a line ends with Enter is a
 * decision (a command to run) not a default.
 * @param {Call} call @param {string} name @param {string} id @param {string} text
 */
export const sendShell = (call, name, id, text) =>
  call(`/shell/${name}/send`, { id, data: Buffer.from(text).toString("base64") });

/** @param {Call} call @param {string} name @param {string} id */
export const pollShell = (call, name, id) => call(`/shell/${name}/poll`, { id });

/** @param {Call} call @param {string} name @param {string} id */
export const closeShell = (call, name, id) => call(`/shell/${name}/close`, { id });

/**
 * Run one command and return its output — open, send, poll to completion, close.
 *
 * A byte stream carries no "the command finished" signal, so this appends a
 * sentinel `echo` after the command and reads until the sentinel comes back:
 * everything before it is the command's output. The pipe does not echo stdin, so
 * the sentinel appears only from the `echo` running, not from the line being
 * typed. Bounded by `maxPolls`, so a command that never returns the sentinel
 * ends the loop rather than hanging.
 *
 * @param {Call} call
 * @param {string} name
 * @param {string} command
 * @param {{ wait?: (ms: number) => Promise<void>, pollMs?: number, maxPolls?: number, token?: string, raw?: boolean }} [options]
 * @returns {Promise<{ok: true, output: string, complete: boolean} | {ok: false, error: string}>}
 */
export async function execShell(call, name, command, { wait = defaultWait, pollMs = 150, maxPolls = 200, token, raw = false } = {}) {
  const opened = await openShell(call, name);
  if (!opened.ok) return { ok: false, error: opened.error ?? "could not open a shell" };
  const id = opened.response?.id;
  if (!id) return { ok: false, error: "the shell opened without an id" };

  // A sentinel the command's own output is very unlikely to contain, so finding
  // it means the command finished, not that it printed the word.
  const mark = token ?? `HAIL_DONE_${Math.random().toString(36).slice(2, 12)}`;
  // The command's bytes never touch a shell parser on the way to the sentinel:
  // they are base64 (no spaces, quotes, or newlines of their own), decoded and
  // run in a fresh `sh` on the far side, so an unbalanced quote, a trailing
  // backslash, or an embedded newline in the command cannot bleed into the
  // `echo` that marks completion. Needs `base64` and `sh` on the target — both
  // coreutils, present anywhere this runs. `raw` sends the command unwrapped for
  // the rare case a bashism or the interactive shell's own state is wanted.
  const b64 = Buffer.from(command).toString("base64");
  const line = raw ? `${command}\necho ${mark}\n` : `printf %s ${b64} | base64 -d | sh\necho ${mark}\n`;
  const sent = await sendShell(call, name, id, line);
  if (!sent.ok) {
    await closeShell(call, name, id);
    return { ok: false, error: sent.error ?? "could not send the command" };
  }

  let out = "";
  let complete = false;
  for (let i = 0; i < maxPolls; i += 1) {
    const polled = await pollShell(call, name, id);
    if (!polled.ok) {
      await closeShell(call, name, id);
      return { ok: false, error: polled.error ?? "the shell stopped answering" };
    }
    if (polled.response?.data) out += Buffer.from(polled.response.data, "base64").toString();
    const at = out.indexOf(mark);
    if (at !== -1) {
      // Everything up to the sentinel is the command's output; drop the sentinel
      // line and a trailing newline the shell left before it.
      out = out.slice(0, at).replace(/\n$/, "");
      complete = true;
      break;
    }
    if (polled.response?.closed) {
      complete = true;
      break;
    }
    await wait(pollMs);
  }

  await closeShell(call, name, id);
  return { ok: true, output: out, complete };
}

/** @param {number} ms */
function defaultWait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
