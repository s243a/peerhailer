# A files plugin

**Status: built.** A peer holding `files:<name>` can list, read and — when the
share is declared writable — write files in a named **share** on this machine,
over an encrypted arrival. Local directories and HTTP origins are supported as
backends today.

## What it is

A **share** is a named place this machine will serve files from. A peer names a
share and a path; it never learns the disk layout, the command, or which backend
sits behind the name. It is the "hand that one file to that peer" case — a config,
a key, a pairing URL, a small archive — not a directory sync (that is Tailscale or
rsync, and better at it). Bytes cross as base64 in a request/response, capped at
`MAX_FILE` (8 MiB): this is a channel for small-to-moderate files, not a stream.

Routes follow the tunnel and chat shape — `list`, `stat`, `get`, `put` under
`/files/<name>/` — so it needs no change to what a plugin is. Its own capability,
`files:<name>`, says nothing about `tunnel:*` or `directory`: a peer you exchange a
file with is not thereby a peer that may drive your agent.

## Security is the job

- **No escape.** A caller path is resolved *inside* the share root and re-checked
  against the real (symlink-followed) root. A `..`, an absolute path, a drive
  letter, a `~`, or a symlink that points out of the share is **refused, not
  clamped**. A share is a subtree, never a foothold on the rest of the disk.
- **Read-only by default.** `put` exists only for a share declared `writable`, and
  a write cannot escape the root either.
- **Bounded.** File size (`MAX_FILE`) and listing length (`MAX_ENTRIES`) are
  capped, so a peer cannot make this machine read a huge file into memory or
  enumerate the world.
- **Encrypted arrival**, like chat: the fabric cannot see what a file holds, so it
  must not carry one in the clear.

## Backends

A share's backend is where the bytes actually live, behind the same routes:

| backend | list | get | put | notes |
| --- | --- | --- | --- | --- |
| **local** | ✓ | ✓ | ✓ (writable) | a directory subtree; the default |
| **http** | — | ✓ | ✓ (writable) | fronts a URL store; plain HTTP has no listing, so `list` is refused cleanly |

The backend interface is small (`supports`, `list`, `get`, `put`), so another
protocol is a new adapter, not a new plugin. Note the project's zero-dependency
rule: **SMB and SFTP would each need a third-party client library**, so they are
deliberately *not* included — add one only if that trade is accepted. FTP is
implementable in raw sockets and could be added without a dependency.

## Declaring a share

```sh
hail shares add docs /srv/docs                      # read-only local directory
hail shares add drop /srv/drop --writable           # a writable drop box
hail shares add repo --backend http --base https://host/files/   # front an http store
hail shares list
hail shares remove docs
```

Then grant a peer the capability (no built-in profile does): add `files:docs` to a
profile and admit the peer with it.

## Driving a peer's share

```sh
hail files <peer> docs list [path]            # a directory listing
hail files <peer> docs get report.pdf ./out.pdf   # download to a local file (or stdout)
hail files <peer> drop put notes/today.md ./today.md   # upload (needs a writable share)
```

## Not built

- The sealed relay to a non-peer (see `docs/chat.md`) applies here too and is not
  built: a share is served to admitted peers only.
- A **Files** section on the daemon `--ui` page browses a peer's share (secure
  mode): pick a peer and a share, navigate directories, download a file, upload one
  to the current directory. It proxies to the peer over the same signed `callPeer`
  path — the peer's plugin still enforces every bound, so the page trusts nothing
  new. A more permissive **mount** mode (exposing a share to external tools) is the
  next step; see below.

## Mounting for external tools (built)

The page's explorer is the *most secure* surface: nothing leaves the browser, and
each read or write is an explicit click. The *permissive* mode lets the **operating
system mount** a share so any external tool uses it as ordinary files. From the
Files section, **Mount for external tools** starts a small **loopback WebDAV**
bridge over the share and hands back a `http://127.0.0.1:<port>/` URL with per-OS
instructions (macOS Finder → Connect to Server; Windows → Map network drive; Linux
→ davfs2/rclone). Unmount from the same list.

WebDAV is chosen because it is HTTP — **no dependency**, and every OS mounts it
natively; a real FUSE mount would need a binding, against the zero-dep rule. Each
verb (`OPTIONS`, `PROPFIND`, `GET`, `PUT`) is translated to the plugin's own routes
over the signed `callPeer` path, so the peer still enforces every bound. Only the
verbs the plugin supports are offered — `DELETE`, `MKCOL` and `LOCK` answer `501`
rather than pretending, so a mount is browse + read + write-file, not a full POSIX
filesystem (and Windows/macOS write may want `LOCK`, which is not implemented).

**A mount is a genuine escalation.** It is reachable by *every* local process, not
one reviewed click — so it binds loopback only, is operator-started on the control
door, and writes still depend on the remote share being writable (a `PUT` to a
read-only share is refused upstream and surfaces as `403`).
