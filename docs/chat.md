# A chat plugin

**Status: designed, not built.**

## Why this one is not already solved

Most things this project reached for turned out to exist. Tailscale carries
files between machines you own, T3 mints short-lived pairing tokens and shows
them as a QR code, and both do it better than a peer fabric would.

A message between two machines is the exception. Nothing here provides one, and
the cases are ordinary: hand a pairing URL to the machine that needs it, say
*"the build box is going down"*, ask a peer for something it has not published.
It is small, and it is the kind of small that people actually use.

## Shape

**A plugin**, because it is neither presence nor discovery, and because someone
running a headless relay should not inherit an inbox.

**Memory only.** Messages live in the process and die with it. Nothing reaches
the directory file, which keeps the credential-free invariant true for a feature
whose obvious first use is passing somebody a pairing URL. Restarting the daemon
is how you clear it, and that is a feature rather than a limitation.

**Its own capability.** `chat` says nothing about `tunnel:acp` and nothing about
`directory`. A peer you will exchange messages with is not thereby a peer that
may drive your agent.

**Bounded.** A ring of at most N messages per conversation, each capped in size,
each expiring by age. An inbox that grows until memory runs out is a way for a
peer to end the daemon, and one that keeps everything is a log nobody meant to
keep.

Routes follow the tunnel plugin's shape — `send`, `poll`, `clear` — so this needs
no change to what a plugin is.

## Two inboxes, not one

The interesting half is accepting messages from things that are **not peers**: a
script, a device with no identity, something on the LAN. Useful precisely when
you cannot authenticate the other end.

That is also what makes it dangerous, and the danger is specific rather than
theoretical. Put together a chat, senders nobody authenticated, and the habit of
passing pairing URLs through it, and you have built a phishing channel: a
stranger writes *"here is your pairing URL"*, a person pastes it into T3, and the
five-minute expiry does not help because the human did the work.

So:

| | Peers | Arbitrary sources |
| --- | --- | --- |
| Identity | a key, verified | an address, observed |
| Default | off until `chat` is granted | **off entirely** |
| Shown | by peer name | by address, never a name |
| Where | the inbox | **a separate inbox** |
| Rendering | plain text | plain text, never actionable |

**A separate place, not a label.** A label on a busy screen is a thing people
stop seeing; a different view is not. This is the same reasoning as showing a
competing key as its own line rather than a flag on an existing one.

**Never resolved to a name.** A name is what makes a message look vouched for. An
unauthenticated sender that arrives from `192.168.1.40` is displayed as
`192.168.1.40`, even when a peer is admitted at that address — *especially* then,
because that is the case a person would misread.

**Never actionable.** No clickable links, no "open this", nothing that shortens
the path between an unauthenticated message and a redeemed credential. The text
is text.

## Its own port

Arbitrary sources listen on a **separate port** from peer traffic, because a
listener is the unit of firewall policy: a rule can only distinguish two things
by the port they arrive on. One port for peers, another for strangers, and
`iptables` can admit the second only from the household LAN without touching the
first.

That is the general rule this project keeps rediscovering — the control API is on
its own socket for the same reason, and tunnel routes should be, too. Enforcement
by socket cannot be broken by editing a conditional.

### Source lists, and their honest weight

Allow and deny lists in the manner of `iptables` are the right size for what they
do, with two qualifications.

**They bound reachability, not identity.** A rule about `192.168.1.0/24` is a
rule about whoever holds those addresses today. It turns "anyone" into "anyone in
the house", which is worth having and is not authentication.

**They are the weaker of two options where both exist.** On Linux the OS firewall
is better tested than anything written here, and the listener already binds per
interface. An app-level list earns its place on **Windows**, where there is no
`iptables` to lean on, and for **visibility** — a list the page can show is a list
someone will read.

If built: **CIDR, never string patterns.** `192.168.1.*` also matches
`192.168.10.5` and says nothing about IPv6. Deny checked before allow, and
default deny, so an empty configuration admits nobody rather than everybody.

## What this is not

**Not durable.** No history, no sync, no delivery receipts. A message not read
before a restart is gone, and building otherwise would mean a store, which would
mean the credential-free invariant needs an exception.

**Not a transport.** Tunnels carry bytes to a service; this carries text to a
person. Anything that wants a protocol should use the other one.

**Not authenticated when the sender is not a peer**, which is stated here rather
than implied because every other input in this project is.

## Open

- **Should a peer be able to send to a peer it has not admitted?** Symmetric
  admission is the obvious answer and it makes the first message impossible,
  which is exactly the case an unauthenticated inbox exists to cover.
- **Notification.** A message nobody polls for is a message nobody reads. Polling
  is the plugin shape today; a machine that only checks when a human opens a page
  will be a machine that misses things.
- **Whether the arbitrary inbox should exist at all**, or whether the honest
  answer is that a stranger who wants to reach you can be admitted first.
