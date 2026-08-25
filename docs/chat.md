# A chat plugin

**Status: the plugin is built; the sealed relay to a non-peer (below) is designed.**
Short messages between admitted peers work today, over an encrypted arrival.
Reaching someone who is *not* a peer — sealed so the relay cannot read it —
depends on the relay, which is not built.

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

## Reaching someone who is not a peer

The useful half is talking to something with no identity here: a script, a device,
someone who has not been admitted. The obvious answer is an inbox that accepts
unauthenticated messages. That answer is rejected below; this is the better one.

**Give the stranger a relay, not a listener.** Someone who cannot be
authenticated talks to a machine you chose to expose; that machine holds a peer
relationship with the destination and passes the message on. The destination
never opens a port to strangers and never parses input from one — its code only
ever handles peers.

That is a genuine reduction rather than a relabelling. An arbitrary inbox puts
unauthenticated parsing in *every* node; a relay puts it in one you picked, and
the blast radius of a bug in it is that machine.

It costs an extra node, which is the honest overhead. In exchange the same
mechanism becomes reusable: the relay is a peer doing a peer's job, so it is
bounded by `RELAY` and by whatever the destination will accept from it, rather
than by new machinery.

### Sealed to the destination, so the relay cannot read it

A relay that carries text can read text. The fix is to seal the message to the
destination before handing it over, which turns the relay into a carrier rather
than a reader — and, as recorded in the tunnel design, carrying what you cannot
read is safer for the one carrying it too.

This is the case that earns the **second key type**. Identities here are Ed25519,
which signs and cannot encrypt, so sealing requires each peer to publish an
X25519 encryption key in its record, signed by its identity key. That is the
standard arrangement — age and Signal both do it — and Node performs X25519 ECDH
directly, so no curve conversion or field arithmetic is involved.

**And it would be the most dangerous code in this project.** ECDH, HKDF and an
AEAD is a standard composition and still a bespoke assembly, in a codebase whose
safety argument is that it is small enough to read, written by whoever is
quickest to volunteer. If built it should be the thing reviewed hardest, and it
should not be built before there is a relay to need it.

The ordering that follows: relay first, sealed messages second, and a chat that
works between admitted peers before either.

## Considered and rejected: an inbox for unauthenticated senders

The first design accepted messages directly from things that are not peers,
shown by source address rather than name, in a second view, on a second port.
The reasoning is kept because it applies to *any* unauthenticated input, and
because the relay above has to honour most of it anyway.

### Why it is a phishing surface

Three things together: a chat, senders nobody authenticated, and the habit of
passing pairing URLs through it. A stranger writes *"here is your pairing URL"*,
a person pastes it into T3, and the five-minute expiry does not help because the
human did the work. It is the one place in this design where the payload and the
channel make each other worse.

### The rules it would have needed, which the relay still needs

**A separate place, not a label.** A label on a busy screen is a thing people
stop seeing; a different view is not. The same reasoning as showing a competing
key on its own line rather than as a flag.

**Never resolved to a name.** A name is what makes a message look vouched for.
Something relayed from an unidentified party is shown as unidentified, even when
a peer is admitted at the address it came from — *especially* then, because that
is the case a person would misread.

**Never actionable.** No clickable links, nothing that shortens the path between
an unauthenticated message and a redeemed credential. The text is text.

### And the part the relay makes unnecessary

**Its own port.** A listener is the unit of firewall policy, so an inbox for
strangers belongs on a socket of its own, filtered separately from the port peers
use. That rule is right and it still holds for the *relay* — but a destination
running no such listener needs no such rule.

**Source allow and deny lists.** In the manner of `iptables`, and worth two
qualifications. They bound reachability rather than identity: a rule about
`192.168.1.0/24` concerns whoever holds those addresses today, which turns
"anyone" into "anyone in the house" and is not authentication. And they are the
weaker of two options wherever an OS firewall exists — earning their place on
Windows, where there is no `iptables`, and for visibility, since a list the page
can show is a list someone will read. If built: CIDR never string patterns
(`192.168.1.*` also matches `192.168.10.5` and ignores IPv6), deny before allow,
default deny.

These now describe the **relay's** exposure rather than every node's, which is
the whole gain.

## What this is not

**Not durable.** No history, no sync, no delivery receipts. A message not read
before a restart is gone, and building otherwise would mean a store, which would
mean the credential-free invariant needs an exception.

**Not a transport.** Tunnels carry bytes to a service; this carries text to a
person. Anything that wants a protocol should use the other one.

**Not authenticated end to end when a relay is involved.** A relay vouches for
delivery, never for content — it says *somebody gave me this for you*, and who
that somebody was is exactly what it cannot tell you. Stated rather than implied,
because every other input in this project carries an identity.

## Open

- **Should a peer be able to send to a peer it has not admitted?** Symmetric
  admission is the obvious answer and it makes the first message impossible —
  which is the case the relay exists to cover, so the two answers have to agree.
- **Notification.** A message nobody polls for is a message nobody reads. Polling
  is the plugin shape today; a machine that only checks when a human opens a page
  will be a machine that misses things.

