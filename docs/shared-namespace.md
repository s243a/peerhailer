# A namespace of what peers share

**Status: designed, not built.** Written to be reviewed alongside the code, not
ahead of it. It depends on an open decision — see "What this waits on".

## The problem

The directory answers *who exists* and *where they answered*. That is presence,
and presence alone is inert: the GUI shows four machines and their addresses,
and there is nothing to do with any of them. What is missing is a way for a peer
to say **what it will answer for** — and for that to be as reviewable as the
peer list itself.

The motivating case is concrete. A T3 Code instance on one machine needs a token
to control another. Copy-and-paste is how that happens now, which means the
token crosses a clipboard, a chat window, or a screenshot — every one of them
snoopable and none of them revocable. Handing it over an authenticated peer link
is strictly better. The problem is that "hand over a token" is exactly the thing
this project has spent its design refusing to do.

## Keeping the directory credential-free

`grants.js` states the invariant: *the directory deliberately holds no
credentials — a record says a machine exists and where it answered, and nothing
in it opens a door.* A namespace containing `token` is a door, and putting one
in a replicated record would undo the property that makes records safe to gossip.

The resolution is that **leaves are offers, not values**. A leaf says *this
machine will answer for this, if you are allowed to ask*. Reading one is a
request, answered at the moment it is asked — a freshly minted grant, a plugin
call, a value the holder produces on demand. Nothing about the answer is stored
by the reader or carried in any record. The directory keeps saying "this machine
exists"; the tree adds "and this is what it will answer for", which is a
statement about capability rather than a secret.

That distinction is what keeps a stolen directory worthless. Reading a directory
tells an attacker what exists. It never tells them a value, and it never lets
them ask for one, because asking is authenticated and authorised separately.

## Addressing: by identity, not by position or name

The obvious spelling is `peer[1].token`. It should not be, for the same reason
blocking prefers keys over names: position and names are both mutable, and an
address that silently comes to mean a different machine is a way to hand the
wrong peer something.

```
self/
  name, fingerprint                 any admitted peer
  services/
    t3/token                        capability t3:token:read, plus a grant

peers/<fingerprint>/
  name, addresses                   what the directory already holds
  services/…                        learned by asking, never stored
```

Names stay as labels for humans. Resolution is by fingerprint, and a name that
resolves to an unexpected key is an error rather than a redirect.

## Visibility is its own capability

Two states — readable or not — force a bad choice: either every admitted peer
learns your whole topology, or nothing is discoverable without out-of-band
knowledge. Three states avoid it:

| State | The peer can |
| --- | --- |
| **hidden** | not tell the leaf exists |
| **listed** | see that it exists, not its value |
| **readable** | ask, and be answered |

Splitting *list* from *read* is what lets `trusted` enumerate your services while
`known` sees only that a machine is there. It also makes the GUI honest: a
listed-but-not-readable leaf can be shown greyed, so you can see what a peer is
withholding from you and decide whether to ask for it.

The default for anything a plugin declares should be **hidden**, so that
installing a plugin does not silently widen what the world can see about you.

## Plugins contribute subtrees

No new machinery. A plugin already declares the capability its routes require;
it now also declares the subtree it contributes, and the same capability gates
both. No plugin, no subtree — which preserves the property that people do not
inherit features they did not ask for.

It follows that the tree is not a key-value store the daemon owns. The daemon
owns the shape and the gating; plugins own the leaves. Nothing is written into
the tree from outside — a peer cannot cause a leaf to appear on your machine.

## Reading, and watching

T3 polling a plugin for events is the same question from the other end: a reader
wanting to know when something changes without asking repeatedly. Two shapes,
and the choice is not obvious:

- **Read on demand.** Simple, stateless, and every read is an authorisation
  point. Costs a round trip per question, and a poller re-authorises constantly.
- **Watch a subtree.** One authorisation, then changes flow. Cheaper, but
  authorisation becomes a thing with a lifetime rather than an event, and "you
  may watch this" is a longer-lived permission than "you may read this once" —
  closer to a credential than this design usually allows.

A middle option worth considering: watches are grants, so they expire and are
subject-bound like everything else, and a watcher renews rather than holds.

## What this waits on

**Whether admitting a candidate grants `trusted`.** The GUI currently warns that
a peer naming another tells you it exists, not that you should talk to it — and
then its admit button assigns `trusted`, which would enumerate every service
here. Until that is settled, the tree's default visibility cannot be settled
either, because they are the same question asked twice.

## Not built

Nothing here exists in code. It is written down so a reviewer can argue with the
shape before it hardens, and so the credential-free invariant is defended
explicitly rather than quietly broken later.
