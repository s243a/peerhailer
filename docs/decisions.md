# Decisions

Choices that would otherwise be re-litigated, with the reasoning that produced
them and what would change them back.

## JavaScript with JSDoc, not TypeScript

**Decided.** The library is JavaScript, annotated with JSDoc, and type-checked
by `tsc` in strict mode. `npm run types` emits `.d.ts` files for anything
embedding it.

TypeScript is the better default for most projects, and this is not an argument
against types. The checking here *is* TypeScript's: `strict`,
`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, the same inference and
the same errors, on the same compiler. Turning it on found 49 errors on the
first run, two of which were latent bugs where a `null` return was assigned
straight into the directory. The question was never whether to have types.

The question was whether to have a **build step**, and for this program the
answer is no.

**The file you edit is the file that runs.** This daemon's failure mode is
silence: nothing answers, which is also what working looks like. Diagnosing that
usually means being on the machine, opening the file, changing something and
restarting. A compile step in that loop is a step in the wrong place, and source
maps are a poor substitute for a stack trace that points at the line you are
reading.

Three smaller consequences follow from the same property. `node --test` runs the
shipped files, so tests cannot pass against a build that differs from what is
published. There is nothing to install before the daemon runs, on machines whose
whole appeal is that they are small and already there. And an npm release is the
source, so what someone reads is what executed.

**What this costs.** JSDoc is more verbose than type annotations, and generics
or conditional types are awkward enough that the code avoids them. That is
affordable here because this is records, maps and HTTP handlers rather than a
type-level library — but it is a real cost, not a free lunch.

**What would change it.** If the covert transport arrives and brings a key
schedule and handshake state machine with it, the type-level work may stop being
awkward and start being necessary. Converting is cheap while the annotations are
already correct: JSDoc is most of the labour of a port, and the rest is
mechanical. It gets more expensive the longer it waits, which is worth
remembering rather than discovering.

## The daemon is optional

**Decided.** Every CLI command works against the stored directory with nothing
running.

A tool for reaching machines that must itself be running before it will answer
questions fails exactly when it is needed — during an outage, on a box that has
just rebooted, when something is already wrong. The daemon exists to *answer*
hails from elsewhere, not to be the only way in to what this machine knows.

## The directory is a file you can read

**Decided.** Plain JSON under `~/.config/peerhailer/`, written atomically.

The same reasoning. When nothing answers, the first useful question is "what
does this machine actually believe", and the fastest answer is `cat`. A format
requiring the tool to interpret it makes the tool a prerequisite for debugging
the tool.

Atomic because the alternative is a directory truncated by a crash mid-write,
which is a machine that has quietly forgotten every peer it knew.

## Identity is a key; the name is a label

**Decided.** Every machine holds an Ed25519 keypair, generated on first use, and
records are signed. A name identifies a peer to a person; the key identifies it
to the software.

Names cannot carry the weight. Two machines may choose the same one, a peer may
rename itself tomorrow, and a name arriving over the network is a claim anyone
could make. Without a key, an address in a record is a stranger's suggestion
about where to find your machine.

Generated on first use rather than asked for, because a setup step people skip
protects nothing. The private key lives beside the directory, not in it, at mode
600 — the directory is a file people are invited to read and paste into bug
reports.

Ed25519 from Node's own crypto: small keys, small signatures, no dependencies,
and no parameters to get wrong.

## A peer is admitted into a profile

**Decided.** `trusted` by default, and it grants hailing and directory access —
not everything.

Admission is not one thing. "I know this machine exists" and "this machine may
use my services" are different grants, and collapsing them makes every peer you
can name a peer that can act. Relaying in particular spends this machine's
bandwidth and exposure on someone else's traffic; enrolment changes how it is
reachable. Both are decisions, not consequences of being known.

An unknown profile name resolves to `trusted` rather than to nothing. Failing
shut would mean a peer that silently stops working after a config edit or a
version bump — a failure indistinguishable from a network problem, which is the
worst way for this to break.
