# NostrGit client ordering and convergence

This behavior follows
[NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md),
[NIP-09](https://github.com/nostr-protocol/nips/blob/master/09.md),
[NIP-22](https://github.com/nostr-protocol/nips/blob/master/22.md), and
[NIP-34](https://github.com/nostr-protocol/nips/blob/master/34.md),
[NIP-39](https://github.com/nostr-protocol/nips/blob/master/39.md), and
[NIP-65](https://github.com/nostr-protocol/nips/blob/master/65.md).

The client assumes no causal ordering from relays, timestamps, relay
responses, or event arrival. An issue, one of its comments, and that
comment's parent may become visible in any order and may be returned by
different repository relays.

## Collection algebra

The event's `tags` array is an ordered wire sequence because its exact order is
part of the signed NIP-01 serialization. The client never rewrites a received
event. Interpretation of that sequence uses narrower types:

- `relays`, `clone`, `web`, `maintainers`, `p` mentions, `t` labels, filter
  values, and deletion targets are sets. Duplicates and permutation have no
  meaning. Sorting is only canonical presentation and cannot imply precedence.
- `d`, `name`, `description`, `subject`, `a`, `c`, `branch-name`,
  `merge-base`, marked `r/euc`, `K`, and `k` are optional scalar fields.
  Repeating one value is harmless; distinct values are ambiguous and the event
  is rejected for that use.
- NIP-22 `E` and `e` are single `(event ID, author)` relations for this
  client's event-scoped comments. Conflicting tuples are invalid. Uppercase
  and lowercase relations remain distinct even if both name the same event.
- Marked patch `e/reply` tags are single parent relations. A status `e/root`
  is a single root-ID relation. Other `e` tags cannot win by tag position.
- Verified events are a map keyed by immutable event ID. Addressable versions
  are reducer input grouped by `(kind,pubkey,d)`.
- Comments and patches are graphs. Statuses and addressable versions are
  reducer input sets. Neither becomes a list merely because JavaScript stores
  it in an array.
- A kind-30618 state is a map from fully qualified ref names to commit IDs,
  plus an optional scalar `HEAD`. Publishing state emits a complete fetched
  branch/tag snapshot.
- Relay endpoints, branches, tags, and Git tree entries are sets/maps.
  `projects.list`, Git commit ancestry, tag-object chains, and a newly uploaded
  patch series are the true ordered sequences.

## Identity and causality

- Event IDs are immutable identities. Every relay event is checked for a
  matching ID and a valid Schnorr signature before it enters client state.
- Events timestamped more than five minutes in the future are not cached or
  reduced. This bounds clock skew without letting a future-dated replacement
  or status suppress valid state indefinitely.
- A kind `1621` issue belongs to a repository through its exact NIP-34 `a`
  address.
- A kind `1111` comment belongs to an issue through its uppercase NIP-22
  `E/K/P` root tags.
- Its immediate parent is identified only by lowercase `e/k/p` tags.
- For scalar `p`, `P`, and `t` tags, only element 1 is the semantic value.
  Relay hints or other later elements cannot satisfy an author, owner, root,
  or label check.
- A kind `1617` patch set is ordered only by marked NIP-10 `e` reply tags:
  the root has `["t", "root"]`, and each later patch replies to its immediate
  predecessor. Series members must have the exact repository address, but
  NIP-34 does not require every revision or series member to use the original
  root author's pubkey. If a reply tag supplies a parent-author field, it must
  match the actual parent. Relay delivery and timestamps never establish
  patch order.
- `created_at` never establishes parentage. It is used only to order siblings,
  with event ID as the deterministic tie-breaker.
- Status kinds are the explicit NIP-34 set `1630`, `1631`, `1632`, and `1633`;
  the client does not interpret an integer interval as a semantic kind group.
- Replaceable repository announcements and states use NIP-01 replacement
  ordering per exact `kind:pubkey:d` coordinate: newest `created_at`, then the
  lowest event ID for an exact tie. Older cached versions do not become current
  merely because the winning version was deleted by exact event ID.

## Replacement and deletion

- Kinds `30617` and `30618` are addressable events. The client retains versions
  for convergence but selects exactly one NIP-01 winner per coordinate before
  applying visibility rules.
- Publishing a new `30617` version preserves the connected publisher's
  non-form tags (including `maintainers`, `r`, `t`, and `u`) from that
  publisher's current, non-deleted coordinate. It never copies authority tags
  from another publisher's announcement.
- Kind `5` deletion requests are retained as tombstones, not treated as a
  transient relay response. The target and request may arrive in either order.
- An `e` deletion applies only when the request author is also the target event
  author. An `a` deletion likewise applies only to the author's exact
  addressable coordinate and only to versions with `created_at` less than or
  equal to the deletion request's timestamp.
- Every `a` tag on a kind `5` event is a deletion target under NIP-09; it is
  never harmless repository context. Deleting a comment or star therefore
  emits only its exact `e` target and does not copy the repository address.
- Deleting a kind `5` deletion request has no effect. A missing deletion request
  in a later relay response does not resurrect anything already tombstoned.
- Deleted issues, patches, pull requests, statuses, announcements, and states
  are hidden. A deleted comment becomes a content-free tombstone in its
  original tree position, allowing non-deleted descendants to remain visible.
- The optional `k` tags on deletion requests are hints. Authorization comes
  from comparing the signed request pubkey with the actual target pubkey.

## Out-of-order convergence

1. Query repository announcements and issue roots.
2. Query comments using every known root event ID.
   If a comment reached a relay before its issue, it is discovered as soon as
   a later poll discovers the issue; no arrival-order assumption is involved.
   Every message in a kind `1617` patch set is also a comment scope, so comments
   attached to a later patch are queried even though only the first patch is
   the proposal/status root.
   Kind `1619` PR updates are discovered by their uppercase `E` root reference
   in the same way. An update is accepted only from the PR author and only when
   its `E/P/a` references and tip commit are valid.
3. Merge verified events by event ID with the previously known set. A partial
   relay response never replaces the known set.
4. Retain comments whose parents are not present, but do not render them yet.
5. On every later poll, re-evaluate all retained comments. A child becomes
   renderable as soon as its complete chain to the issue root is present.
6. Build `parent ID -> children` adjacency lists, sort siblings, and render a
   depth-first traversal. Every nesting depth remains visually distinct; deep
   threads scroll horizontally instead of being flattened. Relay response
   order is discarded.
7. Query kind `5` requests by every known target ID and address, merge them into
   the same cache, and reapply tombstones. Thus a deletion received before its
   target takes effect when the target is discovered, and a deletion received
   later removes or tombstones an already-rendered target.
8. Build patch sets from their reply graph after all currently known kind
   `1617` events have been merged. A deleted intermediate patch remains as a
   content-free graph tombstone so later patches do not lose their position.
   If multiple messages reply to the same parent, the UI identifies a branched
   graph and shows the parent event IDs; it does not turn sibling timestamps
   into a fictional total patch order.
9. Treat a kind `1618` event's optional `e` root-patch reference as an
   unresolved relationship until the patch arrives. The referenced ID drives
   exact patch, status, comment, and deletion queries immediately, so a PR,
   patch, and closing status converge in any arrival order.

The client polls every 20 seconds while visible and immediately after the
page becomes visible again. Manual refresh uses the same merge path. Comment
draft text and cursor selection survive an automatic refresh.

Primary author lines display three independent facts: the human actor, whether
the event came from GitHub or Nostr, and which key signed it. The deployment's
public bridge key is an explicit client trust anchor, so an arbitrary event
cannot label itself as bridge-signed merely by copying a `gh_user` tag. Raw
event IDs and signing keys remain available under Technical details.

For visible non-bridge authors, the client also queries kind `10011` NIP-39
external-identity snapshots. Kind `10011` is regular replaceable: the client
first selects exactly one winner per author by newest `created_at`, then lowest
event ID, and only then applies deletion. It never unions claims from different
versions or resurrects an older version when the winner was deleted. A GitHub
claim is displayed as a link beside the existing byline only after GitHub's
Gist API confirms that the named account owns a single-file Gist whose content
is the exact NIP-39 proof for that author's npub. Relay and GitHub verification
run after repository activity is rendered; failure leaves the ordinary Nostr
byline unchanged. This assertion is optional presentation metadata. It never
authorizes a bridge crossing, selects a GitHub token, or creates an account
link. Before querying kind `10011`, the client independently reduces each
visible author's kind `10002` NIP-65 relay-list snapshot and its exact
deletions, then adds write-capable personal relays to the collaboration-relay
fallback. NIP-46 signer transport relays are unrelated and are never used for
this inference. To bound background work deterministically, one refresh
considers the lexically first 256 visible author keys, at most eight canonical
GitHub claims from each current snapshot, at most four write relays per
author, eight collaboration relays, and twelve identity relays overall. At
most 32 GitHub proofs are checked in one refresh, and an unchanged successfully
checked snapshot is revalidated after one hour. A new replacement or deletion
bypasses that age cache immediately.

After a relay acknowledgement, the already verified signed event is merged
into the same cache immediately. Repository announcements are attempted on
every configured relay but require one acknowledgement; unavailable relays
are reported instead of blocking the publish. Rendering therefore does not
depend on a relay returning the new event in a subsequent query.

Discovery is deliberately staged: an announcement may appear after repository
content, and an issue may appear after its comments. Each newly discovered
level unlocks the next reference-based query during that poll or the next one.

Repository collaboration is anchored only by the latest non-deleted 30617
whose publisher appears in the deployed host's NIP-05 names map. The client
does not accept an arbitrary announcement merely because its `d` tag matches a
line in `projects.list`.

## Limits outside the client's control

Convergence requires at least one configured relay to retain and eventually
return each event. No client can reconstruct an event that every relay has
discarded or refuses to serve. Browser persistence is opportunistic and may
be refused when site-storage quota is exhausted, so relays remain the durable
event stores rather than the browser.

Nostr filters provide no standard offset or event-ID tie cursor. If one relay
caps a filter after more than 5000 matching events with the same `created_at`,
the client cannot prove that the relay returned every same-second event.
Reference-specific queries, multiple configured relays, cache merging, and
repeated polling reduce that risk but cannot create a pagination primitive the
protocol does not expose.

A NIP-09 request cannot guarantee erasure from every relay or third-party
client. This client guarantees only its own presentation behavior once it has
received and cryptographically verified both the target and a valid deletion
request.

## Issue and pull-request workflow

- NIP-34 issue, PR, patch, and comment bodies are immutable regular events.
  NIP-34 defines no interoperable event for editing an existing issue title or
  description. The detail view states this explicitly and directs corrections
  to the discussion.
- Issues, PRs, and root patches each have a detail view with the same validated,
  out-of-order NIP-22 comment tree and composer.
- A patch-set detail view exposes a separate NIP-22 discussion scope for every
  patch message, because NIP-34 permits replies to any kind `1617` event.
- Patches and PRs are peer NIP-34 proposal types, not aliases. They have
  separate Pull Requests and Patches tabs and publishing forms, backed by the
  same repository-wide event cache and relationship indexes. A kind `1617`
  event carries one actual `git format-patch` message; a patch set is a causal
  chain of those events. A kind `1618` PR instead points to a source clone URL
  and source tip commit that the target repository can fetch.
- A PR may reference a root patch with an `e` tag. Both detail views provide
  cross-tab links. Converting a patch publishes the linked PR first and then a
  separate kind `1632` status. If closing fails after the PR is acknowledged,
  the PR remains visible and its detail view offers a close retry.
- The PR form treats the repository being viewed as the target and never
  guesses the source clone, source branch, source tip, or merge base from the
  target checkout. NIP-34 identifies a target repository but does not define a
  separate target-branch tag.
- The patch form accepts individual `git format-patch` files or an mbox stream,
  emits one event per message, and refuses payloads large enough to violate the
  NIP-34 recommendation to use PRs around 60 KB per patch event.
- The detail composer can publish the explicit NIP-34 statuses: `1630` Open,
  `1631` Resolved/Merged/Applied, `1632` Closed, and `1633` Draft. A newer Open
  status reopens a resolved, merged/applied, closed, or draft root.
- Status publication is allowed only for the root author or a maintainer of the
  current repository announcement. Received status events must also name both
  the repository publisher and root author in their required `p` tags.
- A PR author can publish a kind `1619` update with a new tip commit, clone URL,
  and optional merge base. The newest valid author update is displayed.
- Marking a PR merged or a patch applied records the Nostr collaboration state;
  it does not modify the Git repository. A one-click Git merge requires a
  separate authenticated server write operation.

## Git and browser-state correctness

- The visual theme follows the browser or operating-system light/dark
  preference. Both the authored palette and browser-provided controls use the
  selected color scheme; no client-side account or persistent override is
  required.
- Repository URLs are derived relative to the deployed `index.html`; there is
  no dependency on `/git/`, `/auth/`, or `auth.friendly-machines.com`.
- Reading and publishing Nostr collaboration events uses relays and the
  browser's NIP-07 signer directly. The auth site is not in this data path.
- `projects.list` entries must be safe relative paths with unique identifiers.
  Browser filesystem directories use an injective encoded path rather than a
  lossy character replacement.
- Git fetches use the server-advertised default branch, prune removed remote
  refs and tags, distinguish branches from same-named tags with fully qualified
  refs, reject ambiguous short-ref routes, and represent an actually empty
  repository without inventing branches.
- Concurrent loads of one repository share a single fetch. Navigation
  generations prevent a slower obsolete route from overwriting the latest
  repository, ref, tree, or blob view.
- Missing paths and blobs clear stale content and display an explicit error.
  Submodule entries are identified and are not passed to the blob reader.
- NIP-34 state publication snapshots every fetched branch and tag plus the
  default HEAD, follows annotated tags to actual commit IDs, and aborts if the
  repository ref set changes during resolution.
- Relay events must satisfy the local copy of the exact NIP-01 subscription
  filter as well as signature and event-ID verification before caching.
- A signer response must use the connected pubkey and preserve the exact
  requested event payload. Publications are serialized to prevent accidental
  double submissions.
- Partial relay failures are shown as incomplete cached views, not definitive
  empty results. A refresh requested during another refresh is queued rather
  than discarded.
- External script versions are fixed and protected with SHA-384 subresource
  integrity hashes.
