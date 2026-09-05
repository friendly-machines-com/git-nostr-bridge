# NostrGit client ordering and convergence

## Architectural invariant: TWO SEPARATE LAYERS — read before changing code

**Trusted-person moderation is a separate, downstream PRESENTATION layer.
It MUST NOT change the event set, protocol ranking, graph structure, repository
authority, or Git state used by the first layer. This separation is deliberate,
not an implementation detail to simplify away during refactoring.**

```text
Verified, immutable event-ID cache + retained NIP-09 deletion requests
    |
    v
LAYER 1: protocol validity, repository authority, replacement/status/update
         selection, and reference-graph construction
    |
    | authoritative result and graph (independent of moderation preferences)
    v
LAYER 2: viewer-selected trusted-person labels + local visibility policy
         -> render normally, warn, or show a content-free placeholder
```

The cache also holds moderation labels and their deletion requests as verified
facts. Sharing storage and a refresh loop does NOT merge these two layers.
With the same cached facts, changing the viewer's trusted moderators MUST leave
all first-layer winners, permissions, refs, statuses, and graph edges unchanged.
Only their permitted presentation changes.

This README is persistent architectural context for future maintainers and AI
assistants, who may have neither this conversation nor the whole file in context.
Keep large explanations canonical, but repeat short safeguards in the sections
where they prevent mistakes. A cross-reference supplements a local constraint;
it is not a substitute for one. Before changing this document, audit every
removal for lost meaning, qualifications, and local context. Do not make the user
rediscover missing safeguards. Documentation cleanup must not silently change
architecture; if code and documentation disagree, investigate rather than
rewriting either to assume a different design.

### How first-layer ranking actually works

There is **no universal reputation score or global event ranking**. "Ranking"
here means deterministic, event-type-specific selection among protocol
candidates, not popularity, Web of Trust, moderator votes, or relay arrival order.

- **Eligibility:** verify signatures/event IDs, timestamp bounds, repository
  membership, kind-specific references, and author permissions. Newer does not
  mean authorized. See [identity and reference validation](#identity-and-causality)
  and [repository permissions](#how-repository-discovery-and-permissions-work).
- **Addressable repository announcements and state:** group versions by exact
  `(kind, pubkey, d)` coordinate. Select the greatest `created_at`; if timestamps
  tie, select the lexically lowest event ID. Select that coordinate's head
  **before** applying its author-authorized deletion. Deleting that head does
  not resurrect an older version of the same coordinate. Only the domain's
  exact announcement coordinate is authoritative. Effective state is selected
  from valid, non-deleted heads authored by current maintainers, using newest
  timestamp and lowest-ID tie-break again.
- **Regular replaceable identity and relay-list snapshots:** likewise select
  one head per `(kind, pubkey)`, newest timestamp then lowest event ID, before
  deletion. Never union older snapshots or fall back to a superseded snapshot
  merely because its head was deleted.
- **Contribution statuses and PR updates:** these are ordinary events with
  application-specific reducers, not addressable replacements. Among eligible,
  non-deleted events, choose newest `created_at`, then lowest event ID. Statuses
  require the contribution author or a current maintainer; PR updates require
  the original PR author and valid references/source data.
  Author deletion of one of these ordinary events can expose an older eligible
  result under the existing reducer. **That is first-layer deletion behavior,
  not permission for second-layer moderation to cause fallback.**
- **CI:** among authorized, non-deleted reports, select the newest per commit
  and `(signing key, check name)`, with lowest event ID breaking ties; then roll
  up the resulting checks. CI's latest-check convention is not the moderation
  label algorithm.
- **Issues, comments, and patch series:** distinct immutable contributions do
  not become versions of one another. Root lists use newest-first display order
  with lowest-ID ties. Comment/patch parentage comes only from validated event
  references; siblings use oldest-first timestamp order with lowest-ID ties.
  A display ordering MUST NOT be mistaken for replacement or causal ordering.

NIP-09 author-authorized deletion belongs to these protocol semantics. A trusted
moderator's spam label is NOT a NIP-09 deletion of the target and MUST NOT be
inserted into the target's deletion index.

### If the first-layer winner is labeled spam

**Select first, then apply visibility to the selected result. NEVER remove spam-
labeled candidates and rerun selection to promote the runner-up.**

For example, suppose a PR author publishes two valid source updates:

```text
update A: created_at = 100, source tip = commit A
update B: created_at = 200, source tip = commit B

Layer 1 selects B.
A trusted moderator labels B spam; the viewer's policy says "hide".
Layer 2 shows a placeholder instead of B's source fields.
Layer 1 STILL selects B. A MUST NOT be displayed as the current source tip.
```

The hidden result remains distinguishable from absent, invalid, unresolved, or
author-deleted data. Withdrawing a label or removing a trusted moderator reveals
the same selected result only if no other applicable hiding judgment remains.
**Show anyway** locally reveals that result but never overrides author deletion.
Newly received protocol facts may independently change which result is selected.
A genuinely newer eligible update can become the winner through layer 1; its
visibility is then evaluated separately by layer 2.

Not every first-layer result is eligible for moderation. **Repository
announcements, accepted branch/tag state, workflow status selection, CI results,
and actual Git refs/commits/trees are outside the moderation target scope.**
A spam label aimed at these objects does not hide or replace them. Hiding a
patch submission never hides its commit from a maintainer-published branch.
The moderated payload kinds are issues, PR submissions/updates, individual
patch messages/revisions, and comments.

For graph nodes rather than replacement winners, retain the node's ID, parent
relation, position, and non-hidden descendants. Hiding a root does not label its
descendants. The [visibility UI](#visibility-ui-and-publication) describes how
these preserved nodes are presented.

**Forbidden architectural shortcuts:** filtering moderated events before
`latestPrUpdate` or other first-layer reducers; treating hidden as deleted;
feeding visibility-filtered arrays into graph construction or discovery;
adding trusted moderators to maintainer/status/CI authorization sets; rewriting
Git state to match a moderated view. Regression tests must preserve this
boundary, including "hidden winner does not promote runner-up."

See [Trusted-person moderation and local visibility](#trusted-person-moderation-and-local-visibility)
for the separate label algebra, withdrawal rules, and local preference behavior.

This behavior follows
[NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md),
[NIP-09](https://github.com/nostr-protocol/nips/blob/master/09.md),
[NIP-22](https://github.com/nostr-protocol/nips/blob/master/22.md), and
[NIP-34](https://github.com/nostr-protocol/nips/blob/master/34.md),
[NIP-32](https://github.com/nostr-protocol/nips/blob/master/32.md),
[NIP-39](https://github.com/nostr-protocol/nips/blob/master/39.md), and
[NIP-65](https://github.com/nostr-protocol/nips/blob/master/65.md).

The client assumes no causal ordering from relays, timestamps, relay
responses, or event arrival. An issue, one of its comments, and that
comment's parent may become visible in any order and may be returned by
different repository relays.

## How repository discovery and permissions work

**Moderation trust is not repository authority. Never add viewer-selected
moderators to maintainer, status-author, or CI-runner permission sets.**

Git repository names still come from the server's ordinary `projects.list`.
For a repository such as `mobileapp.git`, the browser removes the `.git`
suffix and looks for the NIP-34 repository identifier `mobileapp`.

The browser then follows this bootstrap chain:

1. Fetch `https://<this-domain>/.well-known/nostr.json?name=_`.
2. Treat only `names._` as the domain's repository-announcement key.
3. Read that key's optional NIP-05 `relays` entry and combine it with any
   anonymous relay preferences saved locally by this browser.
4. Ask those discovery relays for the exact signed event
   `30617:<names._>:<repository-id>`.
5. After accepting that announcement, use the relays inside its signed
   `relays` tag for repository state, issues, patches, pull requests,
   comments, and statuses.

There is no globally hardcoded discovery relay in the client. The website's
NIP-05 relay hints answer “where can I find this domain's announcements?”;
each accepted repository announcement answers “where does this project
collaborate?” Visitors may supplement or disable those hints under **Relay
settings**, without logging in or exposing a Nostr identity. If discovery is
not configured or is temporarily unavailable, ordinary anonymous Git browsing
continues to work and the Nostr portion reports the problem.

A correct Nostr signature proves which key authored an event; it does not give
that key every repository permission. The client applies this model:

- Only the domain key in `names._` can publish an effective repository
  announcement for a hosted `projects.list` identifier.
- Only current maintainers named by that accepted announcement can publish
  effective kind `30618` branches and tags.
- Anyone can open an issue, submit a patch or pull request, and participate in
  its discussion.
- Only a pull request's original author can publish its kind `1619` source-tip
  updates.
- In accordance with NIP-34, only the root issue/proposal author or a current
  repository maintainer can publish its effective open, resolved/merged,
  closed, or draft status.
- Only current maintainers of the accepted announcement, or keys it
  designates as CI runners, can publish an effective commit CI status.

These checks are made while reducing received events, not merely while showing
publication buttons. Consequently, a malicious relay or participant cannot
make a newer unauthorized state or status event override an authorized one.
Removing a maintainer from the current announcement also removes that key's
authority when cached state and statuses are evaluated again.

After the user signs in and explicitly chooses to publish, repository relays
remain the mandatory destinations. When current kind `10002` NIP-65 lists can
be found through the already-known domain or repository relays, the client
also publishes to the author's write relays and mentioned recipients' read
relays. Those personal relays supplement the project rendezvous; they never
replace or crowd its signed repository relays out of the bounded destination
set.

The header starts in **Browsing anonymously** mode and does not contact a
browser extension. **Sign in** uses the active account from a compatible Nostr
browser extension. Once signed in, the same control becomes **Sign out**;
signing out forgets the key in this page but does not modify the extension's
own account or lock state. To use another key, sign out here, select it in the
extension, and sign in again.

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
- `created_at` never establishes parentage. Within comment and patch graphs,
  it orders siblings only, with event ID as the deterministic tie-breaker.
- Status kinds are the explicit NIP-34 set `1630`, `1631`, `1632`, and `1633`;
  the client does not interpret an integer interval as a semantic kind group.
- Replaceable repository announcements and states use NIP-01 replacement
  ordering per exact `kind:pubkey:d` coordinate: newest `created_at`, then the
  lowest event ID for an exact tie. Older cached versions do not become current
  merely because the winning version was deleted by exact event ID.

## Replacement and deletion

**Hidden is not deleted. A spam label must not become a deletion tombstone for
its target, and hiding a selected winner must not promote an older candidate.**

Head selection and its interaction with deletion are defined in
[first-layer ranking](#how-first-layer-ranking-actually-works). The following
rules define NIP-09 target authorization and tombstone retention.

- Kinds `30617` and `30618` are addressable events. Retain versions for
  convergence, but select exactly one NIP-01 head per coordinate before applying
  deletion: newest `created_at`, then lowest event ID. Deleting the selected
  head does not resurrect an older version of that coordinate.
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

**Build graphs and discover references independently of moderation visibility.
Hidden parents remain graph nodes; their descendants and later updates must
still be discoverable.**

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
external-identity snapshots. Select one replaceable head per author: newest
`created_at`, then lowest event ID, and only then apply deletion. Never union
claims across versions or resurrect an older snapshot when the head is deleted.
A GitHub claim is displayed as a link beside the existing byline only after
GitHub's Gist API confirms that the named account owns a single-file Gist whose
content
is the exact NIP-39 proof for that author's npub. Relay and GitHub verification
run after repository activity is rendered; failure leaves the ordinary Nostr
byline unchanged. This assertion is optional presentation metadata. It never
authorizes a bridge crossing, selects a GitHub token, or creates an account
link. Before querying kind `10011`, the client independently reduces each
visible author's kind `10002` NIP-65 relay-list snapshot: newest `created_at`,
then lowest event ID, before exact deletion, without fallback to an older head.
It then adds write-capable personal relays to the collaboration-relay fallback.
NIP-46 signer transport relays are unrelated and are never used for this inference. To bound background work deterministically, one refresh
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

Repository collaboration remains anchored to the selected, non-deleted `30617`
head at the exact `30617:<host NIP-05 names._ key>:<projects.list identifier>`
coordinate. Other NIP-05 aliases gain no authority; a matching `d` tag alone is
insufficient. A deleted head must not revive an older announcement.

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
- Only the root author or a current repository maintainer may publish an
  effective status. Received events must also name both the repository
  publisher and root author in their required `p` tags. Among valid, non-deleted
  statuses, newest `created_at` wins, with lowest event ID breaking ties.
  Moderator trust grants no status authority.
- Only the original PR author may publish an effective kind `1619` source-tip
  update, carrying a commit, clone URL, and optional merge base. Among valid,
  non-deleted updates, newest `created_at` wins, with lowest event ID breaking
  ties. **Select first, then apply visibility: a hidden latest update remains
  selected; never substitute an older source tip.** Details:
  [first-layer ranking](#how-first-layer-ranking-actually-works) and the
  [hidden-winner rule](#if-the-first-layer-winner-is-labeled-spam).
- Marking a PR merged or a patch applied records the Nostr collaboration state;
  it does not modify the Git repository. A one-click Git merge requires a
  separate authenticated server write operation.

## Trusted-person moderation and local visibility

**This is a separate, downstream presentation layer. It never changes protocol
selection, repository permissions, graph structure, or Git state.**

**Moderation settings…** selects people whose public judgments affect this
browser's collaboration views. Preferences are origin-local, versioned browser
storage, independent of the Nostr signing account. Browsing and configuring
moderation never contacts a signer. Signing in or out does not change viewing
preferences. No moderator, maintainer, follow graph, or bridge key is trusted
for moderation automatically.

Each source is a public key (hex or npub input), a scope (all repositories or an
exact `30617` repository coordinate), optional secure WebSocket relay hints, and
an action for each category: **hide**, **warn**, or **ignore**. Adding the same
key and scope updates that preference. Under **Trusted people**, **Stop trusting
this person everywhere** removes that key's global and repository-specific
entries throughout this browser's origin-local settings. **Remove only this
scope entry** removes just the displayed entry; other scopes for that person
remain active. Both recompute visibility immediately from cached facts without
signing or waiting for relays. Other trusted people's judgments still apply.
Late query results cannot reinstate removed trust. These settings are not
published or synchronized; "everywhere" does not mean other devices or origins.
Removing trust never deletes events or changes first-layer authority or winners.

### Label collection algebra

The application convention uses NIP-32 kind `1985` events with namespace
`org.nostr.git.moderation`. The initial categories are `spam` and
`copyright-complaint`. A copyright complaint is a moderator's claim, not a legal
finding. Publishing creates one category targeting one immutable event ID:

    ["L", "org.nostr.git.moderation"]
    ["l", "spam", "org.nostr.git.moderation"]
    ["e", "<target-event-id>", "<relay-hint>"]

- Recognized, explicitly namespace-qualified label pairs and exact `e` targets
  are sets. Duplicate tags, duplicate events, and tag permutation do not alter
  decisions. Unknown categories, unqualified labels, unrelated namespaces, and
  free-form explanations do not create instructions.
- Incoming events can contain multiple recognized categories and event targets;
  each recognized category applies to each `e` target. This client does not
  interpret `p`, `a`, `r`, or `t` label targets as author/repository bans.
- Ordinary label events are independent assertions, **not replaceable state**.
  There is no latest-wins rule, expiry, or approval that cancels another label.
  Every applicable non-deleted label contributes. Hide outranks warn; ignore
  contributes nothing. Reasons retain the signing key, category, label event
  ID, and explanation, in deterministic presentation order.
- A moderator withdraws their own label with kind `5`, an exact `e` target naming
  the **label**, and optional `k=1985`. The client never copies the contribution
  ID or repository `a` address into that deletion. The deletion must be signed
  by the label's own author; retain it even if the label has not arrived yet.
  Deleting a deletion request cannot restore a label. A surviving second label
  can still hide the contribution after the first is withdrawn. Full
  [NIP-09 authorization and tombstone rules](#replacement-and-deletion) apply.

### Discovery and convergence

After discovering roots, patch references, comments, and PR updates, each poll
queries selected moderators by author, namespace, and exact target IDs. Queries
use raw collaboration candidates, including hidden and unresolved graph members,
not the presentation-filtered lists. Each request batch contains at most 32
moderator keys and 128 target IDs; batches execute sequentially. No timestamp
high-water mark excludes late-arriving old labels.

Queries use repository collaboration relays followed by explicit moderator relay
hints, respecting the existing 12-relay destination bound and locally disabled
relays. There is no new hardcoded relay or implicit NIP-65 moderator discovery.
A moderator whose judgments live elsewhere must provide a usable relay hint.

Verified results merge into the existing event-ID cache. Every poll also queries
exact-ID deletions for relevant cached labels, even when that poll returned no
labels. A target, label, and label withdrawal can arrive in any order; retained
facts are reduced again. Empty or partial responses never retract judgments.
Settings changes during an active refresh apply immediately and queue another
refresh; late responses may add facts but cannot reinstate an obsolete trust
selection. Separate moderation diagnostics describe incomplete queries while
cached judgments remain effective.

The label and deletion stages finish before the newly fetched collaboration
snapshot is rendered. This is not a guarantee against seeing as-yet undiscovered
unwanted content: no known restriction means **no known restriction**, not
moderator approval. The same relay retention, query-limit, and opportunistic
browser-persistence limits described above apply to moderation.

### Visibility UI and publication

**Hide the selected payload, not its identity or graph position. Do not rerun
selection to promote a runner-up. Hidden is not deleted.**

Moderation applies only to collaboration payloads: issues, PRs and their updates,
patch messages/revisions, and comments. Keep graph nodes and visible descendants
in place. Repository announcements, workflow status selection, CI results, and
Git refs/commits/trees remain unaffected. The
[layer boundary and hidden-winner rule](#if-the-first-layer-winner-is-labeled-spam)
explain why.

Hidden payloads and titles are not inserted into rendered content, including
linked previews and patch-discussion selector text. Placeholders show provenance
and **Show anyway**. Reveal is temporary, repository/event-scoped browser memory;
it never overrides author deletion. Counts distinguish visible, hidden, and
deleted content; missing parents remain a separate unresolved state. Hidden
content is excluded from optional author-identity enrichment.

Preserve comment draft text and cursor selection across moderation rerenders.
A reply whose selected target becomes hidden retains that target and draft, but
requires reveal or an explicit new target before publishing. Never silently
redirect the reply to a different parent.

**Publish moderation label…** is separate from **Publish status**. Any signed-in
person can publish a label; only explicitly trusting viewers apply it. After a
relay acknowledgement, the verified label or withdrawal enters the cache and
local visibility is recomputed immediately, before relay read-back. Existing
signer payload validation, publication serialization, and repository-first
publication routing are reused.

Moderation is not erasure, a bandwidth filter, or copyright compliance machinery.
Hidden events remain in the browser's verified cache and can still be retained
and served by relays and other clients. Collaboration content remains escaped
plaintext; this feature adds no automatic attachment or media fetching.

## Commit CI status badges

**CI and moderation use separate label namespaces and trust rules. Moderation
must neither alter CI results nor grant CI-runner authority.**

Continuous-integration results for a commit are NIP-32 label events (kind
`1985`). A CI label names the commit with a `c` tag, its namespace with an
`L` tag, and the status with an `l` tag whose third element repeats the
namespace:

    ["c", "<40- or 64-hex commit ID>"]
    ["L", "org.nostr.ci.status"]
    ["l", "success", "org.nostr.ci.status"]
    ["name", "cuirass/x86_64"]
    ["url", "https://ci.friendly-machines.com/eval/12/dashboard"]

The accepted namespaces are the fixed set `org.nostr.ci.status`, `ci/status`,
and `nip34.ci`; any other label event is unrelated curation metadata and is
never reduced as a CI status. Recognized statuses are success (`success`,
`pass`, `passed`, `ok`), failure (`failure`, `fail`, `failed`, `error`), and
pending (`pending`, `running`, `in_progress`). An unrecognized status word is
kept as an unanswered check; it can never roll up as passed. An unqualified
`["l", "<status>"]` is accepted only when the event carries exactly one CI
namespace, and distinct status values on one event are ambiguous and rejected.

- Only current maintainers of the accepted announcement, plus keys it designates
  with `ci_runner` (or `runner`) tags, may publish effective CI results. A label
  that names a repository through an `a` tag must name this repository.
- Labels are queried on the repository's signed collaboration relays, both by
  repository address and by the commit IDs currently selectable in the code
  view, so a runner that publishes only a commit reference still converges.
  Deletion requests for discovered labels are fetched like any other content.
- For each commit and `(signing key, check name)`, choose the newest authorized,
  non-deleted report by `created_at`, with lowest event ID breaking ties. An
  exact deletion signed by the report's author removes that report; an older
  eligible report may then supply the check. This ordinary-event CI reduction
  is not replaceable-head deletion semantics or moderation-label aggregation.
- The commit banner rolls up the checks for the selected commit: any failure
  fails the commit; otherwise any pending or unrecognized check leaves it
  running; otherwise it passed. A commit with no reports shows a neutral
  badge. The badge expands to the individual checks, each linking to the
  runner-supplied build URL; `url` tags that are not plain `http`/`https`
  addresses are ignored.
- CI labels are presentation-only status. They never modify repository state,
  authorize a merge, or participate in the addressable state snapshot.

## Git and browser-state correctness

**Moderation never changes Git refs, commits, or trees. Hiding a patch submission
must not hide its commit from a maintainer-published branch.**

- Primary interface copy uses repository concepts—issues, pull requests,
  patches, comments, statuses, branches, tags, and relays—without decorating
  ordinary objects with NIP numbers or event kinds. Protocol identifiers stay
  in source comments, advanced relay settings, diagnostics, and **Technical
  details**. Controls that publish signed data are explicitly labelled
  **Publish …**; controls that only open a form are labelled **New …**,
  **Edit …**, or **Set up …**.
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
