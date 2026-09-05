#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

const html = fs.readFileSync(
  path.join(__dirname, "..", "client", "index.html"),
  "utf8"
);
const primaryMarkup = html.slice(0, html.lastIndexOf("<script>"));
assert.match(
  html,
  /<meta\s+name="color-scheme"\s+content="light dark"\s*\/>/,
  "client must advertise both supported color schemes"
);
assert.match(
  html,
  /:root\s*\{[\s\S]*?color-scheme:\s*light dark;/,
  "browser-provided controls must follow the selected color scheme"
);
assert.match(
  html,
  /@media\s*\(prefers-color-scheme:\s*dark\)\s*\{/,
  "client must honor the browser or operating-system dark-mode preference"
);
assert.doesNotMatch(
  html,
  /const\s+DEFAULT_RELAYS|relay\.nostr\.band|["']wss:\/\/nos\.lol["']/,
  "client must not ship universal hardcoded relay defaults"
);
assert.doesNotMatch(
  html,
  /checkExtension\s*\(|nostrService\.checkExtension/,
  "anonymous initialization must not probe a NIP-07 signer"
);
assert.match(
  html,
  /<span>Browsing anonymously<\/span>[\s\S]*?id="nostr-sign-in-button"[\s\S]*?>Sign in<\/button>/,
  "header must describe anonymous browsing and offer a concise sign-in action"
);
assert.doesNotMatch(
  html,
  /nos2x|quickStatusKind|quickStatusLabel|Connect a Nostr signer/,
  "client UX must not claim an undetected provider or duplicate status actions"
);
assert.doesNotMatch(
  primaryMarkup,
  /Nostr Issues|NIP-34 Issues|Nostr Pull Requests|Nostr Patches|Nostr State|State Broadcast|Ref Snapshot|Kind 16(?:17|18|19|21)|NIP-34 \/ NIP-22/,
  "primary repository UI must not expose protocol qualifiers or event kinds"
);
assert.match(
  primaryMarkup,
  /Issues for this repository[\s\S]*Pull requests for this repository[\s\S]*Patches for this repository/,
  "repository collaboration headings must preserve their user-facing context"
);
for (const [handler, label] of [
  ["submitNewIssue", "Publish issue"],
  ["submitNewPR", "Publish pull request"],
  ["submitNewPatch", "Publish patch set"],
  ["submitPrUpdate", "Publish pull request update"],
  ["submitAnnouncement", "Publish collaboration settings"],
  ["broadcastRepoState", "Publish branch and tag snapshot"]
]) {
  assert.match(
    primaryMarkup,
    new RegExp(`onclick="app\\.${handler}\\(\\)"[^>]*>${label}<\\/button>`),
    `${handler} must have an explicit publish label`
  );
}
assert.match(
  html,
  /onclick="app\.setRootStatus\([^>]+>Publish status<\/button>/,
  "status publication must be labelled as publication"
);
assert.match(
  html,
  /onclick="app\.submitRootComment\([^>]+>Publish comment<\/button>/,
  "comment publication must be labelled as publication"
);
assert.match(
  primaryMarkup,
  /Repository relays \(1–4, one per line\):[\s\S]*These relays store repository discussions and proposals/,
  "advanced relay settings must call relays by their actual name"
);
assert.doesNotMatch(
  html,
  /\.flatMap\(repositoryRelayUrls\)/,
  "relay helper with optional settings must not receive Array callback arguments"
);
assert.doesNotMatch(
  html,
  /No Nostr issues|No Nostr pull requests|No Nostr root patches|Issue published to Nostr|PR published to Nostr|Patch published to Nostr|NIP-34 issue titles/,
  "generated task copy must not leak redundant transport or protocol labels"
);
const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
  .filter(match => !/\bsrc\s*=/.test(match[1]));
assert.equal(scripts.length, 1, "expected one inline client script");

const boot = [
  "    const app = new App();",
  '    window.addEventListener("DOMContentLoaded", () => app.init());',
  '    window.addEventListener("hashchange", () => app.route());'
].join("\n");
const expose = [
  "    globalThis.__clientTest = {",
  "      MODERATION_NAMESPACE, MODERATION_SETTINGS_KEY, moderationLabelEntries,",
  "      normalizeModerationSettings, reduceModerationLabels, moderationWithdrawalTags,",
  "      App, NostrService, activeReplaceableEvents, actorLabel,",
  "      attributionHtml, attributionLabel, buildDeletionIndex, eventIsDeleted,",
  "      cloneUrlSetFromText, extractCiStatusEntry, hasRepositoryOwnerTag,",
  "      domainDiscoveryRelayUrls, effectiveRepositoryState,",
  "      githubNip39Claims, gistVerifiesNip39,",
  "      isNostrEventShape, isRepositoryStarReaction,",
  "      isValidNip34CollaborationEvent, reduceCommitCiStatuses,",
  "      repositoryStarIdentity,",
  "      repositoryUnstarTags,",
  "      latestAddressableEvents, latestReplaceableEvents, normalizeRelayUrls,",
  "      nip65ReadRelays, nip65WriteRelays,",
  "      repositoryEarliestUniqueCommit, repositoryRelayUrls,",
  "      repositoryStateMap, scalarTagValues,",
  "      uniqueNip22EventReference, uniqueTagValue,",
  "      externalIdentityService, nostrService, verificationService, gitService",
  "    };"
].join("\n");
assert.ok(scripts[0][2].includes(boot), "client boot block changed");
const source = scripts[0][2].replace(boot, expose);

const storage = new Map();
const windowObject = {
  location: {
    hash: "",
    hostname: "friendly-machines.com",
    origin: "https://friendly-machines.com",
    pathname: "/git/index.html"
  },
  crypto: webcrypto,
  NostrTools: { verifyEvent: () => true },
  LightningFS: null,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  queueMicrotask,
  addEventListener() {}
};
const sandbox = {
  AbortController,
  Blob,
  TextDecoder,
  TextEncoder,
  URL,
  WebSocket: { OPEN: 1 },
  alert() {},
  console,
  document: {
    activeElement: null,
    body: { appendChild() {}, removeChild() {} },
    hidden: false,
    addEventListener() {},
    createElement: () => ({}),
    getElementById: () => null
  },
  fetch: async () => {
    throw new Error("network is forbidden in client reducer tests");
  },
  localStorage: {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value)
  },
  navigator: {},
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  window: windowObject
};
windowObject.window = windowObject;
vm.createContext(sandbox);
new vm.Script(source, { filename: "client/index.html:inline" })
  .runInContext(sandbox);

const {
  App,
  NostrService,
  activeReplaceableEvents,
  actorLabel,
  attributionHtml,
  attributionLabel,
  buildDeletionIndex,
  cloneUrlSetFromText,
  domainDiscoveryRelayUrls,
  effectiveRepositoryState,
  eventIsDeleted,
  extractCiStatusEntry,
  externalIdentityService,
  githubNip39Claims,
  gistVerifiesNip39,
  hasRepositoryOwnerTag,
  isNostrEventShape,
  isRepositoryStarReaction,
  isValidNip34CollaborationEvent,
  latestAddressableEvents,
  latestReplaceableEvents,
  nip65ReadRelays,
  nip65WriteRelays,
  normalizeRelayUrls,
  reduceCommitCiStatuses,
  repositoryEarliestUniqueCommit,
  repositoryRelayUrls,
  repositoryStateMap,
  repositoryStarIdentity,
  repositoryUnstarTags,
  scalarTagValues,
  uniqueNip22EventReference,
  uniqueTagValue,
  nostrService: clientNostrService,
  verificationService
} = sandbox.__clientTest;

const owner = "b".repeat(64);
const rootAuthor = "c".repeat(64);
const maintainer = "d".repeat(64);
const attacker = "e".repeat(64);
const rootId = "1".repeat(64);
let passed = 0;
function ok(condition, name) {
  assert.ok(condition, name);
  passed += 1;
  console.log(`  ok  ${name}`);
}

const validWireEvent = {
  id: "1".repeat(64),
  pubkey: owner,
  kind: 1,
  created_at: Math.floor(Date.now() / 1000),
  tags: [],
  content: "",
  sig: "0".repeat(128)
};
ok(
  isNostrEventShape(validWireEvent)
  && !isNostrEventShape({
    ...validWireEvent,
    pubkey: validWireEvent.pubkey.toUpperCase()
  })
  && !isNostrEventShape({ ...validWireEvent, kind: 65536 }),
  "NIP-01 event shape rejects uppercase hex and invalid kinds"
);

const announcement = {
  id: "2".repeat(64),
  pubkey: owner,
  kind: 30617,
  created_at: 100,
  tags: [["d", "dummy"], ["maintainers", maintainer]],
  content: "",
  sig: "0".repeat(128)
};
const previousAnnouncement = {
  ...announcement,
  id: "a".repeat(64),
  created_at: 90
};
const bridgeIssue = {
  ...announcement,
  id: "f".repeat(64),
  pubkey:
    "1443e05c05a0f7141c7430d3dd6da7dcd0905ab49ae5ecf9c82243823fdc3ef1",
  kind: 1621,
  tags: [
    ["gh_user", "daym"],
    [
      "proxy",
      "https://github.com/friendly-machines-com/dummy/issues/5",
      "github"
    ]
  ]
};
ok(
  actorLabel(bridgeIssue) === "@daym"
  && attributionLabel(bridgeIssue)
    === "@daym · From GitHub · Signed by Friendly Machines Bridge"
  && actorLabel({ ...bridgeIssue, pubkey: owner }) !== "@daym",
  "bridge-signed GitHub activity separates actor, origin, and signer"
);
clientNostrService.pubkey = owner;
const directUserComment = {
  ...announcement,
  id: "8".repeat(64),
  kind: 1111,
  tags: []
};
const mirroredUserComment = {
  ...directUserComment,
  id: "9".repeat(64),
  tags: [[
    "proxy",
    "https://github.com/friendly-machines-com/dummy/issues/5",
    "github"
  ]]
};
ok(
  attributionLabel(directUserComment)
    === "You · Posted on Nostr · Signed by your Nostr key"
  && attributionLabel(mirroredUserComment)
    === "You · From GitHub · Signed by your Nostr key",
  "the connected user's direct and GitHub-origin signatures remain distinct"
);
clientNostrService.pubkey = null;
const repositoryStar = {
  id: "b".repeat(64),
  pubkey: rootAuthor,
  kind: 7,
  created_at: 110,
  tags: [
    ["e", previousAnnouncement.id, "", owner],
    ["a", `30617:${owner}:dummy`, "", owner],
    ["p", owner],
    ["k", "30617"]
  ],
  content: "⭐",
  sig: "0".repeat(128)
};
const knownAnnouncements = new Map([
  [announcement.id, announcement],
  [previousAnnouncement.id, previousAnnouncement]
]);
ok(
  isRepositoryStarReaction(
    repositoryStar,
    announcement,
    knownAnnouncements
  )
  && !isRepositoryStarReaction(
    {
      ...repositoryStar,
      tags: repositoryStar.tags.map(tag => (
        tag[0] === "e" ? ["e", "f".repeat(64), "", owner] : tag
      ))
    },
    announcement,
    knownAnnouncements
  ),
  "repository star remains valid across announcement replacement but requires a known matching e target"
);
ok(
  repositoryStarIdentity(repositoryStar)
    === `${rootAuthor}:nostr`
  && repositoryStarIdentity({
    ...repositoryStar,
    tags: [...repositoryStar.tags, ["gh_user", "alice"]]
  }) === `${rootAuthor}:github:alice`,
  "repository star identity distinguishes labelled GitHub proxies"
);
const unstarTags = repositoryUnstarTags(
  [repositoryStar],
  announcement
);
ok(
  unstarTags.some(tag => (
    tag[0] === "e" && tag[1] === repositoryStar.id
  ))
  && !unstarTags.some(tag => tag[0] === "a"),
  "repository unstar targets only the reaction, never the repository address"
);
const malformedOwner = {
  tags: [["p", attacker, owner]]
};
ok(
  scalarTagValues(malformedOwner, "p").join(",") === attacker
  && !hasRepositoryOwnerTag(malformedOwner, announcement)
  && hasRepositoryOwnerTag({ tags: [["p", owner]] }, announcement),
  "p/P authority uses slot 1 only"
);

const scalarDuplicates = { tags: [["subject", "same"], ["subject", "same"]] };
const scalarConflictA = { tags: [["subject", "alpha"], ["subject", "beta"]] };
const scalarConflictB = { tags: [...scalarConflictA.tags].reverse() };
ok(
  uniqueTagValue(scalarDuplicates, "subject") === "same"
  && uniqueTagValue(scalarConflictA, "subject") === null
  && uniqueTagValue(scalarConflictB, "subject") === null,
  "scalar tags collapse identical duplicates and reject conflicts in every order"
);

const relayPermutationA = normalizeRelayUrls([
  "wss://z.example",
  "wss://a.example/",
  "wss://z.example"
]);
const relayPermutationB = normalizeRelayUrls([
  "wss://z.example",
  "wss://z.example",
  "wss://a.example"
]);
ok(
  relayPermutationA.join(",") === "wss://a.example,wss://z.example"
  && relayPermutationB.join(",") === relayPermutationA.join(","),
  "relay collection is a canonical set under duplicates and permutation"
);
ok(
  normalizeRelayUrls([
    "wss://relay.example/#fragment",
    "https://relay.example",
    "wss://user@relay.example"
  ]).length === 0,
  "relay collection rejects fragments, non-WebSocket URLs, and credentials"
);
ok(
  normalizeRelayUrls(undefined).length === 0
  && normalizeRelayUrls(null).length === 0
  && normalizeRelayUrls("wss://not-an-array.example").length === 0
  && repositoryRelayUrls(announcement, {}).length === 0
  && domainDiscoveryRelayUrls({ relays: undefined }, {}).length === 0,
  "missing or malformed optional relay collections reduce to an empty set"
);

const relaySettings = {
  version: 1,
  additionalRelays: ["wss://additional.example"],
  discoveryRelays: ["wss://directory.example"],
  disabledRelays: ["wss://disabled.example"]
};
ok(
  domainDiscoveryRelayUrls({
    pubkey: owner,
    relays: ["wss://domain.example", "wss://disabled.example"]
  }, relaySettings).join(",")
    === [
      "wss://domain.example",
      "wss://directory.example",
      "wss://additional.example"
    ].join(",")
  && repositoryRelayUrls({
    ...announcement,
    tags: [
      ...announcement.tags,
      ["relays", "wss://repository.example", "wss://disabled.example"]
    ]
  }, relaySettings).join(",")
    === [
      "wss://repository.example",
      "wss://additional.example"
    ].join(","),
  "domain discovery and repository collaboration relays remain separate roles"
);

ok(
  cloneUrlSetFromText("https://z.example/x.git\nhttps://a.example/x.git\nhttps://z.example/x.git")
    .join(",") === "https://a.example/x.git,https://z.example/x.git",
  "pull-request clone alternatives are a canonical set"
);

const subordinate = {
  ...announcement,
  tags: [...announcement.tags, ["u", `30617:${attacker}:upstream`]]
};
const subordinateMaintainers = verificationService.maintainerPubkeys(subordinate);
ok(
  !subordinateMaintainers.has(owner)
  && subordinateMaintainers.has(maintainer),
  "subordinate publisher is not an implicit maintainer"
);

const app = new App();
app.cacheEvents([announcement]);
const reloadedApp = new App();
ok(
  reloadedApp.cachedEvents(event => event.id === announcement.id).length === 1,
  "verified event ledger survives reload and an empty observation"
);
const root = {
  id: rootId,
  pubkey: rootAuthor,
  kind: 1621,
  created_at: 100,
  tags: [["a", `30617:${owner}:dummy`], ["p", owner]],
  content: "root"
};
const malformedStatus = {
  id: "3".repeat(64),
  pubkey: rootAuthor,
  kind: 1632,
  created_at: 120,
  tags: [
    ["e", rootId, "", "root"],
    ["p", attacker, owner],
    ["p", attacker, rootAuthor]
  ],
  content: ""
};
const validStatus = {
  ...malformedStatus,
  id: "4".repeat(64),
  tags: [
    ["e", rootId, "", "root"],
    ["p", owner],
    ["p", rootAuthor]
  ]
};
const unauthorizedNewerStatus = {
  ...validStatus,
  id: "5".repeat(64),
  pubkey: attacker,
  created_at: 999
};
ok(
  app.statusEventFor(root, {
    announcement,
    statuses: [malformedStatus]
  }) === null
  && app.statusEventFor(root, {
    announcement,
    statuses: [malformedStatus, validStatus, unauthorizedNewerStatus]
  })?.id === validStatus.id,
  "malformed or unauthorized newer statuses cannot shadow a root-author status"
);

const maintainerStatus = {
  ...validStatus,
  id: "6".repeat(64),
  pubkey: maintainer,
  created_at: 130
};
const revokedAnnouncement = {
  ...announcement,
  id: "7".repeat(64),
  created_at: 200,
  tags: [["d", "dummy"]]
};
ok(
  app.statusEventFor(root, {
    announcement,
    statuses: [validStatus, maintainerStatus]
  })?.id === maintainerStatus.id
  && app.statusEventFor(root, {
    announcement: revokedAnnouncement,
    statuses: [maintainerStatus]
  }) === null,
  "current maintainers may set status and revoked maintainers may not"
);

const ciCommit = "5".repeat(40);
const cuirassLabel = {
  id: "ab".repeat(32),
  pubkey: maintainer,
  kind: 1985,
  created_at: 300,
  tags: [
    ["c", ciCommit],
    ["L", "org.nostr.ci.status"],
    ["l", "success", "org.nostr.ci.status"],
    ["name", "cuirass/x86_64"],
    ["url", "https://ci.friendly-machines.com/eval/12/dashboard"]
  ],
  content: "All builds succeeded."
};
const failingRunnerLabel = {
  id: "ac".repeat(32),
  pubkey: owner,
  kind: 1985,
  created_at: 301,
  tags: [
    ["c", ciCommit],
    ["L", "ci/status"],
    ["l", "failure", "ci/status"],
    ["name", "guix/aarch64"]
  ],
  content: ""
};
const unauthorizedCiLabel = {
  ...cuirassLabel,
  id: "ad".repeat(32),
  pubkey: attacker,
  created_at: 999,
  tags: [
    ...cuirassLabel.tags,
    ["l", "failure", "org.nostr.ci.status"]
  ]
};
const deletedCiLabel = {
  ...cuirassLabel,
  id: "ae".repeat(32),
  created_at: 250
};
const ciDeletion = {
  id: "af".repeat(32),
  pubkey: maintainer,
  kind: 5,
  created_at: 400,
  tags: [["e", deletedCiLabel.id]],
  content: ""
};
const ciDeletionIndex = buildDeletionIndex([ciDeletion]);
ok(
  extractCiStatusEntry(cuirassLabel)?.state === "success"
  && extractCiStatusEntry(cuirassLabel)?.commit === ciCommit
  && extractCiStatusEntry(failingRunnerLabel)?.state === "failure"
  && extractCiStatusEntry({ ...cuirassLabel, kind: 1984 }) === null
  && extractCiStatusEntry({
    ...cuirassLabel,
    tags: [["L", "org.nostr.ci.status"]]
  }) === null
  && extractCiStatusEntry({
    ...cuirassLabel,
    tags: [
      ...cuirassLabel.tags,
      ["l", "failure", "org.nostr.ci.status"]
    ]
  }) === null
  && extractCiStatusEntry({
    ...cuirassLabel,
    tags: [
      ...cuirassLabel.tags.filter(tag => tag[0] !== "l"),
      ["l", "OK"]
    ]
  })?.state === "success"
  && extractCiStatusEntry({
    ...cuirassLabel,
    tags: [
      ...cuirassLabel.tags.filter(tag => tag[0] !== "url"),
      ["url", "javascript:alert(1)"]
    ]
  })?.url === null,
  "label extraction accepts one unambiguous CI status and rejects others"
);
const ciAggregates = reduceCommitCiStatuses(
  [
    cuirassLabel,
    failingRunnerLabel,
    unauthorizedCiLabel,
    deletedCiLabel
  ],
  announcement,
  ciDeletionIndex
);
ok(
  ciAggregates.get(ciCommit)?.overall === "failure"
  && ciAggregates.get(ciCommit)?.checks.length === 2
  && ciAggregates.get(ciCommit)?.checks
    .every(check => check.pubkey !== attacker)
  && !ciAggregates.has("6".repeat(40)),
  "only authorized, non-deleted runner labels reach a commit roll-up"
);
const stalePendingLabel = {
  ...cuirassLabel,
  id: "b1".repeat(32),
  created_at: 200,
  tags: [
    ...cuirassLabel.tags.filter(tag => tag[0] !== "l"),
    ["l", "pending", "org.nostr.ci.status"]
  ]
};
const supersededRunner = reduceCommitCiStatuses(
  [cuirassLabel, stalePendingLabel],
  announcement,
  buildDeletionIndex([])
);
ok(
  supersededRunner.get(ciCommit)?.overall === "success"
  && supersededRunner.get(ciCommit)?.checks.length === 1
  && supersededRunner.get(ciCommit)?.checks[0].createdAt
    === cuirassLabel.created_at,
  "the newest label per runner and check name wins"
);
const runnerKey = "f".repeat(64);
const runnerAnnouncement = {
  ...announcement,
  id: "b2".repeat(32),
  tags: [
    ["d", "dummy"],
    ["ci_runner", runnerKey],
    ["runner", "not-a-key"]
  ]
};
const designatedRunnerLabel = {
  ...cuirassLabel,
  id: "b3".repeat(32),
  pubkey: runnerKey
};
ok(
  reduceCommitCiStatuses(
    [designatedRunnerLabel],
    runnerAnnouncement,
    buildDeletionIndex([])
  ).get(ciCommit)?.overall === "success"
  && reduceCommitCiStatuses(
    [designatedRunnerLabel],
    announcement,
    buildDeletionIndex([])
  ).size === 0
  && reduceCommitCiStatuses(
    [cuirassLabel],
    revokedAnnouncement,
    buildDeletionIndex([])
  ).size === 0,
  "designated CI runners keep authority that revoked maintainers lose"
);
const foreignAddressLabel = {
  ...cuirassLabel,
  id: "b4".repeat(32),
  tags: [
    ...cuirassLabel.tags,
    ["a", "30617:9999999999999999999999999999999999999999999999999999999999999999:other"]
  ]
};
ok(
  reduceCommitCiStatuses(
    [foreignAddressLabel],
    announcement,
    buildDeletionIndex([])
  ).size === 0,
  "a CI label naming another repository never applies here"
);
const unknownStatusLabel = {
  ...cuirassLabel,
  id: "b5".repeat(32),
  tags: [
    ...cuirassLabel.tags.filter(tag => tag[0] !== "l"),
    ["l", "cancelled", "org.nostr.ci.status"]
  ]
};
ok(
  reduceCommitCiStatuses(
    [unknownStatusLabel],
    announcement,
    buildDeletionIndex([])
  ).get(ciCommit)?.overall === "pending",
  "an unrecognized status never rolls up as passed"
);

const ciApp = new App();
ciApp.currentRepo = { id: "dummy" };
ciApp.nostrData = {
  dummy: { ciStatuses: reduceCommitCiStatuses(
    [cuirassLabel],
    announcement,
    buildDeletionIndex([])
  ) }
};
const ciBannerElement = { innerHTML: "" };
const defaultGetElementById = sandbox.document.getElementById;
sandbox.document.getElementById = id => (
  id === "banner-ci" ? ciBannerElement : defaultGetElementById(id)
);
ciApp.renderCommitCiBadge(ciCommit);
ok(
  ciBannerElement.innerHTML.includes("passed (1)")
  && ciBannerElement.innerHTML.includes("cuirass/x86_64")
  && ciBannerElement.innerHTML.includes(
    "https://ci.friendly-machines.com/eval/12/dashboard"
  )
  && ciBannerElement.innerHTML.includes("All builds succeeded."),
  "the commit banner renders the passed roll-up with its check links"
);
const hostileLabel = {
  ...cuirassLabel,
  id: "b6".repeat(32),
  content: "<script>alert(1)</script>",
  tags: [
    ...cuirassLabel.tags.filter(tag => tag[0] !== "name" && tag[0] !== "url"),
    ["name", "<script>name</script>"],
    ["url", "javascript:alert(1)"]
  ]
};
ciApp.nostrData = {
  dummy: { ciStatuses: reduceCommitCiStatuses(
    [hostileLabel],
    announcement,
    buildDeletionIndex([])
  ) }
};
ciApp.renderCommitCiBadge(ciCommit);
ok(
  !ciBannerElement.innerHTML.includes("<script>")
  && !ciBannerElement.innerHTML.includes("javascript:")
  && ciBannerElement.innerHTML.includes("&lt;script&gt;"),
  "check names, descriptions, and URLs are escaped or dropped"
);
ciApp.nostrData = {};
ciApp.renderCommitCiBadge(ciCommit);
ok(
  ciBannerElement.innerHTML.includes("no CI"),
  "a commit without reports shows the neutral no-checks badge"
);
sandbox.document.getElementById = defaultGetElementById;

const parent = {
  id: "5".repeat(64),
  pubkey: maintainer,
  kind: 1111,
  created_at: 130,
  tags: [
    ["E", rootId, "", rootAuthor],
    ["K", "1621"],
    ["P", rootAuthor],
    ["e", rootId, "", rootAuthor],
    ["k", "1621"],
    ["p", rootAuthor]
  ],
  content: "parent"
};
const child = {
  id: "6".repeat(64),
  pubkey: attacker,
  kind: 1111,
  created_at: 110,
  tags: [
    ["E", rootId, "", rootAuthor],
    ["K", "1621"],
    ["P", rootAuthor],
    ["e", parent.id, "", parent.pubkey],
    ["k", "1111"],
    ["p", parent.pubkey]
  ],
  content: "child arrived first"
};
const commentData = { comments: [child, parent] };
const acceptedComments = app.validCommentsForRoot(root, commentData);
const commentRows = app.commentTreeRows(root, acceptedComments);
ok(
  acceptedComments.length === 2
  && commentRows.map(row => `${row.comment.id}:${row.depth}`).join(",")
     === `${parent.id}:0,${child.id}:1`,
  "comment tree converges when child arrives before parent"
);

const conflictingRootReference = {
  ...parent,
  id: "0".repeat(64),
  tags: [
    ...parent.tags,
    ["E", "f".repeat(64), "", rootAuthor]
  ]
};
ok(
  uniqueNip22EventReference(conflictingRootReference, "E") === null
  && app.validCommentsForRoot(root, {
    comments: [conflictingRootReference]
  }).length === 0
  && app.validCommentsForRoot(root, {
    comments: [{
      ...conflictingRootReference,
      tags: [...conflictingRootReference.tags].reverse()
    }]
  }).length === 0,
  "conflicting NIP-22 roots are rejected independently of tag order"
);

const malformedComment = {
  ...parent,
  id: "7".repeat(64),
  tags: parent.tags.map(tag => (
    tag[0] === "P" || tag[0] === "p"
      ? [tag[0], attacker, tag[1]]
      : tag
  ))
};
ok(
  app.validCommentsForRoot(root, {
    comments: [malformedComment]
  }).length === 0,
  "malformed comment hint slots cannot satisfy P/p authors"
);

const target = {
  id: "8".repeat(64),
  pubkey: rootAuthor,
  kind: 1621,
  created_at: 100,
  tags: [],
  content: ""
};
const deletion = {
  id: "9".repeat(64),
  pubkey: rootAuthor,
  kind: 5,
  created_at: 120,
  tags: [["e", target.id], ["k", "1621"]],
  content: ""
};
const deletionIndex = buildDeletionIndex([deletion]);
ok(
  eventIsDeleted(target, deletionIndex)
  && !eventIsDeleted(deletion, deletionIndex),
  "deletion-before-target tombstones target but not deletion request"
);

const replacementHighId = {
  id: "f".repeat(64),
  pubkey: owner,
  kind: 30617,
  created_at: 200,
  tags: [["d", "dummy"]],
  content: "high"
};
const replacementLowId = {
  ...replacementHighId,
  id: "a".repeat(64),
  content: "low"
};
ok(
  latestAddressableEvents([
    replacementHighId,
    replacementLowId
  ])[0].id === replacementLowId.id,
  "addressable same-time tie selects lowest event id"
);

const nip39Older = {
  id: "4".repeat(64),
  pubkey: rootAuthor,
  kind: 10011,
  created_at: 100,
  tags: [["i", "github:old-name", "abcde"]],
  content: ""
};
const nip39TieHigh = {
  ...nip39Older,
  id: "f".repeat(64),
  created_at: 200,
  tags: [["i", "github:high-name", "bcdef"]]
};
const nip39TieLow = {
  ...nip39TieHigh,
  id: "3".repeat(64),
  tags: [["i", "github:low-name", "cdef0"]]
};
const nip39OtherAuthor = {
  ...nip39TieHigh,
  id: "2".repeat(64),
  pubkey: attacker,
  created_at: 150
};
const nip39Heads = latestReplaceableEvents([
  nip39TieHigh,
  nip39OtherAuthor,
  nip39Older,
  nip39TieLow
], 10011);
ok(
  nip39Heads.length === 2
  && nip39Heads.find(event => event.pubkey === rootAuthor)?.id === nip39TieLow.id
  && nip39Heads.find(event => event.pubkey === attacker)?.id === nip39OtherAuthor.id,
  "regular replaceable identities reduce per author with the NIP-01 tie-break"
);
const nip39Deletion = {
  id: "5".repeat(64),
  pubkey: rootAuthor,
  kind: 5,
  created_at: 201,
  tags: [["e", nip39TieLow.id]],
  content: ""
};
ok(
  activeReplaceableEvents(
    [nip39Older, nip39TieHigh, nip39TieLow],
    10011,
    buildDeletionIndex([nip39Deletion])
  ).length === 0,
  "deleting the current identity snapshot does not resurrect an older version"
);

const nip39Claims = githubNip39Claims({
  ...nip39TieLow,
  tags: [
    ["i", "github:Zulu", "ABCDEF"],
    ["i", "github:alice", "12345"],
    ["i", "github:ALICE", "12345"],
    ["i", "GitHub:wrong-prefix", "abcde"],
    ["i", "github:-invalid", "abcde"],
    ["i", "github:valid", "not-a-gist-id"]
  ]
});
ok(
  JSON.stringify(nip39Claims) === JSON.stringify([
    { login: "alice", proof: "12345" },
    { login: "zulu", proof: "abcdef" }
  ]),
  "NIP-39 GitHub claims are a validated, deduplicated, canonical set"
);

ok(
  JSON.stringify(nip65WriteRelays({
    ...nip39TieLow,
    kind: 10002,
    tags: [
      ["r", "wss://write.example", "write"],
      ["r", "wss://both.example"],
      ["r", "wss://read.example", "read"],
      ["r", "wss://write.example", "write"],
      ["r", "ws://insecure.example", "write"]
    ]
  })) === JSON.stringify([
    "wss://both.example",
    "wss://write.example"
  ])
  && JSON.stringify(nip65ReadRelays({
    ...nip39TieLow,
    kind: 10002,
    tags: [
      ["r", "wss://write.example", "write"],
      ["r", "wss://both.example"],
      ["r", "wss://read.example", "read"]
    ]
  })) === JSON.stringify([
    "wss://both.example",
    "wss://read.example"
  ]),
  "NIP-65 routing separates canonical author-write and recipient-read sets"
);

const claimedNpub = "npub1example";
const exactProof = `Verifying that I control the following Nostr public key: ${claimedNpub}`;
const validGist = {
  owner: { login: "Alice" },
  files: {
    "nostr.txt": {
      content: exactProof,
      truncated: false
    }
  }
};
ok(
  gistVerifiesNip39(validGist, "alice", claimedNpub)
  && !gistVerifiesNip39({
    ...validGist,
    owner: { login: "mallory" }
  }, "alice", claimedNpub)
  && !gistVerifiesNip39({
    ...validGist,
    files: {
      ...validGist.files,
      "extra.txt": { content: exactProof, truncated: false }
    }
  }, "alice", claimedNpub)
  && !gistVerifiesNip39({
    ...validGist,
    files: {
      "nostr.txt": { content: `${exactProof}\n`, truncated: false }
    }
  }, "alice", claimedNpub),
  "NIP-39 verification requires the claimed GitHub owner and one exact proof file"
);

externalIdentityService.githubByPubkey.set(rootAuthor, [{
  login: "alice",
  proof: "12345"
}]);
externalIdentityService.githubByPubkey.set(bridgeIssue.pubkey, [{
  login: "not-the-bridge-actor",
  proof: "67890"
}]);
const enrichedAttribution = attributionHtml({
  ...directUserComment,
  pubkey: rootAuthor
});
ok(
  enrichedAttribution.includes("✓ GitHub @alice")
  && enrichedAttribution.includes('href="https://github.com/alice"')
  && attributionLabel({
    ...directUserComment,
    pubkey: rootAuthor
  }).includes("GitHub @alice (verified)")
  && !attributionHtml(bridgeIssue).includes("not-the-bridge-actor"),
  "verified GitHub identity enriches user bylines but never relabels bridge signatures"
);
externalIdentityService.githubByPubkey.delete(rootAuthor);
externalIdentityService.githubByPubkey.delete(bridgeIssue.pubkey);

const ambiguousAddressA = {
  ...root,
  tags: [
    ["a", `30617:${owner}:dummy`],
    ["a", `30617:${owner}:other`],
    ["p", owner]
  ]
};
ok(
  !isValidNip34CollaborationEvent(ambiguousAddressA, announcement)
  && !isValidNip34CollaborationEvent({
    ...ambiguousAddressA,
    tags: [...ambiguousAddressA.tags].reverse()
  }, announcement),
  "collaboration destination is a scalar and never selected by tag order"
);

const eucA = "1".repeat(40);
const eucB = "2".repeat(40);
ok(
  repositoryEarliestUniqueCommit({
    tags: [["r", eucA, "euc"], ["r", eucA, "euc"]]
  }) === eucA
  && repositoryEarliestUniqueCommit({
    tags: [["r", eucA, "euc"], ["r", eucB, "euc"]]
  }) === null
  && repositoryEarliestUniqueCommit({
    tags: [["r", eucB, "euc"], ["r", eucA, "euc"]]
  }) === null,
  "earliest-unique-commit is one scalar marked relation"
);

const stateRef = "refs/heads/main";
const stateCommitA = "3".repeat(40);
const stateCommitB = "4".repeat(40);
ok(
  repositoryStateMap({
    kind: 30618,
    tags: [
      ["HEAD", `ref: ${stateRef}`],
      [stateRef, stateCommitA],
      [stateRef, stateCommitA]
    ]
  })?.refs.get(stateRef) === stateCommitA
  && repositoryStateMap({
    kind: 30618,
    tags: [[stateRef, stateCommitA], [stateRef, stateCommitB]]
  }) === null
  && repositoryStateMap({
    kind: 30618,
    tags: [[stateRef, stateCommitB], [stateRef, stateCommitA]]
  }) === null,
  "repository state is a ref map and conflicting values never use tag order"
);

const authorizedState = {
  id: "8".repeat(64),
  pubkey: maintainer,
  kind: 30618,
  created_at: 200,
  tags: [["d", "dummy"], [stateRef, stateCommitA]]
};
const unauthorizedNewerState = {
  ...authorizedState,
  id: "9".repeat(64),
  pubkey: attacker,
  created_at: 999,
  tags: [["d", "dummy"], [stateRef, stateCommitB]]
};
ok(
  effectiveRepositoryState(
    [authorizedState, unauthorizedNewerState],
    announcement,
    buildDeletionIndex([])
  )?.id === authorizedState.id
  && effectiveRepositoryState(
    [authorizedState],
    revokedAnnouncement,
    buildDeletionIndex([])
  ) === null,
  "unauthorized newer state cannot shadow authorized state and revocation is immediate"
);

const patchRoot = {
  id: "a".repeat(64),
  pubkey: rootAuthor,
  kind: 1617,
  created_at: 100,
  tags: [["a", `30617:${owner}:dummy`], ["p", owner], ["t", "root"]],
  content: "root patch"
};
const patchTwo = {
  id: "b".repeat(64),
  pubkey: maintainer,
  kind: 1617,
  created_at: 300,
  tags: [
    ["a", `30617:${owner}:dummy`],
    ["p", owner],
    ["e", patchRoot.id, "", "reply", patchRoot.pubkey]
  ],
  content: "second patch"
};
const patchThree = {
  id: "c".repeat(64),
  pubkey: attacker,
  kind: 1617,
  created_at: 200,
  tags: [
    ["a", `30617:${owner}:dummy`],
    ["p", owner],
    ["e", patchTwo.id, "", "reply", patchTwo.pubkey]
  ],
  content: "third patch arrived first"
};
ok(
  app.patchSeriesForRoot(patchRoot, {
    patches: [patchThree, patchTwo, patchRoot]
  }).map(event => event.id).join(",")
    === [patchRoot.id, patchTwo.id, patchThree.id].join(","),
  "patch series follows reply IDs rather than arrival or timestamps"
);

const revisionRoot = {
  id: "d".repeat(64),
  pubkey: maintainer,
  kind: 1617,
  created_at: 400,
  tags: [
    ["a", `30617:${owner}:dummy`],
    ["p", owner],
    ["t", "root"],
    ["t", "root-revision"],
    ["e", patchRoot.id, "", "reply", patchRoot.pubkey]
  ],
  content: "revision root patch"
};
const revisionSecond = {
  id: "e".repeat(64),
  pubkey: maintainer,
  kind: 1617,
  created_at: 410,
  tags: [
    ["a", `30617:${owner}:dummy`],
    ["p", owner],
    ["e", revisionRoot.id, "", "reply", revisionRoot.pubkey]
  ],
  content: "revision second patch"
};
const acceptedRevisionStatus = {
  id: "8".repeat(64),
  pubkey: rootAuthor,
  kind: 1631,
  created_at: 500,
  tags: [
    ["e", patchRoot.id, "", "root"],
    ["e", revisionRoot.id, "", "reply"],
    ["p", owner],
    ["p", patchRoot.pubkey],
    ["p", revisionRoot.pubkey]
  ],
  content: ""
};
const patchRevisionData = {
  announcement,
  patchRoots: [patchRoot],
  patches: [
    revisionSecond,
    patchThree,
    revisionRoot,
    patchTwo,
    patchRoot
  ],
  statuses: [acceptedRevisionStatus]
};
const patchGroups = app.patchGroupsForRoot(patchRoot, patchRevisionData);
ok(
  patchGroups.length === 2
  && patchGroups[0].series.map(event => event.id).join(",")
    === [patchRoot.id, patchTwo.id, patchThree.id].join(",")
  && patchGroups[1].series.map(event => event.id).join(",")
    === [revisionRoot.id, revisionSecond.id].join(","),
  "patch revisions remain separate causal series under the original patch"
);
ok(
  app.statusKindFor(patchRoot, patchRevisionData) === 1631
  && app.statusKindFor(revisionRoot, patchRevisionData) === 1631,
  "accepted patch revision inherits Applied from the root status"
);
const unacceptedRevision = {
  ...revisionRoot,
  id: "7".repeat(64),
  created_at: 420
};
const unacceptedData = {
  ...patchRevisionData,
  patches: [...patchRevisionData.patches, unacceptedRevision]
};
ok(
  app.statusKindFor(unacceptedRevision, unacceptedData) === 1632,
  "unaccepted revision inherits Closed when the original patch is Applied"
);

(async () => {
  const gitService = sandbox.__clientTest.gitService;
  const originalGitMethods = Object.fromEntries(
    ["loadRepo", "getBranches", "getTags", "getDefaultBranch"].map(key => [key, gitService[key]])
  );
  const originalDocumentLookup = sandbox.document.getElementById;
  const controls = new Map();
  sandbox.document.getElementById = id => {
    if (!controls.has(id)) controls.set(id, {
      innerHTML: "old repository", textContent: "old repository", disabled: false,
      style: {}, classList: { add() {}, remove() {}, toggle() {} }
    });
    return controls.get(id);
  };
  const repoApp = new App();
  repoApp.currentRepo = { id: "old" };
  repoApp.currentRef = "old-branch";
  repoApp.clearCommitCiBadge = () => {};
  let collaborationRepo;
  repoApp.loadNostrTabs = () => { collaborationRepo = repoApp.currentRepo.id; };
  const nextRepo = { id: "new", path: "new", name: "New" };
  let rejectLoad;
  gitService.loadRepo = () => new Promise((_resolve, reject) => { rejectLoad = reject; });
  const loading = repoApp.ensureRepoLoaded(nextRepo);
  assert.equal(collaborationRepo, "new", "collaboration refresh must precede Git completion");
  assert.equal(repoApp.currentRef, null);
  for (const id of ["branch-select", "commit-select"]) {
    assert.equal(controls.get(id).innerHTML, "");
    assert.equal(controls.get(id).disabled, true);
  }
  rejectLoad(new Error("Could not find HEAD"));
  assert.equal(await loading, false);
  assert.equal(repoApp.currentDir, null);
  assert.match(controls.get("file-table-body").innerHTML, /Failed to load repository: Could not find HEAD/);
  assert.equal(controls.get("branch-select").disabled, true);

  gitService.loadRepo = async () => "/new";
  gitService.getBranches = async () => ["main"];
  gitService.getTags = async () => [];
  gitService.getDefaultBranch = async () => { throw new Error("default branch failed"); };
  assert.equal(await repoApp.ensureRepoLoaded(nextRepo), false);
  assert.equal(repoApp.currentDir, null, "partial initialization must remain retryable");
  gitService.getDefaultBranch = async () => "main";
  assert.equal(await repoApp.ensureRepoLoaded(nextRepo), true);
  assert.equal(controls.get("branch-select").disabled, false);
  assert.equal(repoApp.currentRef, "refs/remotes/origin/main");
  controls.get("commit-select").innerHTML = "current commits";
  assert.equal(await repoApp.ensureRepoLoaded(nextRepo), true);
  assert.equal(controls.get("commit-select").innerHTML, "current commits",
    "navigation within a loaded repository must preserve controls");
  Object.assign(gitService, originalGitMethods);
  sandbox.document.getElementById = originalDocumentLookup;

  const proofAuthors = Array.from(
    {length: 33},
    (_, index) => (index + 1).toString(16).padStart(64, "0")
  );
  const proofHeads = proofAuthors.map((pubkey, index) => ({
    id: (index + 101).toString(16).padStart(64, "0"),
    pubkey,
    kind: 10011,
    created_at: 500,
    tags: [[
      "i",
      `github:user${index + 1}`,
      (index + 10000).toString(16).padStart(5, "0")
    ]],
    content: ""
  }));
  const originalProofCheck = externalIdentityService.verifyGithubClaim;
  let proofChecks = 0;
  externalIdentityService.verifyGithubClaim = async (_pubkey, claim) => {
    proofChecks += 1;
    return {status: "valid", identity: claim};
  };
  await externalIdentityService.reconcile(proofAuthors, proofHeads);
  const budgetApplied = proofChecks === 32
    && externalIdentityService.githubIdentities(proofAuthors[31]).length === 1
    && externalIdentityService.githubIdentities(proofAuthors[32]).length === 0;
  externalIdentityService.githubByPubkey.set(proofAuthors[32], [{
    login: "stale",
    proof: "abcde"
  }]);
  externalIdentityService.checkedHeads.set(proofAuthors[32], {
    eventId: "f".repeat(64),
    checkedAt: Date.now()
  });
  for (const pubkey of proofAuthors.slice(0, 32)) {
    const checked = externalIdentityService.checkedHeads.get(pubkey);
    checked.checkedAt = 0;
  }
  await externalIdentityService.reconcile(proofAuthors, proofHeads);
  ok(
    budgetApplied
    && proofChecks === 64
    && externalIdentityService.githubIdentities(proofAuthors[32]).length === 0,
    "aggregate Gist budget is bounded and never retains a superseded badge"
  );
  externalIdentityService.verifyGithubClaim = originalProofCheck;
  externalIdentityService.githubByPubkey.clear();
  externalIdentityService.checkedHeads.clear();

  const originalDomainLookup = verificationService.getDomainPubkeys.bind(
    verificationService
  );
  verificationService.getDomainPubkeys = async () => ({
    zed: owner,
    alpha: owner
  });
  ok(
    await verificationService.verifyNip05(
      owner,
      "friendly-machines.com"
    ) === "alpha@friendly-machines.com",
    "NIP-05 alias map uses a deterministic display representative"
  );
  verificationService.getDomainPubkeys = originalDomainLookup;

  const originalDomainDocumentLookup =
    verificationService.getDomainDocument.bind(verificationService);
  verificationService.getDomainDocument = async () => ({
    names: {
      _: owner,
      dannym: attacker
    },
    relays: {
      [owner]: ["wss://domain.example"],
      [attacker]: ["wss://attacker.example"]
    }
  });
  const domainAuthority = await verificationService.getDomainAuthority(
    "friendly-machines.com"
  );
  ok(
    domainAuthority.pubkey === owner
    && domainAuthority.relays.join(",") === "wss://domain.example",
    "only NIP-05 names._ and that key's relay hints anchor repository discovery"
  );
  verificationService.getDomainDocument = originalDomainDocumentLookup;

  const bootstrapAnnouncement = {
    id: "d".repeat(64),
    pubkey: owner,
    kind: 30617,
    created_at: Math.floor(Date.now() / 1000) - 10,
    tags: [
      ["d", "dummy"],
      ["name", "Dummy"],
      ["description", "Bootstrap integration fixture"],
      ["clone", "https://friendly-machines.com/git/dummy.git"],
      ["web", "https://friendly-machines.com/git/#/repo/dummy"],
      ["relays", "wss://repository.example"]
    ],
    content: "",
    sig: "1".repeat(128)
  };
  const originalAuthorityLookup = verificationService.getDomainAuthority;
  const originalNostrFetch = clientNostrService.fetchEvents;
  const previousDomainDocument = verificationService.domainCache.get(
    "friendly-machines.com"
  );
  storage.clear();
  verificationService.domainCache.set("friendly-machines.com", {
    names: { _: owner },
    relays: { [owner]: ["wss://domain.example"] }
  });
  verificationService.getDomainAuthority = async () => ({
    pubkey: owner,
    relays: ["wss://domain.example"],
    document: verificationService.domainCache.get("friendly-machines.com")
  });
  clientNostrService.fetchEvents = async filters => (
    filters.some(filter => (
      Array.isArray(filter.kinds) && filter.kinds.includes(30617)
    ))
      ? [bootstrapAnnouncement]
      : []
  );
  try {
    const bootstrapApp = new App();
    bootstrapApp.repositories = [{
      id: "dummy",
      name: "dummy.git",
      desc: "dummy Git Repository",
      path: "dummy.git"
    }];
    await bootstrapApp.refreshAllNostr(false);
    ok(
      isNostrEventShape(bootstrapAnnouncement)
      && bootstrapApp.nostrError === null
      && bootstrapApp.discoveryRelayUrls.join(",")
        === "wss://domain.example"
      && bootstrapApp.nostrData.dummy?.announcement?.id
        === bootstrapAnnouncement.id
      && repositoryRelayUrls(
        bootstrapApp.nostrData.dummy.announcement
      ).join(",") === "wss://repository.example",
      "empty-storage refresh follows NIP-05 discovery into a real-shaped repository announcement"
    );
  } finally {
    verificationService.getDomainAuthority = originalAuthorityLookup;
    clientNostrService.fetchEvents = originalNostrFetch;
    clientNostrService.relayUrls = [];
    storage.clear();
    if (previousDomainDocument === undefined) {
      verificationService.domainCache.delete("friendly-machines.com");
    } else {
      verificationService.domainCache.set(
        "friendly-machines.com",
        previousDomainDocument
      );
    }
  }

  const identityOriginalGetElementById = sandbox.document.getElementById;
  const identityBadge = { textContent: "" };
  const signInButton = { textContent: "", title: "" };
  sandbox.document.getElementById = id => (
    id === "user-badge"
      ? identityBadge
      : id === "nostr-sign-in-button"
        ? signInButton
        : null
  );
  clientNostrService.pubkey = owner;
  clientNostrService.renderBadge();
  const signedInStateIsClear =
    identityBadge.textContent.startsWith("Signed in · ")
    && signInButton.textContent === "Sign out";
  await clientNostrService.toggleLogin();
  ok(
    signedInStateIsClear
    && clientNostrService.pubkey === null
    && identityBadge.textContent === "Browsing anonymously"
    && signInButton.textContent === "Sign in"
    && signInButton.title.includes("Nostr browser extension"),
    "header sign-in toggles back to explicit page-level anonymous mode"
  );
  sandbox.document.getElementById = identityOriginalGetElementById;
  clientNostrService.pubkey = owner;

  const closedService = new NostrService();
  closedService.ensureConnected = async () => {};
  const closedRelay = "wss://closed.example";
  closedService.sockets.set(closedRelay, {
    readyState: 1,
    send(message) {
      const decoded = JSON.parse(message);
      if (decoded[0] === "REQ") {
        closedService.handleMessage({
          data: JSON.stringify([
            "CLOSED",
            decoded[1],
            "blocked: test"
          ])
        }, closedRelay);
      }
    }
  });
  await assert.rejects(
    closedService.fetchEvents([{ kinds: [1621] }], 100, [closedRelay]),
    /blocked: test/
  );
  ok(
    closedService.takeQueryWarnings().some(warning => (
      warning.includes(closedRelay) && warning.includes("blocked: test")
    )),
    "CLOSED without EOSE is an incomplete relay query"
  );

  const partialService = new NostrService();
  partialService.ensureConnected = async () => {};
  const completeRelay = "wss://complete.example";
  const failedRelay = "wss://failed.example";
  partialService.sockets.set(completeRelay, {
    readyState: 1,
    send(message) {
      const decoded = JSON.parse(message);
      if (decoded[0] === "REQ") {
        partialService.handleMessage({
          data: JSON.stringify(["EOSE", decoded[1]])
        }, completeRelay);
      }
    }
  });
  partialService.sockets.set(failedRelay, {
    readyState: 1,
    send(message) {
      const decoded = JSON.parse(message);
      if (decoded[0] === "REQ") {
        partialService.handleMessage({
          data: JSON.stringify([
            "CLOSED",
            decoded[1],
            "error: test"
          ])
        }, failedRelay);
      }
    }
  });
  const partialEvents = await partialService.fetchEvents(
    [{ kinds: [1621] }],
    100,
    [completeRelay, failedRelay]
  );
ok(
  partialEvents.length === 0
    && partialService.takeQueryWarnings().some(warning => (
      warning.includes(failedRelay) && warning.includes("error: test")
    )),
  "one EOSE keeps results while another relay failure stays visible"
);

const activityStatus = { textContent: "" };
const originalGetElementById = sandbox.document.getElementById;
sandbox.document.getElementById = id => (
  id === "nostr-refresh-status" ? activityStatus : null
);
const activityApp = new App();
activityApp.nostrLoaded = true;
activityApp.nostrDiagnostics = [
  "wss://failed.example: connection unavailable"
];
activityApp.updateNostrRefreshUi();
ok(
  activityStatus.textContent.includes(
    "Repository activity loaded from available relays"
  )
  && activityStatus.textContent.includes("wss://failed.example")
  && !activityStatus.textContent.includes("cached"),
  "an optional relay warning names the relay without claiming cache-only data"
);
activityApp.nostrError = "wss://failed.example: connection unavailable";
activityApp.updateNostrRefreshUi();
ok(
  activityStatus.textContent.includes("The refresh was incomplete")
  && activityStatus.textContent.includes("wss://failed.example"),
  "an incomplete refresh is distinct and retains the relay diagnostics"
);
sandbox.document.getElementById = originalGetElementById;

const statePreview = { textContent: "" };
sandbox.document.getElementById = id => (
  id === "state-json-preview" ? statePreview : null
);
activityApp.currentRepo = { id: "dummy", name: "dummy" };
activityApp.repositoryStateTags = async () => [
  ["d", "dummy"],
  ["HEAD", "ref: refs/heads/main"],
  ["refs/heads/main", "1".repeat(40)],
  ["refs/tags/v1.0", "2".repeat(40)]
];
await activityApp.updateStatePreview();
ok(
  statePreview.textContent.includes("Default branch: main")
  && statePreview.textContent.includes(`main  ${"1".repeat(40)}`)
  && statePreview.textContent.includes(`v1.0  ${"2".repeat(40)}`)
  && !statePreview.textContent.includes("30618"),
  "branches and tags preview describes Git state without protocol payload jargon"
);
sandbox.document.getElementById = originalGetElementById;

const signedPublication = async requested => {
    const serialized = JSON.stringify([
      0,
      owner,
      requested.created_at,
      requested.kind,
      requested.tags,
      requested.content
    ]);
    const digest = await webcrypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(serialized)
    );
    const id = Array.from(
      new Uint8Array(digest),
      byte => byte.toString(16).padStart(2, "0")
    ).join("");
    return {
      ...requested,
      id,
      pubkey: owner,
      sig: "0".repeat(128)
    };
  };
  windowObject.nostr = {
    getPublicKey: async () => owner,
    signEvent: signedPublication
  };
  const publicationService = new NostrService();
  publicationService.ensureConnected = async () => {};
  const acceptingRelay = "wss://accepting.example";
  const rejectingRelay = "wss://rejecting.example";
  publicationService.sockets.set(acceptingRelay, {
    readyState: 1,
    send(message) {
      const event = JSON.parse(message)[1];
      publicationService.handleMessage({
        data: JSON.stringify(["OK", event.id, true, "saved"])
      }, acceptingRelay);
    }
  });
  publicationService.sockets.set(rejectingRelay, {
    readyState: 3,
    send() {
      throw new Error("closed relay must not be used");
    }
  });
  await publicationService.signAndPublish({
    kind: 30617,
    tags: [["d", "dummy"]],
    content: ""
  }, [acceptingRelay, rejectingRelay]);
  ok(
    publicationService.takePublicationWarnings().some(warning => (
      warning.includes(rejectingRelay) && warning.includes("unavailable")
    )),
    "one relay acknowledgement succeeds and unavailable relays remain visible"
  );

  publicationService.sockets.set(rejectingRelay, {
    readyState: 1,
    send(message) {
      const event = JSON.parse(message)[1];
      publicationService.handleMessage({
        data: JSON.stringify(["OK", event.id, true, "saved"])
      }, rejectingRelay);
    }
  });
  await publicationService.signAndPublish({
    kind: 30617,
    tags: [["d", "dummy"]],
    content: ""
  }, [acceptingRelay, rejectingRelay], 2);
  ok(
    true,
    "publication can still require two independent acknowledgements when requested"
  );

  // Moderation is a projection of retained facts, not an authority reducer.
  const {
    MODERATION_NAMESPACE: namespace, MODERATION_SETTINGS_KEY: settingsKey,
    moderationLabelEntries, normalizeModerationSettings, reduceModerationLabels,
    moderationWithdrawalTags
  } = sandbox.__clientTest;
  const address = `30617:${owner}:dummy`;
  const policy = { sources: [{ pubkey: attacker, scope: address, relays: [],
    actions: { spam: "hide", "copyright-complaint": "warn" } }] };
  const modLabel = { ...validWireEvent, id: "a1".repeat(32), pubkey: attacker,
    kind: 1985, tags: [["L", namespace], ["l", "spam", namespace], ["e", root.id]],
    content: "<script>moderator explanation</script>" };
  const withdrawal = { ...validWireEvent, id: "a2".repeat(32), pubkey: attacker,
    kind: 5, tags: moderationWithdrawalTags(modLabel) };
  const reduce = (events, settings = policy, repoAddress = address) =>
    reduceModerationLabels(events, buildDeletionIndex(events), settings, repoAddress);
  ok(reduce([modLabel]).get(root.id)?.action === "hide"
    && reduce([modLabel], { sources: [] }).size === 0
    && reduce([modLabel], policy, `30617:${owner}:other`).size === 0,
    "only explicitly selected moderator keys and repository scopes affect visibility");
  const reordered = { ...modLabel, tags: [...modLabel.tags, ...modLabel.tags].reverse() };
  ok(JSON.stringify([...reduce([modLabel]).entries()]) === JSON.stringify([...reduce([reordered, reordered]).entries()]),
    "label targets, qualified categories and repeated deliveries are semantic sets");
  ok(moderationLabelEntries({ ...modLabel, tags: [["L", namespace], ["l", "spam"], ["e", root.id]] }).length === 0
    && moderationLabelEntries({ ...modLabel, tags: [["L", namespace], ["l", "spam", "other"], ["e", root.id]] }).length === 0
    && moderationLabelEntries({ ...modLabel, tags: [["L", namespace], ["l", "unknown", namespace], ["e", root.id]] }).length === 0,
    "unqualified, foreign and unknown moderation labels never become instructions");
  const permutations = values => values.length ? values.flatMap((value, i) =>
    permutations(values.filter((_, j) => i !== j)).map(rest => [value, ...rest])) : [[]];
  for (const sequence of permutations([root, modLabel, withdrawal])) {
    const received = [];
    for (const event of sequence) {
      received.push(event);
      const hidden = reduce(received).has(root.id);
      assert.equal(hidden, received.includes(modLabel) && !received.includes(withdrawal));
    }
    assert.equal(reduce(received).size, 0);
  }
  ok(true, "target, label and withdrawal converge in all six arrival orders");
  const forgedWithdrawal = { ...withdrawal, pubkey: owner };
  const deleteDeletion = { ...validWireEvent, kind: 5, pubkey: attacker, tags: [["e", withdrawal.id]] };
  ok(reduce([modLabel, forgedWithdrawal]).has(root.id)
    && !reduce([modLabel, withdrawal, deleteDeletion]).has(root.id)
    && !moderationWithdrawalTags(modLabel).some(tag => tag[0] === "a" || tag[1] === root.id),
    "withdrawals require the label author and never delete contributions or undo tombstones");
  const anotherLabel = { ...modLabel, id: "a3".repeat(32) };
  const complaint = { ...modLabel, id: "a4".repeat(32), tags: [["L", namespace], ["l", "copyright-complaint", namespace], ["e", root.id]] };
  ok(reduce([modLabel, anotherLabel, complaint]).get(root.id).reasons.length === 3
    && reduce([modLabel, anotherLabel, complaint, withdrawal]).get(root.id).action === "hide"
    && reduce([modLabel, complaint, withdrawal]).get(root.id).action === "warn",
    "same-time labels are independent; withdrawing one retains others and hide outranks warn");
  ok(normalizeModerationSettings({ sources: [policy.sources[0], policy.sources[0], { pubkey: "invalid" }] }).sources.length === 1,
    "moderator preferences normalize duplicates and reject invalid public keys");

  const modApp = new App();
  modApp.nostrEventCache = new Map();
  modApp.moderationSettings = policy;
  modApp.currentRepo = { id: "dummy", name: "dummy" };
  const secretRoot = { ...root, content: "ROOT_PAYLOAD_SECRET", tags: [...root.tags, ["subject", "ROOT_TITLE_SECRET"]] };
  const secretParent = { ...parent, content: "PARENT_PAYLOAD_SECRET" };
  const parentLabel = { ...modLabel, id: "a5".repeat(32), tags: [["L", namespace], ["l", "spam", namespace], ["e", parent.id]] };
  modApp.cacheEvents([secretRoot, modLabel, parentLabel]);
  const modData = { announcement, address, issues: [secretRoot], pullRequests: [], patchRoots: [], patches: [], prUpdates: [],
    statuses: [], comments: [secretParent, child], stars: [], deletionIndex: buildDeletionIndex([]) };
  modApp.nostrData = { dummy: modData };
  modApp.nostrLoaded = true;
  modApp.reapplyModeration();
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, { innerHTML: "", textContent: "", value: "", className: "",
      classList: { add() {}, remove() {}, toggle() {} }, focus() {}, setSelectionRange() {} });
    return elements.get(id);
  };
  sandbox.document.getElementById = element;
  modApp.renderNostrList("issues-list", [secretRoot], modData, "Empty");
  ok(!element("issues-list").innerHTML.includes("ROOT_PAYLOAD_SECRET")
    && !element("issues-list").innerHTML.includes("ROOT_TITLE_SECRET")
    && element("issues-list").innerHTML.includes("Show anyway")
    && !element("issues-list").innerHTML.includes("<script>"),
    "hidden list payloads and titles are absent from DOM; explanations are escaped");
  modApp.renderThreadView(root.id, "issue");
  const threadHtml = element("issue-detail-content").innerHTML;
  ok(!threadHtml.includes("ROOT_PAYLOAD_SECRET") && !threadHtml.includes("ROOT_TITLE_SECRET")
    && !threadHtml.includes("PARENT_PAYLOAD_SECRET") && threadHtml.includes(child.content)
    && threadHtml.includes('data-depth="1"'),
    "direct links redact root and parent payloads without suppressing visible descendants");
  modApp.currentCommentParentId = parent.id;
  element("issue-comment-body").value = "retained draft";
  modApp.renderThreadView(root.id, "issue");
  ok(modApp.commentDrafts.get(root.id) === "retained draft"
    && modApp.currentCommentParentId === parent.id
    && element("comment-reply-context").textContent.includes("now hidden"),
    "a newly hidden reply target preserves the draft and relation rather than silently redirecting");
  modApp.moderationReveals.add(`${address}:${root.id}`);
  modApp.renderThreadView(root.id, "issue");
  ok(element("issue-detail-content").innerHTML.includes("ROOT_PAYLOAD_SECRET")
    && modApp.presentationCount([secretRoot, secretParent], modData) === "1 (+1 hidden)",
    "temporary reveal restores only the selected payload and counts match visibility");
  modApp.moderationSettings = { sources: [] };
  modApp.reapplyModeration();
  ok(!modApp.moderationHidden(secretParent, modData), "removing trust immediately restores cached content");
  modApp.moderationSettings = policy;
  modApp.cacheEvents([withdrawal]);
  modApp.cacheEvents([]);
  modApp.reapplyModeration();
  const reloaded = new App();
  ok(!modData.moderation.has(root.id)
    && !reduce(reloaded.cachedEvents(() => true)).has(root.id),
    "empty observations and cache reload never resurrect a withdrawn label");
  ok(!verificationService.maintainerPubkeys(announcement).has(attacker)
    && !verificationService.isAuthorizedStatus({ ...modLabel, kind: 1632 }, secretRoot, announcement)
    && reduceCommitCiStatuses([modLabel], announcement, buildDeletionIndex([])).size === 0
    && !modApp.moderationDecision(announcement, modData),
    "moderator trust grants no repository or status authority and labels are not CI results");

  const hiddenPatch = { ...patchTwo, content: "Subject: PATCH_TITLE_SECRET\nPATCH_BODY_SECRET" };
  const hiddenRevision = { ...revisionRoot, content: "Subject: REVISION_TITLE_SECRET\nREVISION_BODY_SECRET" };
  const patchLabel = { ...modLabel, id: "a6".repeat(32), tags: [["L", namespace], ["l", "spam", namespace], ["e", patchTwo.id], ["e", revisionRoot.id]] };
  modApp.cacheEvents([patchLabel]);
  Object.assign(modData, { patchRoots: [patchRoot], patches: [patchThree, hiddenPatch, patchRoot, hiddenRevision, revisionSecond] });
  modApp.reapplyModeration();
  modApp.renderThreadView(patchRoot.id, "patch");
  const patchHtml = element("pr-detail-content").innerHTML;
  ok(!patchHtml.includes("PATCH_TITLE_SECRET") && !patchHtml.includes("PATCH_BODY_SECRET")
    && !patchHtml.includes("REVISION_TITLE_SECRET") && !patchHtml.includes("REVISION_BODY_SECRET")
    && patchHtml.includes(patchThree.content) && patchHtml.includes(revisionSecond.content)
    && patchHtml.includes("(hidden)"),
    "hidden intermediate patches and revision roots retain descendants without leaking payload or selector titles");
  const pr = { ...validWireEvent, id: "a7".repeat(32), pubkey: rootAuthor, kind: 1618, created_at: 100,
    tags: [["a", address], ["p", owner], ["subject", "PR_TITLE_SECRET"], ["clone", "https://old.example/repo.git"], ["c", "1".repeat(40)], ["e", patchRoot.id]] };
  const update = { ...validWireEvent, id: "a8".repeat(32), pubkey: rootAuthor, kind: 1619, created_at: 200,
    tags: [["a", address], ["p", owner], ["E", pr.id], ["P", rootAuthor], ["clone", "https://new.example/UPDATE_SECRET.git"], ["c", "2".repeat(40)]] };
  const updateLabel = { ...modLabel, id: "a9".repeat(32), tags: [["L", namespace], ["l", "spam", namespace], ["e", update.id]] };
  Object.assign(modData, { pullRequests: [pr], prUpdates: [update] });
  modApp.cacheEvents([pr, update, updateLabel]);
  modApp.reapplyModeration();
  modApp.renderThreadView(pr.id, "pr");
  ok(modApp.latestPrUpdate(pr, modData).id === update.id
    && !element("pr-detail-content").innerHTML.includes("UPDATE_SECRET")
    && !element("pr-detail-content").innerHTML.includes("old.example")
    && !element("pr-detail-content").innerHTML.includes("Source tip:"),
    "hidden latest PR update withholds source data without selecting an older tip");
  const prLabel = { ...modLabel, id: "aa".repeat(32), tags: [["L", namespace], ["l", "spam", namespace], ["e", pr.id]] };
  modApp.cacheEvents([prLabel]);
  modApp.reapplyModeration();
  modApp.renderThreadView(patchRoot.id, "patch");
  ok(!element("pr-detail-content").innerHTML.includes("PR_TITLE_SECRET"),
    "linked PR previews do not leak hidden titles");
  modData.deletionIndex = buildDeletionIndex([{ ...withdrawal, pubkey: rootAuthor, tags: [["e", pr.id]] }]);
  const revealCount = modApp.moderationReveals.size;
  modApp.revealModeratedEvent(pr.id);
  ok(modApp.moderationReveals.size === revealCount, "Show anyway never overrides an author deletion");
  modData.deletionIndex = buildDeletionIndex([]);

  const priorFetch = clientNostrService.fetchEvents;
  const priorModRefresh = modApp.refreshAllNostr;
  const queryLog = [];
  modApp.nostrEventCache = new Map([[modLabel.id, modLabel]]);
  clientNostrService.fetchEvents = async (filters, timeout, relays, recordWarnings, onWarning) => {
    queryLog.push({ filters, relays });
    if (filters[0].kinds.includes(1985)) { onWarning?.("one moderator relay unavailable"); return []; }
    return [withdrawal];
  };
  await modApp.refreshModerationLabels([root.id], [address], ["wss://project.example"]);
  ok(queryLog.some(query => query.filters.some(filter => filter.kinds.includes(1985)
      && filter.authors[0] === attacker && filter["#e"][0] === root.id && !filter["#a"]))
    && queryLog.some(query => query.filters.some(filter => filter.kinds.includes(5) && filter["#e"].includes(modLabel.id)))
    && modApp.moderationDiagnostics.includes("one moderator relay unavailable")
    && eventIsDeleted(modLabel, buildDeletionIndex(modApp.cachedEvents(() => true))),
    "empty label responses still query cached-label withdrawals and report partial moderation failures");
  modApp.moderationSettings = { sources: [] };
  queryLog.length = 0;
  await modApp.refreshModerationLabels([root.id], [address], ["wss://project.example"]);
  ok(queryLog.length === 0, "no selected moderators means no moderation relay queries");
  modApp.moderationSettings = policy;
  clientNostrService.fetchEvents = async filters => {
    if (filters[0].kinds.includes(1985)) {
      modApp.moderationSettings = { sources: [] };
      modApp.moderationGeneration++;
      return [modLabel];
    }
    return [];
  };
  await modApp.refreshModerationLabels([root.id], [address], ["wss://project.example"]);
  modApp.reapplyModeration();
  ok(modData.moderation.size === 0, "late query results cannot restore a moderator removed during refresh");
  clientNostrService.fetchEvents = priorFetch;
  modApp.refreshAllNostr = () => {};
  modApp.renderModerationUpdate = () => modApp.reapplyModeration();
  modApp.setModerationSettings(policy);
  const signedInKey = clientNostrService.pubkey;
  clientNostrService.pubkey = null;
  const anonymousPolicy = new App().moderationSettings;
  clientNostrService.pubkey = signedInKey;
  ok(anonymousPolicy.sources[0].pubkey === attacker && storage.has(settingsKey),
    "local moderation preferences persist independently of sign-in without probing an extension");
  const revokeApp = new App();
  const otherAddress = `30617:${owner}:other`;
  const otherRoot = { ...secretRoot, id: "b1".repeat(32), tags: [["a", otherAddress], ["p", owner]] };
  const otherLabel = { ...modLabel, id: "b2".repeat(32), tags: [["L", namespace], ["l", "spam", namespace], ["e", otherRoot.id]] };
  const remainingLabel = { ...parentLabel, id: "b3".repeat(32), pubkey: maintainer };
  const allScopes = { sources: [
    ...["*", address, otherAddress].map(scope => ({ ...policy.sources[0], scope })),
    { ...policy.sources[0], pubkey: maintainer, scope: "*" }
  ] };
  revokeApp.nostrEventCache = new Map();
  revokeApp.cacheEvents([secretRoot, otherRoot, modLabel, otherLabel, remainingLabel]);
  const revokeData = { ...modData, moderation: new Map() };
  const revokeOtherData = { ...modData, address: otherAddress, issues: [otherRoot], moderation: new Map() };
  revokeApp.nostrData = { dummy: revokeData, other: revokeOtherData };
  revokeApp.currentRepo = { id: "dummy", name: "dummy" };
  let revocationDialog = "";
  let refreshRequests = 0;
  revokeApp.moderationDialog = (_, body) => { revocationDialog = body; };
  revokeApp.renderModerationUpdate = () => revokeApp.reapplyModeration();
  revokeApp.refreshAllNostr = () => { refreshRequests++; };
  revokeApp.setModerationSettings(allScopes);
  revokeApp.openModerationSettings();
  ok((revocationDialog.match(/Stop trusting this person everywhere<\/button>/g) || []).length === 2
    && (revocationDialog.match(/Remove only this scope entry<\/button>/g) || []).length === 4
    && revocationDialog.indexOf("Trusted people") < revocationDialog.indexOf("Add or update a trusted person"),
    "moderation dialog groups people with prominent all-scope revocation and explicit scoped removal");
  const repositoryEntry = revokeApp.moderationSettings.sources.findIndex(source => source.pubkey === attacker && source.scope === address);
  revokeApp.removeModerationSource(repositoryEntry);
  ok(revokeApp.moderationSettings.sources.filter(source => source.pubkey === attacker).length === 2
    && revokeApp.moderationHidden(secretRoot, revokeData),
    "removing only a repository entry leaves the same person's global trust intact");
  revokeApp.setModerationSettings(allScopes);
  const generationBeforeRevoke = revokeApp.moderationGeneration;
  const rawIdsBeforeRevoke = [...revokeApp.nostrEventCache.keys()].sort().join(",");
  const selectedPrBeforeRevoke = revokeApp.latestPrUpdate(pr, revokeData);
  // Hold an already-started label query until after the key is revoked.
  let finishOldQuery;
  clientNostrService.fetchEvents = filters => filters[0].kinds.includes(1985)
    ? new Promise(resolve => { finishOldQuery = resolve; }) : Promise.resolve([]);
  const oldQuery = revokeApp.refreshModerationLabels([root.id], [address], ["wss://project.example"]);
  revokeApp.removeModerationPerson(attacker);
  ok(!revokeApp.moderationSettings.sources.some(source => source.pubkey === attacker)
    && revokeApp.moderationSettings.sources.some(source => source.pubkey === maintainer)
    && !revokeApp.moderationHidden(secretRoot, revokeData)
    && !revokeApp.moderationHidden(otherRoot, revokeOtherData)
    && revokeApp.moderationHidden(secretParent, revokeData)
    && revokeApp.moderationGeneration > generationBeforeRevoke
    && refreshRequests > 0,
    "stop trusting everywhere immediately revokes every scope while retaining other people's judgments");
  ok(!new App().moderationSettings.sources.some(source => source.pubkey === attacker)
    && [...revokeApp.nostrEventCache.keys()].sort().join(",") === rawIdsBeforeRevoke
    && revokeApp.latestPrUpdate(pr, revokeData) === selectedPrBeforeRevoke,
    "all-scope revocation persists across reload without deleting facts or changing the selected PR update");
  finishOldQuery([modLabel]);
  await oldQuery;
  revokeApp.reapplyModeration();
  ok(!revokeApp.moderationHidden(secretRoot, revokeData)
    && !revocationDialog.includes(`app.removeModerationPerson('${attacker}')`),
    "an in-flight label query cannot undo all-scope revocation and the dialog removes the person");
  clientNostrService.fetchEvents = priorFetch;
  modApp.setModerationSettings(policy);

  const oldSignAndPublish = clientNostrService.signAndPublish;
  const oldLogin = clientNostrService.login;
  const oldPublicationRelays = modApp.publicationRelayUrls;
  let publishedTemplate;
  let publicationCount = 0;
  clientNostrService.pubkey = attacker;
  clientNostrService.login = async () => true;
  modApp.publicationRelayUrls = async () => ["wss://project.example"];
  clientNostrService.signAndPublish = async template => {
    publishedTemplate = template;
    publicationCount++;
    return { ...validWireEvent, ...template, id: (publicationCount === 1 ? "ab" : "ac").repeat(32), pubkey: attacker };
  };
  modApp.nostrEventCache = new Map([[secretRoot.id, secretRoot]]);
  modApp.moderationPublishContext = { id: secretRoot.id, repoId: "dummy" };
  element("label-category").value = "spam";
  element("label-explanation").value = "Public spam judgment";
  await modApp.publishModerationLabel();
  const publishedLabel = modApp.nostrEventCache.get("ab".repeat(32));
  ok(publishedTemplate?.kind === 1985 && publishedLabel
    && publishedTemplate.tags.some(tag => tag[0] === "e" && tag[1] === secretRoot.id)
    && !publishedTemplate.tags.some(tag => tag[0] === "a" || tag[0] === "p")
    && modData.moderation.has(secretRoot.id),
    "acknowledged label publication updates visibility immediately without closing or author-banning");
  await modApp.withdrawModerationLabel(publishedLabel.id, "dummy");
  ok(publishedTemplate.kind === 5
    && publishedTemplate.tags[0][1] === publishedLabel.id
    && !modData.moderation.has(secretRoot.id)
    && modApp.nostrEventCache.has(secretRoot.id),
    "acknowledged label withdrawal restores visibility immediately while retaining the contribution");
  clientNostrService.pubkey = owner;
  await modApp.withdrawModerationLabel(publishedLabel.id, "dummy");
  ok(publicationCount === 2, "another signer cannot publish a withdrawal through the moderation UI");
  clientNostrService.signAndPublish = oldSignAndPublish;
  clientNostrService.login = oldLogin;
  clientNostrService.pubkey = signedInKey;
  modApp.publicationRelayUrls = oldPublicationRelays;
  modApp.refreshAllNostr = priorModRefresh;
  sandbox.document.getElementById = originalGetElementById;
  storage.delete(settingsKey);

  console.log(`\n${passed} passed, 0 failed`);
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
