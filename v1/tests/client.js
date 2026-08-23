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
  "      App, NostrService, activeReplaceableEvents, actorLabel,",
  "      attributionHtml, attributionLabel, buildDeletionIndex, eventIsDeleted,",
  "      cloneUrlSetFromText, hasRepositoryOwnerTag,",
  "      githubNip39Claims, gistVerifiesNip39,",
  "      isNostrEventShape, isRepositoryStarReaction,",
  "      isValidNip34CollaborationEvent, repositoryStarIdentity,",
  "      repositoryUnstarTags,",
  "      latestAddressableEvents, latestReplaceableEvents, normalizeRelayUrls,",
  "      nip65WriteRelays,",
  "      repositoryEarliestUniqueCommit, repositoryStateMap, scalarTagValues,",
  "      uniqueNip22EventReference, uniqueTagValue,",
  "      externalIdentityService, nostrService, verificationService",
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
  eventIsDeleted,
  externalIdentityService,
  githubNip39Claims,
  gistVerifiesNip39,
  hasRepositoryOwnerTag,
  isNostrEventShape,
  isRepositoryStarReaction,
  isValidNip34CollaborationEvent,
  latestAddressableEvents,
  latestReplaceableEvents,
  nip65WriteRelays,
  normalizeRelayUrls,
  repositoryEarliestUniqueCommit,
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
ok(
  app.statusEventFor(root, {
    announcement,
    statuses: [malformedStatus]
  }) === null
  && app.statusEventFor(root, {
    announcement,
    statuses: [malformedStatus, validStatus]
  })?.id === validStatus.id,
  "malformed status hint slots cannot satisfy required p tags"
);

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
  ]),
  "NIP-65 identity discovery uses the canonical write-relay set"
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
  }).includes("GitHub @alice (verified via NIP-39)")
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

  console.log(`\n${passed} passed, 0 failed`);
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
