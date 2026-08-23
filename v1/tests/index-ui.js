"use strict";

const fs = require("fs");
const html = fs.readFileSync(
  require("path").join(__dirname, "..", "index.html"),
  "utf8"
);
const scriptStart = html.indexOf("<script>");
const scriptEnd = html.indexOf("</script>", scriptStart);
if (scriptStart < 0 || scriptEnd < 0) {
  throw new Error("index.html inline script is missing");
}
const script = html.slice(scriptStart + 8, scriptEnd);

function element(id) {
  return {
    id,
    className: "",
    innerHTML: "",
    textContent: "",
    disabled: false,
    onclick: null,
    value: "",
    style: {display: ""},
    insertAdjacentHTML(_position, value) {
      this.innerHTML += value;
    },
  };
}

const elements = new Map();
for (const id of [
  "statusbox",
  "link-section",
  "link-body",
  "check",
  "why",
  "nostr-signin",
  "nostr-signin-error",
  "nip39-section",
  "nip39-proof",
  "nip39-managed-account",
  "nip39-workflow",
  "nip39-setup",
  "nip39-preview",
  "nip39-error",
  "nip39-auth",
  "nip39-message",
  "nip39-identities",
  "nip39-gist-url",
  "nip39-start",
  "nip39-copy",
  "nip39-remove",
  "nip39-confirm",
  "nip39-cancel",
]) {
  elements.set(id, element(id));
}
const nip39Steps = ["gist", "review", "sign", "publish"].map(step => {
  const mark = {textContent: ""};
  return {
    className: "",
    dataset: {step},
    querySelector(selector) {
      return selector === ".stepmark" ? mark : null;
    },
  };
});
global.document = {
  hidden: false,
  getElementById(id) {
    return elements.get(id) || null;
  },
  querySelectorAll(selector) {
    return selector === "#nip39-steps li" ? nip39Steps : [];
  },
};

const pubkey = "a".repeat(64);
const challenge = {
  kind: 27235,
  created_at: 1787397000,
  tags: [
    ["u", "https://auth.friendly-machines.com/v1/status.php"],
    ["method", "POST"],
    ["action", "recover-link-session"],
    ["challenge", "b".repeat(64)],
  ],
  content: "",
};
global.window = {
  nostr: {
    async getPublicKey() {
      return pubkey;
    },
    async signEvent(requested) {
      return {
        ...requested,
        pubkey,
        id: "c".repeat(64),
        sig: "d".repeat(128),
      };
    },
  },
};

const requests = [];
let nip39Workflow = null;
global.fetch = async (url, options = {}) => {
  const method = options.method || "GET";
  const body = options.body ? JSON.parse(options.body) : null;
  requests.push({url, method, body});
  let payload;
  if (url === "/v1/nip39.php" && method === "POST") {
    if (body?.action === "start") {
      nip39Workflow = {
        id: 41,
        status: "pending",
        phase: "preparing",
        action: body.mode,
        identities: [],
        publications: {},
      };
    } else if (body?.action === "advance"
        && nip39Workflow?.phase === "preparing") {
      nip39Workflow = {
        ...nip39Workflow,
        phase: "awaiting_confirmation",
        identities: [
          {identity: "github:alice", proof: "abcde"},
          {identity: "mastodon:example/@alice", proof: "post-id"},
        ],
      };
    } else if (body?.action === "confirm") {
      nip39Workflow = {
        ...nip39Workflow,
        phase: "ready_to_sign",
      };
    } else if (body?.action === "advance"
        && nip39Workflow?.phase === "ready_to_sign") {
      nip39Workflow = {
        ...nip39Workflow,
        status: "done",
        phase: "publishing",
        event_id: "e".repeat(64),
        publications: {
          "wss://nos.lol": {status: "pending", last_error: null},
        },
      };
    } else {
      throw new Error("unexpected NIP-39 request");
    }
    payload = {
      available: true,
      github: {login: "alice"},
      nostr: {npub: "npub1test", pubkey},
      proof_text:
        "Verifying that I control the following Nostr public key: npub1test",
      workflow: nip39Workflow,
    };
  } else if (method === "GET" && url === "/v1/nip39.php") {
    payload = {
      available: true,
      github: {login: "alice"},
      nostr: {npub: "npub1test", pubkey},
      proof_text:
        "Verifying that I control the following Nostr public key: npub1test",
      workflow: nip39Workflow,
    };
  } else if (method === "GET") {
    payload = {
      browser_session: false,
      identity_recognized: false,
      github: null,
      nostr: null,
      fully_linked: false,
    };
  } else if (body?.action === "challenge") {
    payload = {challenge, expires_at: challenge.created_at + 300};
  } else if (body?.action === "recover") {
    if (JSON.stringify(body.event.tags) !== JSON.stringify(challenge.tags)) {
      throw new Error("browser changed recovery tags");
    }
    payload = {
      browser_session: true,
      identity_recognized: true,
      github: {login: "alice"},
      nostr: {npub: "npub1test", pubkey},
      fully_linked: true,
      recovered: true,
    };
  } else {
    throw new Error("unexpected request");
  }
  return {
    ok: true,
    status: 200,
    async json() {
      return payload;
    },
  };
};
global.alert = () => {
  throw new Error("status UX must not use alert");
};
global.setTimeout = () => 0;
global.setInterval = () => 1;
Object.defineProperty(global, "navigator", {
  configurable: true,
  value: {
    clipboard: {
      async writeText() {},
    },
  },
});

new Function(script)();

async function settle() {
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
}

(async () => {
  await settle();
  const button = elements.get("nostr-signin");
  if (typeof button.onclick !== "function") {
    throw new Error("Sign in with Nostr button was not bound");
  }
  await button.onclick();
  await settle();

  if (requests.length !== 4
      || requests[0].method !== "GET"
      || requests[1].body?.action !== "challenge"
      || requests[2].body?.action !== "recover"
      || requests[3].url !== "/v1/nip39.php"
      || requests[3].method !== "GET") {
    throw new Error("browser recovery request sequence is wrong");
  }
  if (!elements.get("statusbox").innerHTML.includes("Fully bridged")
      || !elements.get("statusbox").innerHTML.includes("@alice")) {
    throw new Error("recovered link was not rendered");
  }
  if (elements.get("link-section").style.display !== "none"
      || elements.get("link-body").style.display !== "none") {
    throw new Error("linking actions remained visible after recovery");
  }
  if (elements.get("nip39-section").style.display !== ""
      || !elements.get("nip39-proof").textContent.includes("npub1test")) {
    throw new Error("optional NIP-39 setup was not shown after full linking");
  }
  if (html.includes("Recover with nos2x")
      || html.includes("Identify this browser with nos2x")
      || html.includes("Not linked yet")) {
    throw new Error("obsolete recovery wording remains in index.html");
  }

  elements.get("nip39-gist-url").value =
    "https://gist.github.com/alice/abcde";
  await elements.get("nip39-start").onclick();
  await settle();
  await settle();
  if (nip39Workflow?.phase !== "awaiting_confirmation"
      || elements.get("nip39-preview").style.display !== ""
      || !elements.get("nip39-identities").innerHTML.includes("mastodon:example/@alice")) {
    throw new Error("NIP-39 proof preparation did not reach complete-set review");
  }
  const actionsBeforeConfirmation = requests
    .filter(request => request.url === "/v1/nip39.php" && request.method === "POST")
    .map(request => request.body?.action);
  if (JSON.stringify(actionsBeforeConfirmation) !== JSON.stringify([
    "start",
    "advance",
  ])) {
    throw new Error("NIP-39 UX requested signing before explicit confirmation");
  }

  await elements.get("nip39-confirm").onclick();
  await settle();
  await settle();
  if (nip39Workflow?.phase !== "publishing"
      || !elements.get("nip39-message").textContent.includes("signature is safely recorded")) {
    throw new Error("confirmed NIP-39 UX did not advance to durable publication");
  }
  console.log("index.html account and NIP-39 UX OK");
})().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
