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
]) {
  elements.set(id, element(id));
}
global.document = {
  getElementById(id) {
    return elements.get(id) || null;
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
global.fetch = async (url, options = {}) => {
  const method = options.method || "GET";
  const body = options.body ? JSON.parse(options.body) : null;
  requests.push({url, method, body});
  let payload;
  if (method === "GET") {
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

  if (requests.length !== 3
      || requests[0].method !== "GET"
      || requests[1].body?.action !== "challenge"
      || requests[2].body?.action !== "recover") {
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
  if (html.includes("Recover with nos2x")
      || html.includes("Identify this browser with nos2x")
      || html.includes("Not linked yet")) {
    throw new Error("obsolete recovery wording remains in index.html");
  }
  console.log("index.html Nostr sign-in UX OK");
})().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
