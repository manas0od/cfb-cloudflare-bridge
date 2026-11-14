
import { DurableObject } from "cloudflare:workers";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";

const VERSION = "0.6.1";
const MCP_PROTOCOL = "2025-03-26";
const MAX_BODY = 4096;
const REQUEST_TIMEOUT = 5000;

const WORKER_URL =
  "https://claude-freedom-bridge.manasodvaigaod.workers.dev";

const MCP_RESOURCE = `${WORKER_URL}/mcp`;
const SESSION_COOKIE = "__Host-cfb-session";
const CSRF_COOKIE = "__Host-cfb-csrf";
const SESSION_SECONDS = 12 * 60 * 60;

// ---------- GENERAL HELPERS ----------

function jsonRpc(id, result) {
  return Response.json({
    jsonrpc: "2.0",
    id,
    result
  });
}

function jsonRpcError(id, code, message) {
  return Response.json({
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code, message }
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  for (const item of cookie.split(";")) {
    const index = item.indexOf("=");

    if (index < 0) continue;

    const key = item.slice(0, index).trim();

    if (key === name) {
      return item.slice(index + 1).trim();
    }
  }

  return null;
}

function setCookie(headers, name, value, options = {}) {
  const parts = [
    `${name}=${value}`,
    "Path=/",
    "Secure",
    "SameSite=Strict"
  ];

  if (options.httpOnly) {
    parts.push("HttpOnly");
  }

  if (options.maxAge !== undefined) {
    parts.push(`Max-Age=${options.maxAge}`);
  }

  headers.append("Set-Cookie", parts.join("; "));
}

function clearCookie(headers, name) {
  headers.append(
    "Set-Cookie",
    `${name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`
  );
}

async function constantTimeEqual(a, b) {
  const encoder = new TextEncoder();

  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b))
  ]);

  const aa = new Uint8Array(hashA);
  const bb = new Uint8Array(hashB);

  let difference = 0;

  for (let i = 0; i < aa.length; i++) {
    difference |= aa[i] ^ bb[i];
  }

  return difference === 0;
}

// ---------- TERMUX AGENT AUTHENTICATION ----------

async function validToken(request, expectedToken) {
  if (!expectedToken) return false;

  const actual = request.headers.get("Authorization") || "";
  const expected = `Bearer ${expectedToken}`;

  return constantTimeEqual(actual, expected);
}

// ---------- SIGNED LOGIN SESSION ----------

async function sessionSignature(payload, secret) {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign", "verify"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(payload)
  );

  return Array.from(new Uint8Array(signature))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function createSession(secret) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  const payload = `v1.${expires}`;
  const signature = await sessionSignature(payload, secret);

  return `${payload}.${signature}`;
}

async function verifySession(request, secret) {
  if (!secret || secret.length < 32) return false;

  const cookie = getCookie(request, SESSION_COOKIE);

  if (!cookie) return false;

  const parts = cookie.split(".");

  if (parts.length !== 3 || parts[0] !== "v1") {
    return false;
  }

  const expires = Number(parts[1]);

  if (!Number.isSafeInteger(expires)) return false;
  if (expires <= Math.floor(Date.now() / 1000)) return false;

  const payload = `${parts[0]}.${parts[1]}`;
  const expected = await sessionSignature(payload, secret);

  return constantTimeEqual(parts[2], expected);
}

// ---------- LOGIN PAGE ----------

function safeNext(value, request) {
  try {
    const base = new URL(request.url);
    const target = new URL(value || "/authorize", base);

    if (target.origin !== base.origin) return "/authorize";
    if (target.pathname !== "/authorize") return "/authorize";
    if (target.hash) return "/authorize";

    return target.pathname + target.search;
  } catch {
    return "/authorize";
  }
}

function loginPage(csrf, next, error = false) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>CFB Login</title>
<style>
body {
  margin: 0;
  min-height: 100vh;
  display: grid;
  place-items: center;
  background: #10131b;
  color: #eef1f8;
  font-family: system-ui, sans-serif;
}
main {
  width: min(360px, calc(100% - 48px));
  padding: 24px;
  background: #1b202c;
  border-radius: 14px;
}
h1 { font-size: 22px; }
p { color: #aeb8ca; }
input {
  box-sizing: border-box;
  width: 100%;
  padding: 13px;
  margin: 10px 0;
  border: 1px solid #424b60;
  border-radius: 8px;
  background: #10131b;
  color: white;
}
button {
  width: 100%;
  padding: 13px;
  margin-top: 10px;
  border: 0;
  border-radius: 8px;
  background: #6c8cff;
  color: #10131b;
  font-weight: 700;
}
.error { color: #ff8585; }
</style>
</head>
<body>
<main>
<h1>Claude Freedom Bridge</h1>
<p>Sign in to authorize your MCP connection.</p>
${error ? '<p class="error">Incorrect password or expired login form.</p>' : ""}
<form method="POST">
<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
<input type="hidden" name="next" value="${escapeHtml(next)}">
<input
  type="password"
  name="password"
  placeholder="Login password"
  autocomplete="current-password"
  required
>
<button type="submit">Sign in</button>
</form>
</main>
</body>
</html>`;
}

function htmlResponse(html, headers = new Headers(), status = 200) {
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
  );

  return new Response(html, { status, headers });
}

// ---------- OAUTH AUTHORIZATION PAGE ----------

function consentPage(details, handle) {
  const name = escapeHtml(details.clientName);

  const publisher = details.clientDomain
    ? `Published by <strong>${escapeHtml(details.clientDomain)}</strong>.`
    : "This application registered itself; its name is not verified.";

  const scopes = details.scope
    .map(scope => `
      <label>
        <input type="checkbox" name="scope"
          value="${escapeHtml(scope)}" checked>
        ${escapeHtml(scope)}
      </label>
    `)
    .join("<br>");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize CFB</title>
<style>
body {
  margin: 0;
  min-height: 100vh;
  display: grid;
  place-items: center;
  background: #10131b;
  color: #eef1f8;
  font-family: system-ui, sans-serif;
}
main {
  width: min(420px, calc(100% - 48px));
  padding: 24px;
  background: #1b202c;
  border-radius: 14px;
}
p { color: #b7c0d0; }
label { display: block; margin: 12px 0; }
button {
  padding: 12px 18px;
  margin: 12px 8px 0 0;
  border: 0;
  border-radius: 8px;
  font-weight: 700;
}
.allow { background: #6c8cff; }
.deny { background: #343b4b; color: white; }
</style>
</head>
<body>
<main>
<h1>Authorize access</h1>
<h2>${name}</h2>
<p>${publisher}</p>
<p>Access will be sent to:
<strong>${escapeHtml(details.redirectHost)}</strong>
</p>
${details.redirectIsLoopback
  ? "<p><strong>Warning:</strong> This application is requesting access through a local computer address. Continue only if you initiated this sign-in.</p>"
  : ""}
<form method="POST">
<input type="hidden" name="handle" value="${escapeHtml(handle)}">
${scopes}
<button class="allow" name="decision" value="approve">Allow</button>
<button class="deny" name="decision" value="deny">Deny</button>
</form>
</main>
</body>
</html>`;
}

// ---------- AUTHORIZE ENDPOINT ----------
//
// /authorize serves THREE different requests. They must be told apart by
// what the request contains, never by whether a session cookie happens to be
// present:
//
//   GET                      -> login page (no session) or consent page
//   POST with "password"     -> the LOGIN form
//   POST with "handle"       -> the CONSENT form
//
// (v0.6.0 decided by session state alone. A login form submitted while a
// valid session cookie existed was therefore treated as a consent form, and
// failed with "Missing authorization handle.")

function showLoginPage(request, status = 200) {
  let csrf = getCookie(request, CSRF_COOKIE);

  if (!csrf || !/^[a-f0-9]{32}$/.test(csrf)) {
    csrf = crypto.randomUUID().replace(/-/g, "");
  }

  const url = new URL(request.url);
  const next = url.pathname + url.search;

  const headers = new Headers();

  setCookie(headers, CSRF_COOKIE, csrf, {
    maxAge: 600
  });

  return htmlResponse(loginPage(csrf, next), headers, status);
}

async function handleLoginPost(request, form, sessionSecret, loginPassword) {
  const csrfForm = String(form.get("csrf") || "");
  const csrfCookie = getCookie(request, CSRF_COOKIE);

  if (
    !csrfCookie ||
    !/^[a-f0-9]{32}$/.test(csrfCookie) ||
    !(await constantTimeEqual(csrfForm, csrfCookie))
  ) {
    return new Response("Invalid login form. Reload and try again.", {
      status: 403
    });
  }

  const suppliedPassword = String(form.get("password") || "");

  if (
    !(await constantTimeEqual(suppliedPassword, loginPassword))
  ) {
    return htmlResponse(
      loginPage(
        csrfCookie,
        safeNext(String(form.get("next") || ""), request),
        true
      ),
      new Headers(),
      401
    );
  }

  const session = await createSession(sessionSecret);
  const headers = new Headers();

  setCookie(headers, SESSION_COOKIE, session, {
    httpOnly: true,
    maxAge: SESSION_SECONDS
  });

  clearCookie(headers, CSRF_COOKIE);

  headers.set(
    "Location",
    safeNext(String(form.get("next") || ""), request)
  );

  return new Response(null, {
    status: 303,
    headers
  });
}

function authorizationFailure(error) {
  if (error?.redirectTo) {
    return Response.redirect(error.redirectTo, 302);
  }

  console.error("CFB authorization error:", error);

  return new Response(
    "Authorization failed. Please restart the sign-in process.",
    { status: 400 }
  );
}

async function showConsentPage(request, oauth) {
  try {
    const authRequest = await oauth.parseAuthRequest(request);
    const details = await oauth.describeConsent(authRequest);
    const consent = await oauth.beginConsent(authRequest);

    consent.headers.set(
      "Content-Type",
      "text/html; charset=utf-8"
    );

    return htmlResponse(
      consentPage(details, consent.handle),
      consent.headers
    );
  } catch (error) {
    return authorizationFailure(error);
  }
}

async function handleConsentPost(request, form, oauth) {
  const handle = String(form.get("handle") || "");

  if (!handle) {
    return new Response("Missing authorization handle.", {
      status: 400
    });
  }

  try {
    if (form.get("decision") !== "approve") {
      const denied = await oauth.denyConsent(request, handle);

      return new Response(null, {
        status: 302,
        headers: denied.headers
      });
    }

    const approved = await oauth.approveConsent(
      request,
      handle,
      {
        scope: form.getAll("scope").map(String)
      }
    );

    const { redirectTo } = await oauth.completeAuthorization({
      request: approved.request,
      userId: "cfb-owner",
      metadata: {},
      scope: approved.request.scope,
      props: {
        userId: "cfb-owner"
      }
    });

    approved.headers.set("Location", redirectTo);

    return new Response(null, {
      status: 302,
      headers: approved.headers
    });
  } catch (error) {
    return authorizationFailure(error);
  }
}

async function handleAuthorize(request, env) {
  const oauth = env.OAUTH_PROVIDER;
  const sessionSecret = env.CFB_SESSION_SECRET;
  const loginPassword = env.CFB_LOGIN_PASSWORD;

  if (!sessionSecret || sessionSecret.length < 32 || !loginPassword) {
    return new Response("OAuth login secrets are not configured.", {
      status: 500
    });
  }

  const signedIn = await verifySession(request, sessionSecret);

  if (request.method === "GET") {
    if (!signedIn) {
      return showLoginPage(request);
    }

    return showConsentPage(request, oauth);
  }

  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const contentLength = Number(
    request.headers.get("Content-Length") || "0"
  );

  if (contentLength > MAX_BODY) {
    return new Response("Request too large", { status: 413 });
  }

  const form = await request.formData();

  // LOGIN form: always handled as a login, whether or not a session
  // cookie is already present. CSRF and password are re-checked.
  if (form.has("password")) {
    return handleLoginPost(
      request,
      form,
      sessionSecret,
      loginPassword
    );
  }

  // CONSENT form: only valid for a signed-in browser.
  if (form.has("handle")) {
    if (!signedIn) {
      // The login session expired between the consent page and the
      // click. Show the login page again; after login the browser is
      // sent back to /authorize and gets a fresh consent page.
      return showLoginPage(request, 401);
    }

    return handleConsentPost(request, form, oauth);
  }

  return new Response("Invalid authorization form submission.", {
    status: 400
  });
}

// ---------- MCP TOOLS ----------

async function handleMcp(request, env, stub) {
  if (request.method !== "POST") {
    return new Response("POST required", { status: 405 });
  }

  const body = await request.text();

  if (body.length > MAX_BODY) {
    return new Response("Request too large", { status: 413 });
  }

  let data;

  try {
    data = JSON.parse(body);
  } catch {
    return jsonRpcError(null, -32700, "Parse error");
  }

  if (
    !data ||
    data.jsonrpc !== "2.0" ||
    typeof data.method !== "string" ||
    (
      !Object.prototype.hasOwnProperty.call(data, "id") &&
      !data.method.startsWith("notifications/")
    )
  ) {
    return jsonRpcError(data?.id ?? null, -32600, "Invalid request");
  }

  const id = data.id ?? null;
  const params = data.params || {};

  if (data.method === "notifications/initialized") {
    return new Response(null, { status: 202 });
  }

  if (data.method === "notifications/cancelled") {
    return new Response(null, { status: 202 });
  }

  if (data.method === "initialize") {
    return jsonRpc(id, {
      protocolVersion: MCP_PROTOCOL,
      capabilities: {
        tools: {
          listChanged: false
        }
      },
      serverInfo: {
        name: "claude-freedom-bridge",
        version: VERSION
      },
      instructions:
        "CFB provides read-only status diagnostics and an echo test. It does not provide shell execution."
    });
  }

  if (data.method === "ping") {
    return jsonRpc(id, {});
  }

  if (data.method === "tools/list") {
    return jsonRpc(id, {
      tools: [
        {
          name: "status",
          description:
            "Check whether the connected Termux agent is online and get device runtime information.",
          inputSchema: {
            type: "object",
            properties: {},
            additionalProperties: false
          }
        },
        {
          name: "echo",
          description:
            "Send a test message through the Termux agent and receive it back.",
          inputSchema: {
            type: "object",
            properties: {
              message: {
                type: "string",
                description: "The message to echo back.",
                maxLength: 1000
              }
            },
            required: ["message"],
            additionalProperties: false
          }
        }
      ]
    });
  }

  if (data.method === "tools/call") {
    if (!params || typeof params.name !== "string") {
      return jsonRpcError(id, -32602, "Invalid tool parameters");
    }

    const action = params.name;
    const args = params.arguments || {};

    if (!["status", "echo"].includes(action)) {
      return jsonRpcError(id, -32602, "Unknown tool");
    }

    if (
      !args ||
      typeof args !== "object" ||
      Array.isArray(args)
    ) {
      return jsonRpcError(id, -32602, "Invalid tool arguments");
    }

    if (
      action === "echo" &&
      (
        typeof args.message !== "string" ||
        args.message.length > 1000
      )
    ) {
      return jsonRpcError(id, -32602, "Invalid echo message");
    }

    if (action === "status" && Object.keys(args).length !== 0) {
      return jsonRpcError(id, -32602, "Status takes no arguments");
    }

    const requestId = crypto.randomUUID().replace(/-/g, "");

    let upstream;

    try {
      upstream = await stub.fetch(
        new Request("https://bridge.internal/request", {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            type: "request",
            request_id: requestId,
            action,
            payload: action === "echo"
              ? { message: args.message }
              : {}
          })
        })
      );
    } catch {
      return jsonRpc(id, {
        isError: true,
        content: [{
          type: "text",
          text: "Could not contact the CFB Durable Object."
        }]
      });
    }

    let result;

    try {
      result = await upstream.json();
    } catch {
      return jsonRpc(id, {
        isError: true,
        content: [{
          type: "text",
          text: "Invalid response from CFB Durable Object."
        }]
      });
    }

    if (!upstream.ok || !result.result?.ok) {
      return jsonRpc(id, {
        isError: true,
        content: [{
          type: "text",
          text: JSON.stringify(result)
        }]
      });
    }

    return jsonRpc(id, {
      content: [{
        type: "text",
        text: JSON.stringify(result.result)
      }],
      structuredContent: result.result,
      isError: false
    });
  }

  return jsonRpcError(id, -32601, "Method not found");
}

// ---------- MCP AUTHENTICATED HANDLER ----------

const mcpHandler = {
  async fetch(request, env, ctx) {
    const id = env.BRIDGE.idFromName("main");
    const stub = env.BRIDGE.get(id);

    return handleMcp(request, env, stub);
  }
};

// ---------- PUBLIC / AGENT HANDLER ----------

const defaultHandler = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({
        status: "ok",
        service: "claude-freedom-bridge",
        version: VERSION
      });
    }

    const id = env.BRIDGE.idFromName("main");
    const stub = env.BRIDGE.get(id);

    if (url.pathname === "/do-status") {
      return stub.fetch("https://bridge.internal/status");
    }

    if (
      url.pathname === "/connect" ||
      url.pathname === "/request"
    ) {
      if (!(await validToken(request, env.BRIDGE_TOKEN))) {
        return new Response("Unauthorized", {
          status: 401
        });
      }
    }

    if (url.pathname === "/connect") {
      if (
        request.method !== "GET" ||
        request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
      ) {
        return new Response("WebSocket required", {
          status: 426
        });
      }

      return stub.fetch(request);
    }

    if (url.pathname === "/request") {
      if (request.method !== "POST") {
        return new Response("POST required", {
          status: 405
        });
      }

      const body = await request.text();

      if (body.length > MAX_BODY) {
        return new Response("Request too large", {
          status: 413
        });
      }

      return stub.fetch(
        new Request("https://bridge.internal/request", {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body
        })
      );
    }

    if (url.pathname === "/authorize") {
      return handleAuthorize(request, env);
    }

    return Response.json({
      service: "claude-freedom-bridge",
      message: "Worker is running",
      version: VERSION
    });
  }
};

// ---------- OAUTH PROVIDER ----------

export default new OAuthProvider({
  apiRoute: "/mcp",
  apiHandler: mcpHandler,
  defaultHandler,

  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",

  scopesSupported: ["mcp:read"],
  requiredScopes: ["mcp:read"],

  resourceMetadata: {
    resource: MCP_RESOURCE
  },

  clientIdMetadataDocumentEnabled: true
});

// ---------- DURABLE OBJECT ----------

export class Bridge extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.pending = new Map();
    this.recentIds = new Set();
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/status") {
      const connections = this.ctx.getWebSockets("agent").filter(
        ws => ws.readyState === WebSocket.OPEN
      ).length;

      return Response.json({
        status: "ready",
        durable_object: "Bridge",
        connections,
        version: VERSION
      });
    }

    if (url.pathname === "/request") {
      if (request.method !== "POST") {
        return new Response("POST required", {
          status: 405
        });
      }

      let data;

      try {
        data = await request.json();
      } catch {
        return Response.json({
          error: "invalid_json"
        }, {
          status: 400
        });
      }

      if (
        !data ||
        data.type !== "request" ||
        typeof data.request_id !== "string" ||
        !/^[a-zA-Z0-9_-]{8,64}$/.test(data.request_id) ||
        !data.payload ||
        typeof data.payload !== "object" ||
        Array.isArray(data.payload)
      ) {
        return Response.json({
          error: "invalid_request"
        }, {
          status: 400
        });
      }

      if (!["status", "echo"].includes(data.action)) {
        return Response.json({
          error: "unsupported_action"
        }, {
          status: 400
        });
      }

      if (this.recentIds.has(data.request_id)) {
        return Response.json({
          error: "duplicate_request_id"
        }, {
          status: 409
        });
      }

      const sockets = this.ctx.getWebSockets("agent").filter(
        ws => ws.readyState === WebSocket.OPEN
      );

      if (sockets.length !== 1) {
        return Response.json({
          error: "agent_unavailable"
        }, {
          status: 503
        });
      }

      if (
        data.action === "echo" &&
        (
          typeof data.payload.message !== "string" ||
          data.payload.message.length > 1000
        )
      ) {
        return Response.json({
          error: "invalid_echo_message"
        }, {
          status: 400
        });
      }

      const socket = sockets[0];
      const requestId = data.request_id;

      this.recentIds.add(requestId);

      if (this.recentIds.size > 256) {
        this.recentIds.delete(
          this.recentIds.values().next().value
        );
      }

      try {
        const result = await new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            this.pending.delete(requestId);
            reject(new Error("request_timeout"));
          }, REQUEST_TIMEOUT);

          this.pending.set(requestId, {
            resolve,
            reject,
            timer,
            socket
          });

          try {
            socket.send(JSON.stringify(data));
          } catch {
            clearTimeout(timer);
            this.pending.delete(requestId);
            reject(new Error("send_failed"));
          }
        });

        return Response.json(result);
      } catch (error) {
        return Response.json({
          error: error.message || "request_failed"
        }, {
          status: 504
        });
      }
    }

    if (url.pathname === "/connect") {
      if (
        request.method !== "GET" ||
        request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
      ) {
        return new Response("WebSocket required", {
          status: 426
        });
      }

      for (const oldSocket of this.ctx.getWebSockets("agent")) {
        try {
          oldSocket.close(4001, "Replaced by reconnect");
        } catch {}
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);

      this.ctx.acceptWebSocket(server, ["agent"]);

      server.serializeAttachment({
        role: "agent",
        connectedAt: Date.now()
      });

      server.send(JSON.stringify({
        type: "connected",
        protocol: 1
      }));

      return new Response(null, {
        status: 101,
        webSocket: client
      });
    }

    return new Response("Not found", {
      status: 404
    });
  }

  async webSocketMessage(ws, message) {
    if (typeof message !== "string" || message.length > 8192) {
      return;
    }

    let data;

    try {
      data = JSON.parse(message);
    } catch {
      return;
    }

    if (
      data.type === "ping" &&
      typeof data.id === "string" &&
      data.id.length <= 64
    ) {
      ws.send(JSON.stringify({
        type: "pong",
        id: data.id
      }));
      return;
    }

    if (
      data.type === "response" &&
      typeof data.request_id === "string"
    ) {
      const pending = this.pending.get(data.request_id);

      if (!pending || pending.socket !== ws) return;

      clearTimeout(pending.timer);
      this.pending.delete(data.request_id);
      pending.resolve(data);
    }
  }

  async webSocketClose(ws) {
    for (const [id, pending] of this.pending) {
      if (pending.socket === ws) {
        clearTimeout(pending.timer);
        this.pending.delete(id);
        pending.reject(new Error("agent_disconnected"));
      }
    }
  }

  async webSocketError(ws) {
    for (const [id, pending] of this.pending) {
      if (pending.socket === ws) {
        clearTimeout(pending.timer);
        this.pending.delete(id);
        pending.reject(new Error("websocket_error"));
      }
    }
  }
}
