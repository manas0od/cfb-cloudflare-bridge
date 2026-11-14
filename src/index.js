
import { DurableObject } from "cloudflare:workers";

const VERSION = "0.4.0";
const MAX_BODY = 4096;
const REQUEST_TIMEOUT = 5000;

async function validToken(request, expectedToken) {
  if (!expectedToken) return false;

  const actual = request.headers.get("Authorization") || "";
  const expected = `Bearer ${expectedToken}`;
  const encoder = new TextEncoder();

  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(actual)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected))
  ]);

  const aa = new Uint8Array(a);
  const bb = new Uint8Array(b);

  let difference = 0;
  for (let i = 0; i < aa.length; i++) {
    difference |= aa[i] ^ bb[i];
  }

  return difference === 0;
}

export default {
  async fetch(request, env) {
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

    if (url.pathname === "/connect" || url.pathname === "/request") {
      if (!(await validToken(request, env.BRIDGE_TOKEN))) {
        return new Response("Unauthorized", { status: 401 });
      }
    }

    if (url.pathname === "/connect") {
      if (
        request.method !== "GET" ||
        request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
      ) {
        return new Response("WebSocket required", { status: 426 });
      }

      return stub.fetch(request);
    }

    if (url.pathname === "/request") {
      if (request.method !== "POST") {
        return new Response("POST required", { status: 405 });
      }

      const body = await request.text();

      if (body.length > MAX_BODY) {
        return new Response("Request too large", { status: 413 });
      }

      return stub.fetch(
        new Request("https://bridge.internal/request", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body
        })
      );
    }

    return Response.json({
      service: "claude-freedom-bridge",
      message: "Worker is running"
    });
  }
};

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
        return new Response("POST required", { status: 405 });
      }

      let data;

      try {
        data = await request.json();
      } catch {
        return Response.json({ error: "invalid_json" }, { status: 400 });
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
        return Response.json({ error: "invalid_request" }, { status: 400 });
      }

      if (!["status", "echo"].includes(data.action)) {
        return Response.json({ error: "unsupported_action" }, { status: 400 });
      }

      if (this.recentIds.has(data.request_id)) {
        return Response.json({ error: "duplicate_request_id" }, { status: 409 });
      }

      const sockets = this.ctx.getWebSockets("agent").filter(
        ws => ws.readyState === WebSocket.OPEN
      );

      if (sockets.length !== 1) {
        return Response.json({ error: "agent_unavailable" }, { status: 503 });
      }

      if (
        data.action === "echo" &&
        (typeof data.payload.message !== "string" ||
         data.payload.message.length > 1000)
      ) {
        return Response.json({ error: "invalid_echo_message" }, { status: 400 });
      }

      const socket = sockets[0];
      const requestId = data.request_id;

      this.recentIds.add(requestId);
      if (this.recentIds.size > 256) {
        this.recentIds.delete(this.recentIds.values().next().value);
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
        }, { status: 504 });
      }
    }

    if (url.pathname === "/connect") {
      if (
        request.method !== "GET" ||
        request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
      ) {
        return new Response("WebSocket required", { status: 426 });
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

    return new Response("Not found", { status: 404 });
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
      ws.send(JSON.stringify({ type: "pong", id: data.id }));
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
