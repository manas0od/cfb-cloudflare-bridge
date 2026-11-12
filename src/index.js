
import { DurableObject } from "cloudflare:workers";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({
        status: "ok",
        service: "claude-freedom-bridge",
        version: "0.3.0"
      });
    }

    const id = env.BRIDGE.idFromName("main");
    const stub = env.BRIDGE.get(id);

    if (url.pathname === "/do-status") {
      return stub.fetch("https://bridge.internal/status");
    }

    if (url.pathname === "/connect") {
      if (request.method !== "GET") {
        return new Response("Method not allowed", { status: 405 });
      }

      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return new Response("WebSocket required", { status: 426 });
      }

      if (!env.BRIDGE_TOKEN) {
        return new Response("Server configuration error", { status: 503 });
      }

      const authorization = request.headers.get("Authorization") || "";
      const expected = `Bearer ${env.BRIDGE_TOKEN}`;

      const encoder = new TextEncoder();
      const [actualHash, expectedHash] = await Promise.all([
        crypto.subtle.digest("SHA-256", encoder.encode(authorization)),
        crypto.subtle.digest("SHA-256", encoder.encode(expected))
      ]);

      const a = new Uint8Array(actualHash);
      const b = new Uint8Array(expectedHash);
      let difference = 0;

      for (let i = 0; i < a.length; i++) {
        difference |= a[i] ^ b[i];
      }

      if (difference !== 0) {
        return new Response("Unauthorized", { status: 401 });
      }

      return stub.fetch(request);
    }

    return Response.json({
      service: "claude-freedom-bridge",
      message: "Worker is running"
    });
  }
};

export class Bridge extends DurableObject {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/status") {
      return Response.json({
        status: "ready",
        durable_object: "Bridge",
        connections: this.ctx.getWebSockets("agent").length,
        version: "0.2.0"
      });
    }

    if (url.pathname === "/connect") {
      if (request.method !== "GET" ||
          request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return new Response("WebSocket required", { status: 426 });
      }

      const existing = this.ctx.getWebSockets("agent")
        .filter(ws => ws.readyState === WebSocket.OPEN);

      if (existing.length > 0) {
        return new Response("Agent already connected", { status: 409 });
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
      ws.send(JSON.stringify({
        type: "error",
        error: "invalid_message"
      }));
      return;
    }

    let data;

    try {
      data = JSON.parse(message);
    } catch {
      ws.send(JSON.stringify({
        type: "error",
        error: "invalid_json"
      }));
      return;
    }

    if (data.type === "ping" &&
        typeof data.id === "string" &&
        data.id.length <= 64) {
      ws.send(JSON.stringify({
        type: "pong",
        id: data.id
      }));
      return;
    }

    ws.send(JSON.stringify({
      type: "error",
      error: "unsupported_message"
    }));
  }

  async webSocketClose(ws, code, reason) {
    ws.close(code, reason);
  }

  async webSocketError(ws, error) {
    console.error("WebSocket error");
  }
}
