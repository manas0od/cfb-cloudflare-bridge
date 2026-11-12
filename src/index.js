
import { DurableObject } from "cloudflare:workers";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({
        status: "ok",
        service: "claude-freedom-bridge",
        version: "0.2.0"
      });
    }

    if (url.pathname === "/do-status") {
      const id = env.BRIDGE.idFromName("main");
      const stub = env.BRIDGE.get(id);
      return stub.fetch("https://bridge.internal/status");
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
        version: "0.1.0"
      });
    }

    return new Response("Not found", { status: 404 });
  }
}
