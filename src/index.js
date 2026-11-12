export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({
        status: "ok",
        service: "claude-freedom-bridge",
        version: "0.1.0"
      });
    }

    return Response.json({
      service: "claude-freedom-bridge",
      message: "Worker is running"
    });
  }
};
