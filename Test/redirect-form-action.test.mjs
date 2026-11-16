import fs from "node:fs";
const src = fs.readFileSync(new URL("../src/index.js", import.meta.url), "utf8");
const fn = src.match(/function redirectFormAction[\s\S]*?\n}\n/)[0];
const redirectFormAction = new Function(fn + "; return redirectFormAction;")();
const cases = [
  ["https://claude.ai/api/mcp/auth_callback", "https://claude.ai"],
  ["http://localhost:6274/cb", "http://localhost:6274"],
  ["http://127.0.0.1:33418/cb", "http://127.0.0.1:33418"],
  ["http://[::1]:8080/cb", "http://[::1]:8080"],
  ["claude://oauth/cb", "claude:"],
  ["com.example.app:/cb", "com.example.app:"],
  ["https://a.com;script-src *.evil.com/x", null],   // directive injection via ';'
  ["https://a.com,b.com/x", null],                   // list injection via ','
  ["https://exa mple.com/x", null],
  ["not a url", null],
  ["javascript:alert(1)", null],
  ["data:text/html,x", null],
  ["file:///etc/passwd", null],
];
let bad = 0;
for (const [input, want] of cases) {
  const got = redirectFormAction(input);
  const ok = got === want; if (!ok) bad++;
  console.log(ok ? "PASS" : "FAIL", JSON.stringify(input), "->", JSON.stringify(got));
}
process.exit(bad ? 1 : 0);
