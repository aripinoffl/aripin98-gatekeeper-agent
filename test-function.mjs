/**
 * Smoke test for the Vercel function entry (api/agent.mjs).
 *
 * Imports the function the way Vercel would (GATEKEEPER_NO_LISTEN=1, test
 * secret, throwaway seen-store) and invokes the default handler with mock
 * req/res objects — no port is bound. Covers:
 *   (a) GET  /agent            -> 200 {"ok":true}
 *   (b) POST signed preflight  -> 200 + valid response signature
 *   (c) POST signed valid task -> APPROVE, proof verified locally with
 *       snarkjs against circuits/verification_key.json
 *
 * Run: npm run test:function   (the HTTP end-to-end suite is `npm test`)
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const AGENT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SECRET = "test-secret-for-function-smoke-test";
const SIG_HEADER = "x-agent-games-signature";

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0x1111111111111111111111111111111111111111";

const vk = JSON.parse(
  fs.readFileSync(path.join(AGENT_DIR, "circuits", "verification_key.json"), "utf8"),
);

// Env must be set BEFORE the function module (and through it server.mjs)
// is imported: server.mjs reads its config at module scope.
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gatekeeper-fn-test-"));
process.env.AGENT_GAMES_HMAC_SECRET = SECRET;
process.env.GATEKEEPER_NO_LISTEN = "1";
process.env.SEEN_STORE_PATH = path.join(tmpDir, "seen.json");

const { default: handler } = await import("./api/agent.mjs");

// ---------------------------------------------------------------------------
// tiny check framework (same style as test.mjs)
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];
function check(name, cond, extra = "") {
  if (cond) {
    passed++;
    console.log(`  ok    ${name}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`  FAIL  ${name} ${extra}`);
  }
}

// ---------------------------------------------------------------------------
// mock req/res + invocation
// ---------------------------------------------------------------------------

function mockReq({ method, url, headers = {}, body = null }) {
  const req = Readable.from(body === null ? [] : [Buffer.from(body)]);
  req.method = method;
  req.url = url;
  req.headers = headers;
  return req;
}

function invoke(req) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("handler timed out")), 60_000);
    const res = {
      status: null,
      headers: {},
      body: "",
      headersSent: false,
      writeHead(status, headers) {
        this.status = status;
        Object.assign(this.headers, headers ?? {});
        this.headersSent = true;
        return this;
      },
      end(chunk) {
        if (chunk) this.body += chunk;
        clearTimeout(timer);
        resolve(this);
      },
    };
    Promise.resolve(handler(req, res)).catch((e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

function sign(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function responseSignatureValid(rawBody, headerValue) {
  if (!headerValue) return false;
  const expected = crypto.createHmac("sha256", SECRET).update(rawBody).digest();
  if (!/^[0-9a-fA-F]{64}$/.test(String(headerValue).trim())) return false;
  return crypto.timingSafeEqual(Buffer.from(headerValue, "hex"), expected);
}

// ---------------------------------------------------------------------------
// cases
// ---------------------------------------------------------------------------

try {
  console.log("[a] GET /agent (via the /api/agent rewrite path)");
  {
    const res = await invoke(mockReq({ method: "GET", url: "/api/agent" }));
    check("GET -> 200", res.status === 200, `got ${res.status}`);
    check("GET body is {\"ok\":true}", res.body === JSON.stringify({ ok: true }), res.body);
  }

  console.log("\n[b] POST signed preflight");
  {
    const body = JSON.stringify({
      type: "agent-games.preflight.v1",
      agent_id: "test-agent",
      nonce: "n-fn-1",
    });
    const res = await invoke(
      mockReq({
        method: "POST",
        url: "/api/agent",
        headers: { [SIG_HEADER]: sign(SECRET, body) },
        body,
      }),
    );
    check("preflight -> 200", res.status === 200, `got ${res.status}: ${res.body}`);
    check(
      "preflight body shape",
      res.body === JSON.stringify({ ok: true, protocolVersion: "v1" }),
      res.body,
    );
    check(
      "preflight response signature valid",
      responseSignatureValid(res.body, res.headers[SIG_HEADER]),
    );
  }

  console.log("\n[c] POST signed valid task -> APPROVE with locally verified proof");
  {
    const body = JSON.stringify({
      type: "agent-games.proof-gatekeeper.v1",
      task_id: "gk_fn_smoke_valid_1",
      mode: "practice",
      issued_at: "2026-11-15T00:00:00Z",
      deadline_at: "2026-11-15T00:01:00Z",
      input: {
        registered_vk: VK,
        proof_vk: VK,
        minimum: "1000",
        public_balance: "1460",
        expiry_block: 19842201,
        current_block: 19832000,
        recipient: ADDR,
        condition_recipient: ADDR,
        amount: "500",
        max_transfer: "1000",
        proof_tx: "0xtx_gk_fn_smoke_valid_1",
      },
    });
    const res = await invoke(
      mockReq({
        method: "POST",
        url: "/api/agent",
        headers: { [SIG_HEADER]: sign(SECRET, body) },
        body,
      }),
    );
    check("task -> 200", res.status === 200, `got ${res.status}: ${res.body}`);
    let json = null;
    try {
      json = JSON.parse(res.body);
    } catch { /* leave null */ }
    check("decision APPROVE", json?.decision === "APPROVE", res.body);
    check("reason VALID_CONDITION", json?.reason_code === "VALID_CONDITION");
    check("13 public signals", json?.public_signals?.length === 13);
    check(
      "response signature valid",
      responseSignatureValid(res.body, res.headers[SIG_HEADER]),
    );
    check(
      "proof verifies locally (snarkjs)",
      Boolean(json?.proof) &&
        (await snarkjs.groth16.verify(vk, json.public_signals, json.proof)),
    );
  }
} finally {
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

console.log(`\n=== function smoke test: ${passed} passed, ${failed} failed ===`);
if (failures.length) console.log("failures:", failures.join("; "));
process.exit(failed === 0 ? 0 : 1);
