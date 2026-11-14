/**
 * Local end-to-end test for the Proof Gatekeeper agent.
 *
 * Boots the real server (child process, test secret, throwaway seen-store),
 * then exercises: health, preflight (+ response-signature check), bad
 * signatures, one valid task with LOCAL proof verification via snarkjs
 * against circuits/verification_key.json, all six traps (each provable
 * trap's proof is also verified locally), malformed input, and idempotent
 * redelivery (byte-identical cached response).
 *
 * Run: npm test
 */

import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const AGENT_DIR = path.dirname(fileURLToPath(import.meta.url));
const PORT = 18787;
const BASE = `http://127.0.0.1:${PORT}/agent`;
const SECRET = "test-secret-for-local-tests-only";
const SIG_HEADER = "x-agent-games-signature";

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const VK_OTHER = "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047";
const ADDR = "0x1111111111111111111111111111111111111111";
const ADDR2 = "0x2222222222222222222222222222222222222222";

const vk = JSON.parse(
  fs.readFileSync(path.join(AGENT_DIR, "circuits", "verification_key.json"), "utf8"),
);

// ---------------------------------------------------------------------------
// tiny check framework
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
// http helpers
// ---------------------------------------------------------------------------

function sign(secret, rawBody, encoding = "hex") {
  const mac = crypto.createHmac("sha256", secret).update(rawBody).digest();
  return encoding === "hex" ? mac.toString("hex") : mac.toString("base64");
}

function responseSignatureValid(rawBody, headerValue) {
  if (!headerValue) return false;
  const expected = crypto.createHmac("sha256", SECRET).update(rawBody).digest();
  let candidate = null;
  let v = String(headerValue).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice(7);
  if (/^[0-9a-fA-F]{64}$/.test(v)) candidate = Buffer.from(v, "hex");
  else {
    const b = Buffer.from(v, "base64");
    if (b.length === 32) candidate = b;
  }
  return candidate && crypto.timingSafeEqual(candidate, expected);
}

async function post(rawBody, signature) {
  const headers = { "Content-Type": "application/json" };
  if (signature !== undefined) headers[SIG_HEADER] = signature;
  const t0 = Date.now();
  const res = await fetch(BASE, { method: "POST", headers, body: rawBody });
  const text = await res.text();
  const ms = Date.now() - t0;
  let json = null;
  try {
    json = JSON.parse(text);
  } catch { /* leave null */ }
  return { status: res.status, headers: res.headers, rawBody: text, json, ms };
}

function taskBody(taskId, overrides = {}, inputOverrides = {}) {
  const input = {
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
    proof_tx: "0xtx_" + taskId,
    ...inputOverrides,
  };
  return JSON.stringify({
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "practice",
    issued_at: "2026-11-15T00:00:00Z",
    deadline_at: "2026-11-15T00:01:00Z",
    input,
    ...overrides,
  });
}

async function postTask(taskId, inputOverrides = {}) {
  const body = taskBody(taskId, {}, inputOverrides);
  return post(body, sign(SECRET, body));
}

async function proofVerifies(r) {
  if (!r.json?.proof || !Array.isArray(r.json?.public_signals)) return false;
  return snarkjs.groth16.verify(vk, r.json.public_signals, r.json.proof);
}

// ---------------------------------------------------------------------------
// boot the server
// ---------------------------------------------------------------------------

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gatekeeper-test-"));
const child = spawn("node", [path.join(AGENT_DIR, "server.mjs")], {
  env: {
    ...process.env,
    AGENT_GAMES_HMAC_SECRET: SECRET,
    PORT: String(PORT),
    SEEN_STORE_PATH: path.join(tmpDir, "seen.json"),
  },
  stdio: ["ignore", "pipe", "pipe"],
});
let serverLog = "";
child.stdout.on("data", (d) => (serverLog += d));
child.stderr.on("data", (d) => (serverLog += d));

async function waitReady(deadlineMs = 30000) {
  const t0 = Date.now();
  while (Date.now() - t0 < deadlineMs) {
    try {
      const res = await fetch(BASE);
      if (res.status === 200) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

const latencies = [];

try {
  check("server boots and becomes ready", await waitReady());
  console.log("--- server log so far ---");
  console.log(serverLog.trim().split("\n").map((l) => "  | " + l).join("\n"));

  // (1) health -------------------------------------------------------------
  console.log("\n[1] GET health");
  {
    const t0 = Date.now();
    const res = await fetch(BASE);
    const body = await res.text();
    latencies.push(["GET /agent (health)", Date.now() - t0]);
    check("GET /agent -> 200", res.status === 200);
    check("health body is {\"ok\":true}", body === JSON.stringify({ ok: true }), body);
  }

  // (2) preflight ----------------------------------------------------------
  console.log("\n[2] preflight");
  {
    const body = JSON.stringify({
      type: "agent-games.preflight.v1",
      agent_id: "test-agent",
      nonce: "n-1",
    });
    const r = await post(body, sign(SECRET, body));
    latencies.push(["POST preflight", r.ms]);
    check("preflight -> 200", r.status === 200);
    check(
      "preflight body shape",
      r.rawBody === JSON.stringify({ ok: true, protocolVersion: "v1" }),
      r.rawBody,
    );
    check(
      "preflight response signature valid",
      responseSignatureValid(r.rawBody, r.headers.get(SIG_HEADER)),
    );

    // encoding tolerance: base64 MAC with sha256= prefix must also pass
    const r2 = await post(body, "sha256=" + sign(SECRET, body, "base64"));
    check("preflight with base64+sha256= signature -> 200", r2.status === 200);
  }

  // (3) bad signatures -------------------------------------------------------
  console.log("\n[3] bad signatures");
  {
    const body = JSON.stringify({ type: "agent-games.preflight.v1" });
    const rWrong = await post(body, sign("wrong-secret", body));
    check("wrong-secret signature -> 401", rWrong.status === 401);
    const rMissing = await post(body, undefined);
    check("missing signature -> 401", rMissing.status === 401);
    const tampered = body.replace("preflight", "preflighX");
    const rTampered = await post(tampered, sign(SECRET, body));
    check("tampered body -> 401", rTampered.status === 401);
  }

  // (4) valid task -----------------------------------------------------------
  console.log("\n[4] valid task -> APPROVE with locally verified proof");
  let firstValid = null;
  {
    const r = await postTask("gk_test_valid_1");
    firstValid = r;
    latencies.push(["POST valid task (prove)", r.ms]);
    check("valid task -> 200", r.status === 200);
    check("decision APPROVE", r.json?.decision === "APPROVE", r.rawBody);
    check("reason VALID_CONDITION", r.json?.reason_code === "VALID_CONDITION");
    check(
      "proof shape groth16/bn128",
      r.json?.proof?.protocol === "groth16" && r.json?.proof?.curve === "bn128",
    );
    check("13 public signals", r.json?.public_signals?.length === 13);
    check("decision signal = 1", r.json?.public_signals?.[11] === "1");
    check("proof_tx echoed", r.json?.proof_tx === "0xtx_gk_test_valid_1");
    check(
      "response signature valid",
      responseSignatureValid(r.rawBody, r.headers.get(SIG_HEADER)),
    );
    check("proof verifies locally (snarkjs)", await proofVerifies(r));
  }

  // (5) the six traps --------------------------------------------------------
  console.log("\n[5] traps");
  const traps = [
    ["VK_SUBSTITUTION", { proof_vk: VK_OTHER }],
    ["THRESHOLD_MISMATCH", { public_balance: "999" }],
    ["EXPIRED_CONDITION", { current_block: 19842201 }],
    ["RECIPIENT_MISMATCH", { condition_recipient: ADDR2 }],
    ["AMOUNT_OVERFLOW", { amount: "1001" }],
  ];
  for (const [reason, inputOverrides] of traps) {
    const r = await postTask(`gk_test_trap_${reason.toLowerCase()}`, inputOverrides);
    latencies.push([`POST trap ${reason}`, r.ms]);
    check(`${reason}: decision REJECT`, r.json?.decision === "REJECT", r.rawBody);
    check(`${reason}: reason_code`, r.json?.reason_code === reason, r.rawBody);
    check(`${reason}: decision signal = 0`, r.json?.public_signals?.[11] === "0");
    check(`${reason}: proof verifies locally`, await proofVerifies(r));
  }
  {
    // PROOF_REUSED: different task_id, same proof_tx as the valid task.
    const r = await postTask("gk_test_reuse_2", { proof_tx: "0xtx_gk_test_valid_1" });
    latencies.push(["POST trap PROOF_REUSED", r.ms]);
    check("PROOF_REUSED: decision REJECT", r.json?.decision === "REJECT", r.rawBody);
    check("PROOF_REUSED: reason_code", r.json?.reason_code === "PROOF_REUSED");
    check("PROOF_REUSED: no proof field", !("proof" in (r.json ?? {})));
    check("PROOF_REUSED: no public_signals field", !("public_signals" in (r.json ?? {})));
    check("PROOF_REUSED: proof_tx echoed", r.json?.proof_tx === "0xtx_gk_test_valid_1");
  }
  {
    // malformed input -> INVALID_TASK, no proof
    const r = await postTask("gk_test_malformed", { minimum: "not-a-number" });
    check("malformed: REJECT/INVALID_TASK", r.json?.decision === "REJECT" && r.json?.reason_code === "INVALID_TASK", r.rawBody);
    check("malformed: no proof field", !("proof" in (r.json ?? {})));
  }

  // (6) idempotent redelivery --------------------------------------------------
  console.log("\n[6] redelivery of the first task_id");
  {
    const body = taskBody("gk_test_valid_1");
    const r = await post(body, sign(SECRET, body));
    latencies.push(["POST redelivery (cached)", r.ms]);
    check("redelivery -> 200", r.status === 200);
    check(
      "redelivery body byte-identical to original",
      r.rawBody === firstValid.rawBody,
    );
    check(
      "redelivery signature header identical",
      r.headers.get(SIG_HEADER) === firstValid.headers.get(SIG_HEADER),
    );
    check("redelivery still APPROVE (not PROOF_REUSED)", r.json?.reason_code === "VALID_CONDITION");
  }
} finally {
  child.kill("SIGTERM");
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// summary
// ---------------------------------------------------------------------------

console.log("\n--- latencies (this throttled VM) ---");
for (const [name, ms] of latencies) console.log(`  ${name}: ${ms} ms`);
console.log(`\n=== ${passed} passed, ${failed} failed ===`);
if (failures.length) console.log("failures:", failures.join("; "));
process.exit(failed === 0 ? 0 : 1);
