/**
 * Smoke test for the Steal the VFY integration in the Gatekeeper service.
 *
 * Boots the real server (child process, dummy HMAC secret, throwaway
 * seen-store) and exercises, over HTTP:
 *   (1) a correctly HMAC-signed steal-the-vfy envelope -> 200, schema-exact
 *       response (matchId/turn echoed, EXTRACT 10 for a mid-game state),
 *       9 public signals with signals[1] == the commitment computed from
 *       params [10,0,0,0,0,0,0,0] + the secret-derived salt, the proof
 *       verified locally with snarkjs against circuits-steal/vk.json, the
 *       publicInputsHash recomputed independently, and a valid response
 *       signature;
 *   (2) a HOLD case (opponent balance 0): action has NO amount key, and
 *       its proof verifies too;
 *   (3) a Gatekeeper task through the SAME process -> APPROVE with a
 *       locally verified gatekeeper proof (original flow untouched);
 *   (4) unsigned and wrongly-signed steal envelopes -> 401.
 *
 * The expected salt is recomputed here from first principles —
 * HMAC-SHA256(secret, "steal-the-vfy-salt") as BigInt mod the BN128
 * prime — not imported from server.mjs, so the test pins the derivation
 * itself. The commitment is computed with the strategy module's own
 * computeCommitment.
 *
 * Run: node test-steal.mjs   (the Gatekeeper suites are `npm test` and
 * `npm run test:function`)
 */

import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import {
  computeCommitment,
  publicInputsHash,
} from "./steal-strategy.mjs";

const AGENT_DIR = path.dirname(fileURLToPath(import.meta.url));
const PORT = 18788;
const BASE = `http://127.0.0.1:${PORT}/agent`;
const SECRET = "dummy-secret-for-steal-smoke-test";
const SIG_HEADER = "x-agent-games-signature";

const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const STEAL_PARAMS = [10, 0, 0, 0, 0, 0, 0, 0];

const GK_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0x1111111111111111111111111111111111111111";

const stealVk = JSON.parse(
  fs.readFileSync(path.join(AGENT_DIR, "circuits-steal", "vk.json"), "utf8"),
);
const gatekeeperVk = JSON.parse(
  fs.readFileSync(path.join(AGENT_DIR, "circuits", "verification_key.json"), "utf8"),
);

// Expected salt + commitment, derived independently of server.mjs.
const expectedSalt =
  BigInt(
    "0x" +
      crypto.createHmac("sha256", SECRET).update("steal-the-vfy-salt").digest("hex"),
  ) % BN128_PRIME;
const expectedCommitment = await computeCommitment(STEAL_PARAMS, expectedSalt);

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
// http helpers
// ---------------------------------------------------------------------------

function sign(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function responseSignatureValid(rawBody, headerValue) {
  if (!headerValue) return false;
  const expected = crypto.createHmac("sha256", SECRET).update(rawBody).digest();
  if (!/^[0-9a-fA-F]{64}$/.test(String(headerValue).trim())) return false;
  return crypto.timingSafeEqual(Buffer.from(headerValue, "hex"), expected);
}

async function post(rawBody, signature) {
  const headers = { "Content-Type": "application/json" };
  if (signature !== undefined) headers[SIG_HEADER] = signature;
  const t0 = Date.now();
  const res = await fetch(BASE, { method: "POST", headers, body: rawBody });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch { /* leave null */ }
  return { status: res.status, headers: res.headers, rawBody: text, json, ms: Date.now() - t0 };
}

function stealBody({ matchId, turn, selfBalance, opponentBalance }) {
  return JSON.stringify({
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    mode: "practice",
    matchId,
    turn,
    issuedAt: "2026-11-16T00:00:00Z",
    deadlineAt: "2026-11-16T00:05:00Z",
    state: {
      selfBalance,
      opponentBalance,
      selfFortifiedUntilTurn: null,
      opponentFortifiedUntilTurn: null,
    },
    strategyCommitment: { hash: expectedCommitment.hex },
    resolverVersion: "v1",
    nonce: `nonce-${matchId}-${turn}`,
  });
}

// ---------------------------------------------------------------------------
// boot the server
// ---------------------------------------------------------------------------

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "steal-test-"));
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

try {
  check("server boots and becomes ready", await waitReady());
  console.log("--- server log so far ---");
  console.log(serverLog.trim().split("\n").map((l) => "  | " + l).join("\n"));
  check(
    "boot log prints the expected strategy commitment (hash only)",
    serverLog.includes(`steal-the-vfy: strategy commitment ${expectedCommitment.hex}`),
  );

  // (1) signed steal turn, mid-game state -> EXTRACT 10 -------------------
  console.log("\n[1] signed steal turn (self 95 / opp 105, turn 7) -> EXTRACT 10");
  {
    const matchId = crypto.randomUUID();
    const body = stealBody({ matchId, turn: 7, selfBalance: 95, opponentBalance: 105 });
    const r = await post(body, sign(SECRET, body));
    console.log(`  (turn answered in ${r.ms} ms)`);
    check("steal turn -> 200", r.status === 200, `got ${r.status}: ${r.rawBody}`);
    check("matchId echoed exactly", r.json?.matchId === matchId, r.rawBody);
    check("turn echoed exactly", r.json?.turn === 7);
    check(
      "action is EXTRACT 10",
      r.json?.action?.type === "EXTRACT" && r.json?.action?.amount === 10,
      JSON.stringify(r.json?.action),
    );
    check(
      "action has exactly {type, amount}",
      r.json?.action && Object.keys(r.json.action).sort().join(",") === "amount,type",
    );
    check("policyProof.circuitVersion is v1", r.json?.policyProof?.circuitVersion === "v1");
    check("proof present", Boolean(r.json?.policyProof?.proof?.pi_a));
    check(
      "9 public signals",
      r.json?.policyProof?.public_signals?.length === 9,
      `got ${r.json?.policyProof?.public_signals?.length}`,
    );
    check(
      "public_signals[1] == expected commitment",
      r.json?.policyProof?.public_signals?.[1] === expectedCommitment.decimal,
      r.json?.policyProof?.public_signals?.[1],
    );
    check(
      "public_signals carry the echoed state (turn/self/opp/action/amount)",
      r.json?.policyProof?.public_signals?.[3] === "7" &&
        r.json?.policyProof?.public_signals?.[4] === "95" &&
        r.json?.policyProof?.public_signals?.[5] === "105" &&
        r.json?.policyProof?.public_signals?.[6] === "2" &&
        r.json?.policyProof?.public_signals?.[7] === "10",
      JSON.stringify(r.json?.policyProof?.public_signals),
    );
    check(
      "publicInputsHash matches independent recomputation",
      r.json?.policyProof?.publicInputsHash ===
        publicInputsHash({
          commitment: expectedCommitment.decimal,
          matchId,
          turn: 7,
          selfBalance: 95,
          opponentBalance: 105,
          action: "EXTRACT",
          amount: 10,
        }),
      r.json?.policyProof?.publicInputsHash,
    );
    check(
      "agentTimestamp + fresh idempotencyKey present",
      typeof r.json?.agentTimestamp === "string" && r.json.agentTimestamp.length > 0 &&
        typeof r.json?.idempotencyKey === "string" && r.json.idempotencyKey.length > 0,
    );
    check(
      "response signature valid (signed like Gatekeeper responses)",
      responseSignatureValid(r.rawBody, r.headers.get(SIG_HEADER)),
    );
    check(
      "proof verifies against circuits-steal/vk.json (snarkjs)",
      Boolean(r.json?.policyProof) &&
        (await snarkjs.groth16.verify(
          stealVk,
          r.json.policyProof.public_signals,
          r.json.policyProof.proof,
        )),
    );
  }

  // (2) HOLD case: opponent balance 0 -> HOLD, amount key omitted ---------
  console.log("\n[2] signed steal turn (self 40 / opp 0, turn 3) -> HOLD, no amount key");
  {
    const matchId = crypto.randomUUID();
    const body = stealBody({ matchId, turn: 3, selfBalance: 40, opponentBalance: 0 });
    const r = await post(body, sign(SECRET, body));
    check("steal HOLD turn -> 200", r.status === 200, `got ${r.status}: ${r.rawBody}`);
    check("action is HOLD", r.json?.action?.type === "HOLD", JSON.stringify(r.json?.action));
    check(
      "HOLD action omits amount entirely (schema)",
      r.json?.action && !("amount" in r.json.action),
      JSON.stringify(r.json?.action),
    );
    check(
      "HOLD proof verifies against vk.json",
      Boolean(r.json?.policyProof) &&
        (await snarkjs.groth16.verify(
          stealVk,
          r.json.policyProof.public_signals,
          r.json.policyProof.proof,
        )),
    );
  }

  // (3) Gatekeeper flow through the same process ---------------------------
  console.log("\n[3] Gatekeeper task via the same server -> APPROVE, proof verifies");
  {
    const body = JSON.stringify({
      type: "agent-games.proof-gatekeeper.v1",
      task_id: "gk_steal_smoke_valid_1",
      mode: "practice",
      issued_at: "2026-11-16T00:00:00Z",
      deadline_at: "2026-11-16T00:01:00Z",
      input: {
        registered_vk: GK_VK,
        proof_vk: GK_VK,
        minimum: "1000",
        public_balance: "1460",
        expiry_block: 19842201,
        current_block: 19832000,
        recipient: ADDR,
        condition_recipient: ADDR,
        amount: "500",
        max_transfer: "1000",
        proof_tx: "0xtx_gk_steal_smoke_valid_1",
      },
    });
    const r = await post(body, sign(SECRET, body));
    check("gatekeeper task -> 200", r.status === 200, `got ${r.status}: ${r.rawBody}`);
    check("decision APPROVE", r.json?.decision === "APPROVE", r.rawBody);
    check("reason VALID_CONDITION", r.json?.reason_code === "VALID_CONDITION");
    check("13 public signals (gatekeeper circuit)", r.json?.public_signals?.length === 13);
    check(
      "gatekeeper proof verifies locally (snarkjs)",
      Boolean(r.json?.proof) &&
        (await snarkjs.groth16.verify(gatekeeperVk, r.json.public_signals, r.json.proof)),
    );
  }

  // (4) signature enforcement on steal envelopes ---------------------------
  console.log("\n[4] unsigned / wrongly-signed steal envelopes -> 401");
  {
    const body = stealBody({
      matchId: crypto.randomUUID(),
      turn: 1,
      selfBalance: 100,
      opponentBalance: 100,
    });
    const rUnsigned = await post(body, undefined);
    check("unsigned steal envelope -> 401", rUnsigned.status === 401, `got ${rUnsigned.status}`);
    const rWrong = await post(body, sign("wrong-secret", body));
    check("wrong-secret steal envelope -> 401", rWrong.status === 401, `got ${rWrong.status}`);
    const tampered = body.replace('"turn":1', '"turn":2');
    const rTampered = await post(tampered, sign(SECRET, body));
    check("tampered steal body -> 401", rTampered.status === 401, `got ${rTampered.status}`);
  }
} finally {
  child.kill("SIGTERM");
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

console.log(`\n=== steal smoke test: ${passed} passed, ${failed} failed ===`);
if (failures.length) console.log("failures:", failures.join("; "));
process.exit(failed === 0 ? 0 : 1);
