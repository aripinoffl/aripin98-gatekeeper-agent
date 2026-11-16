/**
 * Proof Gatekeeper agent — zkVerify Agent Games.
 *
 * Plain Node.js HTTP service (no framework). The platform POSTs HMAC-signed
 * task envelopes to /agent; this service verifies the signature over the RAW
 * body before parsing, applies a deterministic fail-closed policy, generates
 * a real Groth16 proof locally with snarkjs against the official gatekeeper
 * circuit, and returns a signed JSON response.
 *
 * The same endpoint also answers "Steal the VFY" turns: envelopes with
 * eventId "steal-the-vfy" are routed (after the same signature check) to
 * steal-strategy.mjs; all Gatekeeper behavior is unchanged.
 *
 * Config is env-only (see .env.example / README.md). No secrets in code.
 */

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { handleStealTurn, computeCommitment } from "./steal-strategy.mjs";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const AGENT_DIR = path.dirname(fileURLToPath(import.meta.url));

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
if (!SECRET) {
  console.error(
    "FATAL: AGENT_GAMES_HMAC_SECRET is not set. " +
      "Set it in the environment (see .env.example); there is no default.",
  );
  process.exit(1);
}

const PORT = Number.parseInt(process.env.PORT || "8787", 10);
const CIRCUITS_DIR = process.env.CIRCUITS_DIR || path.join(AGENT_DIR, "circuits");
const SEEN_STORE_PATH =
  process.env.SEEN_STORE_PATH || path.join(AGENT_DIR, "data", "seen.json");
const WASM_PATH = path.join(CIRCUITS_DIR, "gatekeeper.wasm");
const ZKEY_PATH = path.join(CIRCUITS_DIR, "gatekeeper_final.zkey");

const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const PROTOCOL_VERSION = "v1";
const SIGNATURE_HEADER = "x-agent-games-signature";
const MAX_BODY_BYTES = 1_000_000;

/** BN128 (bn254) scalar field prime. */
export const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ---------------------------------------------------------------------------
// HMAC-SHA256 signing / verification
//
// Outbound: lowercase hex digest in the x-agent-games-signature header.
// Inbound: the same MAC bytes accepted as hex or base64, with an optional
// "sha256=" prefix, compared in constant time. Accepting two encodings of
// the identical MAC is a representation tolerance, not a weakening.
// ---------------------------------------------------------------------------

export function signBody(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function decodeCandidate(headerValue) {
  let v = String(headerValue).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice("sha256=".length).trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, "hex");
  try {
    const b = Buffer.from(v, "base64");
    if (b.length === 32) return b;
  } catch {
    /* fall through */
  }
  return null;
}

export function verifyBodySignature(secret, rawBody, headerValue) {
  if (!headerValue) return false;
  const candidate = decodeCandidate(headerValue);
  if (!candidate) return false;
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest();
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

/**
 * Deterministic per-task circuit salt (private input):
 * HMAC-SHA256(secret, "gatekeeper-salt:" + task_id) reduced mod p.
 * Deterministic so a redelivered task reproduces identical proof inputs;
 * secret-bound so it is not predictable to third parties.
 */
export function deriveSalt(secret, taskId) {
  const digest = crypto
    .createHmac("sha256", secret)
    .update(`gatekeeper-salt:${taskId}`)
    .digest();
  return BigInt("0x" + digest.toString("hex")) % BN128_PRIME;
}

// ---------------------------------------------------------------------------
// Steal the VFY (second track on this same endpoint)
//
// Envelopes whose eventId is "steal-the-vfy" are routed to
// handleStealTurn (steal-strategy.mjs) after the shared HMAC verification;
// every other envelope follows the Gatekeeper flow below, unchanged.
//
// The committed policy is params [10,0,0,0,0,0,0,0] ("always EXTRACT 10").
// Its circuit salt is DERIVED from the existing HMAC secret —
// HMAC-SHA256(secret, "steal-the-vfy-salt") reduced mod p, the same
// construction deriveSalt uses — so no new secret or file is introduced.
// The commitment that must be registered on the dashboard for this agent
// is Poseidon(params, salt); it is computed and logged once at startup
// (the hash only — never the secret or the salt).
// ---------------------------------------------------------------------------

export function deriveStealSalt(secret) {
  const digest = crypto
    .createHmac("sha256", secret)
    .update("steal-the-vfy-salt")
    .digest();
  return BigInt("0x" + digest.toString("hex")) % BN128_PRIME;
}

const STEAL_PARAMS = [10, 0, 0, 0, 0, 0, 0, 0];
const stealConfig = { params: STEAL_PARAMS, salt: deriveStealSalt(SECRET) };

computeCommitment(STEAL_PARAMS, stealConfig.salt)
  .then((c) => {
    console.log(
      `steal-the-vfy: strategy commitment ${c.hex} ` +
        `(params [${STEAL_PARAMS.join(",")}], salt derived from the HMAC secret)`,
    );
  })
  .catch((e) => {
    // Not fatal to the Gatekeeper flow; steal turns will fail closed in
    // handleStealTurn if the commitment cannot be recomputed there.
    console.error(`steal-the-vfy: startup commitment computation failed: ${e.message}`);
  });

// ---------------------------------------------------------------------------
// Field conversion + input parsing
// ---------------------------------------------------------------------------

/**
 * Convert an envelope value to a BN128 field element (decimal string).
 * Hex/decimal integers are reduced mod p (a 32-byte hash does not fit the
 * field; reduction preserves the equality checks the circuit performs).
 * Free-form identifiers (e.g. task_id "gk_8d31_…") are SHA-256 hashed first.
 */
export function toFieldElement(v) {
  let n;
  if (typeof v === "bigint") {
    n = v;
  } else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else n = BigInt("0x" + crypto.createHash("sha256").update(s).digest("hex"));
  }
  return (((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME).toString(10);
}

/** Parse a non-negative integer given as a decimal string, hex string, or number. */
export function parseUint(v) {
  if (typeof v === "number") {
    return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  }
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

function normalizeHex(v) {
  return (v ?? "").trim().toLowerCase();
}

/** Structural validation + parsing of the envelope `input`. Null = malformed. */
export function parseInput(input) {
  if (!input || typeof input !== "object") return null;
  const minimum = parseUint(input.minimum);
  const publicBalance = parseUint(input.public_balance);
  const amount = parseUint(input.amount);
  const maxTransfer = parseUint(input.max_transfer);
  const expiryBlock = parseUint(input.expiry_block);
  const currentBlock = parseUint(input.current_block);
  if (
    minimum === null || publicBalance === null || amount === null ||
    maxTransfer === null || expiryBlock === null || currentBlock === null
  ) {
    return null;
  }
  for (const k of ["registered_vk", "proof_vk", "recipient", "condition_recipient", "proof_tx"]) {
    if (typeof input[k] !== "string" || !input[k]) return null;
  }
  return {
    registeredVk: input.registered_vk,
    proofVk: input.proof_vk,
    minimum,
    publicBalance,
    expiryBlock,
    currentBlock,
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    amount,
    maxTransfer,
    proofTx: input.proof_tx,
  };
}

// ---------------------------------------------------------------------------
// Deterministic policy. Precedence is part of the protocol: the checks run
// in exactly this order, and the circuit asserts decision == AND of the five
// field checks, so the boundaries must mirror it exactly:
//   balance >= minimum passes · amount <= max_transfer passes ·
//   current_block < expiry_block passes.
// ---------------------------------------------------------------------------

export function evaluate(parsed, isProofTxSeen) {
  if (normalizeHex(parsed.proofVk) !== normalizeHex(parsed.registeredVk)) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  }
  if (isProofTxSeen(parsed.proofTx)) {
    // Documented special case: a reused-proof task has no proof to submit.
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  }
  if (parsed.publicBalance < parsed.minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  }
  if (parsed.currentBlock >= parsed.expiryBlock) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  }
  if (normalizeHex(parsed.recipient) !== normalizeHex(parsed.conditionRecipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  }
  if (parsed.amount > parsed.maxTransfer) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}

/**
 * Circuit inputs for gatekeeper.wasm (signal names recovered from the
 * official artifact and confirmed by proving):
 *   taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
 *   expiryBlock, currentBlock, recipient, conditionRecipient, amount,
 *   maxTransfer, decision, salt (private)
 * Public signals come back as:
 *   [Poseidon(taskId, salt), ...the 12 public inputs in the order above...]
 */
export function buildCircuitInputs(taskId, parsed, decision, salt) {
  return {
    taskId: toFieldElement(taskId),
    registeredVkHash: toFieldElement(parsed.registeredVk),
    proofVkHash: toFieldElement(parsed.proofVk),
    minimum: parsed.minimum.toString(10),
    publicBalance: parsed.publicBalance.toString(10),
    expiryBlock: parsed.expiryBlock.toString(10),
    currentBlock: parsed.currentBlock.toString(10),
    recipient: toFieldElement(parsed.recipient),
    conditionRecipient: toFieldElement(parsed.conditionRecipient),
    amount: parsed.amount.toString(10),
    maxTransfer: parsed.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(10),
  };
}

// ---------------------------------------------------------------------------
// Seen-set + idempotency cache, JSON-file backed.
//   seen:  normalized (lowercase) proof_tx values seen on provable tasks
//   cache: task_id -> exact raw response body string (byte-identical replay)
// ---------------------------------------------------------------------------

class Store {
  constructor(file) {
    this.file = file;
    this.seen = new Set();
    this.cache = new Map();
    try {
      const j = JSON.parse(fs.readFileSync(file, "utf8"));
      for (const x of j.seen ?? []) this.seen.add(x);
      for (const [k, v] of Object.entries(j.cache ?? {})) this.cache.set(k, v);
    } catch (e) {
      if (e.code !== "ENOENT") {
        console.error(`seen-store: starting empty (${e.message})`);
      }
    }
  }

  save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp`;
    fs.writeFileSync(
      tmp,
      JSON.stringify({ seen: [...this.seen], cache: Object.fromEntries(this.cache) }),
    );
    fs.renameSync(tmp, this.file);
  }

  hasSeen(proofTx) {
    return this.seen.has(normalizeHex(proofTx));
  }

  markSeen(proofTx) {
    const k = normalizeHex(proofTx);
    if (!this.seen.has(k)) {
      this.seen.add(k);
      this.save();
    }
  }

  getCached(taskId) {
    return this.cache.get(taskId);
  }

  setCached(taskId, rawBody) {
    this.cache.set(taskId, rawBody);
    this.save();
  }
}

// ---------------------------------------------------------------------------
// Prover artifacts. The wasm + zkey are loaded ONCE (lazily, via
// ensureReady below) and kept in memory as Buffers; snarkjs accepts Buffers
// for both. Every copy — local file or fresh download — is sha256-checked
// against the pinned hashes of the official artifacts, and a mismatch
// aborts startup: proving against an unverified circuit is never OK.
//
// Load order per artifact:
//   1. The CIRCUITS_DIR file, if present (hash-checked like everything
//      else, so a corrupted local copy fails fast).
//   2. Download from the official agentgames.zkverify.io URL, hash-check,
//      then best-effort save into CIRCUITS_DIR for later starts (skipped
//      silently on read-only filesystems — in-memory-only works, which is
//      what serverless deployments rely on).
//
// Proving is serialized through a promise chain so concurrent tasks cannot
// interleave witness generation on this small VM.
// ---------------------------------------------------------------------------

const ARTIFACTS = [
  {
    name: "gatekeeper.wasm",
    file: WASM_PATH,
    url: "https://agentgames.zkverify.io/circuits/gatekeeper.wasm",
    sha256: "be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f",
  },
  {
    name: "gatekeeper_final.zkey",
    file: ZKEY_PATH,
    url: "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey",
    sha256: "adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d",
  },
];

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function assertArtifactHash({ name, sha256 }, buf) {
  const actual = sha256Hex(buf);
  if (actual !== sha256) {
    throw new Error(
      `circuit artifact ${name}: sha256 mismatch — expected ${sha256}, got ${actual}. ` +
        "Refusing to run with an unverified artifact.",
    );
  }
}

async function downloadArtifact({ name, url }) {
  console.log(`circuit artifact ${name}: not on disk, downloading ${url}`);
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`circuit artifact ${name}: download failed (HTTP ${res.status})`);
  }
  return Buffer.from(await res.arrayBuffer());
}

async function loadArtifact(spec) {
  let local = null;
  try {
    local = fs.readFileSync(spec.file);
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  if (local) {
    assertArtifactHash(spec, local);
    console.log(`circuit artifact ${spec.name}: loaded from ${spec.file} (sha256 verified)`);
    return local;
  }
  const buf = await downloadArtifact(spec);
  assertArtifactHash(spec, buf);
  console.log(`circuit artifact ${spec.name}: downloaded (sha256 verified)`);
  try {
    fs.writeFileSync(spec.file, buf);
  } catch {
    // CIRCUITS_DIR may not exist yet on a writable filesystem: create it
    // with a PLAIN mkdir and retry once. Never mkdirSync(..., recursive)
    // here — its parent-walk can spin forever on virtual filesystems
    // (observed on /proc), which would wedge startup on exactly the
    // read-only hosts this fallback exists for.
    try {
      fs.mkdirSync(path.dirname(spec.file));
      fs.writeFileSync(spec.file, buf);
    } catch {
      /* read-only filesystem — the in-memory copy is authoritative */
    }
  }
  return buf;
}

let wasmBuf;
let zkeyBuf;

/**
 * One-time startup: load + verify the circuit artifacts, then warm the
 * prover (see warmUp below). Idempotent and concurrency-safe — concurrent
 * callers share one promise. A failed attempt is NOT latched, so the next
 * caller retries: a transient download error must not brick a warm
 * serverless instance. Both the plain server entry and the Vercel function
 * handler go through here, so importing this module (GATEKEEPER_NO_LISTEN=1)
 * has no artifact or network side effects until the first request.
 */
let readyPromise = null;
export function ensureReady() {
  if (!readyPromise) {
    readyPromise = (async () => {
      [wasmBuf, zkeyBuf] = await Promise.all(ARTIFACTS.map(loadArtifact));
      await warmUp();
    })();
    readyPromise.catch(() => {
      readyPromise = null;
    });
  }
  return readyPromise;
}

let proveChain = Promise.resolve();
function prove(inputs) {
  const run = proveChain.then(() => snarkjs.groth16.fullProve(inputs, wasmBuf, zkeyBuf));
  proveChain = run.then(
    () => {},
    () => {},
  );
  return run;
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function sendSigned(res, status, rawBody) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    [SIGNATURE_HEADER]: signBody(SECRET, rawBody),
  });
  res.end(rawBody);
}

function sendJson(res, status, obj, signed = false) {
  const rawBody = JSON.stringify(obj);
  if (signed) return sendSigned(res, status, rawBody);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(rawBody);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (c) => {
      total += c.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Task handling
// ---------------------------------------------------------------------------

const store = new Store(SEEN_STORE_PATH);

async function handleTask(envelope) {
  const taskId = envelope.task_id;
  if (typeof taskId !== "string" || !taskId) {
    return { status: 200, rawBody: JSON.stringify({ decision: "REJECT", reason_code: "INVALID_TASK" }) };
  }

  // Idempotency first: a redelivered task_id replays the original response
  // byte-for-byte and must NOT be misread as proof reuse.
  const cached = store.getCached(taskId);
  if (cached !== undefined) return { status: 200, rawBody: cached };

  const parsed = parseInput(envelope.input);
  if (!parsed) {
    const resp = { decision: "REJECT", reason_code: "INVALID_TASK" };
    const ptx = envelope.input?.proof_tx;
    if (typeof ptx === "string" && ptx) resp.proof_tx = ptx;
    const rawBody = JSON.stringify(resp);
    store.setCached(taskId, rawBody);
    return { status: 200, rawBody };
  }

  const outcome = evaluate(parsed, (tx) => store.hasSeen(tx));

  const resp = { decision: outcome.decision, reason_code: outcome.reason_code };
  if (outcome.provable) {
    // First sight of this proof_tx on a provable task: record it before
    // proving, so a concurrent/duplicate delivery cannot slip past the
    // reuse check.
    store.markSeen(parsed.proofTx);
    const inputs = buildCircuitInputs(
      taskId,
      parsed,
      outcome.decision,
      deriveSalt(SECRET, taskId),
    );
    try {
      const { proof, publicSignals } = await prove(inputs);
      resp.proof = {
        pi_a: proof.pi_a,
        pi_b: proof.pi_b,
        pi_c: proof.pi_c,
        protocol: "groth16",
        curve: "bn128",
      };
      resp.public_signals = publicSignals;
    } catch (e) {
      // Fail closed: never emit an unproven decision. Not cached — a
      // redelivery may retry the (transient) proving failure.
      console.error(`proving failed for task ${taskId}: ${e.message}`);
      return {
        status: 200,
        rawBody: JSON.stringify({
          decision: "REJECT",
          reason_code: "INVALID_TASK",
          proof_tx: parsed.proofTx,
        }),
      };
    }
  }
  resp.proof_tx = parsed.proofTx;

  const rawBody = JSON.stringify(resp);
  store.setCached(taskId, rawBody);
  return { status: 200, rawBody };
}

async function handlePost(req, res) {
  let raw;
  try {
    raw = await readBody(req);
  } catch {
    return sendJson(res, 413, { error: "body_too_large" });
  }

  // Signature over the RAW body, verified BEFORE any JSON parsing.
  if (!verifyBodySignature(SECRET, raw, req.headers[SIGNATURE_HEADER])) {
    return sendJson(res, 401, { error: "invalid_signature" });
  }

  let envelope;
  try {
    envelope = JSON.parse(raw.toString("utf8"));
  } catch {
    return sendSigned(
      res,
      400,
      JSON.stringify({ decision: "REJECT", reason_code: "INVALID_TASK" }),
    );
  }

  // Steal the VFY turns share this endpoint and its HMAC scheme but are
  // NOT Gatekeeper tasks: route them on eventId BEFORE any Gatekeeper
  // envelope validation (type/task fields) runs. The response is signed
  // exactly like every other post-parse response (sendSigned).
  if (envelope?.eventId === "steal-the-vfy") {
    const t0 = Date.now();
    const result = await handleStealTurn(envelope, stealConfig);
    console.log(
      `steal turn ${envelope.matchId} #${envelope.turn} -> ${result.action.type} ` +
        `in ${Date.now() - t0} ms`,
    );
    return sendSigned(res, 200, JSON.stringify(result));
  }

  if (envelope?.type === PREFLIGHT_TYPE) {
    return sendSigned(
      res,
      200,
      JSON.stringify({ ok: true, protocolVersion: PROTOCOL_VERSION }),
    );
  }

  if (envelope?.type === TASK_TYPE) {
    const t0 = Date.now();
    const { status, rawBody } = await handleTask(envelope);
    let label = "INVALID_TASK";
    try {
      label = JSON.parse(rawBody).reason_code ?? label;
    } catch { /* keep default */ }
    console.log(`task ${envelope.task_id} -> ${label} in ${Date.now() - t0} ms`);
    return sendSigned(res, status, rawBody);
  }

  return sendSigned(
    res,
    400,
    JSON.stringify({ decision: "REJECT", reason_code: "INVALID_TASK" }),
  );
}

/**
 * The /agent router, shared verbatim by the plain HTTP server below and
 * the Vercel function (api/agent.mjs). Expects a Node-style req/res pair;
 * POST bodies are read as a raw stream (the HMAC covers the raw bytes).
 */
export function handleRequest(req, res) {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname !== "/agent") {
    return sendJson(res, 404, { error: "not_found" });
  }
  if (req.method === "GET") {
    return sendJson(res, 200, { ok: true });
  }
  if (req.method === "POST") {
    handlePost(req, res).catch((e) => {
      console.error(`unhandled handler error: ${e.stack ?? e}`);
      if (!res.headersSent) sendJson(res, 500, { error: "internal_error" });
    });
    return;
  }
  return sendJson(res, 405, { error: "method_not_allowed" });
}

const server = http.createServer(handleRequest);

// ---------------------------------------------------------------------------
// Startup: ensureReady() loads + hash-verifies the artifacts and warms the
// prover (compiles the wasm and exercises the full pipeline once) so the
// first real task is not the cold one. Fail fast if any of that fails —
// every provable task depends on it. With GATEKEEPER_NO_LISTEN=1 (the
// Vercel function import) nothing here runs; the handler calls
// ensureReady() itself on the first request.
// ---------------------------------------------------------------------------

async function warmUp() {
  const dummyParsed = {
    registeredVk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
    proofVk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
    minimum: 1000n,
    publicBalance: 1460n,
    expiryBlock: 19842201n,
    currentBlock: 19832000n,
    recipient: "0x1111111111111111111111111111111111111111",
    conditionRecipient: "0x1111111111111111111111111111111111111111",
    amount: 500n,
    maxTransfer: 1000n,
    proofTx: "0xwarmup",
  };
  const inputs = buildCircuitInputs(
    "gk_warmup",
    dummyParsed,
    "APPROVE",
    deriveSalt(SECRET, "gk_warmup"),
  );
  const t0 = Date.now();
  await prove(inputs);
  console.log(`prover warm-up prove ok in ${Date.now() - t0} ms`);
}

if (process.env.GATEKEEPER_NO_LISTEN !== "1") {
  ensureReady()
    .then(() => {
      server.listen(PORT, () => {
        console.log(
          `proof-gatekeeper agent listening on :${PORT} (POST /agent), ` +
            `circuits=${CIRCUITS_DIR}, store=${SEEN_STORE_PATH}`,
        );
      });
    })
    .catch((e) => {
      console.error(`FATAL: agent startup failed: ${e.message}`);
      process.exit(1);
    });
}

export { server };
