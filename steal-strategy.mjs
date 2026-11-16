/**
 * Steal the VFY — committed-policy strategy module (zkVerify Agent Games).
 *
 * The vfy-policy circuit (Groth16/BN128, vk_hash 0x6c56509f…be047) enforces a
 * threshold policy over (selfBalance, opponentBalance). The policy family was
 * reverse-engineered by probing the official vfy-policy.wasm (FNV-1a signal
 * discovery + proof experiments, 2026-11-16) and is implemented here exactly:
 *
 *   params = [a, f, h, d, 0, 0, 0, 0]        a in 1..10, d in {0,1}
 *   commitment = Poseidon(params[0..7], salt)         (9-input Poseidon)
 *
 *   decide(self, opp):
 *     if self < f            -> FORTIFY
 *     else if opp <= h       -> HOLD
 *     else if d == 1         -> HOLD
 *     else                   -> EXTRACT a
 *
 *   Circuit-enforced facts (all verified by generating real proofs):
 *   - FORTIFY branch is strict: self == f does NOT fortify.
 *   - HOLD branch is inclusive: opp == h DOES hold.
 *   - EXTRACT amount is pinned: amount == a, and 1 <= a <= 10.
 *   - params[3] is a boolean: 1 replaces the EXTRACT branch with HOLD
 *     (FORTIFY branch still applies); any value >= 2 makes every move
 *     unprovable.
 *   - params[4..7] must be 0: any nonzero value makes every move unprovable.
 *   - The policy cannot see the turn number or fortify timers: they are not
 *     circuit inputs. Inputs are exactly: commitment, matchId, turnNumber,
 *     selfBalance, opponentBalance, action, amount, circuitVersion (public)
 *     and salt, strategyParams[0..7] (private).
 *
 * Chosen tournament parameters (see STRATEGY.md for the maximin argument and
 * the self-play simulation): a=10, f=0, h=0, d=0 — "always EXTRACT 10",
 * which is provable in every reachable state and can never lose a match
 * against any policy in the circuit's family.
 *
 * INTEGRATION NOTE: this is the copy of steal/strategy.mjs that lives in
 * the Gatekeeper agent project (imported by server.mjs). The only changes
 * from the original are the artifact paths (circuits-steal/ beside this
 * file, STEAL_CIRCUITS_DIR override). Policy/proof logic is unchanged.
 */

import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");

const HERE = path.dirname(fileURLToPath(import.meta.url));
// Integrated copy inside the Gatekeeper agent project: the official
// artifacts live in circuits-steal/ BESIDE this file. Resolution is
// module-relative (never cwd-relative), so proving works identically
// when the agent runs as `node server.mjs` and when server.mjs is
// imported by the Vercel function (api/agent.mjs). STEAL_CIRCUITS_DIR
// overrides the directory, mirroring the Gatekeeper's CIRCUITS_DIR.
const STEAL_CIRCUITS_DIR =
  process.env.STEAL_CIRCUITS_DIR || path.join(HERE, "circuits-steal");
export const WASM_PATH = path.join(STEAL_CIRCUITS_DIR, "vfy-policy.wasm");
export const ZKEY_PATH = path.join(STEAL_CIRCUITS_DIR, "vfy-policy_final.zkey");
export const VK_HASH = "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047";

export const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };
export const FORTIFY_COST = 2;
export const FORTIFY_BLOCK = 6;
export const EXTRACT_CAP = 10;
export const START_BALANCE = 100;
export const MATCH_TURNS = 20;

/** The committed tournament strategy. params[4..7] must stay 0 (circuit). */
export const STRATEGY_PARAMS = [10, 0, 0, 0, 0, 0, 0, 0];

/**
 * Pure policy function — mirrors the vfy-policy circuit branch-for-branch.
 * state: { selfBalance, opponentBalance } (numbers or numeric strings).
 * Returns { type: "HOLD" | "FORTIFY" } or { type: "EXTRACT", amount }.
 * The amount key is present ONLY for EXTRACT (the turn-response schema
 * rejects an amount field on HOLD/FORTIFY, even when it is 0).
 */
export function decideMove(state, params = STRATEGY_PARAMS) {
  const self = Number(state.selfBalance);
  const opp = Number(state.opponentBalance);
  const [a, f, h, d] = params;
  if (self < f) return { type: "FORTIFY" };
  if (opp <= h) return { type: "HOLD" };
  if (d === 1) return { type: "HOLD" };
  return { type: "EXTRACT", amount: a };
}

/** Validate a parameter vector against the circuit-enforced constraints. */
export function validateParams(params) {
  if (!Array.isArray(params) || params.length !== 8) throw new Error("params must have exactly 8 entries");
  const [a, , , d] = params;
  if (!Number.isInteger(a) || a < 1 || a > EXTRACT_CAP) throw new Error("params[0] (extract amount) must be an integer in 1..10");
  if (d !== 0 && d !== 1) throw new Error("params[3] (defensive flag) must be 0 or 1");
  for (let i = 4; i < 8; i++) if (params[i] !== 0) throw new Error(`params[${i}] must be 0 (circuit rejects nonzero)`);
  for (let i = 0; i < 8; i++) if (!Number.isInteger(params[i]) || params[i] < 0) throw new Error(`params[${i}] must be a non-negative integer`);
  return true;
}

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

/** commitment = Poseidon(params[0..7], salt). Returns { decimal, hex }. */
export async function computeCommitment(params = STRATEGY_PARAMS, salt) {
  validateParams(params);
  const poseidon = await getPoseidon();
  const v = poseidon.F.toObject(poseidon([...params.map(BigInt), BigInt(salt)]));
  return { decimal: v.toString(), hex: "0x" + v.toString(16).padStart(64, "0") };
}

/* ------------------------------------------------------------------ */
/* keccak-256 (pure JS; Node's crypto offers sha3-256, not keccak).    */
/* Verified against the canonical empty-string / "abc" test vectors.   */
/* ------------------------------------------------------------------ */

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const KECCAK_ROT = [
  [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
];
const MASK64 = (1n << 64n) - 1n;
const rotl64 = (x, n) => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64);

function keccakF1600(s) {
  for (let round = 0; round < 24; round++) {
    const c = [], d = [];
    for (let x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    for (let x = 0; x < 5; x++) d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) s[x + 5 * y] ^= d[x];
    const b = new Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++)
      b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(s[x + 5 * y], KECCAK_ROT[x][y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++)
      s[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & b[((x + 2) % 5) + 5 * y]);
    s[0] ^= KECCAK_RC[round];
  }
}

/** keccak256 of a Uint8Array -> hex string (no 0x). */
export function keccak256(bytes) {
  const rate = 136; // 1088 bits for keccak-256
  const s = new Array(25).fill(0n);
  const padded = Array.from(bytes);
  padded.push(0x01);
  while (padded.length % rate !== rate - 1) padded.push(0x00);
  padded.push(0x80);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + j]);
      s[i] ^= lane;
    }
    keccakF1600(s);
  }
  let out = "";
  for (let i = 0; i < 4; i++) {
    let lane = s[i];
    for (let j = 0; j < 8; j++) { out += (lane & 0xffn).toString(16).padStart(2, "0"); lane >>= 8n; }
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Turn handling                                                       */
/* ------------------------------------------------------------------ */

/** matchId (UUID string) -> field element decimal string, as the circuit expects. */
export function matchIdToField(matchId) {
  const hex = String(matchId).replace(/^0x/i, "").replace(/-/g, "");
  return BigInt("0x" + hex).toString();
}

function hex32(v) {
  return BigInt(v).toString(16).padStart(64, "0");
}

/**
 * policyProof.publicInputsHash, exactly as specified on the /build page:
 * keccak256 of the ABI-packed (32-byte big-endian each) fields
 * [commitment, matchId, turn, selfBalance, opponentBalance, actionCode,
 *  amount, circuitVersion=1].
 */
export function publicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount }) {
  const fields = [
    commitment, matchIdToField(matchId), turn, selfBalance, opponentBalance,
    ACTION_CODE[action], amount ?? 0, 1,
  ];
  const bytes = new Uint8Array(32 * fields.length);
  fields.forEach((v, i) => {
    const h = hex32(v);
    for (let j = 0; j < 32; j++) bytes[i * 32 + j] = parseInt(h.slice(j * 2, j * 2 + 2), 16);
  });
  return "0x" + keccak256(bytes);
}

/** Circuit input object for snarkjs.groth16.fullProve. */
export function buildCircuitInputs({ commitment, matchId, turn, state, move, params, salt }) {
  return {
    commitment: String(commitment),
    matchId: matchIdToField(matchId),
    turnNumber: String(turn),
    selfBalance: String(state.selfBalance),
    opponentBalance: String(state.opponentBalance),
    action: String(ACTION_CODE[move.type]),
    amount: String(move.type === "EXTRACT" ? move.amount : 0),
    circuitVersion: "1",
    salt: String(salt),
    strategyParams: params.map(String),
  };
}

let proveChain = Promise.resolve();
function proveSerialized(inputs) {
  // snarkjs fullProve is CPU-heavy; serialize so concurrent turns never
  // interleave witness generation (same pattern as the Gatekeeper agent).
  const run = proveChain.then(() => snarkjs.groth16.fullProve(inputs, WASM_PATH, ZKEY_PATH));
  proveChain = run.catch(() => {});
  return run;
}

/**
 * Handle one Steal turn envelope -> schema-exact turn response.
 * envelope: { matchId, turn, state: { selfBalance, opponentBalance, ... },
 *             strategyCommitment: { hash } }
 * config:   { params, salt }  (salt: decimal string / BigInt)
 *
 * The response omits action.amount for HOLD/FORTIFY (schema rejects it),
 * echoes matchId/turn exactly, and carries a fresh idempotencyKey.
 */
export async function handleStealTurn(envelope, config) {
  const params = config.params ?? STRATEGY_PARAMS;
  validateParams(params);
  const salt = BigInt(config.salt);
  const { matchId, turn, state } = envelope;

  const computed = await computeCommitment(params, salt);
  // The envelope carries the commitment the platform froze at pairing; the
  // proof must be made against THAT value. If it differs from our computed
  // commitment, our params/salt no longer match the registration — fail
  // loudly rather than emitting an unprovable response.
  const commitment = envelope.strategyCommitment?.hash
    ? BigInt(envelope.strategyCommitment.hash).toString()
    : computed.decimal;
  if (commitment !== computed.decimal) {
    throw new Error("strategyCommitment.hash does not match params+salt (registration drift)");
  }

  const move = decideMove(state, params);
  const inputs = buildCircuitInputs({ commitment, matchId, turn, state, move, params, salt });
  const { proof, publicSignals } = await proveSerialized(inputs);

  const action = move.type === "EXTRACT" ? { type: "EXTRACT", amount: move.amount } : { type: move.type };
  return {
    matchId,
    turn,
    action,
    policyProof: {
      circuitVersion: "v1",
      proof,
      public_signals: publicSignals,
      publicInputsHash: publicInputsHash({
        commitment, matchId, turn,
        selfBalance: state.selfBalance, opponentBalance: state.opponentBalance,
        action: move.type, amount: move.type === "EXTRACT" ? move.amount : 0,
      }),
    },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: randomUUID(),
  };
}

/** Load { params, salt } from a JSON file (kept out of any public repo). */
export function loadStrategyConfig(file) {
  const raw = JSON.parse(readFileSync(file, "utf8"));
  const params = raw.params.map(Number);
  validateParams(params);
  return { params, salt: BigInt(raw.salt) };
}
