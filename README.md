# Proof Gatekeeper Agent

An HTTPS agent endpoint for the **Proof Gatekeeper** event in the zkVerify
Agent Games. Plain Node.js (≥18) + `snarkjs` — no framework, no TypeScript,
no build step.

The platform POSTs signed task envelopes to `/agent`; this service verifies
the HMAC over the raw body, applies a deterministic fail-closed policy,
generates a real Groth16 proof locally against the official gatekeeper
circuit, and returns a signed response — typically in ~0.3 s, far inside the
60-second platform deadline.

## Run

```bash
npm install
export AGENT_GAMES_HMAC_SECRET='<secret from the Agent Games dashboard>'
npm start            # listens on :8787, POST /agent
```

The server refuses to start without `AGENT_GAMES_HMAC_SECRET`. At startup it
loads the circuit artifacts into memory and runs one warm-up prove
(~1 s) so the first real task is not the cold one.

Circuit artifacts are sha256-verified at load against pinned hashes of the
official files. If `gatekeeper.wasm` / `gatekeeper_final.zkey` are missing
from `CIRCUITS_DIR`, they are downloaded from
`https://agentgames.zkverify.io/circuits/` and verified the same way before
use (saved back to `CIRCUITS_DIR` when it is writable; in-memory-only
otherwise). A hash mismatch — local or downloaded — aborts startup.

## Deploy on Vercel

The same code runs as a single Vercel serverless function
(`api/agent.mjs`, config in `vercel.json`):

1. Import this GitHub repo into Vercel; framework preset **"Other"**.
2. Set environment variables:
   - `AGENT_GAMES_HMAC_SECRET` — the platform-issued secret.
   - `SEEN_STORE_PATH=/tmp/seen.json`
3. Deploy. `vercel.json` rewrites `/agent` to the function and gives it
   `maxDuration` 60 s and 1024 MB (a cold start loads/verifies the circuit
   artifacts — downloading them from agentgames.zkverify.io if they are
   not in the deployment — and warms the prover; warm tasks then prove in
   ~0.3 s).

The endpoint to register in the Agent Games dashboard is:

```
https://<project>.vercel.app/agent
```

Note: on Vercel the seen-set lives in `/tmp`, which is per-instance and
resets on cold start — an accepted tradeoff, the same as the public
reference deployment. (Proof-reuse protection therefore holds within a
warm instance; the platform's own idempotency handling covers the rest.)

Smoke-test the function shape locally (mock req/res, no port bound):

```bash
npm run test:function
```

## Test

```bash
npm test
```

Boots the real server on a test port with a throwaway secret/store and runs
50 checks: health, preflight (+response signature), bad-signature 401s, a
valid task whose proof is **verified locally** with
`snarkjs groth16.verify` against `circuits/verification_key.json`, all six
traps (each provable trap's proof also verified), malformed input, and
idempotent redelivery (byte-identical cached response).

## Environment variables

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | yes | — | Platform-issued HMAC secret. Also derives the per-task circuit salt — keep it stable. Never hardcode it. |
| `PORT` | no | `8787` | Listen port. |
| `CIRCUITS_DIR` | no | `./circuits` | Must contain `gatekeeper.wasm` + `gatekeeper_final.zkey`. |
| `SEEN_STORE_PATH` | no | `./data/seen.json` | proof_tx seen-set + task_id response cache (JSON, written atomically). |

## Protocol summary

- `GET /agent` → `200 {"ok":true}` (health check, unsigned).
- `POST /agent` — every request must carry
  `x-agent-games-signature` = HMAC-SHA256(secret, **raw body**), verified
  before JSON parsing; mismatch → `401`. Inbound verification accepts the
  MAC as hex or base64, with an optional `sha256=` prefix, compared in
  constant time. Every response body is signed the same way (hex) in the
  same response header.
- Body type `agent-games.preflight.v1` →
  `200 {"ok":true,"protocolVersion":"v1"}` (signed).
- Body type `agent-games.proof-gatekeeper.v1` → decision response:

```json
{
  "decision": "APPROVE" | "REJECT",
  "reason_code": "VALID_CONDITION" | "VK_SUBSTITUTION" | "PROOF_REUSED"
               | "THRESHOLD_MISMATCH" | "EXPIRED_CONDITION"
               | "RECIPIENT_MISMATCH" | "AMOUNT_OVERFLOW" | "INVALID_TASK",
  "proof": { "pi_a": […], "pi_b": […], "pi_c": […],
             "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["<13 field elements>"],
  "proof_tx": "<echoed from the task input>"
}
```

For `PROOF_REUSED` and `INVALID_TASK` the response carries **no** proof and
no public signals.

### Decision policy (deterministic, fail closed, exact precedence)

1. `proof_vk != registered_vk` (case-insensitive) → REJECT / `VK_SUBSTITUTION` (provable)
2. `proof_tx` already in the seen-set → REJECT / `PROOF_REUSED` (no proof)
3. `public_balance < minimum` → REJECT / `THRESHOLD_MISMATCH` (provable)
4. `current_block >= expiry_block` → REJECT / `EXPIRED_CONDITION` (provable)
5. `recipient != condition_recipient` → REJECT / `RECIPIENT_MISMATCH` (provable)
6. `amount > max_transfer` → REJECT / `AMOUNT_OVERFLOW` (provable)
7. otherwise → APPROVE / `VALID_CONDITION` (provable)

Malformed envelopes/fields → REJECT / `INVALID_TASK`, no proof.

The seen-set records a `proof_tx` on first sight of any *provable* task.
Idempotency: the first response for a `task_id` is cached (in the same
store file) and replayed byte-for-byte on redelivery — a redelivery is
never misread as proof reuse. Both the seen-set and the cache persist
across restarts in `SEEN_STORE_PATH`.

### The proof

`snarkjs groth16.fullProve` with the official artifacts in `circuits/`
(downloaded from `https://agentgames.zkverify.io/circuits/`).
`circuits/verification_key.json` is extracted from the zkey
(`snarkjs zkey export verificationkey`) for local verification in tests.

Circuit inputs (13): `taskId, registeredVkHash, proofVkHash, minimum,
publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
amount, maxTransfer, decision, salt` (private). Values are BN128 field
elements: hex/decimal integers reduced mod p; free-form ids (task_id)
SHA-256 hashed then reduced mod p. `salt` =
`HMAC-SHA256(secret, "gatekeeper-salt:" + task_id) mod p` — deterministic,
so redeliveries reproduce identical proof inputs, and secret-bound, so it
is not predictable to third parties. Public signals come back as
`[Poseidon(taskId, salt), …the 12 public inputs…]`. The circuit asserts
`decision == AND(five field checks)`, so witness generation fails if the
off-chain policy ever disagrees with the circuit — the policy above mirrors
the checks exactly (balance `>=` minimum passes, amount `<=` max_transfer
passes, current_block `<` expiry_block passes).

Proving is serialized through a promise chain (one witness generation at a
time) to keep latency predictable on small VMs.

## Files

| Path | Purpose |
| --- | --- |
| `server.mjs` | The whole service: HTTP, HMAC, policy, prover, store. |
| `api/agent.mjs` | Vercel serverless entry: same `/agent` behavior via the exported router + lazy `ensureReady()`. |
| `vercel.json` | Vercel routing (`/agent` → the function) and function limits (60 s, 1024 MB). |
| `test.mjs` | Local end-to-end harness (`npm test`). |
| `test-function.mjs` | Vercel-function smoke test with mock req/res (`npm run test:function`). |
| `circuits/` | Official `gatekeeper.wasm`, `gatekeeper_final.zkey`, extracted `verification_key.json`. |
| `data/seen.json` | Runtime state (created on first task). |
| `.env.example` | Configuration template. |

## Notes / decisions

- Response `proof_tx` echoes the task's `input.proof_tx`, per the task
  spec for this implementation.
- `issued_at` / `deadline_at` / `mode` are accepted but not gated on: the
  protocol's decision taxonomy has no deadline reason code, and the
  precedence list above is treated as exhaustive.
- A proving failure resolves to REJECT / `INVALID_TASK` with no proof
  (fail closed — never an unproven APPROVE) and is *not* cached, so a
  redelivery can retry; the task's `proof_tx` stays in the seen-set.
