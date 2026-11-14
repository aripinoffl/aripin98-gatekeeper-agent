/**
 * Vercel serverless entry for the Proof Gatekeeper agent.
 *
 * vercel.json rewrites the public path /agent to this function
 * (/api/agent). Behavior is exactly the local server's /agent route —
 * this file only adapts the runtime:
 *
 *   - bodyParser is disabled: the platform's HMAC covers the RAW request
 *     body, so the handler must receive the unparsed stream.
 *   - GATEKEEPER_NO_LISTEN is defaulted to "1" BEFORE server.mjs is
 *     imported (hence the dynamic import): importing server.mjs then
 *     binds no port and runs no warm-up, and ensureReady() performs the
 *     one-time artifact load (local files, or the sha256-pinned download
 *     fallback) + prover warm-up lazily on the first request, shared
 *     across warm invocations of this function instance.
 *   - After the /agent -> /api/agent rewrite, req.url may carry either
 *     path; it is normalized to /agent before hitting the shared router.
 *
 * Required env: AGENT_GAMES_HMAC_SECRET and SEEN_STORE_PATH=/tmp/seen.json
 * (the seen-set is per-instance and resets on cold start — accepted
 * tradeoff, same as the public reference deployment).
 */

process.env.GATEKEEPER_NO_LISTEN ??= "1";

const { ensureReady, handleRequest } = await import("../server.mjs");

export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
  try {
    await ensureReady();
  } catch (e) {
    console.error(`agent not ready: ${e.stack ?? e}`);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "agent_not_ready" }));
    return;
  }

  try {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname === "/api/agent" || url.pathname === "/agent") {
      req.url = "/agent" + url.search;
    }
  } catch {
    /* leave req.url untouched; the router will 404 an unparseable path */
  }

  handleRequest(req, res);
}
