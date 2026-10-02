// Driven by internal/server/tssdk_test.go against a real kit: the SDK's
// browser sign-in (two steps around the magic link the Go test opens), then
// token verification, the API client and event verification.
//
//   node e2e/run.mjs authorize <state-file>          → prints the authorize URL
//   node e2e/run.mjs finish <state-file> <callback>  → prints a JSON report
//
// Env: KIT_ISSUER, KIT_CLIENT, KIT_REDIRECT; for finish also KIT_EVENT_SECRET,
// KIT_EVENT_BODY, KIT_EVENT_SIG.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { KitAuth, KitClient, createVerifier, verifyEvent } from "../dist/src/index.js";

const [mode, stateFile, callback] = process.argv.slice(2);
const env = (k) => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} is required`);
  return v;
};
const storage = {
  load: () => (existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, "utf8")) : {}),
  getItem(k) { return this.load()[k] ?? null; },
  setItem(k, v) { const m = this.load(); m[k] = v; writeFileSync(stateFile, JSON.stringify(m)); },
  removeItem(k) { const m = this.load(); delete m[k]; writeFileSync(stateFile, JSON.stringify(m)); },
};
const auth = new KitAuth({ issuer: env("KIT_ISSUER"), clientId: env("KIT_CLIENT"), redirectUri: env("KIT_REDIRECT"), storage });

if (mode === "authorize") {
  process.stdout.write(await auth.authorizeURL({ locale: "sv" }));
} else if (mode === "finish") {
  const tokens = await auth.handleCallback(callback);
  const verifier = await createVerifier({ issuer: env("KIT_ISSUER"), clientId: env("KIT_CLIENT") });
  const identity = await verifier.verify(tokens.accessToken);
  const client = new KitClient({ issuer: env("KIT_ISSUER") });
  const entitlements = await client.entitlements(tokens.accessToken);
  const account = await client.account(tokens.accessToken);
  const refreshed = await auth.refresh(tokens.refreshToken);
  const refreshedIdentity = await verifier.verify(refreshed.accessToken);
  let replay = "accepted";
  try { await auth.refresh(tokens.refreshToken); } catch (e) { replay = e.code; }
  const event = await verifyEvent(env("KIT_EVENT_SECRET"), env("KIT_EVENT_SIG"), env("KIT_EVENT_BODY"));
  let forged = "accepted";
  try { await verifyEvent("kwh_wrong", env("KIT_EVENT_SIG"), env("KIT_EVENT_BODY")); } catch (e) { forged = e.name; }
  process.stdout.write(JSON.stringify({ identity, entitlements, account, refreshedAccount: refreshedIdentity.accountId,
    replay, event, forged, hasRefresh: Boolean(tokens.refreshToken) }));
} else {
  throw new Error("mode: authorize | finish");
}
