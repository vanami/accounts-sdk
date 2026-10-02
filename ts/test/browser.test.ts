import { test } from "node:test";
import assert from "node:assert/strict";
import { KitAuth, KitAuthError, type KitStorage } from "../src/index.js";
import { base64url, utf8 } from "../src/encoding.js";

class MemoryStorage implements KitStorage {
  m = new Map<string, string>();
  getItem(k: string) { return this.m.get(k) ?? null; }
  setItem(k: string, v: string) { this.m.set(k, v); }
  removeItem(k: string) { this.m.delete(k); }
}

const issuer = "https://accounts.test";
function fakeFetch(onToken: (form: URLSearchParams) => Record<string, unknown>, status = 200) {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const f = (async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    if (url === issuer + "/.well-known/openid-configuration") {
      return Response.json({ issuer, authorization_endpoint: issuer + "/authorize", token_endpoint: issuer + "/oauth/token",
        end_session_endpoint: issuer + "/end_session" });
    }
    if (url === issuer + "/oauth/token") {
      return Response.json(onToken(new URLSearchParams(String(init?.body))), { status });
    }
    return new Response("{}", { status: 404 });
  }) as typeof fetch;
  return { f, calls };
}

const idToken = (claims: Record<string, unknown>) =>
  `${base64url(utf8('{"alg":"RS256"}'))}.${base64url(utf8(JSON.stringify(claims)))}.sig`;

test("PKCE sign-in: authorize URL, callback, code exchange, nonce", async () => {
  const storage = new MemoryStorage();
  let sentNonce = "";
  let form: URLSearchParams | undefined;
  const { f } = fakeFetch((fm) => {
    form = fm;
    return { access_token: "at", id_token: idToken({ nonce: sentNonce, aud: ["mail"] }), refresh_token: "rt", expires_in: 900 };
  });
  const auth = new KitAuth({ issuer: issuer + "/", clientId: "mail", redirectUri: "https://mail.test/cb", storage, fetch: f });
  const u = new URL(await auth.authorizeURL({ prompt: "select_account", locale: "sv", returnTo: "/settings" }));
  assert.equal(u.origin + u.pathname, issuer + "/authorize");
  const q = u.searchParams;
  assert.equal(q.get("client_id"), "mail");
  assert.equal(q.get("response_type"), "code");
  assert.equal(q.get("code_challenge_method"), "S256");
  assert.equal(q.get("prompt"), "select_account");
  assert.equal(q.get("ui_locales"), "sv");
  const pending = JSON.parse(storage.getItem("kit:signin:" + q.get("state"))!);
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(pending.verifier))));
  assert.equal(q.get("code_challenge"), challenge, "the challenge is S256 of the stored verifier");
  sentNonce = q.get("nonce")!;

  const tokens = await auth.handleCallback(`https://mail.test/cb?code=c1&state=${q.get("state")}`);
  assert.equal(tokens.accessToken, "at");
  assert.equal(tokens.refreshToken, "rt");
  assert.equal(tokens.returnTo, "/settings");
  assert.equal(form?.get("grant_type"), "authorization_code");
  assert.equal(form?.get("code"), "c1");
  assert.equal(form?.get("code_verifier"), pending.verifier);
  assert.equal(form?.get("client_id"), "mail");
  assert.equal(form?.get("redirect_uri"), "https://mail.test/cb");
  // The pending sign-in is single use.
  await assert.rejects(auth.handleCallback(`https://mail.test/cb?code=c1&state=${q.get("state")}`), KitAuthError);
});

test("callback refusals", async () => {
  const storage = new MemoryStorage();
  const { f } = fakeFetch(() => ({ access_token: "at", id_token: idToken({ nonce: "someone-else", aud: ["mail"] }), expires_in: 900 }));
  const auth = new KitAuth({ issuer, clientId: "mail", redirectUri: "https://mail.test/cb", storage, fetch: f });
  await assert.rejects(auth.handleCallback("https://mail.test/cb?code=c&state=forged"), /invalid_state/);
  await assert.rejects(auth.handleCallback("https://mail.test/cb?error=access_denied&error_description=no"), /access_denied/);
  const state = new URL(await auth.authorizeURL()).searchParams.get("state");
  await assert.rejects(auth.handleCallback(`https://mail.test/cb?code=c&state=${state}`), /nonce/, "an id token for another sign-in");
  // An expired pending sign-in.
  let clock = 0;
  const late = new KitAuth({ issuer, clientId: "mail", redirectUri: "https://mail.test/cb", storage, fetch: f, now: () => clock });
  const s2 = new URL(await late.authorizeURL()).searchParams.get("state");
  clock = 31 * 60_000;
  await assert.rejects(late.handleCallback(`https://mail.test/cb?code=c&state=${s2}`), /expired/);
});

test("token errors, refresh, logout, signIn navigates", async () => {
  const { f } = fakeFetch(() => ({ error: "invalid_grant", error_description: "gone" }), 400);
  let went = "";
  const auth = new KitAuth({ issuer, clientId: "mail", redirectUri: "https://mail.test/cb", storage: new MemoryStorage(), fetch: f,
    navigate: (u) => { went = u; } });
  await assert.rejects(auth.refresh("rt"), /invalid_grant: gone/);
  await auth.signIn({ loginHint: "a@b.se" });
  assert.equal(new URL(went).searchParams.get("login_hint"), "a@b.se");
  const out = new URL(await auth.logoutURL("idt", "https://mail.test/"));
  assert.equal(out.pathname, "/end_session");
  assert.equal(out.searchParams.get("id_token_hint"), "idt");
  assert.equal(out.searchParams.get("post_logout_redirect_uri"), "https://mail.test/");
});
