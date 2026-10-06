import { test } from "node:test";
import assert from "node:assert/strict";
import { KitSession, userOf } from "../src/session.js";
import type { Tokens } from "../src/kit.js";

class Memory {
  m = new Map<string, string>();
  getItem(k: string) { return this.m.get(k) ?? null; }
  setItem(k: string, v: string) { this.m.set(k, v); }
  removeItem(k: string) { this.m.delete(k); }
}

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
const idToken = (claims: object) => `${b64({ alg: "RS256" })}.${b64(claims)}.sig`;

function fakeAuth(now: () => number) {
  const calls: string[] = [];
  let n = 0;
  const tokens = (): Tokens => ({ accessToken: `at-${++n}`, refreshToken: `rt-${n}`, idToken: idToken({ sub: "u1", email: "anna@kund.se" }), expiresAt: new Date(now() + 15 * 60_000) });
  return {
    calls,
    auth: {
      async signIn(o: object) { calls.push("signIn " + JSON.stringify(o)); },
      async handleCallback(u: string) { calls.push("callback " + new URL(u).searchParams.get("code")); return { ...tokens(), returnTo: "/after" }; },
      async refresh(rt: string) { calls.push("refresh " + rt); if (rt === "rt-dead") throw new Error("invalid_grant"); return { ...tokens(), idToken: undefined }; },
      async logoutURL(id: string, back?: string) { calls.push("logout"); return `https://kit.test/end_session?back=${back}`; },
    },
  };
}

test("a sign-in on the redirect URI, refresh before expiry, sign-out", async () => {
  let clock = 1_800_000_000_000;
  const now = () => clock;
  const storage = new Memory();
  const { auth, calls } = fakeAuth(now);
  const went: string[] = [];
  const s = new KitSession({ issuer: "https://kit.test", clientId: "app", redirectUri: "https://app.test/cb", storage, auth, now, navigate: (u) => went.push(u) });
  const seen: string[] = [];
  s.subscribe(() => seen.push(s.getSnapshot().status));

  assert.equal(await s.init("https://app.test/cb?code=c1&state=st"), "/after");
  assert.deepEqual(s.getSnapshot(), { status: "signedIn", user: { id: "u1", email: "anna@kund.se" } });
  assert.equal(await s.getAccessToken(), "at-1");

  // Another page load in the same tab restores the tokens.
  const again = new KitSession({ issuer: "https://kit.test", clientId: "app", redirectUri: "https://app.test/cb", storage, auth, now });
  await again.init("https://app.test/somewhere");
  assert.equal(again.getSnapshot().status, "signedIn");

  // A minute before expiry: refreshed once, even when asked twice at once; the ID token kept.
  clock += 14.5 * 60_000;
  const [a, b] = await Promise.all([s.getAccessToken(), s.getAccessToken()]);
  assert.equal(a, "at-2");
  assert.equal(b, "at-2");
  assert.equal(calls.filter((c) => c.startsWith("refresh")).length, 1);
  assert.equal(s.getSnapshot().user?.email, "anna@kund.se");

  await s.signOut("https://app.test/");
  assert.equal(s.getSnapshot().status, "signedOut");
  assert.equal(storage.getItem("kit:tokens"), null);
  assert.deepEqual(went, ["https://kit.test/end_session?back=https://app.test/"]);
  assert.ok(seen.includes("signedIn") && seen.at(-1) === "signedOut");
});

test("a refused refresh signs out", async () => {
  let clock = 1_800_000_000_000;
  const storage = new Memory();
  storage.setItem("kit:tokens", JSON.stringify({ accessToken: "old", refreshToken: "rt-dead", expiresAt: clock - 1 }));
  const { auth } = fakeAuth(() => clock);
  const s = new KitSession({ issuer: "https://kit.test", clientId: "app", redirectUri: "https://app.test/cb", storage, auth, now: () => clock });
  await s.init("https://app.test/");
  assert.equal(s.getSnapshot().status, "signedIn");
  assert.equal(await s.getAccessToken(), undefined);
  assert.equal(s.getSnapshot().status, "signedOut");
});

test("no tokens: signed out; junk tokens and ID tokens are survived", async () => {
  const storage = new Memory();
  storage.setItem("kit:tokens", "{not json");
  const { auth } = fakeAuth(Date.now);
  const s = new KitSession({ issuer: "https://kit.test", clientId: "app", redirectUri: "https://app.test/cb", storage, auth });
  await s.init("https://app.test/");
  assert.equal(s.getSnapshot().status, "signedOut");
  assert.equal(userOf("garbage"), undefined);
  assert.equal(userOf(undefined), undefined);
});
