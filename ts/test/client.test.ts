import { test } from "node:test";
import assert from "node:assert/strict";
import { KitClient, KitAPIError } from "../src/index.js";

test("calls the kit API with the user's token and maps errors", async () => {
  const seen: Array<{ method: string; url: string; auth: string | null; body: unknown }> = [];
  const f = (async (url: string, init: RequestInit = {}) => {
    const h = new Headers(init.headers);
    seen.push({ method: init.method ?? "GET", url, auth: h.get("Authorization"), body: init.body ? JSON.parse(String(init.body)) : undefined });
    if (url.endsWith("/api/v1/checkout")) return Response.json({ url: "https://checkout.stripe.test/s" });
    if (url.endsWith("/api/v1/accounts")) return Response.json({ accounts: [{ id: "a1", name: "Kund AB", role: "admin", current: true }] });
    if (url.endsWith("/api/v1/invitations")) return Response.json({ error: "already a member of this account" }, { status: 409 });
    return new Response(null, { status: 204 });
  }) as typeof fetch;
  const c = new KitClient({ issuer: "https://accounts.test/", fetch: f });

  assert.equal(await c.checkout("tok", { plan: "pro", interval: "month", success_url: "https://m/ok", cancel_url: "https://m/no" }),
    "https://checkout.stripe.test/s");
  assert.equal((await c.accounts("tok"))[0]?.name, "Kund AB");
  await c.setRole("tok", "u/1", "admin");
  await c.removeMember("tok", "u1");
  const err = await c.invite("tok", "a@b.se", "member", "sv").catch((e) => e);
  assert.ok(err instanceof KitAPIError);
  assert.equal(err.status, 409);
  assert.match(err.message, /already a member/);

  assert.deepEqual(seen.map((s) => `${s.method} ${s.url}`), [
    "POST https://accounts.test/api/v1/checkout",
    "GET https://accounts.test/api/v1/accounts",
    "PATCH https://accounts.test/api/v1/members/u%2F1",
    "DELETE https://accounts.test/api/v1/members/u1",
    "POST https://accounts.test/api/v1/invitations",
  ]);
  assert.ok(seen.every((s) => s.auth === "Bearer tok"));
  assert.deepEqual(seen[2]?.body, { role: "admin" });
  assert.deepEqual(seen[4]?.body, { email: "a@b.se", role: "member", locale: "sv" });
});
