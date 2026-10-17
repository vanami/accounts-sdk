import { test } from "node:test";
import assert from "node:assert/strict";
import { KitClient, KitAPIError, isTooManyAccounts, isSeatLimit } from "../src/index.js";

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

test("billingURL links to the kit's billing page for the account and service", () => {
  const c = new KitClient({ issuer: "https://accounts.test/", product: "mail" });
  assert.equal(c.billingURL("a/1"), "https://accounts.test/account/organisations/a%2F1/billing/mail");
  assert.equal(c.billingURL("a1", { plan: "business", interval: "year" }),
    "https://accounts.test/account/organisations/a1/billing/mail/change?plan=business&interval=year");
  assert.equal(c.billingURL("a1", { plan: "pro" }), "https://accounts.test/account/organisations/a1/billing/mail/change?plan=pro&interval=month");
  assert.throws(() => new KitClient({ issuer: "https://accounts.test" }).billingURL("a1"), /needs the client's product/);
});

test("createAccount makes the user's first organisation, and says when they own too many", async () => {
  const seen: Array<{ method: string; url: string; auth: string | null; body: unknown }> = [];
  const f = (async (url: string, init: RequestInit = {}) => {
    const body = init.body ? JSON.parse(String(init.body)) : undefined;
    seen.push({ method: init.method ?? "GET", url, auth: new Headers(init.headers).get("Authorization"), body });
    if (body?.name === "Full") return Response.json({ error: "too_many_accounts", message: "…" }, { status: 409 });
    return Response.json({ id: "a2", name: "Acme", role: "owner", current: false }, { status: 201 });
  }) as typeof fetch;
  const c = new KitClient({ issuer: "https://accounts.test", fetch: f });

  const a = await c.createAccount("tok", "Acme");
  assert.equal(a.id, "a2");
  assert.equal(a.role, "owner");
  assert.deepEqual(seen[0], { method: "POST", url: "https://accounts.test/api/v1/accounts", auth: "Bearer tok", body: { name: "Acme" } });
  const err = await c.createAccount("tok", "Full").catch((e) => e);
  assert.ok(isTooManyAccounts(err) && !isSeatLimit(err), String(err));
  assert.ok(!isTooManyAccounts(new KitAPIError(409, "seat_limit")));
});
