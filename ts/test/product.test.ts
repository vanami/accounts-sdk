import { test } from "node:test";
import assert from "node:assert/strict";
import { KitClient, KitAPIError, label, planOf, priceOf, roleOf, unknownKeys, type Product } from "../src/index.js";

const catalogue: Product = {
  product: "isms", name: { en: "ISMS" },
  plans: [
    { key: "free", name: { en: "free" }, free: true, prices: [], entitlements: { export: false }, usage: {} },
    { key: "pro", name: { en: "Pro", sv: "Pro" }, free: false, trial_days: 30, usage: {}, entitlements: { export: true },
      prices: [{ interval: "year", amount: 499000, currency: "sek", tax_behavior: "exclusive" }] },
  ],
  meters: [], entitlements: [{ key: "export", kind: "flag", label: { en: "Export" } }],
  permissions: [{ key: "isms.read", label: { en: "isms.read" } }, { key: "isms.write", label: { en: "Edit the register", sv: "Redigera registret" } }],
  roles: [{ key: "editor", label: { en: "Editor", sv: "Redigerare" }, permissions: ["isms.read", "isms.write"] }],
  default_roles: { owner: "editor", admin: "editor", member: "editor" }, over_limit: "block_new",
};

test("catalogue is read without a token, cached and revalidated by its ETag", async () => {
  let calls = 0, revalidations = 0, cacheControl = "public, max-age=60", down = false;
  const f = (async (url: string, init: RequestInit = {}) => {
    calls++;
    if (down) throw new TypeError("fetch failed");
    const h = new Headers(init.headers);
    assert.equal(h.get("Authorization"), null);
    if (!url.endsWith("/api/v1/products/isms")) return Response.json({ error: "no such product" }, { status: 404 });
    const headers = { ETag: '"v1"', "Cache-Control": cacheControl };
    if (h.get("If-None-Match") === '"v1"') { revalidations++; return new Response(null, { status: 304, headers }); }
    return Response.json(catalogue, { headers });
  }) as typeof fetch;
  const c = new KitClient({ issuer: "https://accounts.test/", fetch: f, product: "isms" });

  const p = await c.catalogue();
  const pro = planOf(p, "pro")!;
  assert.equal(pro.trial_days, 30);
  assert.equal(priceOf(pro, "year")?.amount, 499000);
  assert.equal(label(roleOf(p, "editor")!.label, "sv-SE"), "Redigerare");
  assert.equal(label(roleOf(p, "editor")!.label, "de"), "Editor");
  await c.catalogue("isms");
  assert.equal(calls, 1, "a fresh catalogue is not fetched again");

  // A different issuer: a cache entry of its own, revalidated each time.
  cacheControl = "no-cache";
  const c2 = new KitClient({ issuer: "https://other.test", fetch: f });
  await c2.catalogue("isms");
  await c2.catalogue("isms");
  await c2.catalogue("isms");
  assert.equal(revalidations, 2);
  down = true;
  assert.equal((await c2.catalogue("isms")).product, "isms", "the last answer while the kit is down");
  down = false;
  const err = await c2.catalogue("nope").catch((e) => e);
  assert.ok(err instanceof KitAPIError && err.status === 404);
  await assert.rejects(new KitClient({ issuer: "https://accounts.test", fetch: f }).catalogue(), /needs a product/);
});

test("unknownKeys names what the catalogue does not declare", () => {
  assert.deepEqual(unknownKeys(catalogue, { permissions: ["isms.write", "isms.wrte"], entitlements: ["export", "approvals"],
    plans: ["pro", "business"], meters: ["documents"] }),
    ["permission isms.wrte", "entitlement approvals", "plan business", "meter documents"]);
  assert.deepEqual(unknownKeys(catalogue, { permissions: ["isms.read"], plans: ["free"] }), []);
});
