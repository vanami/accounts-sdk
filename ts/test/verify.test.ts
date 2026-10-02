import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createVerifier, KitTokenError, has, limit, require as requireEntitlement, NotEntitledError, bearer } from "../src/index.js";
import { base64url, utf8 } from "../src/encoding.js";

// A stand-in kit: discovery + JWKS over HTTP, keys the test controls.
async function fakeKit() {
  const alg = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
  const mk = async (kid: string) => {
    const pair = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    return { kid, pair, jwk: { kty: "RSA", n: jwk.n, e: jwk.e, kid, use: "sig", alg: "RS256" } };
  };
  const keys = [await mk("k1")];
  let jwksHits = 0;
  const server: Server = createServer((req, res) => {
    res.setHeader("Content-Type", "application/json");
    if (req.url === "/.well-known/openid-configuration") {
      res.end(JSON.stringify({ issuer, jwks_uri: issuer + "/keys" }));
    } else if (req.url === "/keys") {
      jwksHits++;
      res.end(JSON.stringify({ keys: keys.map((k) => k.jwk) }));
    } else {
      res.statusCode = 404;
      res.end("{}");
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const sign = async (claims: Record<string, unknown>, opts: { kid?: string; alg?: string; key?: CryptoKey } = {}) => {
    const k = keys.find((x) => x.kid === (opts.kid ?? "k1")) ?? keys[0]!;
    const h = base64url(utf8(JSON.stringify({ alg: opts.alg ?? "RS256", kid: opts.kid ?? "k1", typ: "JWT" })));
    const p = base64url(utf8(JSON.stringify(claims)));
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", opts.key ?? k.pair.privateKey, utf8(h + "." + p));
    return `${h}.${p}.${base64url(new Uint8Array(sig))}`;
  };
  return { issuer, keys, mk, sign, server, hits: () => jwksHits };
}

const now = 1_800_000_000_000;
const good = (issuer: string, extra: Record<string, unknown> = {}) => ({
  iss: issuer, sub: "user-1", aud: ["mail"], exp: now / 1000 + 900, client_id: "mail", scope: "openid email",
  account_id: "acc-1", account_role: "owner", plan: "pro", entitlements: { domains: 10, catch_all: true, aliases: 0 }, ...extra,
});

test("verifies the kit's tokens and refuses everything else", async (t) => {
  const kit = await fakeKit();
  t.after(() => kit.server.close());
  let clock = now;
  const v = await createVerifier({ issuer: kit.issuer + "/", clientId: "mail", now: () => clock });

  const id = await v.verify(await kit.sign(good(kit.issuer)));
  assert.equal(id.userId, "user-1");
  assert.equal(id.accountId, "acc-1");
  assert.equal(id.role, "owner");
  assert.equal(id.plan, "pro");
  assert.deepEqual(id.scopes, ["openid", "email"]);
  assert.equal(limit(id, "domains"), 10);
  assert.equal(has(id, "catch_all"), true);
  assert.equal(has(id, "aliases"), false);
  requireEntitlement(id, "domains", 10);
  assert.throws(() => requireEntitlement(id, "domains", 11), NotEntitledError);
  assert.throws(() => requireEntitlement(id, "unknown"), NotEntitledError);
  // A string audience works too.
  await v.verify(await kit.sign(good(kit.issuer, { aud: "mail" })));

  const other = await kit.mk("other");
  const bad: Record<string, Promise<string> | string> = {
    "another service's token": kit.sign(good(kit.issuer, { aud: ["peppol"] })),
    "another issuer": kit.sign(good("https://evil.example")),
    expired: kit.sign(good(kit.issuer, { exp: now / 1000 - 31 })),
    "not yet valid": kit.sign(good(kit.issuer, { nbf: now / 1000 + 31 })),
    "no account": kit.sign(good(kit.issuer, { account_id: "" })),
    "signed by a key the kit does not publish": kit.sign(good(kit.issuer), { key: other.pair.privateKey }),
    "alg none": (async () => {
      const [h, p] = (await kit.sign(good(kit.issuer))).split(".");
      return `${base64url(utf8(JSON.stringify({ alg: "none", kid: "k1" })))}.${p}.`;
    })(),
    // RS256-signed but labelled otherwise: only RS256 is accepted, whatever verifies.
    "header names another algorithm": kit.sign(good(kit.issuer), { alg: "HS256" }),
    "edited claims": (async () => {
      const [h, , s] = (await kit.sign(good(kit.issuer))).split(".");
      return `${h}.${base64url(utf8(JSON.stringify(good(kit.issuer, { account_id: "acc-2" }))))}.${s}`;
    })(),
    garbage: "a.b",
  };
  for (const [name, tok] of Object.entries(bad)) {
    await assert.rejects(v.verify(await tok), KitTokenError, name);
  }

  // Key rotation: an unknown kid refetches the JWKS — but at most once a minute.
  kit.keys.push(await kit.mk("k2"));
  const rotated = await kit.sign(good(kit.issuer), { kid: "k2" });
  const before = kit.hits();
  await assert.rejects(v.verify(rotated), KitTokenError, "within a minute of the last fetch: no refetch");
  assert.equal(kit.hits(), before);
  clock += 61_000;
  const again = await kit.sign(good(kit.issuer, { exp: clock / 1000 + 900 }), { kid: "k2" });
  assert.equal((await v.verify(again)).accountId, "acc-1");
  assert.equal(kit.hits(), before + 1);
});

test("discovery must name the same issuer", async (t) => {
  const kit = await fakeKit();
  t.after(() => kit.server.close());
  await assert.rejects(createVerifier({ issuer: kit.issuer.replace("127.0.0.1", "localhost"), clientId: "mail" }));
  await assert.rejects(createVerifier({ issuer: kit.issuer, clientId: "" }));
});

test("bearer", () => {
  assert.equal(bearer("Bearer abc.def.ghi"), "abc.def.ghi");
  assert.equal(bearer("Basic xyz"), undefined);
  assert.equal(bearer(undefined), undefined);
});
