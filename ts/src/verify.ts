// Access-token verification for a service's backend (Node, Deno, Bun,
// workers): RS256 by a key the kit publishes, issuer, audience (this
// service's client id), expiry — the same checks as the Go SDK. Every
// failure is a KitTokenError; its reason is for logs, never for callers.

import { buf, fromBase64url, fromUtf8, utf8 } from "./encoding.js";

export interface Identity {
  /** The token's subject: one Vanami ID across services. */
  userId: string;
  /** The account (customer workspace) the token speaks for. */
  accountId: string;
  /** owner | admin | member in that account. */
  role: string;
  scopes: string[];
  /** The service the token was issued to. */
  clientId: string;
  expiresAt: Date;
  /** The account's plan and entitlements in this service when the token was issued (≤ 15 min old). */
  plan: string;
  entitlements: Record<string, number | boolean>;
  /**
   * The caller's role and permissions in this service (doc 07 G172) when its
   * manifest declares them; "" and [] otherwise. As old as the token;
   * KitClient.permissions is real time.
   */
  productRole: string;
  permissions: string[];
  /** How the user signed in (RFC 8176: pwd, otp, hwk, fed, mfa, …). */
  amr: string[];
  /** The plan's member policy when it sets one (G169); undefined = any number of members. */
  seats?: Seats;
  /** After a downgrade below what the account uses: block_new (default) or read_only. */
  overLimit: string;
  /**
   * The user is Vanami staff (doc 07 G179), signed in with two steps. What
   * staff may do is the service's decision; audit it. The kit sets it only
   * after two steps and only in a service's own client's tokens; the SDK
   * also requires mfa. The same as the Go SDK's Staff.
   */
  staff: boolean;
}

export interface Seats {
  pricing: "flat" | "per_seat";
  included?: number;
  /** 0 or absent = no cap. */
  max?: number;
  used: number;
}

/** seatsLeft: how many more members fit; undefined when the plan has no cap. The same as the Go SDK's SeatsLeft. */
export function seatsLeft(id: Identity): number | undefined {
  if (!id.seats || !id.seats.max) return undefined;
  return Math.max(id.seats.max - id.seats.used, 0);
}

export class KitTokenError extends Error {
  constructor(readonly reason: string) {
    super("kit: invalid token");
    this.name = "KitTokenError";
  }
}

/** limit answers an integer entitlement; undefined when the plan does not grant it. */
export function limit(id: Identity, key: string): number | undefined {
  const v = id.entitlements[key];
  return typeof v === "number" ? v : undefined;
}

/** has answers a flag; an integer limit above zero counts as granted. */
export function has(id: Identity, key: string): boolean {
  const v = id.entitlements[key];
  return typeof v === "boolean" ? v : typeof v === "number" && v > 0;
}

export class NotEntitledError extends Error {
  constructor(readonly key: string) {
    super(`kit: the account's plan does not allow this: ${key}`);
    this.name = "NotEntitledError";
  }
}

/** require throws NotEntitledError unless the plan allows n units in total of key (or the flag is set). */
export function require(id: Identity, key: string, n = 1): void {
  const v = id.entitlements[key];
  if (typeof v === "boolean") {
    if (!v) throw new NotEntitledError(key);
    return;
  }
  if (typeof v !== "number" || n > v) throw new NotEntitledError(key);
}

/** can reports whether the caller has a permission in this service. */
/** mfa: the sign-in had two steps (a passkey, or a second factor after the first). */
export function mfa(id: Identity): boolean {
  return id.amr.includes("mfa");
}

export function can(id: Identity, permission: string): boolean {
  return id.permissions.includes(permission);
}

export class ForbiddenError extends Error {
  constructor(readonly permission: string) {
    super(`kit: your role does not allow this: ${permission}`);
    this.name = "ForbiddenError";
  }
}

/**
 * requirePermission throws ForbiddenError (answer 403) unless the caller's
 * role in this service grants the permission. For an action that must not
 * rest on a token up to 15 minutes old, ask KitClient.permissions.
 */
export function requirePermission(id: Identity, permission: string): void {
  if (!can(id, permission)) throw new ForbiddenError(permission);
}

/** requireStaff throws ForbiddenError (answer 403) unless the caller is Vanami staff (G179). The same as the Go SDK's RequireStaff. */
export function requireStaff(id: Identity): void {
  if (!id.staff) throw new ForbiddenError("staff");
}

export interface VerifierOptions {
  /** The kit's URL, e.g. https://accounts.vanami.com */
  issuer: string;
  /** This service's client id (the token's audience). */
  clientId: string;
  fetch?: typeof fetch;
  now?: () => number;
  /** Clock skew allowed, seconds (default 30). */
  leeway?: number;
}

interface JWK {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
}

export interface Verifier {
  verify(token: string): Promise<Identity>;
}

const trim = (s: string) => s.replace(/\/+$/, "");

export async function createVerifier(o: VerifierOptions): Promise<Verifier> {
  if (!o.clientId) throw new Error("kit: clientId (the token's audience) is required");
  const f = o.fetch ?? fetch;
  const now = o.now ?? Date.now;
  const leeway = (o.leeway ?? 30) * 1000;
  const issuer = trim(o.issuer);

  const getJSON = async (url: string) => {
    const res = await f(url, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`kit: GET ${url}: ${res.status}`);
    return res.json();
  };
  const disc = await getJSON(issuer + "/.well-known/openid-configuration");
  if (trim(String(disc.issuer ?? "")) !== issuer || !disc.jwks_uri) {
    throw new Error(`kit: discovery: issuer ${disc.issuer} / jwks_uri ${disc.jwks_uri} do not match ${issuer}`);
  }
  const jwksURI: string = disc.jwks_uri;

  let keys = new Map<string, CryptoKey>();
  let lastFetch = 0;
  const refresh = async () => {
    const set = await getJSON(jwksURI);
    const next = new Map<string, CryptoKey>();
    for (const k of (set.keys ?? []) as JWK[]) {
      if (k.kty !== "RSA" || !k.kid || (k.use && k.use !== "sig")) continue;
      next.set(k.kid, await crypto.subtle.importKey("jwk", { kty: "RSA", n: k.n, e: k.e, alg: "RS256", ext: true },
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]));
    }
    keys = next;
    lastFetch = now();
  };
  await refresh();

  // A key this process has not seen: the kit rotated — refetch, at most once a minute.
  const keyFor = async (kid: string) => {
    const k = keys.get(kid);
    if (k || now() - lastFetch <= 60_000) return k;
    try {
      await refresh();
    } catch {
      return undefined;
    }
    return keys.get(kid);
  };

  return {
    async verify(token: string): Promise<Identity> {
      const parts = token.split(".");
      if (parts.length !== 3) throw new KitTokenError("unparseable");
      const [h, p, s] = parts as [string, string, string];
      let header: { alg?: string; kid?: string; crit?: unknown };
      let claims: Record<string, unknown>;
      let sig: Uint8Array;
      try {
        header = JSON.parse(fromUtf8(fromBase64url(h)));
        claims = JSON.parse(fromUtf8(fromBase64url(p)));
        sig = fromBase64url(s);
      } catch {
        throw new KitTokenError("unparseable");
      }
      if (header.alg !== "RS256" || header.crit !== undefined) throw new KitTokenError(`algorithm ${header.alg}`);
      const key = await keyFor(header.kid ?? "");
      if (!key) throw new KitTokenError("unknown signing key");
      const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, buf(sig), buf(utf8(h + "." + p)));
      if (!ok) throw new KitTokenError("bad signature");

      const aud = typeof claims.aud === "string" ? [claims.aud] : Array.isArray(claims.aud) ? claims.aud : [];
      const exp = typeof claims.exp === "number" ? claims.exp * 1000 : 0;
      const nbf = typeof claims.nbf === "number" ? claims.nbf * 1000 : 0;
      const t = now();
      if (trim(String(claims.iss ?? "")) !== issuer) throw new KitTokenError(`issuer ${claims.iss}`);
      if (!aud.includes(o.clientId)) throw new KitTokenError(`not for audience ${o.clientId}`);
      if (!exp || t > exp + leeway) throw new KitTokenError("expired");
      if (nbf && t + leeway < nbf) throw new KitTokenError("not yet valid");
      if (typeof claims.sub !== "string" || !claims.sub || typeof claims.account_id !== "string" || !claims.account_id) {
        throw new KitTokenError("no subject/account");
      }
      return {
        userId: claims.sub,
        accountId: claims.account_id,
        role: String(claims.account_role ?? ""),
        scopes: String(claims.scope ?? "").split(/\s+/).filter(Boolean),
        clientId: String(claims.client_id ?? ""),
        expiresAt: new Date(exp),
        plan: String(claims.plan ?? ""),
        entitlements: (claims.entitlements ?? {}) as Record<string, number | boolean>,
        productRole: typeof claims.product_role === "string" ? claims.product_role : "",
        permissions: Array.isArray(claims.permissions)
          ? claims.permissions.filter((p: unknown): p is string => typeof p === "string")
          : [],
        amr: Array.isArray(claims.amr) ? claims.amr.filter((m: unknown): m is string => typeof m === "string") : [],
        seats: seatsOf(claims.seats),
        overLimit: typeof claims.over_limit === "string" ? claims.over_limit : "block_new",
        staff: claims.staff === true && Array.isArray(claims.amr) && claims.amr.includes("mfa"),
      };
    },
  };
}

/** bearer extracts the token from an Authorization header value (undefined if absent). */
export function bearer(header: string | null | undefined): string | undefined {
  const m = /^Bearer (\S+)$/.exec(header ?? "");
  return m?.[1];
}

function seatsOf(v: unknown): Seats | undefined {
  if (!v || typeof v !== "object") return undefined;
  const s = v as Record<string, unknown>;
  if ((s.pricing !== "flat" && s.pricing !== "per_seat") || typeof s.used !== "number") return undefined;
  return {
    pricing: s.pricing,
    used: s.used,
    ...(typeof s.included === "number" ? { included: s.included } : {}),
    ...(typeof s.max === "number" ? { max: s.max } : {}),
  };
}
