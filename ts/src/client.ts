import { buf, utf8 } from "./encoding.js";
import { fetchProduct, type Product } from "./product.js";
// The kit's API, called with the signed-in user's access token — from the
// service's backend, or from its front end (CORS allows the service's own
// origins).

export interface CheckoutRequest {
  plan: string;
  interval: "month" | "year";
  success_url: string;
  cancel_url: string;
}

export interface Entitlements {
  product: string;
  plan?: string;
  status?: string;
  entitlements: Record<string, number | boolean>;
  current_period_end?: string;
  cancel_at_period_end?: boolean;
  /** The account has had this product before: a checkout starts no trial (one per account and product). */
  trial_used?: boolean;
  /** The plan is the kit's own trial from first use (G182b); current_period_end is when it ends. A purchase is still possible. */
  trial?: boolean;
  /** The plan was given by the operator (G182c), not bought; current_period_end is when it ends (none = for good). */
  granted?: boolean;
  /** See Identity.seats / overLimit (real time here). */
  seats?: { pricing: "flat" | "per_seat"; included?: number; max?: number; used: number };
  over_limit?: string;
}

export interface Member {
  user_id: string;
  email: string;
  /** In the account: owner | admin | member. */
  role: string;
  joined_at: string;
  /** The member's role in this service when it declares roles (G172). */
  product_role?: string;
  /** false while product_role is the default for their account role. */
  product_role_assigned?: boolean;
  /** The member has two-step verification on. */
  mfa: boolean;
}

/** The caller's role and permissions in this service, read at the time of the call. */
export interface Grant {
  product: string;
  role: string;
  permissions: string[];
}

export interface Invitation {
  id: string;
  account_id: string;
  email: string;
  role: string;
  product: string;
  invited_by: string;
  expires_at: string;
}

export interface Account {
  id: string;
  name: string;
  /** The caller's role. */
  role: string;
  members: Member[];
  /** Owners and admins only. */
  invitations?: Invitation[];
  /** Every member signs in with two steps (setRequireMFA). */
  require_mfa: boolean;
  /** Where invoices go (owners and admins see it). */
  billing_email?: string;
}

export interface AccountSummary {
  id: string;
  name: string;
  role: string;
  current: boolean;
}

export type Role = "owner" | "admin" | "member";

export class KitAPIError extends Error {
  constructor(readonly status: number, readonly code: string) {
    super(`kit: ${status}: ${code}`);
    this.name = "KitAPIError";
  }
}

/** isSeatLimit: refused because every seat on the plan is taken — offer an upgrade (G169). The same as the Go SDK's IsSeatLimit. */
export function isSeatLimit(e: unknown): boolean {
  return e instanceof KitAPIError && e.status === 409 && e.code === "seat_limit";
}

/** An account's use of one meter this calendar month (UTC), as the Go SDK's MeterUsage. */
export interface MeterUsage {
  meter: string;
  used: number;
  included: number;
  /** Minor units per unit beyond included (absent = none: included is a cap — see remaining). */
  overage?: number;
  currency?: string;
  /** The plan caps this meter; false = unlimited, or overage billed. */
  limited: boolean;
  period_start: string;
  period_end: string;
}

/** remaining: units left under a cap; undefined when the meter has no cap. The same as the Go SDK's Remaining. */
export function remaining(u: MeterUsage): number | undefined {
  return u.limited ? Math.max(u.included - u.used, 0) : undefined;
}

export class KitClient {
  private readonly issuer: string;
  private readonly f: typeof fetch;
  private readonly product?: string;
  private readonly serviceSecret?: string;

  /**
   * product and serviceSecret sign the service's own calls (usage, from a
   * background job with no user): the product id and the secret it
   * verifies the kit's events with (`accounts webhook-secret <product>`).
   */
  constructor(o: { issuer: string; fetch?: typeof fetch; product?: string; serviceSecret?: string }) {
    this.issuer = o.issuer.replace(/\/+$/, "");
    this.f = o.fetch ?? globalThis.fetch.bind(globalThis);
    this.product = o.product;
    this.serviceSecret = o.serviceSecret;
  }

  /** reportUsage: account used quantity of meter. The key makes a retry safe (recorded = false for a repeat). A service call. */
  async reportUsage(accountId: string, meter: string, quantity: number, idempotencyKey: string): Promise<boolean> {
    const out = await this.call<{ recorded: boolean }>("POST", "/api/v1/usage", undefined,
      { account_id: accountId, meter, quantity, idempotency_key: idempotencyKey });
    return out.recorded;
  }

  /** usage: this month's use per meter for the token's account. */
  async usage(token: string): Promise<MeterUsage[]> {
    return (await this.call<{ meters: MeterUsage[] }>("GET", "/api/v1/usage", token)).meters;
  }

  /** usageFor: usage for any account of the service (a signed service call). */
  async usageFor(accountId: string): Promise<MeterUsage[]> {
    return (await this.call<{ meters: MeterUsage[] }>("GET", "/api/v1/usage?" + new URLSearchParams({ account_id: accountId }), undefined)).meters;
  }

  /** checkout answers the Stripe Checkout URL (owners and admins; return URLs on the service's own origins). */
  async checkout(token: string, req: CheckoutRequest): Promise<string> {
    return (await this.call<{ url: string }>("POST", "/api/v1/checkout", token, req)).url;
  }

  /**
   * billingURL is the kit's billing page for accountId in this service (the
   * client's product): plan, next payment, card, invoices and billing
   * details, for owners and admins (doc 07 G193). A link to open in the
   * browser, where the user's kit session carries them; with a plan it opens
   * on confirming the change to that plan. Needs `product`.
   */
  billingURL(accountId: string, to?: { plan: string; interval?: "month" | "year" }): string {
    if (!this.product) throw new Error("kit: billingURL needs the client's product");
    let u = `${this.issuer}/account/organisations/${encodeURIComponent(accountId)}/billing/${encodeURIComponent(this.product)}`;
    if (to?.plan) u += "/change?" + new URLSearchParams({ plan: to.plan, interval: to.interval ?? "month" });
    return u;
  }

  /** entitlements: the account's plan in this service, in real time. */
  entitlements(token: string): Promise<Entitlements> {
    return this.call("GET", "/api/v1/entitlements", token);
  }

  account(token: string): Promise<Account> {
    return this.call("GET", "/api/v1/account", token);
  }

  /** accounts: every account the user belongs to (for an account switcher). */
  async accounts(token: string): Promise<AccountSummary[]> {
    return (await this.call<{ accounts: AccountSummary[] }>("GET", "/api/v1/accounts", token)).accounts;
  }

  async renameAccount(token: string, name: string): Promise<void> {
    await this.call("PATCH", "/api/v1/account", token, { name });
  }

  /** setRequireMFA makes two-step verification a rule for the account (owners and admins). */
  async setRequireMFA(token: string, required: boolean): Promise<void> {
    await this.call("PATCH", "/api/v1/account", token, { require_mfa: required });
  }

  /** setBillingEmail sets where invoices go (owners and admins; "" = the buyer's address). */
  async setBillingEmail(token: string, email: string): Promise<void> {
    await this.call("PATCH", "/api/v1/account", token, { billing_email: email });
  }

  /** locale is ignored: the kit's mails are in English. */
  invite(token: string, email: string, role: Role, locale?: string): Promise<Invitation> {
    return this.call("POST", "/api/v1/invitations", token, { email, role, ...(locale ? { locale } : {}) });
  }

  async revokeInvitation(token: string, id: string): Promise<void> {
    await this.call("DELETE", "/api/v1/invitations/" + encodeURIComponent(id), token);
  }

  async setRole(token: string, userId: string, role: Role): Promise<void> {
    await this.call("PATCH", "/api/v1/members/" + encodeURIComponent(userId), token, { role });
  }

  /** permissions answers the caller's role and permissions in this service now. */
  permissions(token: string): Promise<Grant> {
    return this.call("GET", "/api/v1/permissions", token);
  }

  /**
   * setProductRole assigns a member's role in this service (owners and admins;
   * an admin cannot change an owner's). "" returns them to the default.
   */
  async setProductRole(token: string, userId: string, role: string): Promise<void> {
    await this.call("PATCH", "/api/v1/members/" + encodeURIComponent(userId) + "/product-role", token, { role });
  }

  /** removeMember removes a member — with the caller's own user id, leaves. */
  async removeMember(token: string, userId: string): Promise<void> {
    await this.call("DELETE", "/api/v1/members/" + encodeURIComponent(userId), token);
  }

  /** catalogue: the product's plans, prices, roles, permissions and entitlements with their names (D-450); product defaults to the client's. Public, cached as the kit allows (a minute). The same as the Go SDK's Catalogue. */
  async catalogue(product?: string): Promise<Product> {
    const p = product ?? this.product;
    if (!p) throw new Error("kit: catalogue needs a product or the client's product");
    return fetchProduct(this.f, this.issuer, p);
  }

  private async call<T>(method: string, path: string, token: string | undefined, body?: unknown): Promise<T> {
    const raw = body !== undefined ? JSON.stringify(body) : undefined;
    const headers: Record<string, string> = raw !== undefined ? { "Content-Type": "application/json" } : {};
    if (token !== undefined) {
      headers.Authorization = "Bearer " + token;
    } else {
      // A service call: signed with the product's secret.
      if (!this.product || !this.serviceSecret) throw new Error("kit: a service call needs product and serviceSecret");
      headers["Kit-Product"] = this.product;
      headers["Kit-Signature"] = await signService(this.serviceSecret, Math.floor(Date.now() / 1000), method, new URL(this.issuer + path).pathname + new URL(this.issuer + path).search, raw ?? "");
    }
    const res = await this.f(this.issuer + path, { method, headers, body: raw });
    if (!res.ok) {
      const e = (await res.json().catch(() => ({}))) as { error?: string };
      throw new KitAPIError(res.status, e.error ?? res.statusText);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }
}

/** signService: Kit-Signature for a service call (the kit's own string, never an event signature). */
export async function signService(secret: string, unix: number, method: string, uri: string, body: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", buf(utf8(secret)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf(utf8(`${unix}.kit-service.${method} ${uri}\n${body}`))));
  return `t=${unix},v1=` + Array.from(mac, (b) => b.toString(16).padStart(2, "0")).join("");
}
