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
}

export interface Member {
  user_id: string;
  email: string;
  role: string;
  joined_at: string;
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
}

export interface AccountSummary {
  id: string;
  name: string;
  role: string;
  current: boolean;
}

export type Role = "owner" | "admin" | "member";

export class KitAPIError extends Error {
  constructor(readonly status: number, message: string) {
    super(`kit: ${status}: ${message}`);
    this.name = "KitAPIError";
  }
}

export class KitClient {
  private readonly issuer: string;
  private readonly f: typeof fetch;

  constructor(o: { issuer: string; fetch?: typeof fetch }) {
    this.issuer = o.issuer.replace(/\/+$/, "");
    this.f = o.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** checkout answers the Stripe Checkout URL (owners and admins; return URLs on the service's own origins). */
  async checkout(token: string, req: CheckoutRequest): Promise<string> {
    return (await this.call<{ url: string }>("POST", "/api/v1/checkout", token, req)).url;
  }

  /** portal answers the Stripe Customer Portal URL. */
  async portal(token: string, returnURL: string): Promise<string> {
    return (await this.call<{ url: string }>("POST", "/api/v1/portal", token, { return_url: returnURL })).url;
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

  invite(token: string, email: string, role: Role, locale?: "sv" | "en"): Promise<Invitation> {
    return this.call("POST", "/api/v1/invitations", token, { email, role, ...(locale ? { locale } : {}) });
  }

  async revokeInvitation(token: string, id: string): Promise<void> {
    await this.call("DELETE", "/api/v1/invitations/" + encodeURIComponent(id), token);
  }

  async setRole(token: string, userId: string, role: Role): Promise<void> {
    await this.call("PATCH", "/api/v1/members/" + encodeURIComponent(userId), token, { role });
  }

  /** removeMember removes a member — with the caller's own user id, leaves. */
  async removeMember(token: string, userId: string): Promise<void> {
    await this.call("DELETE", "/api/v1/members/" + encodeURIComponent(userId), token);
  }

  private async call<T>(method: string, path: string, token: string, body?: unknown): Promise<T> {
    const res = await this.f(this.issuer + path, {
      method,
      headers: { Authorization: "Bearer " + token, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const e = (await res.json().catch(() => ({}))) as { error?: string };
      throw new KitAPIError(res.status, e.error ?? res.statusText);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }
}
