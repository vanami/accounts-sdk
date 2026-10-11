// Sign-in for a service's front end: the authorization code flow with PKCE
// against the kit (a public client — no secret in the browser). The kit's
// own session makes it single sign-on: a user already signed in at another
// Vanami service comes straight back without a mail.
//
//   const auth = new KitAuth({ issuer, clientId: "mail", redirectUri: location.origin + "/auth/callback" });
//   await auth.signIn();                       // on the sign-in button
//   const tokens = await auth.handleCallback(); // on /auth/callback
//   await auth.signIn({ prompt: "select_account" }); // switch account

import { base64url, buf, fromBase64url, fromUtf8, randomToken, utf8 } from "./encoding.js";

export interface KitStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface KitAuthOptions {
  issuer: string;
  clientId: string;
  redirectUri: string;
  /** Default "openid email offline_access". */
  scope?: string;
  /** Where the pending sign-in is kept between redirect and callback (default sessionStorage). */
  storage?: KitStorage;
  fetch?: typeof fetch;
  /** Navigates the browser (default location.assign). */
  navigate?: (url: string) => void;
  now?: () => number;
}

export interface SignInOptions {
  /** "login": ask for the address even with a kit session; "select_account": show the account picker. */
  prompt?: "login" | "select_account";
  loginHint?: string;
  /** An organisation (account id) to sign in to: a member goes straight in, anyone else gets the picker. */
  accountHint?: string;
  /** "sv" | "en" — the kit's pages and mail. */
  locale?: string;
  /** Kept with the pending sign-in and handed back by handleCallback (e.g. the page to return to). */
  returnTo?: string;
}

export interface Tokens {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt: Date;
  returnTo?: string;
}

export class KitAuthError extends Error {
  constructor(readonly code: string, message?: string) {
    super(`kit: ${code}${message ? ": " + message : ""}`);
    this.name = "KitAuthError";
  }
}

interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint?: string;
}

interface Pending {
  verifier: string;
  nonce: string;
  returnTo?: string;
  createdAt: number;
}

const PREFIX = "kit:signin:";
const PENDING_TTL = 30 * 60_000; // the kit's auth request lives 30 minutes

export class KitAuth {
  private disc?: Promise<Discovery>;
  private readonly o: Required<Omit<KitAuthOptions, "storage" | "navigate">> & Pick<KitAuthOptions, "storage" | "navigate">;

  constructor(o: KitAuthOptions) {
    this.o = { scope: "openid email offline_access", fetch: globalThis.fetch.bind(globalThis), now: Date.now, ...o,
      issuer: o.issuer.replace(/\/+$/, "") };
  }

  private storage(): KitStorage {
    return this.o.storage ?? globalThis.sessionStorage;
  }

  private discovery(): Promise<Discovery> {
    this.disc ??= this.o.fetch(this.o.issuer + "/.well-known/openid-configuration").then(async (r) => {
      if (!r.ok) throw new KitAuthError("discovery_failed", String(r.status));
      const d = (await r.json()) as Discovery;
      if (d.issuer.replace(/\/+$/, "") !== this.o.issuer) throw new KitAuthError("discovery_failed", "issuer mismatch");
      return d;
    });
    return this.disc;
  }

  /** authorizeURL prepares a sign-in (PKCE S256, state, nonce) and answers the kit URL to send the browser to. */
  async authorizeURL(opts: SignInOptions = {}): Promise<string> {
    const d = await this.discovery();
    const verifier = randomToken(32);
    const state = randomToken(16);
    const nonce = randomToken(16);
    const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", buf(utf8(verifier)))));
    const pending: Pending = { verifier, nonce, returnTo: opts.returnTo, createdAt: this.o.now() };
    this.storage().setItem(PREFIX + state, JSON.stringify(pending));
    const q = new URLSearchParams({
      client_id: this.o.clientId, redirect_uri: this.o.redirectUri, response_type: "code", scope: this.o.scope,
      state, nonce, code_challenge: challenge, code_challenge_method: "S256",
    });
    if (opts.prompt) q.set("prompt", opts.prompt);
    if (opts.loginHint) q.set("login_hint", opts.loginHint);
    if (opts.accountHint) q.set("account_hint", opts.accountHint);
    if (opts.locale) q.set("ui_locales", opts.locale);
    return d.authorization_endpoint + "?" + q.toString();
  }

  /** signIn sends the browser to the kit. */
  async signIn(opts: SignInOptions = {}): Promise<void> {
    const url = await this.authorizeURL(opts);
    (this.o.navigate ?? ((u: string) => globalThis.location.assign(u)))(url);
  }

  /** handleCallback finishes a sign-in on the redirect URI: checks state, exchanges the code, checks the nonce. */
  async handleCallback(callbackURL: string = globalThis.location.href): Promise<Tokens> {
    const u = new URL(callbackURL);
    const err = u.searchParams.get("error");
    const state = u.searchParams.get("state") ?? "";
    const raw = state ? this.storage().getItem(PREFIX + state) : null;
    if (raw) this.storage().removeItem(PREFIX + state); // single use, success or not
    if (err) throw new KitAuthError(err, u.searchParams.get("error_description") ?? undefined);
    if (!raw) throw new KitAuthError("invalid_state", "no pending sign-in for this state");
    const pending = JSON.parse(raw) as Pending;
    if (this.o.now() - pending.createdAt > PENDING_TTL) throw new KitAuthError("invalid_state", "the sign-in expired");
    const code = u.searchParams.get("code");
    if (!code) throw new KitAuthError("invalid_request", "no code");
    const tokens = await this.token({ grant_type: "authorization_code", code, redirect_uri: this.o.redirectUri,
      code_verifier: pending.verifier });
    if (tokens.idToken) {
      // Received directly from the token endpoint over TLS (OIDC Core 3.1.3.7):
      // the nonce binds it to this browser's sign-in.
      let claims: { nonce?: string; aud?: string | string[] };
      try {
        claims = JSON.parse(fromUtf8(fromBase64url(tokens.idToken.split(".")[1] ?? "")));
      } catch {
        throw new KitAuthError("invalid_token", "unreadable id token");
      }
      const aud = typeof claims.aud === "string" ? [claims.aud] : claims.aud ?? [];
      if (claims.nonce !== pending.nonce || !aud.includes(this.o.clientId)) {
        throw new KitAuthError("invalid_token", "id token nonce/audience mismatch");
      }
    }
    return { ...tokens, returnTo: pending.returnTo };
  }

  /** refresh trades a refresh token for new tokens (it rotates: keep the new one). */
  refresh(refreshToken: string): Promise<Tokens> {
    return this.token({ grant_type: "refresh_token", refresh_token: refreshToken });
  }

  /** logoutURL signs the browser out of the service and the kit, then returns to postLogoutRedirectUri (registered in the manifest). */
  async logoutURL(idToken: string, postLogoutRedirectUri?: string): Promise<string> {
    const d = await this.discovery();
    if (!d.end_session_endpoint) throw new KitAuthError("unsupported", "no end_session_endpoint");
    const q = new URLSearchParams({ id_token_hint: idToken, client_id: this.o.clientId });
    if (postLogoutRedirectUri) q.set("post_logout_redirect_uri", postLogoutRedirectUri);
    return d.end_session_endpoint + "?" + q.toString();
  }

  private async token(form: Record<string, string>): Promise<Tokens> {
    const d = await this.discovery();
    const res = await this.o.fetch(d.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({ ...form, client_id: this.o.clientId }).toString(),
    });
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok || typeof body.access_token !== "string") {
      throw new KitAuthError(String(body.error ?? "token_failed"), body.error_description ? String(body.error_description) : undefined);
    }
    return {
      accessToken: body.access_token,
      idToken: typeof body.id_token === "string" ? body.id_token : undefined,
      refreshToken: typeof body.refresh_token === "string" ? body.refresh_token : undefined,
      expiresAt: new Date(this.o.now() + Number(body.expires_in ?? 0) * 1000),
    };
  }
}
