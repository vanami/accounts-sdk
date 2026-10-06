// KitSession: sign-in state for an app without a server of its own (a
// static Next export, a single-page app) — PKCE in the browser with the
// SDK's KitAuth, tokens kept per tab, the access token refreshed before it
// expires. Framework-free; the React provider subscribes to it.
//
// With a server, do not use this: sign in on the server so tokens stay in
// httpOnly cookies (see template/), and render SignInButton/AccountMenu
// with props.

import { KitAuth, type KitStorage, type Tokens } from "./kit.js";

export type Status = "loading" | "signedIn" | "signedOut";

/** Who is signed in — from the ID token, for display only (never for authorization). */
export interface User {
  id: string;
  email?: string;
}

export interface Snapshot {
  status: Status;
  user?: User;
}

export interface SessionOptions {
  issuer: string;
  clientId: string;
  /** This app's callback, registered in its manifest (client.redirect_uris). */
  redirectUri: string;
  /** Where tokens and the pending sign-in live (default sessionStorage: one tab, gone when it closes). */
  storage?: KitStorage;
  /** For tests. */
  auth?: Pick<KitAuth, "signIn" | "handleCallback" | "refresh" | "logoutURL">;
  now?: () => number;
  navigate?: (url: string) => void;
}

const KEY = "kit:tokens";
const EARLY = 60_000; // refresh a minute before the access token expires

interface Stored {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number;
}

export class KitSession {
  private snap: Snapshot = { status: "loading" };
  private tokens?: Stored;
  private readonly listeners = new Set<() => void>();
  private readonly auth: NonNullable<SessionOptions["auth"]>;
  private readonly storage: KitStorage;
  private readonly now: () => number;
  private refreshing?: Promise<string>;

  constructor(private readonly o: SessionOptions) {
    this.storage = o.storage ?? globalThis.sessionStorage;
    this.auth = o.auth ?? new KitAuth({ issuer: o.issuer, clientId: o.clientId, redirectUri: o.redirectUri, storage: this.storage, navigate: o.navigate });
    this.now = o.now ?? Date.now;
  }

  subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };

  getSnapshot = (): Snapshot => this.snap;

  private set(s: Snapshot): void {
    this.snap = s;
    for (const fn of this.listeners) fn();
  }

  /**
   * init: on the redirect URI, finish the sign-in (and answer where to go
   * next — the returnTo given to signIn); elsewhere, restore this tab's tokens.
   */
  async init(currentURL: string = globalThis.location?.href ?? ""): Promise<string | undefined> {
    let returnTo: string | undefined;
    const u = currentURL ? new URL(currentURL) : undefined;
    if (u && currentURL.startsWith(this.o.redirectUri) && u.searchParams.has("code")) {
      const t = await this.auth.handleCallback(currentURL);
      returnTo = t.returnTo;
      this.keep(t);
    } else {
      const raw = this.storage.getItem(KEY);
      try {
        this.tokens = raw ? (JSON.parse(raw) as Stored) : undefined;
      } catch {
        this.tokens = undefined;
      }
    }
    this.publish();
    return returnTo;
  }

  private keep(t: Tokens, previousIdToken?: string): void {
    this.tokens = { accessToken: t.accessToken, refreshToken: t.refreshToken, idToken: t.idToken ?? previousIdToken, expiresAt: t.expiresAt.getTime() };
    this.storage.setItem(KEY, JSON.stringify(this.tokens));
  }

  private publish(): void {
    if (!this.tokens) {
      this.set({ status: "signedOut" });
      return;
    }
    this.set({ status: "signedIn", user: userOf(this.tokens.idToken) });
  }

  signIn(opts: { returnTo?: string; prompt?: "login" | "select_account"; locale?: string } = {}): Promise<void> {
    return this.auth.signIn(opts);
  }

  /** The access token for API calls, refreshed when it is about to expire; undefined when signed out. */
  async getAccessToken(): Promise<string | undefined> {
    const t = this.tokens;
    if (!t) return undefined;
    if (this.now() < t.expiresAt - EARLY) return t.accessToken;
    if (!t.refreshToken) {
      this.clear();
      return undefined;
    }
    this.refreshing ??= this.auth.refresh(t.refreshToken).then(
      (n) => {
        this.keep(n, t.idToken);
        this.publish();
        return n.accessToken;
      },
      (e) => {
        this.clear(); // rotated, revoked, a removed member: sign in again
        throw e;
      },
    ).finally(() => (this.refreshing = undefined));
    try {
      return await this.refreshing;
    } catch {
      return undefined;
    }
  }

  private clear(): void {
    this.tokens = undefined;
    this.storage.removeItem(KEY);
    this.publish();
  }

  /** signOut ends this tab's session and the kit's (single sign-out), then returns to postLogoutRedirectUri. */
  async signOut(postLogoutRedirectUri?: string): Promise<void> {
    const idToken = this.tokens?.idToken;
    this.clear();
    if (!idToken) return;
    const url = await this.auth.logoutURL(idToken, postLogoutRedirectUri);
    (this.o.navigate ?? ((u: string) => globalThis.location.assign(u)))(url);
  }
}

/** userOf reads the ID token's claims for display (the token came from the kit's token endpoint over TLS). */
export function userOf(idToken?: string): User | undefined {
  if (!idToken) return undefined;
  try {
    const part = idToken.split(".")[1] ?? "";
    const json = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(part.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));
    return typeof json.sub === "string" ? { id: json.sub, email: typeof json.email === "string" ? json.email : undefined } : undefined;
  } catch {
    return undefined;
  }
}
