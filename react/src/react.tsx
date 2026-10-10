// The provider for apps without a server: <KitProvider> runs a KitSession,
// useKit() answers the state and actions, <SignedIn>/<SignedOut> switch on it.
"use client";

import { createContext, useContext, useEffect, useMemo, useSyncExternalStore, type ReactNode } from "react";
import { KitClient } from "./kit.js";
import { KitSession, type SessionOptions, type Snapshot } from "./session.js";

interface KitContext {
  session: KitSession;
  client: KitClient;
}

const Ctx = createContext<KitContext | null>(null);

export interface KitProviderProps extends SessionOptions {
  children?: ReactNode;
  /** Called after a sign-in finished on the redirect URI, with the returnTo given to signIn (navigate there). */
  onSignedIn?: (returnTo: string | undefined) => void;
  /** A session to use instead (tests, or sharing one across roots). */
  session?: KitSession;
}

export function KitProvider({ children, onSignedIn, session: given, ...o }: KitProviderProps) {
  const session = useMemo(() => given ?? new KitSession(o), [given, o.issuer, o.clientId, o.redirectUri]); // eslint-disable-line react-hooks/exhaustive-deps
  const client = useMemo(() => new KitClient({ issuer: o.issuer }), [o.issuer]);
  useEffect(() => {
    let live = true;
    const onCallback = typeof location !== "undefined" && location.href.startsWith(o.redirectUri);
    session.init().then((returnTo) => {
      if (live && onCallback) onSignedIn?.(returnTo);
    }, (e) => console.error("kit sign-in:", e));
    return () => {
      live = false;
    };
  }, [session]); // eslint-disable-line react-hooks/exhaustive-deps
  return <Ctx.Provider value={{ session, client }}>{children}</Ctx.Provider>;
}

export interface UseKit extends Snapshot {
  signIn: KitSession["signIn"];
  signOut: KitSession["signOut"];
  /** A fresh access token for calling your API or the kit's; undefined when signed out. */
  getAccessToken: KitSession["getAccessToken"];
  /** The kit's API (checkout, team, permissions) — pass it getAccessToken()'s token. */
  client: KitClient;
}

export function useKit(): UseKit {
  const c = useContext(Ctx);
  if (!c) throw new Error("useKit needs a <KitProvider> above it");
  const snap = useSyncExternalStore(c.session.subscribe, c.session.getSnapshot, () => ({ status: "loading" }) as Snapshot);
  return {
    ...snap,
    signIn: (o) => c.session.signIn(o),
    signOut: (u) => c.session.signOut(u),
    getAccessToken: () => c.session.getAccessToken(),
    client: c.client,
  };
}

export function SignedIn({ children }: { children?: ReactNode }) {
  return useKit().status === "signedIn" ? <>{children}</> : null;
}

export function SignedOut({ children }: { children?: ReactNode }) {
  return useKit().status === "signedOut" ? <>{children}</> : null;
}
