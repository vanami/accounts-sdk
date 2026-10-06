// Components that work with props alone — in a Server Component, a client
// component or a static page. With a server, point them at your routes
// (template: /auth/kit/start, /auth/logout); the sign-in itself is the
// kit's hosted page, branded as your service (doc 07 G180).

import type { CSSProperties, ReactNode } from "react";

export type Locale = "sv" | "en";

const labels = {
  en: { signIn: "Sign in", account: "Account", switchAccount: "Switch account", signOut: "Sign out" },
  sv: { signIn: "Logga in", account: "Konto", switchAccount: "Byt konto", signOut: "Logga ut" },
} satisfies Record<Locale, Record<string, string>>;

export interface SignInButtonProps {
  /** Your route that starts the sign-in (with a server), e.g. "/auth/kit/start". Omit with onClick. */
  href?: string;
  /** Without a server: e.g. () => signIn() from useKit(). */
  onClick?: () => void;
  /** "select_account" opens the account picker; "login" asks for the password even with a session. */
  prompt?: "login" | "select_account";
  /** Where to land after signing in (your route passes it on as `next`). */
  next?: string;
  locale?: Locale;
  className?: string;
  style?: CSSProperties;
  children?: ReactNode;
}

export function SignInButton({ href, onClick, prompt, next, locale = "en", className, style, children }: SignInButtonProps) {
  const text = children ?? labels[locale].signIn;
  if (href !== undefined) {
    const q = new URLSearchParams();
    if (prompt) q.set("prompt", prompt);
    if (next) q.set("next", next);
    const qs = q.toString();
    return (
      <a href={qs ? `${href}${href.includes("?") ? "&" : "?"}${qs}` : href} className={className} style={style} data-kit="sign-in">
        {text}
      </a>
    );
  }
  return (
    <button type="button" onClick={onClick} className={className} style={style} data-kit="sign-in">
      {text}
    </button>
  );
}

export interface AccountMenuProps {
  email: string;
  /** The organisation the session speaks for. */
  accountName?: string;
  /** Your account page (plan, billing, team). */
  accountHref?: string;
  /** Your route that starts a sign-in with prompt=select_account. */
  switchAccountHref?: string;
  /** Your sign-out route, posted to (with a server: "/auth/logout"). */
  signOutAction?: string;
  /** Without a server: e.g. () => signOut(location.origin) from useKit(). */
  onSignOut?: () => void;
  locale?: Locale;
  className?: string;
}

/**
 * AccountMenu: who is signed in and in which organisation, with links to
 * the account page, the account switcher and sign-out. A <details>
 * disclosure: no JavaScript needed, so it renders on the server too.
 */
export function AccountMenu({ email, accountName, accountHref, switchAccountHref, signOutAction, onSignOut, locale = "en", className }: AccountMenuProps) {
  const t = labels[locale];
  const initial = (accountName || email).trim().charAt(0).toUpperCase();
  return (
    <details className={className} data-kit="account-menu" style={{ position: "relative" }}>
      <summary aria-label={t.account} style={{ listStyle: "none", cursor: "pointer", display: "inline-flex", alignItems: "center", gap: ".5rem" }}>
        <span aria-hidden style={{ display: "inline-grid", placeItems: "center", width: "2rem", height: "2rem", borderRadius: "999px", background: "currentColor" }}>
          <span style={{ color: "white", mixBlendMode: "difference", fontWeight: 600, fontSize: ".85rem" }}>{initial}</span>
        </span>
        <span>{accountName ?? email}</span>
      </summary>
      <div role="menu" style={{ position: "absolute", right: 0, marginTop: ".4rem", minWidth: "14rem", background: "white", color: "#111", border: "1px solid #e5e7eb", borderRadius: "8px", padding: ".5rem 0", boxShadow: "0 8px 24px rgba(0,0,0,.08)", zIndex: 50 }}>
        <div style={{ padding: ".25rem .9rem .5rem", fontSize: ".8rem", color: "#6b7280", borderBottom: "1px solid #e5e7eb", marginBottom: ".25rem" }}>
          {email}
          {accountName ? <div style={{ color: "#111", fontWeight: 500 }}>{accountName}</div> : null}
        </div>
        {accountHref ? <a role="menuitem" href={accountHref} style={item}>{t.account}</a> : null}
        {switchAccountHref ? <a role="menuitem" href={switchAccountHref} style={item}>{t.switchAccount}</a> : null}
        {signOutAction ? (
          <form method="post" action={signOutAction} style={{ margin: 0 }}>
            <button type="submit" role="menuitem" style={{ ...item, width: "100%", textAlign: "left", background: "none", border: 0, font: "inherit", cursor: "pointer" }}>{t.signOut}</button>
          </form>
        ) : onSignOut ? (
          <button type="button" role="menuitem" onClick={onSignOut} style={{ ...item, width: "100%", textAlign: "left", background: "none", border: 0, font: "inherit", cursor: "pointer" }}>{t.signOut}</button>
        ) : null}
      </div>
    </details>
  );
}

const item: CSSProperties = { display: "block", padding: ".45rem .9rem", color: "inherit", textDecoration: "none", fontSize: ".9rem" };
