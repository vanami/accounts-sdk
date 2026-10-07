import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { AccountMenu, SignInButton } from "../src/components.js";
import { KitProvider, SignedIn, SignedOut } from "../src/react.js";
import { KitSession } from "../src/session.js";

test("SignInButton: a link to your route, with prompt and next; or a button", () => {
  const a = renderToStaticMarkup(<SignInButton href="/auth/kit/start" prompt="select_account" next="/app" />);
  assert.match(a, /<a href="\/auth\/kit\/start\?prompt=select_account&amp;next=%2Fapp"[^>]*>Sign in<\/a>/);
  const b = renderToStaticMarkup(<SignInButton onClick={() => {}}>Start</SignInButton>);
  assert.match(b, /<button type="button"[^>]*>Start<\/button>/);
});

test("AccountMenu: who, which organisation, account, switch, sign-out by POST", () => {
  const m = renderToStaticMarkup(
    <AccountMenu email="anna@kund.se" accountName="Kund AB" accountHref="/app/account" switchAccountHref="/auth/kit/start?prompt=select_account" signOutAction="/auth/logout" />,
  );
  for (const want of ["anna@kund.se", "Kund AB", 'href="/app/account"', ">Account<", ">Switch account<", 'action="/auth/logout"', 'method="post"', ">Sign out<", ">K<"]) {
    assert.ok(m.includes(want), `menu shows ${want}`);
  }
  assert.ok(!renderToStaticMarkup(<AccountMenu email="b@x.se" />).includes("Sign out"), "no sign-out without an action");
});

test("SignedIn / SignedOut follow the session", () => {
  const session = new KitSession({ issuer: "https://kit.test", clientId: "app", redirectUri: "https://app.test/cb",
    storage: { getItem: () => null, setItem() {}, removeItem() {} }, auth: { signIn: async () => {}, handleCallback: async () => { throw new Error() }, refresh: async () => { throw new Error() }, logoutURL: async () => "" } });
  const view = () => renderToStaticMarkup(
    <KitProvider issuer="https://kit.test" clientId="app" redirectUri="https://app.test/cb" session={session}>
      <SignedIn>IN</SignedIn><SignedOut>OUT</SignedOut>
    </KitProvider>,
  );
  assert.equal(view(), "", "loading: neither (server render)");
});
