// Lifecycle events: the kit posts them to the URL in the product's manifest
// (`webhooks`), signed with the product's secret (`accounts webhook-secret
// <product>`). Delivery is at least once — dedupe on event.id; answer 2xx
// only once handled (anything else is retried with backoff).

import { buf, fromHex, utf8 } from "./encoding.js";

export const EventAccountCreated = "account.created";
export const EventMemberAdded = "member.added";
export const EventMemberRoleChanged = "member.role_changed";
export const EventMemberRemoved = "member.removed";
export const EventSubscriptionChanged = "subscription.changed";

/** The header carrying "t=<unix>,v1=<hex hmac-sha256 of "t.body">". */
export const SignatureHeader = "Kit-Signature";
/** How old a signature may be, seconds. */
export const EventTolerance = 300;

export interface KitEvent<T = unknown> {
  id: string;
  type: string;
  product: string;
  created_at: string;
  data: T;
}

export interface MemberData {
  account_id: string;
  user_id: string;
  email: string;
  role: string;
  previous_role?: string;
}

export interface AccountData {
  account_id: string;
  account_name: string;
  user_id: string;
  role: string;
}

export interface SubscriptionData {
  account_id: string;
  product: string;
  plan: string;
  status: string;
  entitled: boolean;
  current_period_end?: string | null;
  cancel_at_period_end: boolean;
}

export class KitSignatureError extends Error {
  constructor() {
    super("kit: invalid event signature");
    this.name = "KitSignatureError";
  }
}

/**
 * verifyEvent checks the Kit-Signature header against the raw request body
 * (the exact bytes received — not re-serialised JSON) and decodes the event.
 */
export async function verifyEvent(secret: string, header: string | null | undefined, body: string | Uint8Array,
  nowMs: number = Date.now()): Promise<KitEvent> {
  let ts = "";
  const sigs: string[] = [];
  for (const part of (header ?? "").split(",")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k === "t") ts = v;
    else if (k === "v1") sigs.push(v);
  }
  if (!/^\d+$/.test(ts) || sigs.length === 0) throw new KitSignatureError();
  if (Math.abs(nowMs / 1000 - Number(ts)) > EventTolerance) throw new KitSignatureError();
  const raw = typeof body === "string" ? utf8(body) : body;
  const key = await crypto.subtle.importKey("raw", buf(utf8(secret)), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const signed = new Uint8Array(ts.length + 1 + raw.length);
  signed.set(utf8(ts + "."), 0);
  signed.set(raw, ts.length + 1);
  let ok = false;
  for (const s of sigs) {
    const got = fromHex(s);
    // subtle.verify compares in constant time.
    if (got && got.length === 32 && (await crypto.subtle.verify("HMAC", key, buf(got), buf(signed)))) ok = true;
  }
  if (!ok) throw new KitSignatureError();
  let ev: KitEvent;
  try {
    ev = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    throw new KitSignatureError();
  }
  if (!ev || typeof ev.id !== "string" || !ev.id || typeof ev.type !== "string" || !ev.type) throw new KitSignatureError();
  return ev;
}
