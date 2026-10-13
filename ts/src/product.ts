// The product catalogue (doc 07 D-450): what a service sells and who may do
// what — plans, prices, usage terms, roles, permissions and entitlements,
// with their names per language — read from the kit instead of a copy of
// the manifest in the service. The same as the Go SDK's Catalogue.
//
//   const p = await kit.catalogue();            // the client's product
//   label(planOf(p, "pro")!.name, "sv");        // "Pro"
//   unknownKeys(p, { permissions: ["isms.write"] }); // [] when all are declared

import { KitAPIError } from "./client.js";

/** A name per language: at least en. */
export type Names = Record<string, string>;

export interface Product {
  product: string;
  name: Names;
  plans: Plan[];
  meters: Meter[];
  entitlements: Entitlement[];
  permissions: Permission[];
  roles: ProductRole[];
  /** Each account role's role in the service until an owner or admin assigns another. */
  default_roles: Record<string, string>;
  over_limit: "block_new" | "read_only";
}

export interface Plan {
  key: string;
  name: Names;
  /** The plan every account has without a subscription. */
  free: boolean;
  prices: Price[];
  entitlements: Record<string, number | boolean>;
  trial_days?: number;
  auto_trial?: boolean;
  seats?: { pricing: "flat" | "per_seat"; included?: number; max?: number; free_roles?: string[] };
  /** Per meter: included per calendar month, and each unit beyond in minor units (absent = a cap). */
  usage: Record<string, { included: number; overage?: number }>;
}

export interface Price {
  interval: "month" | "year";
  /** Minor units: 9900 = 99.00. */
  amount: number;
  currency: string;
  /** exclusive: VAT is added on top; inclusive: the amount includes it. */
  tax_behavior: "exclusive" | "inclusive";
  seat_amount?: number;
}

export interface Meter {
  key: string;
  name: Names;
}

export interface Entitlement {
  key: string;
  kind: "limit" | "flag";
  label: Names;
}

export interface Permission {
  key: string;
  label: Names;
}

export interface ProductRole {
  key: string;
  label: Names;
  permissions: string[];
}

/** label picks a name in locale ("sv", "pt-BR"), then its language ("pt"), then English. The same as the Go SDK's Label. */
export function label(name: Names, locale: string): string {
  return name[locale] || name[locale.split("-")[0] ?? ""] || name.en || "";
}

export function planOf(p: Product, key: string): Plan | undefined {
  return p.plans.find((x) => x.key === key);
}

export function roleOf(p: Product, key: string): ProductRole | undefined {
  return p.roles.find((x) => x.key === key);
}

export function priceOf(plan: Plan, interval: "month" | "year"): Price | undefined {
  return plan.prices.find((x) => x.interval === interval);
}

/** What a service's code checks by name. */
export interface Keys {
  permissions?: string[];
  entitlements?: string[];
  plans?: string[];
  meters?: string[];
}

/**
 * unknownKeys lists the keys the catalogue does not declare, e.g.
 * "permission isms.wrte" — a typo, or something the manifest no longer has.
 * Check it at start-up or in CI. The same as the Go SDK's Unknown.
 */
export function unknownKeys(p: Product, k: Keys): string[] {
  const out: string[] = [];
  const check = (kind: string, want: string[] | undefined, has: Set<string>) => {
    for (const key of want ?? []) if (!has.has(key)) out.push(`${kind} ${key}`);
  };
  check("permission", k.permissions, new Set(p.permissions.map((x) => x.key)));
  check("entitlement", k.entitlements, new Set(p.entitlements.map((x) => x.key)));
  check("plan", k.plans, new Set(p.plans.map((x) => x.key)));
  check("meter", k.meters, new Set(p.meters.map((x) => x.key)));
  return out;
}

interface Cached {
  etag: string;
  body: Product;
  expires: number;
}

// Each catalogue as the kit last answered it, for as long as its
// Cache-Control allows, then revalidated by its ETag.
const cache = new Map<string, Cached>();

/** fetchProduct: GET /api/v1/products/{product}, cached; the last answer while the kit cannot be reached. */
export async function fetchProduct(f: typeof fetch, issuer: string, product: string): Promise<Product> {
  const url = issuer + "/api/v1/products/" + encodeURIComponent(product);
  const hit = cache.get(url);
  if (hit && Date.now() < hit.expires) return hit.body;
  let res: Response;
  try {
    res = await f(url, { headers: hit ? { "If-None-Match": hit.etag } : {} });
  } catch (e) {
    if (hit) return hit.body;
    throw e;
  }
  const expires = Date.now() + maxAge(res.headers.get("Cache-Control")) * 1000;
  if (res.status === 304 && hit) {
    hit.expires = expires;
    return hit.body;
  }
  if (!res.ok) {
    if (hit) return hit.body;
    const e = (await res.json().catch(() => ({}))) as { error?: string };
    throw new KitAPIError(res.status, e.error ?? res.statusText);
  }
  const body = (await res.json()) as Product;
  cache.set(url, { etag: res.headers.get("ETag") ?? "", body, expires });
  return body;
}

function maxAge(cc: string | null): number {
  const m = /(?:^|,)\s*max-age=(\d+)/.exec(cc ?? "");
  return m ? Number(m[1]) : 0;
}
