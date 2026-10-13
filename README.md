# accounts-sdk

SDKs for services that sign in with Vanami accounts (`https://accounts.vanami.com`): sign-in,
access-token verification, entitlements and permissions, lifecycle events, usage, and the
accounts API.

| Package | Install | |
|---|---|---|
| Go | `go get github.com/vanami/accounts-sdk/go` | `go/` — package `kit` |
| TypeScript | `npm install @vanami/accounts` | `ts/` — no runtime dependencies (Web Crypto) |
| React | `npm install @vanami/accounts @vanami/accounts-react` | `react/` — `SignInButton`, `AccountMenu`, `KitProvider` |

Both SDKs make the same token checks: signature against the issuer's published keys,
issuer, audience (a token for one service is never valid at another) and expiry. A change
to one SDK's checks is made in both.

## Go

```go
v, err := kit.NewVerifier(ctx, "https://accounts.vanami.com", "mail")
http.Handle("/v1/", v.Middleware(api))
// in a handler
who, _ := kit.FromContext(r.Context()) // who.UserID, who.AccountID, who.Role
if err := kit.Require(r.Context(), "items", n); err != nil { ... }
```

## TypeScript

```ts
import { createVerifier, KitClient, verifyEvent } from "@vanami/accounts";

const verifier = await createVerifier({ issuer: "https://accounts.vanami.com", clientId: "mail" });
const identity = await verifier.verify(accessToken);
```

## The product catalogue

What the service sells and who may do what, from the kit instead of a copy of the manifest
(doc 07 D-450): plans with prices, usage terms, seats and trials, entitlements, meters, roles
with their permissions, each with a name per language. Public, and cached as the kit allows
(a minute; revalidated by ETag; the last answer while the kit cannot be reached).

```go
p, err := c.Catalogue(ctx, "")                 // c.Product's
pro, _ := p.Plan("pro")
price, _ := pro.Price("year")                  // price.Amount in minor units
kit.Label(pro.Name, "sv")
// at start-up or in CI: the keys the code checks are all declared
if bad := p.Unknown(kit.Keys{Permissions: []string{"isms.write"}, Entitlements: []string{"export"}}); len(bad) > 0 {
	log.Fatalf("not in the manifest: %v", bad)
}
```

```ts
const p = await kit.catalogue();               // the client's product
label(planOf(p, "pro")!.name, "sv");
unknownKeys(p, { permissions: ["isms.write"], entitlements: ["export"] }); // [] when all are declared
```

## Versions

One version for all three packages. Before 1.0, a minor version (0.x → 0.x+1) may break;
a patch never does. Services pin a version and get updates as pull requests (Dependabot),
so their own CI shows whether an update breaks them.

## Development

```sh
npm ci && npm run build && npm test        # TypeScript and React
(cd go && go vet ./... && go test ./...)   # Go
```

## Releasing

1. Set the new version in `ts/package.json` and `react/package.json`, and react's
   `@vanami/accounts` peer and dev dependency to `^<version>`. Run `npm install` and commit.
2. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.

The release workflow checks the versions, tests, publishes both npm packages with
provenance, and tags the Go module `go/v0.2.0`. npm publishing uses trusted publishing:
each package on npmjs.com names `vanami/accounts-sdk` and `release.yml` as its trusted
publisher, so no npm token is stored in this repository.

## License

MIT
