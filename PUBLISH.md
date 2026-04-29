# Publishing zdl-verify (one-time setup + release flow)

This is internal to ZDottedLine — not part of the public spec.

## One-time setup

### 1. Claim the GitHub org

Go to https://github.com/organizations/new and create the `zdottedline` org (free plan is fine for public repos). If unavailable, fall back to `myecommerceinvestments` or your personal account; update `package.json` `repository.url` and `homepage` accordingly, plus the references in `README.md` and `SPEC.md`.

### 2. Create the npm scope

Go to https://www.npmjs.com/org/create and create the `@zdottedline` org. Add yourself as a maintainer. Public packages under a free org are free.

If `@zdottedline` is taken or you want a different name, update `package.json` `name` field.

### 3. Push to GitHub

From this repo's directory (`C:\Users\Derek\ProEcommerceProjects\zdl-verify`):

```bash
git init
git add .
git commit -m "initial commit: zdl-verify v1.0.0"
git branch -M main
git remote add origin git@github.com:zdottedline/zdl-verify.git
git push -u origin main
```

### 4. (Optional but recommended) Set up GitHub Actions CI

Create `.github/workflows/ci.yml`:

```yaml
name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm run typecheck
      - run: npm run build
```

## First release to npm

```bash
# Login (one-time)
npm login

# Verify the package is correctly configured
npm pack --dry-run

# Build + publish
npm publish --access public
```

Subsequent releases:

```bash
npm version patch    # or minor / major per SemVer
git push --tags
npm publish
```

## Marketing the release

Once published:

1. Pin the repo on the `zdottedline` GitHub org profile.
2. Add a `Verify any document yourself` link in the ZDottedLine site footer pointing to `github.com/zdottedline/zdl-verify`.
3. Tweet / LinkedIn-post: "We just open-sourced our verification CLI. If we go away, your signed documents are still independently verifiable. Spec + code: github.com/zdottedline/zdl-verify"

## Updating the spec

If you need to change `SPEC.md` post-launch:

- **Editorial / clarification** — bump `specVersion` patch (1.0.0 → 1.0.1)
- **New optional field / additive** — bump minor (1.0.x → 1.1.0)
- **Breaking change to wire format** — bump major (1.x.x → 2.0.0) AND update the verify endpoint to emit both versions for a transition period

The `specVersion` field in the verify API response should always reflect the version of the spec the API is conforming to.

## Coordinating with the main app

The reference implementation here MUST stay in sync with the server side at `apps/web/src/server/services/blockchain.ts` and `apps/web/src/server/services/opentimestamps.ts` and `apps/web/src/app/api/verify/[id]/route.ts`. If you change the Merkle root algorithm, the chain hash format, or the verify response shape on the server, **also update this repo + bump the spec version** in the same release.

A divergence between server and verifier breaks the entire trust narrative. Treat this as a P0.
