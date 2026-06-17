# Spike: canonical delegation signing

Validates the riskiest technical assumptions behind the
[wallet-auth wire format](../../docs/src/wallet-auth.md#wire-format):

1. The canonical delegation text renders **byte-identically** in TS and Go.
2. An Ed25519 signature made the way a Solana wallet makes it **verifies in Go**
   over the raw UTF-8 content.
3. (Manual) A real wallet's `signMessage` signs the **raw bytes** rather than
   wrapping them in an envelope — open question #2.

## Automated check (no wallet needed)

```sh
node sign.mjs            | go run verify.go   # caps: write, resize
node sign.mjs view-only  | go run verify.go   # empty cap set
```

`sign.mjs` signs with Node's built-in Ed25519; because Ed25519 is RFC 8032
(deterministic), that signature is bit-identical to what tweetnacl / Phantom
produce for the same key + bytes, so verifying it in Go proves the interop.

**Result:** both vectors PASS — identical render (Go == JS) and the signature
verifies in Go over the raw UTF-8 content. Claims 1 and 2 hold.

## Manual wallet check (closes #2)

Wallet extensions inject only on http(s) origins, so serve the page:

```sh
python3 -m http.server 8000     # then open http://localhost:8000/sign.html
```

Connect a wallet, sign, copy the JSON blob, and feed it to the verifier:

```sh
pbpaste | go run verify.go      # or: go run verify.go < wallet.json
```

- **PASS over raw bytes** → the wallet signs raw `signMessage` input; the format
  is final as documented and #2 is closed.
- **FAIL** → the wallet applied a framing (e.g. Solana's `\xffsolana offchain`
  envelope); record which wallet, and the server-side verifier must reproduce
  that framing before signature checks.

Try each target wallet (Phantom, Solflare, Backpack) — behavior can differ.
