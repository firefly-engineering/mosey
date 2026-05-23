import { describe, expect, test } from "vitest";

import { MoseyClient } from "../src/client.js";

// All vectors are produced by the Go reproducers in the
// ship-3pp.2 / ship-3pp.5 commit bodies. The agent keypair seed
// is 0x20..0x3f; the master seed is 0x10..0x2f.
const certHex =
  "0a590a0a30314a304147454e5431122029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd71a05616c69636520072a060880dacfcf0632060880c1d4de063a0a30314a3053455249414c420464656d6f1240ec0060b9e0e484d4158343cd54b2e8cef017db56cb5bd09cc6dcc41e1a7b2474afceffaea1ef1ba4f7c8eddc478bef2d9ebbd6c39b7faa2076f45a87a1f54e01";
const masterPubHex =
  "7776e870b93354f2a0b24c23f2a36cc4e80e223218c1b97926fdd018396a2b9b";
const agentPrivHex =
  "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7";
// Cert minted with notBefore=2020-01-01, notAfter=2021-01-01 — well
// outside any reasonable test wall clock.
const expiredCertHex =
  "0a5a0a0a30314a304147454e5431122029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd71a05616c69636520072a060880c2aff00532060880ccb9ff053a0b30314a3045585049524544420464656d6f1240e082d4a4695fe153d2dd7ed57eb7b802d93bf4565a925ee4f365b55c88b4463553b5373a6b09304dd07216ec327d13ecc624371204bcc9cf37162761e46fc80a";

// connect() reaches the cert-config validation BEFORE opening any
// socket — so we can drive these tests with an unroutable endpoint
// and still exercise the fail-fast paths. validateCertConfig either
// throws synchronously or the endpoint never matters.
const NOWHERE = "ws://127.0.0.1:1"; // port 1 reliably refuses

describe("MoseyClient.connect cert validation", () => {
  test("rejects wrong-length privateKey", async () => {
    await expect(
      MoseyClient.connect({
        endpoint: NOWHERE,
        auth: {
          type: "cert",
          cert: fromHex(certHex),
          privateKey: new Uint8Array(32), // wrong: should be 64
          masterPub: fromHex(masterPubHex),
          workspaceId: "demo",
        },
      }),
    ).rejects.toThrow(/privateKey length 32, want 64/);
  });

  test("rejects wrong-length masterPub", async () => {
    await expect(
      MoseyClient.connect({
        endpoint: NOWHERE,
        auth: {
          type: "cert",
          cert: fromHex(certHex),
          privateKey: fromHex(agentPrivHex),
          masterPub: new Uint8Array(16),
          workspaceId: "demo",
        },
      }),
    ).rejects.toThrow(/masterPub length 16, want 32/);
  });

  test("rejects empty workspaceId", async () => {
    await expect(
      MoseyClient.connect({
        endpoint: NOWHERE,
        auth: {
          type: "cert",
          cert: fromHex(certHex),
          privateKey: fromHex(agentPrivHex),
          masterPub: fromHex(masterPubHex),
          workspaceId: "",
        },
      }),
    ).rejects.toThrow(/workspaceId is required/);
  });

  test("rejects local cert that doesn't verify against masterPub", async () => {
    const wrongMaster = new Uint8Array(32); // all zeros — won't verify
    await expect(
      MoseyClient.connect({
        endpoint: NOWHERE,
        auth: {
          type: "cert",
          cert: fromHex(certHex),
          privateKey: fromHex(agentPrivHex),
          masterPub: wrongMaster,
          workspaceId: "demo",
        },
      }),
    ).rejects.toThrow(/signature does not match/);
  });

  test("rejects already-expired local cert", async () => {
    await expect(
      MoseyClient.connect({
        endpoint: NOWHERE,
        auth: {
          type: "cert",
          cert: fromHex(expiredCertHex),
          privateKey: fromHex(agentPrivHex),
          masterPub: fromHex(masterPubHex),
          workspaceId: "demo",
        },
      }),
    ).rejects.toThrow(/not within validity window/);
  });

  test("rejects cert whose peer_pubkey doesn't match privateKey's public half", async () => {
    // Flip a byte in the public half (bytes 32..64) of the priv key.
    const mismatched = new Uint8Array(fromHex(agentPrivHex));
    mismatched[40] ^= 0x01;
    await expect(
      MoseyClient.connect({
        endpoint: NOWHERE,
        auth: {
          type: "cert",
          cert: fromHex(certHex),
          privateKey: mismatched,
          masterPub: fromHex(masterPubHex),
          workspaceId: "demo",
        },
      }),
    ).rejects.toThrow(/does not match localCert.peer_pubkey/);
  });
});

function fromHex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
