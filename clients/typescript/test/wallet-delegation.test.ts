import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import {
  base58Decode,
  capsToString,
  parseCaps,
  parseContent,
  renderContent,
  verifyDelegation,
  type Fields,
} from "../src/wallet-delegation.js";

// The cross-language contract: Go (wallet) generates these vectors with
// `go test ./wallet -run Golden -update`; the TS renderer must reproduce
// every `content` byte-for-byte and verify every signature. Any drift in
// either language fails here.
interface GoldenVector {
  name: string;
  session: string;
  delegator: string;
  delegate: string;
  caps: string;
  not_before: string;
  not_after: string;
  nonce_hex: string;
  signature_base58: string;
  content: string;
}

const goldenPath = fileURLToPath(
  new URL("../../../wallet/testdata/delegation-vectors.json", import.meta.url),
);
const golden: { vectors: GoldenVector[] } = JSON.parse(readFileSync(goldenPath, "utf8"));

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function fieldsOf(v: GoldenVector): Fields {
  return {
    session: base58Decode(v.session),
    delegator: base58Decode(v.delegator),
    delegate: base58Decode(v.delegate),
    caps: parseCaps(v.caps),
    notBefore: v.not_before,
    notAfter: v.not_after,
    nonce: hexToBytes(v.nonce_hex),
  };
}

describe("delegation golden vectors (Go <-> TS)", () => {
  test("has vectors", () => {
    expect(golden.vectors.length).toBeGreaterThan(0);
  });

  for (const v of golden.vectors) {
    describe(v.name, () => {
      test("renders byte-identical content", () => {
        const got = new TextDecoder().decode(renderContent(fieldsOf(v)));
        expect(got).toBe(v.content);
      });

      test("verifies the Go-produced signature", async () => {
        const ok = await verifyDelegation({
          content: new TextEncoder().encode(v.content),
          signature: base58Decode(v.signature_base58),
        });
        expect(ok).toBe(true);
      });

      test("parseContent round-trips", () => {
        const f = parseContent(new TextEncoder().encode(v.content));
        expect(base58Decode(v.delegator)).toEqual(f.delegator);
        expect(capsToString(f.caps)).toBe(v.caps);
        expect(f.notBefore).toBe(v.not_before);
      });
    });
  }
});

describe("caps", () => {
  test("round-trips every value", () => {
    for (let c = 0; c <= 7; c++) {
      expect(parseCaps(capsToString(c))).toBe(c);
    }
  });

  test("rejects non-canonical", () => {
    for (const s of ["", "write, write", "resize, write", "write,resize", "owner"]) {
      expect(() => parseCaps(s)).toThrow();
    }
  });
});
