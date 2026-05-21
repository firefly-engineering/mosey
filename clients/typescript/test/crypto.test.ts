import { describe, expect, test } from "vitest";
import {
  constantTimeEqual,
  derivePSKKey,
  hmacSHA256,
  MAC_LABEL_CLIENT,
  MAC_LABEL_SERVER,
  PSK_HKDF_INFO,
  labelBytes,
  NONCE_SIZE,
  randomNonce,
} from "../src/crypto.js";

// Vectors are reproduced from running the Go side with a known
// secret + known nonces. The point of these tests is to pin the
// browser implementation to the byte-exact output the Go server
// expects — drift on either side breaks every browser attach.
//
// To regenerate, run a tiny Go program:
//
//   secret := "hunter2"
//   key, _ := derivePSKKey(secret)
//   fmt.Printf("%x\n", key)
//   mac := mac(key[:], "mosey-auth-v1:S", []byte{0x11, ...}, []byte{0x22, ...})
//   fmt.Printf("%x\n", mac)

describe("HKDF derivePSKKey", () => {
  test('"hunter2" derives a stable 32-byte key', async () => {
    // Generated via Go (see file header). If you change PSK_HKDF_INFO,
    // regenerate.
    const expected =
      "5524e6369c82aa671736a313e2db1a1242b4a4bb2af4e81cf025e9eaf9fdb5ca";
    const got = await derivePSKKey("hunter2");
    expect(toHex(got)).toBe(expected);
  });

  test("different secrets derive different keys", async () => {
    const a = await derivePSKKey("hunter2");
    const b = await derivePSKKey("hunter3");
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

describe("HMAC-SHA256", () => {
  test("matches a known fixture for the server-side MAC", async () => {
    const key = await derivePSKKey("hunter2");
    const nonceC = new Uint8Array(NONCE_SIZE).fill(0x11);
    const nonceS = new Uint8Array(NONCE_SIZE).fill(0x22);
    // Generated via Go: mac(key, "mosey-auth-v1:S", nonceC, nonceS)
    const expected =
      "de66fd03e115a77aa6059134baab9d7fa44f270a4185da9ab7041a7a05f6cf89";
    const got = await hmacSHA256(key, labelBytes(MAC_LABEL_SERVER), nonceC, nonceS);
    expect(toHex(got)).toBe(expected);
  });

  test("the client and server labels differ", () => {
    expect(MAC_LABEL_CLIENT).not.toBe(MAC_LABEL_SERVER);
  });
});

describe("constantTimeEqual", () => {
  test("returns true for equal buffers", () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 5]);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  test("returns false for length mismatch", () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });

  test("returns false when any byte differs", () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 6]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });
});

describe("randomNonce", () => {
  test("produces NONCE_SIZE bytes", () => {
    expect(randomNonce()).toHaveLength(NONCE_SIZE);
  });

  test("produces different values on repeated calls", () => {
    const a = randomNonce();
    const b = randomNonce();
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

describe("constants", () => {
  test("HKDF info label is the canonical mosey.v1.psk", () => {
    expect(PSK_HKDF_INFO).toBe("mosey.v1.psk");
  });
});

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
