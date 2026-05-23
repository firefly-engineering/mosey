import { describe, expect, test } from "vitest";
import {
  constantTimeEqual,
  derivePSKKey,
  ed25519Sign,
  ed25519Verify,
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

describe("Ed25519", () => {
  // Vector generated from Go's crypto/ed25519 with a deterministic
  // seed of bytes 0x00..0x1f. Regenerate by running the standalone
  // program in the ship-3pp.1 commit body.
  const seed = fromHex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  );
  const pub = fromHex(
    "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
  );
  // 64-byte Go-style private key = seed || public.
  const priv = new Uint8Array(64);
  priv.set(seed, 0);
  priv.set(pub, 32);
  const message = new TextEncoder().encode("mosey-cert-v1 test message");
  const goSig = fromHex(
    "3887ae7b22817ba1e44c58a9251447f35d1cdc5304f04f5d9ce4d6c5d20b34af3e74e45c015f9ab744a3b2e8fb9ce0a6475a7126c2b3470a010fbcc2bc72ed0d",
  );

  test("verifies a Go-produced signature", async () => {
    expect(await ed25519Verify(pub, message, goSig)).toBe(true);
  });

  test("rejects a tampered message", async () => {
    const tampered = new Uint8Array(message);
    tampered[0] ^= 0x01;
    expect(await ed25519Verify(pub, tampered, goSig)).toBe(false);
  });

  test("rejects a wrong-length signature", async () => {
    expect(await ed25519Verify(pub, message, goSig.slice(0, 32))).toBe(false);
  });

  test("throws on wrong-length public key", async () => {
    await expect(
      ed25519Verify(pub.slice(0, 16), message, goSig),
    ).rejects.toThrow(/public key length/);
  });

  test("sign round-trip with the Go private key matches the Go signature", async () => {
    const sig = await ed25519Sign(priv, message);
    expect(toHex(sig)).toBe(toHex(goSig));
  });

  test("verifies its own sign output", async () => {
    const sig = await ed25519Sign(priv, message);
    expect(await ed25519Verify(pub, message, sig)).toBe(true);
  });

  test("throws on wrong-length private key", async () => {
    await expect(ed25519Sign(seed, message)).rejects.toThrow(
      /private key length/,
    );
  });
});

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function fromHex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
