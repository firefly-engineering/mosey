import { describe, expect, test } from "vitest";

import {
  decodeWalletHandshakeMessage,
  encodeWalletChallengeMessage,
  encodeWalletHelloMessage,
  encodeWalletProofMessage,
  type Delegation,
} from "../src/proto.js";

const bytes = (...vals: number[]) => new Uint8Array(vals);

describe("wallet handshake proto round-trips", () => {
  test("hello with a delegation chain", () => {
    const chain: Delegation[] = [
      { content: bytes(1, 2, 3), signature: bytes(4, 5) },
      { content: bytes(6), signature: bytes(7, 8, 9) },
    ];
    const hello = {
      clientPubkey: bytes(0xaa, 0xbb),
      nonceC: bytes(0x01, 0x02, 0x03, 0x04),
      delegationChain: chain,
    };
    const got = decodeWalletHandshakeMessage(encodeWalletHelloMessage(hello)).hello;
    expect(got).toBeDefined();
    expect(got!.clientPubkey).toEqual(hello.clientPubkey);
    expect(got!.nonceC).toEqual(hello.nonceC);
    expect(got!.delegationChain).toEqual(chain);
  });

  test("hello with empty chain", () => {
    const hello = { clientPubkey: bytes(1), nonceC: bytes(2), delegationChain: [] };
    const got = decodeWalletHandshakeMessage(encodeWalletHelloMessage(hello)).hello;
    expect(got!.delegationChain).toEqual([]);
  });

  test("challenge", () => {
    const ch = { sessionKey: bytes(0x10), nonceS: bytes(0x20, 0x21), serverSig: bytes(0x30) };
    const got = decodeWalletHandshakeMessage(encodeWalletChallengeMessage(ch)).challenge;
    expect(got).toEqual(ch);
  });

  test("proof", () => {
    const p = { clientSig: bytes(0xde, 0xad, 0xbe, 0xef) };
    const got = decodeWalletHandshakeMessage(encodeWalletProofMessage(p)).proof;
    expect(got).toEqual(p);
  });

  test("oneof variants are mutually exclusive", () => {
    const decoded = decodeWalletHandshakeMessage(
      encodeWalletProofMessage({ clientSig: bytes(1) }),
    );
    expect(decoded.hello).toBeUndefined();
    expect(decoded.challenge).toBeUndefined();
    expect(decoded.proof).toBeDefined();
  });
});
