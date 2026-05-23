import { describe, expect, test } from "vitest";
import {
  decodeAuthMessage,
  decodeVarint,
  encodeAuthClientHello,
  encodeAuthClientProof,
  encodeControlResize,
  encodeVarint,
  readProtodelim,
  withProtodelim,
} from "../src/proto.js";

describe("varint", () => {
  test.each([
    [0, [0x00]],
    [1, [0x01]],
    [127, [0x7f]],
    [128, [0x80, 0x01]],
    [300, [0xac, 0x02]],
    [16384, [0x80, 0x80, 0x01]],
  ])("encode(%i) → %j", (n, expected) => {
    expect(Array.from(encodeVarint(n))).toEqual(expected);
  });

  test("round-trip across the byte boundary", () => {
    for (const v of [0n, 1n, 127n, 128n, 16383n, 16384n, 2n ** 32n - 1n, 2n ** 63n - 1n]) {
      const enc = encodeVarint(v);
      const { value, n } = decodeVarint(enc);
      expect(value).toBe(v);
      expect(n).toBe(enc.length);
    }
  });

  test("rejects truncated input", () => {
    expect(() => decodeVarint(new Uint8Array([0x80]))).toThrow(/truncated/);
  });
});

describe("ClientHello encoding", () => {
  // Bytes recorded from `protoc --decode_raw` against the Go side
  // for ClientHello{nonce: [0xaa, 0xbb], label: "owner"}. If this
  // ever drifts, regenerate by encoding the same input in Go and
  // hex-dumping the result.
  const expected = [
    0x0a, 0x0b, // AuthMessage.client_hello: bytes len=11
    0x0a, 0x02, 0xaa, 0xbb, //   ClientHello.nonce: bytes len=2 [aa bb]
    0x12, 0x05, 0x6f, 0x77, 0x6e, 0x65, 0x72, //   ClientHello.label: "owner"
  ];

  test("matches the Go-side wire format byte-for-byte", () => {
    const enc = encodeAuthClientHello({
      nonce: new Uint8Array([0xaa, 0xbb]),
      label: "owner",
    });
    expect(Array.from(enc)).toEqual(expected);
  });

  test("omits the label field when empty (proto3 default-value rule)", () => {
    const enc = encodeAuthClientHello({
      nonce: new Uint8Array([0xaa, 0xbb]),
      label: "",
    });
    expect(Array.from(enc)).toEqual([
      0x0a, 0x04, // AuthMessage.client_hello: bytes len=4
      0x0a, 0x02, 0xaa, 0xbb,
    ]);
  });
});

describe("ClientProof encoding", () => {
  test("uses oneof field number 3", () => {
    const enc = encodeAuthClientProof({ mac: new Uint8Array([0x01, 0x02, 0x03]) });
    expect(Array.from(enc)).toEqual([
      0x1a, 0x05, // AuthMessage.client_proof (field 3): bytes len=5
      0x0a, 0x03, 0x01, 0x02, 0x03,
    ]);
  });
});

describe("ServerProof decoding", () => {
  test("round-trips a fixture matching the Go-side wire bytes", () => {
    // AuthMessage.server_proof (field 2) {nonce: [11 22], mac: [aa bb cc dd]}
    const wire = new Uint8Array([
      0x12, 0x0a, // field 2: bytes len=10
      0x0a, 0x02, 0x11, 0x22, //   nonce: bytes len=2
      0x12, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, //   mac: bytes len=4
    ]);
    const decoded = decodeAuthMessage(wire);
    expect(decoded.serverProof).toBeDefined();
    expect(Array.from(decoded.serverProof!.nonce)).toEqual([0x11, 0x22]);
    expect(Array.from(decoded.serverProof!.mac)).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
  });

  test("ignores unknown future oneof variants without throwing", () => {
    // Field number 9 doesn't exist in AuthMessage today; a
    // forward-compat server adding new variants shouldn't crash an
    // older client.
    const wire = new Uint8Array([
      0x4a, 0x02, 0x01, 0x02, // field 9: bytes len=2
    ]);
    expect(() => decodeAuthMessage(wire)).not.toThrow();
  });
});

describe("Resize control encoding", () => {
  test("encodes cols + rows as tagged varints inside a oneof wrapper", () => {
    const enc = encodeControlResize({ cols: 120, rows: 40 });
    expect(Array.from(enc)).toEqual([
      0x0a, 0x04, // ControlMessage.resize (field 1): bytes len=4
      0x08, 0x78, //   Resize.cols (field 1 varint): 120
      0x10, 0x28, //   Resize.rows (field 2 varint): 40
    ]);
  });

  test("omits zero fields per proto3 default-value rule", () => {
    const enc = encodeControlResize({ cols: 0, rows: 0 });
    expect(Array.from(enc)).toEqual([
      0x0a, 0x00, // ControlMessage.resize: bytes len=0 (empty Resize)
    ]);
  });
});

describe("protodelim framing", () => {
  test("withProtodelim prepends a varint length", () => {
    const body = new Uint8Array([0x01, 0x02, 0x03]);
    expect(Array.from(withProtodelim(body))).toEqual([0x03, 0x01, 0x02, 0x03]);
  });

  test("readProtodelim peels off one message and returns the rest count", () => {
    const buf = new Uint8Array([0x03, 0x01, 0x02, 0x03, 0xff, 0xff]);
    const got = readProtodelim(buf);
    expect(got).not.toBeNull();
    expect(Array.from(got!.msg)).toEqual([0x01, 0x02, 0x03]);
    expect(got!.n).toBe(4);
  });

  test("readProtodelim returns null on incomplete buffer", () => {
    expect(readProtodelim(new Uint8Array([0x05, 0x01, 0x02]))).toBeNull();
    expect(readProtodelim(new Uint8Array([]))).toBeNull();
  });
});

// ────────────────────────────────────────────────────────────────
// Cert messages — vectors generated from Go (see ship-3pp.2 commit
// body for the reproducer). The byte streams are exactly what Go's
// proto.MarshalOptions{Deterministic: true} writes, so a passing
// test pins the TS encoder/decoder to the Go wire format.
// ────────────────────────────────────────────────────────────────

import {
  decodeCert,
  decodeCertHandshakeMessage,
  decodeSignedCertContent,
  encodeCert,
  encodeCertHelloMessage,
  encodeCertProofMessage,
} from "../src/proto.js";

// All hex literals below come from the Go reproducers in the
// ship-3pp.2 commit body.

// Cert + SignedCertContent vector (master-signed alice).
const certHex =
  "0a590a0a30314a304147454e5431122029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd71a05616c69636520072a060880dacfcf0632060880c1d4de063a0a30314a3053455249414c420464656d6f1240ec0060b9e0e484d4158343cd54b2e8cef017db56cb5bd09cc6dcc41e1a7b2474afceffaea1ef1ba4f7c8eddc478bef2d9ebbd6c39b7faa2076f45a87a1f54e01";
const contentHex =
  "0a0a30314a304147454e5431122029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd71a05616c69636520072a060880dacfcf0632060880c1d4de063a0a30314a3053455249414c420464656d6f";
const signatureHex =
  "ec0060b9e0e484d4158343cd54b2e8cef017db56cb5bd09cc6dcc41e1a7b2474afceffaea1ef1ba4f7c8eddc478bef2d9ebbd6c39b7faa2076f45a87a1f54e01";
const agentPubHex =
  "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7";

// Hello + Proof handshake message vectors.
const helloMsgHex =
  "0ac2010a9d010a590a0a30314a304147454e5431122029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd71a05616c69636520072a060880dacfcf0632060880c1d4de063a0a30314a3053455249414c420464656d6f1240ec0060b9e0e484d4158343cd54b2e8cef017db56cb5bd09cc6dcc41e1a7b2474afceffaea1ef1ba4f7c8eddc478bef2d9ebbd6c39b7faa2076f45a87a1f54e011220303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f";
const proofMsgHex =
  "12420a40404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";

describe("Cert encode / decode", () => {
  test("decodeCert recovers content + signature from the Go-produced frame", () => {
    const cert = decodeCert(fromHex(certHex));
    expect(toHex(cert.content)).toBe(contentHex);
    expect(toHex(cert.signature)).toBe(signatureHex);
  });

  test("encodeCert round-trips bytes-exact with the Go form", () => {
    const cert = decodeCert(fromHex(certHex));
    expect(toHex(encodeCert(cert))).toBe(certHex);
  });
});

describe("SignedCertContent decode", () => {
  test("recovers every field from the Go-produced content bytes", () => {
    const scc = decodeSignedCertContent(fromHex(contentHex));
    expect(scc.agentId).toBe("01J0AGENT1");
    expect(toHex(scc.peerPubkey)).toBe(agentPubHex);
    expect(scc.label).toBe("alice");
    expect(scc.capsBits).toBe(0b111);
    expect(scc.serial).toBe("01J0SERIAL");
    expect(scc.workspaceId).toBe("demo");
    // 2026-05-01T00:00:00Z = 1777593600 unix seconds.
    expect(scc.notBefore.seconds).toBe(1777593600n);
    expect(scc.notBefore.nanos).toBe(0);
    // 2027-05-01T00:00:00Z = 1809129600 unix seconds.
    expect(scc.notAfter.seconds).toBe(1809129600n);
    expect(scc.notAfter.nanos).toBe(0);
  });
});

describe("CertHandshakeMessage decode", () => {
  test("recovers a hello variant including the embedded cert", () => {
    const msg = decodeCertHandshakeMessage(fromHex(helloMsgHex));
    expect(msg.hello).toBeDefined();
    expect(msg.proof).toBeUndefined();
    expect(toHex(msg.hello!.cert.content)).toBe(contentHex);
    expect(toHex(msg.hello!.cert.signature)).toBe(signatureHex);
    // Nonce is the 0x30..0x4f range from the Go vector.
    expect(msg.hello!.nonce).toHaveLength(32);
    expect(msg.hello!.nonce[0]).toBe(0x30);
    expect(msg.hello!.nonce[31]).toBe(0x4f);
  });

  test("recovers a proof variant", () => {
    const msg = decodeCertHandshakeMessage(fromHex(proofMsgHex));
    expect(msg.proof).toBeDefined();
    expect(msg.hello).toBeUndefined();
    expect(msg.proof!.signature).toHaveLength(64);
    expect(msg.proof!.signature[0]).toBe(0x40);
    expect(msg.proof!.signature[63]).toBe(0x7f);
  });
});

describe("CertHandshakeMessage encode", () => {
  test("encodeCertHelloMessage matches Go's deterministic output byte-exact", () => {
    const cert = decodeCert(fromHex(certHex));
    // Use the same nonce the Go reproducer used: 0x30..0x4f.
    const nonce = new Uint8Array(32);
    for (let i = 0; i < 32; i++) nonce[i] = 0x30 + i;
    expect(toHex(encodeCertHelloMessage({ cert, nonce }))).toBe(helloMsgHex);
  });

  test("encodeCertProofMessage matches Go's deterministic output byte-exact", () => {
    const signature = new Uint8Array(64);
    for (let i = 0; i < 64; i++) signature[i] = 0x40 + i;
    expect(toHex(encodeCertProofMessage({ signature }))).toBe(proofMsgHex);
  });
});

function fromHex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
