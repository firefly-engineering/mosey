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
