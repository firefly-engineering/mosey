// Hand-rolled protobuf encoders/decoders for the auth + control
// messages mosey carries on the wire. Hand-coded rather than
// generated because the surface is small (three auth messages + one
// resize control message), no protoc / codegen step keeps the
// install path trivial, and a single audit-able file is the right
// fit for a reference client.
//
// Wire format spec: protobuf 3 + protodelim framing (varint length
// prefix + serialized proto). Tag encoding is (field_number << 3)
// | wire_type. We only use wire types:
//   0 (varint) — uint32, bool
//   2 (length-delimited) — bytes, string, embedded message

const tagBytesField = (n: number) => (n << 3) | 2; // bytes / string / message → wire type 2
const tagVarintField = (n: number) => (n << 3) | 0; // uint32 → wire type 0

// encodeVarint writes a uint64 as a base-128 varint.
export function encodeVarint(n: number | bigint): Uint8Array {
  let value = typeof n === "bigint" ? n : BigInt(n);
  const out: number[] = [];
  while (value >= 0x80n) {
    out.push(Number(value & 0x7fn) | 0x80);
    value >>= 7n;
  }
  out.push(Number(value));
  return new Uint8Array(out);
}

// decodeVarint reads one varint and returns its value + the number
// of bytes consumed. Throws on truncated input or values that
// overflow uint64.
export function decodeVarint(buf: Uint8Array, offset = 0): { value: bigint; n: number } {
  let value = 0n;
  let shift = 0n;
  let i = offset;
  for (; i < buf.length; i++) {
    const b = buf[i]!;
    value |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) {
      return { value, n: i - offset + 1 };
    }
    shift += 7n;
    if (shift > 63n) {
      throw new Error("mosey/proto: varint overflows uint64");
    }
  }
  throw new Error("mosey/proto: truncated varint");
}

// concat is a small helper to avoid the verbosity of building
// payloads via TypedArray.set + offset bookkeeping.
function concat(parts: ArrayLike<number>[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// encodeBytesField writes one tagged length-delimited field
// (bytes or string body).
function encodeBytesField(field: number, value: Uint8Array): Uint8Array {
  return concat([
    new Uint8Array([tagBytesField(field)]),
    encodeVarint(value.length),
    value,
  ]);
}

// encodeStringField writes one tagged length-delimited field
// containing UTF-8 encoded text. Empty strings are omitted (proto3
// default-value rule) so the wire form matches what the Go side
// emits.
function encodeStringField(field: number, value: string): Uint8Array {
  if (value === "") return new Uint8Array(0);
  return encodeBytesField(field, new TextEncoder().encode(value));
}

// encodeVarintField writes one tagged varint field. Default-zero
// values are omitted per proto3.
function encodeVarintField(field: number, value: number): Uint8Array {
  if (value === 0) return new Uint8Array(0);
  return concat([
    new Uint8Array([tagVarintField(field)]),
    encodeVarint(value),
  ]);
}

// withProtodelim prepends a varint length to a serialized message
// (the framing protodelim uses on the wire).
export function withProtodelim(body: Uint8Array): Uint8Array {
  return concat([encodeVarint(body.length), body]);
}

// readProtodelim reads a single length-prefixed message from a
// buffered byte queue. Returns the message bytes and the number of
// bytes consumed (header + body), or null when the buffer doesn't
// yet contain a full message.
export function readProtodelim(buf: Uint8Array): { msg: Uint8Array; n: number } | null {
  if (buf.length === 0) return null;
  let length: bigint, headerLen: number;
  try {
    const v = decodeVarint(buf, 0);
    length = v.value;
    headerLen = v.n;
  } catch {
    // Likely truncated varint — wait for more bytes.
    return null;
  }
  const total = headerLen + Number(length);
  if (buf.length < total) return null;
  return { msg: buf.slice(headerLen, total), n: total };
}

// ────────────────────────────────────────────────────────────────
// Auth messages
// ────────────────────────────────────────────────────────────────

export interface ClientHello {
  nonce: Uint8Array;
  label: string;
}

export interface ServerProof {
  nonce: Uint8Array;
  mac: Uint8Array;
}

export interface ClientProof {
  mac: Uint8Array;
}

// encodeAuthClientHello encodes an AuthMessage with the
// client_hello oneof variant set.
export function encodeAuthClientHello(h: ClientHello): Uint8Array {
  const inner = concat([
    encodeBytesField(1, h.nonce),
    encodeStringField(2, h.label),
  ]);
  // AuthMessage.client_hello has field number 1.
  return encodeBytesField(1, inner);
}

// encodeAuthClientProof encodes an AuthMessage with the
// client_proof oneof variant set.
export function encodeAuthClientProof(p: ClientProof): Uint8Array {
  const inner = encodeBytesField(1, p.mac);
  // AuthMessage.client_proof has field number 3.
  return encodeBytesField(3, inner);
}

// decodeAuthMessage parses a length-stripped AuthMessage and
// returns whichever oneof variant is set. Unknown fields are
// skipped so a forward-compatible server adding payload variants
// won't break the parse — the consumer just gets back a partially
// populated object and decides what to do.
export function decodeAuthMessage(buf: Uint8Array): {
  clientHello?: ClientHello;
  serverProof?: ServerProof;
  clientProof?: ClientProof;
} {
  const out: ReturnType<typeof decodeAuthMessage> = {};
  let off = 0;
  while (off < buf.length) {
    const { value: tag, n: tn } = decodeVarint(buf, off);
    off += tn;
    const fieldNum = Number(tag >> 3n);
    const wireType = Number(tag & 0x7n);
    if (wireType !== 2) {
      throw new Error(`mosey/proto: AuthMessage field ${fieldNum} has unexpected wire type ${wireType}`);
    }
    const { value: len, n: ln } = decodeVarint(buf, off);
    off += ln;
    const body = buf.slice(off, off + Number(len));
    off += Number(len);

    switch (fieldNum) {
      case 1:
        out.clientHello = decodeClientHello(body);
        break;
      case 2:
        out.serverProof = decodeServerProof(body);
        break;
      case 3:
        out.clientProof = decodeClientProof(body);
        break;
      // Other field numbers belong to forward-compat oneof
      // variants we don't recognize. Silently skip.
    }
  }
  return out;
}

function decodeClientHello(buf: Uint8Array): ClientHello {
  let nonce: Uint8Array = new Uint8Array(0);
  let label = "";
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) nonce = value as Uint8Array;
    else if (field === 2) label = new TextDecoder().decode(value as Uint8Array);
  }
  return { nonce, label };
}

function decodeServerProof(buf: Uint8Array): ServerProof {
  let nonce: Uint8Array = new Uint8Array(0);
  let mac: Uint8Array = new Uint8Array(0);
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) nonce = value as Uint8Array;
    else if (field === 2) mac = value as Uint8Array;
  }
  return { nonce, mac };
}

function decodeClientProof(buf: Uint8Array): ClientProof {
  let mac: Uint8Array = new Uint8Array(0);
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) mac = value as Uint8Array;
  }
  return { mac };
}

// iterFields walks every (field, wire-decoded value) pair in buf.
// Only handles wire types 0 (varint) and 2 (length-delimited),
// which is all our schemas use. Unknown types throw — better than
// silently misinterpreting a future schema addition.
//
// Length-delimited values are returned as fresh ArrayBuffer-backed
// copies. The copy forces the strict `Uint8Array<ArrayBuffer>`
// type TS 5.7+ expects (subarrays of the input would carry the
// looser `Uint8Array<ArrayBufferLike>` type) and incidentally
// protects callers if the input buffer is later mutated.
function* iterFields(buf: Uint8Array): Generator<{ field: number; value: Uint8Array | bigint }> {
  let off = 0;
  while (off < buf.length) {
    const { value: tag, n: tn } = decodeVarint(buf, off);
    off += tn;
    const field = Number(tag >> 3n);
    const wireType = Number(tag & 0x7n);
    if (wireType === 0) {
      const { value, n } = decodeVarint(buf, off);
      off += n;
      yield { field, value };
    } else if (wireType === 2) {
      const { value: len, n: ln } = decodeVarint(buf, off);
      off += ln;
      const body = new Uint8Array(Number(len));
      body.set(buf.subarray(off, off + Number(len)));
      off += Number(len);
      yield { field, value: body };
    } else {
      throw new Error(`mosey/proto: unsupported wire type ${wireType} for field ${field}`);
    }
  }
}

// ────────────────────────────────────────────────────────────────
// Control messages — Resize is the only one this client emits
// today. Other variants (Signal, SetMode, Promote, Kick, Demote,
// ListClients) follow the same shape; encoders can be added when
// needed.
// ────────────────────────────────────────────────────────────────

export interface Resize {
  cols: number;
  rows: number;
}

// encodeControlResize wraps a Resize as a ControlMessage with the
// resize oneof variant. The result is ready for protodelim framing.
export function encodeControlResize(r: Resize): Uint8Array {
  const inner = concat([
    encodeVarintField(1, r.cols),
    encodeVarintField(2, r.rows),
  ]);
  // ControlMessage.resize has field number 1.
  return encodeBytesField(1, inner);
}
