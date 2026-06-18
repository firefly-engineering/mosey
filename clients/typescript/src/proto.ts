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

// ────────────────────────────────────────────────────────────────
// Cert messages — match api/cert.proto
//
// On the Go side, the master signs SignedCertContent serialized
// with proto.MarshalOptions{Deterministic: true}; we mirror that
// canonical form by emitting fields in ascending field-number
// order with proto3 default-value omission. Verification never
// re-encodes SignedCertContent — the signature covers the bytes
// already on the wire (Cert.content) — so we only need a decoder
// for SignedCertContent here.
// ────────────────────────────────────────────────────────────────

export interface Cert {
  content: Uint8Array;
  signature: Uint8Array;
}

export interface Timestamp {
  seconds: bigint;
  nanos: number;
}

export interface SignedCertContent {
  agentId: string;
  peerPubkey: Uint8Array;
  label: string;
  capsBits: number;
  notBefore: Timestamp;
  notAfter: Timestamp;
  serial: string;
  workspaceId: string;
}

export interface CertHello {
  cert: Cert;
  nonce: Uint8Array;
}

export interface SignedNonce {
  signature: Uint8Array;
}

// encodeCert serializes a Cert. Used to round-trip the local cert
// in tests and to embed in CertHello during the handshake.
export function encodeCert(c: Cert): Uint8Array {
  return concat([
    encodeBytesField(1, c.content),
    encodeBytesField(2, c.signature),
  ]);
}

// decodeCert parses a Cert frame (the bytes the Go side wrote with
// proto.Marshal(Cert)).
export function decodeCert(buf: Uint8Array): Cert {
  let content: Uint8Array = new Uint8Array(0);
  let signature: Uint8Array = new Uint8Array(0);
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) content = value as Uint8Array;
    else if (field === 2) signature = value as Uint8Array;
  }
  return { content, signature };
}

// decodeSignedCertContent parses the bytes Cert.content carries.
// Caller MUST verify Cert.signature against Cert.content with the
// master's public key BEFORE trusting any field returned here.
export function decodeSignedCertContent(buf: Uint8Array): SignedCertContent {
  let agentId = "";
  let peerPubkey: Uint8Array = new Uint8Array(0);
  let label = "";
  let capsBits = 0;
  let notBefore: Timestamp = { seconds: 0n, nanos: 0 };
  let notAfter: Timestamp = { seconds: 0n, nanos: 0 };
  let serial = "";
  let workspaceId = "";
  for (const { field, value } of iterFields(buf)) {
    switch (field) {
      case 1:
        agentId = new TextDecoder().decode(value as Uint8Array);
        break;
      case 2:
        peerPubkey = value as Uint8Array;
        break;
      case 3:
        label = new TextDecoder().decode(value as Uint8Array);
        break;
      case 4:
        capsBits = Number(value as bigint);
        break;
      case 5:
        notBefore = decodeTimestamp(value as Uint8Array);
        break;
      case 6:
        notAfter = decodeTimestamp(value as Uint8Array);
        break;
      case 7:
        serial = new TextDecoder().decode(value as Uint8Array);
        break;
      case 8:
        workspaceId = new TextDecoder().decode(value as Uint8Array);
        break;
    }
  }
  return { agentId, peerPubkey, label, capsBits, notBefore, notAfter, serial, workspaceId };
}

// decodeTimestamp parses google.protobuf.Timestamp:
//   message Timestamp { int64 seconds = 1; int32 nanos = 2; }
// Both are varints. seconds is int64 — Go encodes negative values
// as 10-byte sign-extended varints, but mosey certs never use
// pre-1970 timestamps so we treat it as unsigned-safe.
function decodeTimestamp(buf: Uint8Array): Timestamp {
  let seconds = 0n;
  let nanos = 0;
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) seconds = value as bigint;
    else if (field === 2) nanos = Number(value as bigint);
  }
  return { seconds, nanos };
}

// encodeCertHelloMessage wraps a CertHello as a
// CertHandshakeMessage with the `hello` oneof variant set
// (field 1). Result is the inner message body — the caller passes
// it through withProtodelim() before writing to the wire.
export function encodeCertHelloMessage(h: CertHello): Uint8Array {
  const helloInner = concat([
    encodeBytesField(1, encodeCert(h.cert)),
    encodeBytesField(2, h.nonce),
  ]);
  return encodeBytesField(1, helloInner);
}

// encodeCertProofMessage wraps a SignedNonce as a
// CertHandshakeMessage with the `proof` oneof variant set
// (field 2). Same framing convention as encodeCertHelloMessage.
export function encodeCertProofMessage(p: SignedNonce): Uint8Array {
  const proofInner = encodeBytesField(1, p.signature);
  return encodeBytesField(2, proofInner);
}

// decodeCertHandshakeMessage returns whichever oneof variant the
// peer sent. Caller dispatches on which is defined — exactly one
// will be, on a well-formed message.
export function decodeCertHandshakeMessage(buf: Uint8Array): {
  hello?: CertHello;
  proof?: SignedNonce;
} {
  const out: { hello?: CertHello; proof?: SignedNonce } = {};
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) out.hello = decodeCertHello(value as Uint8Array);
    else if (field === 2) out.proof = decodeSignedNonce(value as Uint8Array);
  }
  return out;
}

function decodeCertHello(buf: Uint8Array): CertHello {
  let cert: Cert = { content: new Uint8Array(0), signature: new Uint8Array(0) };
  let nonce: Uint8Array = new Uint8Array(0);
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) cert = decodeCert(value as Uint8Array);
    else if (field === 2) nonce = value as Uint8Array;
  }
  return { cert, nonce };
}

function decodeSignedNonce(buf: Uint8Array): SignedNonce {
  let signature: Uint8Array = new Uint8Array(0);
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) signature = value as Uint8Array;
  }
  return { signature };
}

// ────────────────────────────────────────────────────────────────
// Wallet handshake messages (api/wallet.proto). Carried on
// /mosey/auth/ as length-delimited WalletHandshakeMessage envelopes
// when the wallet authenticator is in use.
// ────────────────────────────────────────────────────────────────

export interface Delegation {
  content: Uint8Array;
  signature: Uint8Array;
}

export interface WalletHello {
  clientPubkey: Uint8Array;
  nonceC: Uint8Array;
  delegationChain: Delegation[];
}

export interface WalletChallenge {
  sessionKey: Uint8Array;
  nonceS: Uint8Array;
  serverSig: Uint8Array;
}

export interface WalletProof {
  clientSig: Uint8Array;
}

export function encodeDelegation(d: Delegation): Uint8Array {
  return concat([encodeBytesField(1, d.content), encodeBytesField(2, d.signature)]);
}

function decodeDelegation(buf: Uint8Array): Delegation {
  let content: Uint8Array = new Uint8Array(0);
  let signature: Uint8Array = new Uint8Array(0);
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) content = value as Uint8Array;
    else if (field === 2) signature = value as Uint8Array;
  }
  return { content, signature };
}

// encodeWalletHelloMessage wraps a WalletHello as a
// WalletHandshakeMessage with the `hello` oneof variant (field 1).
// Result is the inner body — pass through withProtodelim() to frame.
export function encodeWalletHelloMessage(h: WalletHello): Uint8Array {
  const parts: Uint8Array[] = [
    encodeBytesField(1, h.clientPubkey),
    encodeBytesField(2, h.nonceC),
  ];
  for (const d of h.delegationChain) {
    parts.push(encodeBytesField(3, encodeDelegation(d)));
  }
  return encodeBytesField(1, concat(parts));
}

// encodeWalletChallengeMessage wraps a WalletChallenge as the
// `challenge` oneof variant (field 2). The client only decodes
// challenges from the server; this exists for symmetry and tests.
export function encodeWalletChallengeMessage(c: WalletChallenge): Uint8Array {
  const inner = concat([
    encodeBytesField(1, c.sessionKey),
    encodeBytesField(2, c.nonceS),
    encodeBytesField(3, c.serverSig),
  ]);
  return encodeBytesField(2, inner);
}

// encodeWalletProofMessage wraps a WalletProof as the `proof` oneof
// variant (field 3).
export function encodeWalletProofMessage(p: WalletProof): Uint8Array {
  return encodeBytesField(3, encodeBytesField(1, p.clientSig));
}

export function decodeWalletHandshakeMessage(buf: Uint8Array): {
  hello?: WalletHello;
  challenge?: WalletChallenge;
  proof?: WalletProof;
} {
  const out: { hello?: WalletHello; challenge?: WalletChallenge; proof?: WalletProof } = {};
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) out.hello = decodeWalletHello(value as Uint8Array);
    else if (field === 2) out.challenge = decodeWalletChallenge(value as Uint8Array);
    else if (field === 3) out.proof = decodeWalletProof(value as Uint8Array);
  }
  return out;
}

function decodeWalletHello(buf: Uint8Array): WalletHello {
  let clientPubkey: Uint8Array = new Uint8Array(0);
  let nonceC: Uint8Array = new Uint8Array(0);
  const delegationChain: Delegation[] = [];
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) clientPubkey = value as Uint8Array;
    else if (field === 2) nonceC = value as Uint8Array;
    else if (field === 3) delegationChain.push(decodeDelegation(value as Uint8Array));
  }
  return { clientPubkey, nonceC, delegationChain };
}

function decodeWalletChallenge(buf: Uint8Array): WalletChallenge {
  let sessionKey: Uint8Array = new Uint8Array(0);
  let nonceS: Uint8Array = new Uint8Array(0);
  let serverSig: Uint8Array = new Uint8Array(0);
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) sessionKey = value as Uint8Array;
    else if (field === 2) nonceS = value as Uint8Array;
    else if (field === 3) serverSig = value as Uint8Array;
  }
  return { sessionKey, nonceS, serverSig };
}

function decodeWalletProof(buf: Uint8Array): WalletProof {
  let clientSig: Uint8Array = new Uint8Array(0);
  for (const { field, value } of iterFields(buf)) {
    if (field === 1) clientSig = value as Uint8Array;
  }
  return { clientSig };
}
