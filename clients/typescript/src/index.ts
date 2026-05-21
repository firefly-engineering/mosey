// Public API surface. Re-exports the high-level client + the
// lower-level building blocks consumers may need (custom auth,
// raw stream wrangling, protocol IDs).

export {
  MoseyClient,
  type AuthConfig,
  type ConnectOptions,
  type PSKAuthConfig,
} from "./client.js";

export {
  Stream,
  ProtoAuth,
  ProtoControl,
  ProtoPTY,
  PEER_TOKEN_PREFIX,
  mintPeerToken,
  type OpenOptions,
} from "./transport.js";

export {
  runPSKHandshake,
  AckOK,
  type PSKAuthOptions,
} from "./auth.js";

export {
  derivePSKKey,
  hmacSHA256,
  constantTimeEqual,
  randomNonce,
  PSK_HKDF_INFO,
  MAC_LABEL_CLIENT,
  MAC_LABEL_SERVER,
  NONCE_SIZE,
} from "./crypto.js";

export {
  encodeAuthClientHello,
  encodeAuthClientProof,
  encodeControlResize,
  decodeAuthMessage,
  encodeVarint,
  decodeVarint,
  readProtodelim,
  withProtodelim,
  type ClientHello,
  type ServerProof,
  type ClientProof,
  type Resize,
} from "./proto.js";
