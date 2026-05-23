// Public API surface. Re-exports the high-level client + the
// lower-level building blocks consumers may need (custom auth,
// raw stream wrangling, protocol IDs).

export {
  MoseyClient,
  type AuthConfig,
  type CertAuthConfig,
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
  runCertHandshake,
  CERT_NONCE_SIZE,
  CERT_PROOF_LABEL,
  type CertAuthOptions,
  type Identity,
} from "./cert-auth.js";

export {
  verifyCert,
  CertError,
  CapsBitOwner,
  CapsBitWrite,
  CapsBitResize,
  hasOwner,
  hasWrite,
  hasResize,
  type Claim,
  type CertErrorReason,
  type VerifyOptions,
} from "./cert.js";

export {
  derivePSKKey,
  hmacSHA256,
  constantTimeEqual,
  randomNonce,
  ed25519Sign,
  ed25519Verify,
  PSK_HKDF_INFO,
  MAC_LABEL_CLIENT,
  MAC_LABEL_SERVER,
  NONCE_SIZE,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
} from "./crypto.js";

export {
  encodeAuthClientHello,
  encodeAuthClientProof,
  encodeCert,
  encodeCertHelloMessage,
  encodeCertProofMessage,
  encodeControlResize,
  decodeAuthMessage,
  decodeCert,
  decodeCertHandshakeMessage,
  decodeSignedCertContent,
  encodeVarint,
  decodeVarint,
  readProtodelim,
  withProtodelim,
  type Cert,
  type CertHello,
  type ClientHello,
  type ClientProof,
  type Resize,
  type ServerProof,
  type SignedCertContent,
  type SignedNonce,
  type Timestamp,
} from "./proto.js";
