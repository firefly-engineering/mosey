import { describe, expect, test } from "vitest";

import {
  CertError,
  CapsBitOwner,
  CapsBitResize,
  CapsBitWrite,
  hasOwner,
  hasResize,
  hasWrite,
  verifyCert,
} from "../src/cert.js";
import { decodeCert } from "../src/proto.js";

// Vectors generated from Go (see ship-3pp.2 commit body). The master
// signs an alice cert with workspace_id="demo", valid 2026-05-01 to
// 2027-05-01, full caps (owner|write|resize).
const masterPubHex =
  "7776e870b93354f2a0b24c23f2a36cc4e80e223218c1b97926fdd018396a2b9b";
const certHex =
  "0a590a0a30314a304147454e5431122029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd71a05616c69636520072a060880dacfcf0632060880c1d4de063a0a30314a3053455249414c420464656d6f1240ec0060b9e0e484d4158343cd54b2e8cef017db56cb5bd09cc6dcc41e1a7b2474afceffaea1ef1ba4f7c8eddc478bef2d9ebbd6c39b7faa2076f45a87a1f54e01";

// Inside the validity window — use the midpoint between the two
// boundaries so the test is stable regardless of when it runs.
const insideWindow = new Date("2026-11-01T00:00:00Z");

describe("verifyCert (happy path)", () => {
  test("returns the unpacked Claim with full caps", async () => {
    const cert = decodeCert(fromHex(certHex));
    const claim = await verifyCert(cert, {
      masterPub: fromHex(masterPubHex),
      workspaceId: "demo",
      now: insideWindow,
    });
    expect(claim.agentId).toBe("01J0AGENT1");
    expect(claim.label).toBe("alice");
    expect(claim.serial).toBe("01J0SERIAL");
    expect(claim.workspaceId).toBe("demo");
    expect(claim.capsBits).toBe(CapsBitOwner | CapsBitWrite | CapsBitResize);
    expect(claim.peerPubkey).toHaveLength(32);
    expect(hasOwner(claim)).toBe(true);
    expect(hasWrite(claim)).toBe(true);
    expect(hasResize(claim)).toBe(true);
    expect(claim.notBefore.toISOString()).toBe("2026-05-01T00:00:00.000Z");
    expect(claim.notAfter.toISOString()).toBe("2027-05-01T00:00:00.000Z");
  });
});

describe("verifyCert (rejections)", () => {
  test("wrong master pub → invalid-signature", async () => {
    const cert = decodeCert(fromHex(certHex));
    const wrongMaster = new Uint8Array(32); // all zeros
    await expect(
      verifyCert(cert, {
        masterPub: wrongMaster,
        workspaceId: "demo",
        now: insideWindow,
      }),
    ).rejects.toMatchObject({
      name: "CertError",
      reason: "invalid-signature",
    });
  });

  test("tampered content → invalid-signature", async () => {
    const cert = decodeCert(fromHex(certHex));
    const tampered = new Uint8Array(cert.content);
    tampered[10] ^= 0x01;
    await expect(
      verifyCert({ content: tampered, signature: cert.signature }, {
        masterPub: fromHex(masterPubHex),
        workspaceId: "demo",
        now: insideWindow,
      }),
    ).rejects.toMatchObject({ reason: "invalid-signature" });
  });

  test("now before not_before → expired", async () => {
    const cert = decodeCert(fromHex(certHex));
    await expect(
      verifyCert(cert, {
        masterPub: fromHex(masterPubHex),
        workspaceId: "demo",
        now: new Date("2026-04-01T00:00:00Z"),
      }),
    ).rejects.toMatchObject({ reason: "expired" });
  });

  test("now after not_after → expired", async () => {
    const cert = decodeCert(fromHex(certHex));
    await expect(
      verifyCert(cert, {
        masterPub: fromHex(masterPubHex),
        workspaceId: "demo",
        now: new Date("2027-06-01T00:00:00Z"),
      }),
    ).rejects.toMatchObject({ reason: "expired" });
  });

  test("workspace mismatch → wrong-workspace", async () => {
    const cert = decodeCert(fromHex(certHex));
    await expect(
      verifyCert(cert, {
        masterPub: fromHex(masterPubHex),
        workspaceId: "other",
        now: insideWindow,
      }),
    ).rejects.toMatchObject({ reason: "wrong-workspace" });
  });

  test("empty workspace → malformed (configuration error)", async () => {
    const cert = decodeCert(fromHex(certHex));
    await expect(
      verifyCert(cert, {
        masterPub: fromHex(masterPubHex),
        workspaceId: "",
        now: insideWindow,
      }),
    ).rejects.toMatchObject({ reason: "malformed" });
  });

  test("revoked serial → revoked", async () => {
    const cert = decodeCert(fromHex(certHex));
    await expect(
      verifyCert(cert, {
        masterPub: fromHex(masterPubHex),
        workspaceId: "demo",
        now: insideWindow,
        revoked: new Set(["01J0SERIAL"]),
      }),
    ).rejects.toMatchObject({ reason: "revoked" });
  });

  test("wrong-length master pub → malformed", async () => {
    const cert = decodeCert(fromHex(certHex));
    await expect(
      verifyCert(cert, {
        masterPub: new Uint8Array(16),
        workspaceId: "demo",
        now: insideWindow,
      }),
    ).rejects.toMatchObject({ reason: "malformed" });
  });
});

describe("CertError shape", () => {
  test("messages carry the cert: prefix matching the Go side", () => {
    const e = new CertError("expired", "test message");
    expect(e.message.startsWith("cert: ")).toBe(true);
    expect(e.reason).toBe("expired");
  });
});

function fromHex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
