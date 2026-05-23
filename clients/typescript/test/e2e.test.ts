// End-to-end interop test: spawn a real `mosey launch` server,
// drive it from the TS client, assert PTY bytes echo through.
//
// This is the integration test that catches any drift between the
// Go side and the TS reimplementation of the wire format. Unit
// tests cover proto + crypto in isolation; this one wires them all
// together against the production server.
//
// Requires:
//   - The `mosey` binary built into ../../bin/mosey (the test bails
//     out with a clear message otherwise).
//   - A working Node 22+ WebSocket implementation (built-in since 22).

import {
  spawn,
  spawnSync,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { access, mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, test } from "vitest";
import { MoseyClient } from "../src/index.js";

const moseyBin = resolve(__dirname, "..", "..", "..", "bin", "mosey");

describe("end-to-end interop with `mosey launch`", () => {
  test("PSK auth + PTY echo round-trip", async () => {
    if (!(await fileExists(moseyBin))) {
      console.warn(
        `[skip] e2e: ${moseyBin} not found. Run \`just build\` from the repo root first.`,
      );
      return;
    }
    if (typeof WebSocket === "undefined") {
      console.warn("[skip] e2e: global WebSocket not available; need Node 22+");
      return;
    }

    const launcher = await startLaunch();
    try {
      const client = await MoseyClient.connect({
        endpoint: launcher.endpoint,
        auth: { type: "psk", secret: "hunter2" },
      });
      try {
        const decoder = new TextDecoder();
        let captured = "";
        client.onData((chunk) => {
          captured += decoder.decode(chunk);
        });

        // Send a marker through cat's stdin → reappears on stdout
        // (PTY in cooked mode echoes the input + cat re-emits it).
        client.write(new TextEncoder().encode("hello-ts\n"));

        await waitFor(() => captured.includes("hello-ts"), 5_000);
        expect(captured).toContain("hello-ts");
      } finally {
        await client.close();
      }
    } finally {
      launcher.shutdown();
    }
  }, 20_000);

  test("cert auth + PTY echo round-trip", async () => {
    if (!(await fileExists(moseyBin))) {
      console.warn(
        `[skip] e2e cert: ${moseyBin} not found. Run \`just build\` first.`,
      );
      return;
    }
    if (typeof WebSocket === "undefined") {
      console.warn("[skip] e2e cert: global WebSocket not available; need Node 22+");
      return;
    }

    const ws = await mintWorkspace("demo");
    const launcher = await startLaunch({
      cert: ws.serverCertPath,
      key: ws.serverKeyPath,
      masterPub: ws.masterPubPath,
      workspace: "demo",
    });
    try {
      const client = await MoseyClient.connect({
        endpoint: launcher.endpoint,
        auth: {
          type: "cert",
          cert: await readFile(ws.clientCertPath),
          privateKey: await readKeyFile(ws.clientKeyPath),
          masterPub: await readKeyFile(ws.masterPubPath),
          workspaceId: "demo",
        },
      });
      try {
        const decoder = new TextDecoder();
        let captured = "";
        client.onData((chunk) => {
          captured += decoder.decode(chunk);
        });
        client.write(new TextEncoder().encode("hello-cert\n"));
        await waitFor(() => captured.includes("hello-cert"), 5_000);
        expect(captured).toContain("hello-cert");
      } finally {
        await client.close();
      }
    } finally {
      launcher.shutdown();
    }
  }, 30_000);

  test("cert auth: server rejects cert signed by a different master", async () => {
    if (!(await fileExists(moseyBin))) {
      console.warn(
        `[skip] e2e cert reject: ${moseyBin} not found. Run \`just build\` first.`,
      );
      return;
    }
    if (typeof WebSocket === "undefined") return;

    // Two unrelated workspaces, same workspace_id string so the
    // failure isn't the workspace check — it's the signature check.
    const ws1 = await mintWorkspace("demo");
    const ws2 = await mintWorkspace("demo");

    // Launcher trusts master A; client presents cert signed by
    // master B (with B's masterPub so local validateCertConfig
    // passes). Server-side verify of the client cert fails, server
    // closes the auth stream before ack — client throws.
    const launcher = await startLaunch({
      cert: ws1.serverCertPath,
      key: ws1.serverKeyPath,
      masterPub: ws1.masterPubPath,
      workspace: "demo",
    });
    try {
      await expect(
        MoseyClient.connect({
          endpoint: launcher.endpoint,
          auth: {
            type: "cert",
            cert: await readFile(ws2.clientCertPath),
            privateKey: await readKeyFile(ws2.clientKeyPath),
            // Use master B so the client's local validate passes —
            // we want the rejection to come from the wire, not from
            // local fail-fast checks.
            masterPub: await readKeyFile(ws2.masterPubPath),
            workspaceId: "demo",
          },
        }),
      ).rejects.toThrow();
    } finally {
      launcher.shutdown();
    }
  }, 30_000);
});

// Workspace fixture: a master + a server-side agent cert + a
// client-side agent cert, all minted via the real `mosey cert`
// CLI. Returns absolute paths to each file under a fresh temp dir.
interface Workspace {
  masterPubPath: string;
  serverCertPath: string;
  serverKeyPath: string;
  clientCertPath: string;
  clientKeyPath: string;
}

async function mintWorkspace(workspaceId: string): Promise<Workspace> {
  const dir = await mkdtemp(join(tmpdir(), "mosey-e2e-ws-"));
  const mintMaster = spawnSync(moseyBin, ["cert", "mint-master", "--out", dir], {
    encoding: "utf8",
  });
  if (mintMaster.status !== 0) {
    throw new Error(
      `mint-master failed (exit=${mintMaster.status}): ${mintMaster.stderr}`,
    );
  }
  const masterKeyPath = join(dir, "master.key");
  for (const role of ["server", "client"] as const) {
    const mint = spawnSync(
      moseyBin,
      [
        "cert",
        "mint-agent",
        "--master-key",
        masterKeyPath,
        "--workspace",
        workspaceId,
        "--label",
        role,
        "--caps",
        "owner",
        "--out",
        dir,
      ],
      { encoding: "utf8" },
    );
    if (mint.status !== 0) {
      throw new Error(
        `mint-agent ${role} failed (exit=${mint.status}): ${mint.stderr}`,
      );
    }
  }
  return {
    masterPubPath: join(dir, "master.pub"),
    serverCertPath: join(dir, "server.cert"),
    serverKeyPath: join(dir, "server.key"),
    clientCertPath: join(dir, "client.cert"),
    clientKeyPath: join(dir, "client.key"),
  };
}

// readKeyFile reads a hex-encoded key file (master.pub, *.key) as
// emitted by `mosey cert mint-*`, strips the trailing newline, and
// returns the decoded raw bytes. The Go CLI writes keys as hex
// for copy/paste-ability; the TS client wants raw bytes.
async function readKeyFile(path: string): Promise<Uint8Array> {
  const text = (await readFile(path, "utf8")).trim();
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

interface Launcher {
  endpoint: string;
  shutdown: () => void;
}

interface CertLaunchOptions {
  cert: string;
  key: string;
  masterPub: string;
  workspace: string;
}

async function startLaunch(certOpts?: CertLaunchOptions): Promise<Launcher> {
  const authArgs = certOpts
    ? [
        `--cert=${certOpts.cert}`,
        `--key=${certOpts.key}`,
        `--master-pub=${certOpts.masterPub}`,
        `--workspace=${certOpts.workspace}`,
      ]
    : ["--secret=hunter2"];
  const args = [
    "launch",
    ...authArgs,
    "--listen=ws://127.0.0.1:0",
    "--",
    "cat",
  ];
  const proc: ChildProcessWithoutNullStreams = spawn(moseyBin, args, {
    stdio: ["pipe", "pipe", "pipe"],
  });
  const endpoint = await new Promise<string>((resolveEndpoint, reject) => {
    let stderr = "";
    const onErrData = (b: Buffer) => {
      stderr += b.toString("utf8");
      const m = stderr.match(/listening:\s*(ws:\/\/[^\s]+)/);
      if (m) {
        proc.stderr.off("data", onErrData);
        resolveEndpoint(m[1]!);
      }
    };
    proc.stderr.on("data", onErrData);
    proc.on("exit", (code) =>
      reject(new Error(`mosey launch exited with code ${code} before printing endpoint; stderr was:\n${stderr}`)),
    );
    setTimeout(() => reject(new Error(`timed out waiting for endpoint; stderr so far:\n${stderr}`)), 5_000);
  });
  return {
    endpoint,
    shutdown: () => {
      try {
        proc.kill("SIGTERM");
      } catch {
        // ignore — best-effort
      }
    },
  };
}

async function waitFor(pred: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pred()) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("waitFor: condition not met within timeout");
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
