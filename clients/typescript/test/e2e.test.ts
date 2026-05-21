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

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { access } from "node:fs/promises";
import { resolve } from "node:path";
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
});

interface Launcher {
  endpoint: string;
  shutdown: () => void;
}

async function startLaunch(): Promise<Launcher> {
  const args = [
    "launch",
    "--secret=hunter2",
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
