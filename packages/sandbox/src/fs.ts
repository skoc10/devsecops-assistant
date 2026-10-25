import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { access, constants, lstat, readlink, realpath } from "node:fs/promises";
import type { Sandbox, SandboxFs } from "./types.ts";

/** Host dosya sistemi görünümü: yerel sandbox'lar (bwrap, seatbelt, izolasyonsuz) için. */
export const localSandboxFs: SandboxFs = {
  async executable(path) {
    try {
      await access(path, constants.X_OK);
      return true;
    } catch {
      return false;
    }
  },
  async exists(path) {
    try {
      await lstat(path);
      return true;
    } catch {
      return false;
    }
  },
  async realpath(path) {
    try {
      return await realpath(path);
    } catch {
      return null;
    }
  },
  async readlink(path) {
    try {
      return await readlink(path);
    } catch {
      return null;
    }
  },
  async sha256(path) {
    try {
      const h = createHash("sha256");
      await new Promise<void>((resolve, reject) => {
        const s = createReadStream(path);
        s.on("data", (c) => h.update(c));
        s.on("end", () => resolve());
        s.on("error", reject);
      });
      return h.digest("hex");
    } catch {
      return null;
    }
  },
};

/** Sandbox'ın ikili dosya sistemi; sandbox yoksa veya görünüm vermiyorsa host. */
export function fsOf(sandbox: Sandbox | null | undefined): SandboxFs {
  return sandbox?.fs ?? localSandboxFs;
}
