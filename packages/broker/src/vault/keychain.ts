import { spawn } from "node:child_process";
import { OpsError } from "@ops/contracts";
import type { SecretStore } from "@ops/contracts";

export type Exec = (cmd: string, args: string[], stdin?: Buffer) => Promise<{ code: number; stdout: Buffer; stderr: string }>;

/** Kabuksuz (shell yok) alt süreç yürütücüsü. */
export const defaultExec: Exec = (cmd, args, stdin) =>
  new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });
    const out: Buffer[] = [];
    let err = "";
    child.stdout.on("data", (b: Buffer) => out.push(b));
    child.stderr.on("data", (b: Buffer) => (err += b.toString("utf8")));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, stdout: Buffer.concat(out), stderr: err }));
    child.stdin.end(stdin);
  });

export interface KeychainBackend {
  readonly name: string;
  available(): Promise<boolean>;
  get(service: string, account: string): Promise<Buffer | null>;
  set(service: string, account: string, value: Buffer): Promise<void>;
  delete(service: string, account: string): Promise<boolean>;
}

/**
 * Linux libsecret (`secret-tool`). Değer STDIN'den verilir (argv'de görünmez). Değer base64
 * taşınır. Gerçek anahtar zinciri entegrasyon testi bu geliştirme ortamında yok: komut
 * kurucusu birim testlidir.
 */
export class SecretToolBackend implements KeychainBackend {
  readonly name = "secret-tool";
  private readonly exec: Exec;

  constructor(exec: Exec = defaultExec) {
    this.exec = exec;
  }

  async available(): Promise<boolean> {
    try {
      const r = await this.exec("secret-tool", ["--version"]);
      return r.code === 0;
    } catch {
      return false;
    }
  }

  async get(service: string, account: string): Promise<Buffer | null> {
    const r = await this.exec("secret-tool", ["lookup", "service", service, "account", account]);
    if (r.code !== 0 || r.stdout.length === 0) return null;
    return Buffer.from(r.stdout.toString("utf8").trim(), "base64");
  }

  async set(service: string, account: string, value: Buffer): Promise<void> {
    const r = await this.exec(
      "secret-tool",
      ["store", "--label=ops-assistant", "service", service, "account", account],
      Buffer.from(value.toString("base64")),
    );
    if (r.code !== 0) throw new OpsError("keychain_error", "anahtar zincirine yazılamadı");
  }

  async delete(service: string, account: string): Promise<boolean> {
    const r = await this.exec("secret-tool", ["clear", "service", service, "account", account]);
    return r.code === 0;
  }
}

/**
 * macOS `security`. SINIR (Best-effort): `add-generic-password -w` değeri argv'de taşır; kısa
 * süre `ps` ile görünebilir. Yerel Keychain bağlaması (`@napi-rs/keyring` — doğrulanacak) Faz 3.
 */
export class MacSecurityBackend implements KeychainBackend {
  readonly name = "macos-security";
  private readonly exec: Exec;

  constructor(exec: Exec = defaultExec) {
    this.exec = exec;
  }

  async available(): Promise<boolean> {
    try {
      const r = await this.exec("security", ["help"]);
      return r.code === 0 || r.code === 1;
    } catch {
      return false;
    }
  }

  async get(service: string, account: string): Promise<Buffer | null> {
    const r = await this.exec("security", ["find-generic-password", "-s", service, "-a", account, "-w"]);
    if (r.code !== 0) return null;
    return Buffer.from(r.stdout.toString("utf8").trim(), "base64");
  }

  async set(service: string, account: string, value: Buffer): Promise<void> {
    const r = await this.exec("security", ["add-generic-password", "-U", "-s", service, "-a", account, "-w", value.toString("base64")]);
    if (r.code !== 0) throw new OpsError("keychain_error", "anahtar zincirine yazılamadı");
  }

  async delete(service: string, account: string): Promise<boolean> {
    const r = await this.exec("security", ["delete-generic-password", "-s", service, "-a", account]);
    return r.code === 0;
  }
}

const INDEX_ACCOUNT = "\u0000index";

/** İşletim sistemi anahtar zinciri kasası; adları listelemek için bir dizin girdisi tutar. */
export class OsKeychainStore implements SecretStore {
  readonly kind: string;
  private readonly backend: KeychainBackend;
  private readonly service: string;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(backend: KeychainBackend, service = "ops-assistant") {
    this.backend = backend;
    this.service = service;
    this.kind = `os-keychain:${backend.name}`;
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async readIndex(): Promise<string[]> {
    const raw = await this.backend.get(this.service, INDEX_ACCOUNT);
    if (!raw) return [];
    try {
      return JSON.parse(raw.toString("utf8")) as string[];
    } catch {
      return [];
    }
  }

  async get(key: string): Promise<Uint8Array | null> {
    const v = await this.backend.get(this.service, key);
    return v ? new Uint8Array(v) : null;
  }

  set(key: string, value: Uint8Array): Promise<void> {
    return this.serial(async () => {
      await this.backend.set(this.service, key, Buffer.from(value));
      const idx = await this.readIndex();
      if (!idx.includes(key)) await this.backend.set(this.service, INDEX_ACCOUNT, Buffer.from(JSON.stringify([...idx, key])));
    });
  }

  delete(key: string): Promise<boolean> {
    return this.serial(async () => {
      const ok = await this.backend.delete(this.service, key);
      const idx = await this.readIndex();
      if (idx.includes(key)) await this.backend.set(this.service, INDEX_ACCOUNT, Buffer.from(JSON.stringify(idx.filter((k) => k !== key))));
      return ok;
    });
  }

  async list(prefix: string): Promise<string[]> {
    return (await this.readIndex()).filter((k) => k.startsWith(prefix)).sort();
  }
}
