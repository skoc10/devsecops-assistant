import { readFile } from "node:fs/promises";
import { OpsError, ProfileSchema } from "@ops/contracts";
import type { Profile } from "@ops/contracts";
import { writeFileAtomic } from "./atomic-write.ts";

export interface ProfileRegistryOptions {
  readonly path: string;
  /** Test kipi: yalnız `admit`'in onayladığı (imzalı sahte) profiller yüklenir; prod reddedilir. */
  readonly testMode?: boolean;
  /** Test kipinde zorunlu. `true` veya reddetme sebebi döndürür. */
  readonly admit?: (p: Profile) => true | string;
}

interface FileShape {
  readonly version: 1;
  readonly profiles: unknown[];
}

/** Profil kaydı: secret OLMAYAN tanımlayıcılar (`profiles.json`, 0600). Kimlik materyali kasadadır. */
export class ProfileRegistry {
  private profiles: Profile[];
  private readonly o: ProfileRegistryOptions & { testMode: boolean };
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(opts: ProfileRegistryOptions & { testMode: boolean }, profiles: Profile[]) {
    this.o = opts;
    this.profiles = profiles;
  }

  static async open(opts: ProfileRegistryOptions): Promise<ProfileRegistry> {
    const testMode = opts.testMode ?? process.env["OPS_TEST_MODE"] === "1";
    if (testMode && !opts.admit) {
      throw new OpsError("test_mode_admit_required", "test kipinde profil kabul işlevi (admit) zorunlu");
    }
    const full = { ...opts, testMode };
    let raw: FileShape | null = null;
    try {
      raw = JSON.parse(await readFile(opts.path, "utf8")) as FileShape;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw new OpsError("profiles_corrupt", "profiles.json okunamadı");
    }
    const profiles: Profile[] = [];
    for (const item of raw?.profiles ?? []) {
      const parsed = ProfileSchema.safeParse(item);
      if (!parsed.success) throw new OpsError("profiles_corrupt", "profiles.json geçersiz bir profil içeriyor");
      ProfileRegistry.admitOrThrow(full, parsed.data);
      profiles.push(parsed.data);
    }
    return new ProfileRegistry(full, profiles);
  }

  private static admitOrThrow(o: ProfileRegistryOptions & { testMode: boolean }, p: Profile): void {
    if (!o.testMode) return;
    if (p.environment === "prod") throw new OpsError("test_mode_prod_refused", `test kipinde prod profil reddedilir: ${p.id}`);
    const r = o.admit?.(p) ?? "admit yok";
    if (r !== true) throw new OpsError("test_mode_profile_refused", `test kipinde profil kabul edilmedi (${p.id}): ${r}`);
  }

  list(): Profile[] {
    return [...this.profiles];
  }

  get(id: string): Profile | undefined {
    return this.profiles.find((p) => p.id === id);
  }

  add(profile: Profile, opts: { replace?: boolean } = {}): Promise<void> {
    return this.serial(async () => {
      const parsed = ProfileSchema.parse(profile);
      ProfileRegistry.admitOrThrow(this.o, parsed);
      if (this.profiles.some((p) => p.id === parsed.id) && !opts.replace) {
        throw new OpsError("profile_exists", `profil zaten var: ${parsed.id}`);
      }
      this.profiles = [...this.profiles.filter((p) => p.id !== parsed.id), parsed];
      await this.persist();
    });
  }

  remove(id: string): Promise<boolean> {
    return this.serial(async () => {
      if (!this.profiles.some((p) => p.id === id)) return false;
      this.profiles = this.profiles.filter((p) => p.id !== id);
      await this.persist();
      return true;
    });
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async persist(): Promise<void> {
    await writeFileAtomic(this.o.path, JSON.stringify({ version: 1, profiles: this.profiles } satisfies FileShape, null, 2));
  }
}
