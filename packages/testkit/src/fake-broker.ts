import { randomUUID } from "node:crypto";
import type {
  ApprovalGate,
  ApprovalOutcome,
  ApprovalRequest,
  CredentialBroker,
  Lease,
  LeaseRequest,
  Profile,
  SecretSink,
} from "@ops/contracts";

/**
 * Sahte kimlik aracısı. Her profil için (verilirse) bir "secret" üretip sink'e kaydeder; tutamaç
 * (`CredentialHandle`) secret'ı TAŞIMAZ. Lease sayaçları sızıntı/bırakma testleri içindir.
 */
export class FakeBroker implements CredentialBroker {
  readonly acquired: LeaseRequest[] = [];
  released = 0;
  active = 0;
  failNext = false;
  private readonly secretFor: (profile: Profile) => string | undefined;

  constructor(opts: { secretFor?: (profile: Profile) => string | undefined } = {}) {
    this.secretFor = opts.secretFor ?? (() => undefined);
  }

  readonly primed: string[] = [];

  async prime(profile: Profile, sink: SecretSink): Promise<void> {
    const secret = this.secretFor(profile);
    if (secret !== undefined) sink.add(`profile:${profile.id}`, secret);
    this.primed.push(profile.id);
  }

  async acquire(req: LeaseRequest, sink: SecretSink): Promise<Lease> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error("lease hatası (simüle)");
    }
    const secret = this.secretFor(req.profile);
    if (secret !== undefined) sink.add(`profile:${req.profile.id}`, secret);
    this.acquired.push(req);
    this.active += 1;
    const leaseId = randomUUID();
    let done = false;
    return {
      handle: { kind: "credential-handle", profileId: req.profile.id, leaseId },
      release: async (): Promise<void> => {
        if (done) return;
        done = true;
        this.active -= 1;
        this.released += 1;
      },
    };
  }
}

/** Onay kapısı sahtesi: kararı bir fonksiyon verir; gelen istekler kaydedilir. */
export class FakeApprovalGate implements ApprovalGate {
  readonly requests: ApprovalRequest[] = [];
  private readonly decide: (req: ApprovalRequest) => ApprovalOutcome | boolean;

  constructor(decide: (req: ApprovalRequest) => ApprovalOutcome | boolean = () => true) {
    this.decide = decide;
  }

  async request(req: ApprovalRequest): Promise<ApprovalOutcome> {
    this.requests.push(req);
    const d = this.decide(req);
    if (typeof d === "boolean") {
      return d
        ? { approved: true, approvalId: `appr-${this.requests.length}`, actionHash: req.actionHash }
        : { approved: false, reason: "kullanıcı reddetti" };
    }
    return d;
  }
}
