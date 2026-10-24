type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const num = (v: unknown, d = 0): number => (typeof v === "number" && Number.isFinite(v) ? v : d);
/** Kubelet/çalışma zamanı kaynaklı kısa kod; serbest metni sızdırmaz. */
const token = (v: unknown): string => (typeof v === "string" && /^[A-Za-z0-9_.-]{1,48}$/.test(v) ? v : "Other");
const isoTime = (v: unknown): string | undefined => {
  if (typeof v !== "string") return undefined;
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString();
};
const dnsName = (v: unknown): string => (typeof v === "string" && /^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$/.test(v) ? v : "?");

export interface Finding {
  readonly code: string;
  readonly severity: "critical" | "warning" | "info";
  readonly subject?: string;
  readonly detail?: string;
}

export interface WorkloadHealth {
  workload: Obj;
  pods: Obj;
  images: { container: string; image: string; digest?: string }[];
  hpa: Obj | null;
  pdb: Obj | null;
  nodes: Obj[] | "kapsam-dışı";
  findings: Finding[];
}

function cond(o: Obj, type: string): Obj | undefined {
  return arr(obj(o["status"])["conditions"]).map(obj).find((c) => c["type"] === type);
}

export function summarizeWorkload(kind: string, o: Obj): { workload: Obj; findings: Finding[] } {
  const spec = obj(o["spec"]);
  const status = obj(o["status"]);
  const meta = obj(o["metadata"]);
  const findings: Finding[] = [];
  let desired: number;
  let ready: number;
  let available: number | undefined;
  let updated: number | undefined;
  if (kind === "DaemonSet") {
    desired = num(status["desiredNumberScheduled"]);
    ready = num(status["numberReady"]);
    available = num(status["numberAvailable"]);
    updated = num(status["updatedNumberScheduled"]);
  } else if (kind === "Job") {
    desired = num(spec["completions"], 1);
    ready = num(status["succeeded"]);
  } else {
    desired = num(spec["replicas"], 1);
    ready = num(status["readyReplicas"]);
    available = num(status["availableReplicas"]);
    updated = num(status["updatedReplicas"]);
  }
  const observed = num(status["observedGeneration"], -1);
  const generation = num(meta["generation"], -1);
  const conditions = arr(status["conditions"]).map(obj).map((c) => ({ type: token(c["type"]), status: token(c["status"]), reason: c["reason"] ? token(c["reason"]) : undefined }));

  let rollout: "complete" | "progressing" | "stalled" | "degraded" | "failed" = "complete";
  const progressing = cond(o, "Progressing");
  if (kind === "Job") {
    if (num(status["failed"]) > 0 && ready < desired) rollout = "failed";
    else rollout = ready >= desired ? "complete" : "progressing";
  } else {
    if (observed >= 0 && generation >= 0 && observed < generation) rollout = "progressing";
    else if (ready < desired) rollout = ready === 0 && desired > 0 ? "degraded" : "progressing";
    if (progressing && progressing["status"] === "False" && progressing["reason"] === "ProgressDeadlineExceeded") rollout = "stalled";
  }
  if (desired > 0 && ready === 0 && kind !== "Job") findings.push({ code: "no_ready_replicas", severity: "critical" });
  else if (ready < desired && kind !== "Job") findings.push({ code: "under_replicated", severity: "warning", detail: `${ready}/${desired}` });
  if (rollout === "stalled") findings.push({ code: "progress_deadline_exceeded", severity: "critical" });
  if (kind === "Job" && rollout === "failed") findings.push({ code: "job_failed", severity: "critical" });
  return {
    workload: {
      kind,
      name: dnsName(meta["name"]),
      namespace: dnsName(meta["namespace"]),
      desired,
      ready,
      ...(available !== undefined ? { available } : {}),
      ...(updated !== undefined ? { updated } : {}),
      rollout,
      generation: generation >= 0 ? generation : undefined,
      observedGeneration: observed >= 0 ? observed : undefined,
      conditions,
      /** Son yayılım/ilerleme güncellemesi (Progressing koşulu); zaman çizelgesi için. */
      lastUpdate: isoTime(progressing?.["lastUpdateTime"]),
    },
    findings,
  };
}

const RESTART_WARN = 5;

export function summarizePods(pods: Obj[]): { pods: Obj; images: WorkloadHealth["images"]; findings: Finding[]; nodeNames: string[] } {
  const byPhase: Record<string, number> = {};
  const problems: Obj[] = [];
  const findings: Finding[] = [];
  const images = new Map<string, { container: string; image: string; digest?: string }>();
  const nodes = new Set<string>();
  let notReady = 0;
  let restartsTotal = 0;
  let restartsMax = 0;
  let newest = 0;
  let oldest = Number.POSITIVE_INFINITY;

  for (const p of pods) {
    const meta = obj(p["metadata"]);
    const created = Date.parse(typeof meta["creationTimestamp"] === "string" ? meta["creationTimestamp"] : "");
    if (!Number.isNaN(created)) {
      newest = Math.max(newest, created);
      oldest = Math.min(oldest, created);
    }
    const status = obj(p["status"]);
    const spec = obj(p["spec"]);
    const name = dnsName(meta["name"]);
    const phase = token(status["phase"]);
    byPhase[phase] = (byPhase[phase] ?? 0) + 1;
    if (typeof spec["nodeName"] === "string") nodes.add(dnsName(spec["nodeName"]));
    const ready = arr(status["conditions"]).map(obj).find((c) => c["type"] === "Ready");
    if (!ready || ready["status"] !== "True") notReady += 1;

    if (status["reason"] === "Evicted") findings.push({ code: "pod_evicted", severity: "warning", subject: name });
    const sched = arr(status["conditions"]).map(obj).find((c) => c["type"] === "PodScheduled");
    if (sched && sched["status"] === "False") findings.push({ code: "unschedulable", severity: "critical", subject: name, detail: token(sched["reason"]) });

    for (const cs of arr(status["containerStatuses"]).concat(arr(status["initContainerStatuses"])).map(obj)) {
      const cname = dnsName(cs["name"]);
      const restarts = num(cs["restartCount"]);
      restartsTotal += restarts;
      restartsMax = Math.max(restartsMax, restarts);
      const state = obj(cs["state"]);
      const last = obj(obj(cs["lastState"])["terminated"]);
      const waiting = obj(state["waiting"]);
      const terminated = obj(state["terminated"]);
      const reasonNow = waiting["reason"] ? token(waiting["reason"]) : terminated["reason"] ? token(terminated["reason"]) : undefined;
      const reasonLast = last["reason"] ? token(last["reason"]) : undefined;
      const exitCode = typeof last["exitCode"] === "number" ? (last["exitCode"] as number) : typeof terminated["exitCode"] === "number" ? (terminated["exitCode"] as number) : undefined;
      const image = typeof cs["image"] === "string" ? cs["image"].split("@")[0]?.slice(0, 200) ?? "" : "";
      const imageID = typeof cs["imageID"] === "string" ? (cs["imageID"] as string) : "";
      const digest = /@(sha256:[a-f0-9]{64})/.exec(imageID)?.[1];
      images.set(`${cname}`, { container: cname, image, ...(digest ? { digest } : {}) });

      const bad = reasonNow !== undefined && reasonNow !== "Completed" ? reasonNow : undefined;
      if (bad || reasonLast === "OOMKilled" || restarts >= RESTART_WARN) {
        problems.push({ pod: name, container: cname, state: reasonNow, lastTerminated: reasonLast, exitCode, restarts });
      }
      if (reasonNow === "CrashLoopBackOff") findings.push({ code: "crash_loop", severity: "critical", subject: `${name}/${cname}`, detail: reasonLast ?? undefined });
      else if (reasonNow === "ImagePullBackOff" || reasonNow === "ErrImagePull") findings.push({ code: "image_pull_failed", severity: "critical", subject: `${name}/${cname}` });
      else if (reasonNow === "CreateContainerConfigError" || reasonNow === "CreateContainerError") findings.push({ code: "container_config_error", severity: "critical", subject: `${name}/${cname}` });
      if (reasonLast === "OOMKilled" || reasonNow === "OOMKilled") findings.push({ code: "oom_killed", severity: "critical", subject: `${name}/${cname}` });
      else if (restarts >= RESTART_WARN && reasonNow !== "CrashLoopBackOff") findings.push({ code: "frequent_restarts", severity: "warning", subject: `${name}/${cname}`, detail: String(restarts) });
    }
  }
  return {
    pods: {
      total: pods.length,
      byPhase,
      notReady,
      restarts: { total: restartsTotal, max: restartsMax },
      problems: problems.slice(0, 20),
      newestCreatedAt: newest > 0 ? new Date(newest).toISOString() : undefined,
      oldestCreatedAt: Number.isFinite(oldest) ? new Date(oldest).toISOString() : undefined,
    },
    images: [...images.values()],
    findings,
    nodeNames: [...nodes].slice(0, 10),
  };
}

export function summarizeHpa(hpas: Obj[], kind: string, name: string): { hpa: Obj | null; findings: Finding[] } {
  const h = hpas.map(obj).find((x) => {
    const ref = obj(obj(x["spec"])["scaleTargetRef"]);
    return ref["kind"] === kind && ref["name"] === name;
  });
  if (!h) return { hpa: null, findings: [] };
  const spec = obj(h["spec"]);
  const status = obj(h["status"]);
  const max = num(spec["maxReplicas"]);
  const cur = num(status["currentReplicas"]);
  const des = num(status["desiredReplicas"]);
  const findings: Finding[] = [];
  if (max > 0 && cur >= max && des >= max) findings.push({ code: "hpa_at_max", severity: "warning", detail: `${cur}/${max}` });
  return { hpa: { min: num(spec["minReplicas"], 1), max, current: cur, desired: des }, findings };
}

export function summarizePdb(pdbs: Obj[], podLabels: Record<string, string>): { pdb: Obj | null; findings: Finding[] } {
  const p = pdbs.map(obj).find((x) => {
    const sel = obj(obj(obj(x["spec"])["selector"])["matchLabels"]);
    const keys = Object.keys(sel);
    return keys.length > 0 && keys.every((k) => podLabels[k] === sel[k]);
  });
  if (!p) return { pdb: null, findings: [] };
  const status = obj(p["status"]);
  const allowed = num(status["disruptionsAllowed"]);
  const findings: Finding[] = allowed === 0 ? [{ code: "pdb_blocks_disruption", severity: "info" }] : [];
  return { pdb: { disruptionsAllowed: allowed, currentHealthy: num(status["currentHealthy"]), desiredHealthy: num(status["desiredHealthy"]) }, findings };
}

const PRESSURE = new Set(["MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"]);

export function summarizeNode(n: Obj): { node: Obj; findings: Finding[] } {
  const name = dnsName(obj(n["metadata"])["name"]);
  const conds = arr(obj(n["status"])["conditions"]).map(obj);
  const active = conds.filter((c) => PRESSURE.has(String(c["type"])) && c["status"] === "True").map((c) => token(c["type"]));
  const ready = conds.find((c) => c["type"] === "Ready");
  const findings: Finding[] = active.map((t) => ({ code: `node_${t.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase()}`, severity: "critical" as const, subject: name }));
  if (ready && ready["status"] !== "True") findings.push({ code: "node_not_ready", severity: "critical", subject: name });
  return { node: { name, ready: ready?.["status"] === "True", pressure: active }, findings };
}
