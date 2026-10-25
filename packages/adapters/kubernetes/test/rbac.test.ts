import { describe, expect, it } from "vitest";
import { parseAllDocuments } from "yaml";
import { analyzeRules, generateReadOnlyRbac, READONLY_CLUSTER_RULES, READONLY_NAMESPACED_RULES, ruleAllows } from "../src/index.ts";

function docs(yamlText: string): any[] {
  return parseAllDocuments(yamlText).map((d) => d.toJS());
}

describe("salt okunur RBAC manifest üreticisi", () => {
  it("Secret, exec, proxy ve yazma YOK; yalnız get/list/watch; analiz 'read' çıkar", () => {
    const text = generateReadOnlyRbac({ serviceAccountNamespace: "ops", namespaces: ["payments", "orders"], clusterRead: true });
    const all = docs(text);
    const rules = all.filter((d) => d.kind === "ClusterRole").flatMap((d) => d.rules);
    const verbs = new Set(rules.flatMap((r: any) => r.verbs));
    expect([...verbs].sort()).toEqual(["get", "list", "watch"]);
    const resources = rules.flatMap((r: any) => r.resources) as string[];
    expect(resources).not.toContain("secrets");
    expect(resources.some((r) => r.includes("exec") || r.includes("proxy") || r.includes("portforward") || r === "*")).toBe(false);
    const a = analyzeRules(rules);
    expect(a.effective).toBe("read");
    expect(a.findings).toEqual([]);
    expect(a.secretsReadable).toBe(false);
  });

  it("her namespace için RoleBinding, kümesel okuma yalnız istenirse; uygulayıcı yok (yalnız metin)", () => {
    const a = docs(generateReadOnlyRbac({ serviceAccountNamespace: "ops", namespaces: ["payments", "orders"] }));
    expect(a.filter((d) => d.kind === "RoleBinding").map((d) => d.metadata.namespace)).toEqual(["payments", "orders"]);
    expect(a.some((d) => d.kind === "ClusterRoleBinding")).toBe(false);
    const b = docs(generateReadOnlyRbac({ serviceAccountNamespace: "ops", namespaces: ["x"], clusterRead: true }));
    expect(b.filter((d) => d.kind === "ClusterRoleBinding").length).toBe(1);
    const sa = b.find((d) => d.kind === "ServiceAccount");
    expect(sa.metadata.namespace).toBe("ops");
    expect(generateReadOnlyRbac({ serviceAccountNamespace: "ops", namespaces: ["x"] })).toMatch(/UYGULANMAZ/);
  });

  it("kümesel kurallar da read", () => {
    expect(analyzeRules(READONLY_CLUSTER_RULES).effective).toBe("read");
    expect(analyzeRules(READONLY_NAMESPACED_RULES).effective).toBe("read");
  });
});

describe("analyzeRules / ruleAllows", () => {
  it("sınıf eşlemesi", () => {
    const cls = (r: object) => analyzeRules([r as never]).effective;
    expect(cls({ verbs: ["get"], apiGroups: [""], resources: ["pods"] })).toBe("read");
    expect(cls({ verbs: ["create"], apiGroups: [""], resources: ["configmaps"] })).toBe("mutate");
    expect(cls({ verbs: ["patch"], apiGroups: ["apps"], resources: ["deployments"] })).toBe("deploy");
    expect(cls({ verbs: ["delete"], apiGroups: [""], resources: ["pods"] })).toBe("destroy");
    expect(cls({ verbs: ["*"], apiGroups: ["*"], resources: ["*"] })).toBe("destroy");
    expect(cls({ verbs: ["create"], apiGroups: [""], resources: ["pods/exec"] })).toBe("mutate");
    expect(cls({ verbs: ["get"], apiGroups: [""], resources: [], nonResourceURLs: ["/healthz"] })).toBe("read");
  });

  it("öz-inceleme create (gerçek kümede system:basic-user) yazma sayılmaz; joker grup/kaynakla gizlenemez", () => {
    // kind kümesinde bulundu: her kimliğin SSRR çıktısında bu kurallar vardır; eskiden salt okunur SA 'write_access' alıyordu
    const basic = [
      { verbs: ["create"], apiGroups: ["authorization.k8s.io"], resources: ["selfsubjectaccessreviews", "selfsubjectrulesreviews"] },
      { verbs: ["create"], apiGroups: ["authentication.k8s.io"], resources: ["selfsubjectreviews"] },
    ];
    expect(analyzeRules([...basic, ...READONLY_NAMESPACED_RULES])).toMatchObject({ effective: "read", findings: [] });
    // aynı grupta başka kaynak ya da joker hâlâ sayılır
    expect(analyzeRules([{ verbs: ["create"], apiGroups: ["authorization.k8s.io"], resources: ["subjectaccessreviews"] }]).effective).toBe("mutate");
    expect(analyzeRules([{ verbs: ["create"], apiGroups: ["*"], resources: ["selfsubjectreviews"] }]).effective).toBe("mutate");
    expect(analyzeRules([{ verbs: ["*"], apiGroups: ["authorization.k8s.io"], resources: ["*"] }]).effective).toBe("destroy");
  });

  it("Secret okuma: yalnız çekirdek grupta 'secrets'; joker kaynak da sayılır", () => {
    expect(analyzeRules([{ verbs: ["list"], apiGroups: [""], resources: ["secrets"] }]).secretsReadable).toBe(true);
    expect(analyzeRules([{ verbs: ["get"], apiGroups: ["*"], resources: ["*"] }]).secretsReadable).toBe(true);
    expect(analyzeRules([{ verbs: ["create"], apiGroups: [""], resources: ["secrets"] }]).secretsReadable).toBe(false);
  });

  it("ruleAllows: grup, joker ve alt kaynak", () => {
    const rules = [{ verbs: ["get", "list"], apiGroups: ["apps"], resources: ["deployments"] }, { verbs: ["get"], apiGroups: [""], resources: ["pods", "pods/log"] }];
    expect(ruleAllows(rules, { verb: "get", resource: "deployments", group: "apps" })).toBe(true);
    expect(ruleAllows(rules, { verb: "get", resource: "deployments" })).toBe(false);
    expect(ruleAllows(rules, { verb: "get", resource: "pods/log" })).toBe(true);
    expect(ruleAllows([{ verbs: ["*"], apiGroups: ["*"], resources: ["*"] }], { verb: "delete", resource: "x", group: "y" })).toBe(true);
  });
});
