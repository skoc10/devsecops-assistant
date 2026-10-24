// Sahte Cursor SDK (yalnız testler). Senaryo MOCK_SCENARIO ile seçilir. Gerçek SDK davranışı DEĞİLDİR.
import { readFileSync, readdirSync } from "node:fs";

const scenario = process.env.MOCK_SCENARIO ?? "tools";

function toolByName(opts, suffix) {
  return opts.local.customTools.find((t) => t.name.endsWith(suffix));
}

export const Agent = {
  async create(opts) {
    return {
      async send(prompt) {
        return {
          async cancel() {},
          async *stream() {
            if (scenario === "record") {
              // SDK'ya gelen seçenekler (execute işlevleri hariç) + ortam/dosya görünürlüğü
              const o = JSON.parse(JSON.stringify({ ...opts, apiKey: opts.apiKey ? "<set>" : undefined, local: { ...opts.local, customTools: opts.local.customTools.map((t) => ({ name: t.name })) } }));
              yield { type: "assistant", message: { content: JSON.stringify({ opts: o, prompt, hasApiKey: Boolean(opts.apiKey) }) } };
              return;
            }
            if (scenario === "probe") {
              let kube = "yok";
              try { kube = readFileSync(`${process.env.PROBE_HOME}/.kube/config`, "utf8"); } catch {}
              let home = "yok";
              try { home = readdirSync(process.env.PROBE_HOME_PARENT ?? "/home").join(","); } catch {}
              const envKeys = Object.keys(process.env).sort().join(",");
              let net = "kapali";
              try {
                const { connect } = await import("node:net");
                await new Promise((res, rej) => { const s = connect(Number(process.env.PROBE_PORT), "127.0.0.1", () => { s.destroy(); res(); }); s.on("error", rej); });
                net = "acik";
              } catch {}
              yield { type: "assistant", message: { content: JSON.stringify({ kube, home, envKeys, net, hasApiKey: Boolean(opts.apiKey) }) } };
              return;
            }
            if (scenario === "bypass") {
              yield { type: "assistant", message: { content: "kabuğu deniyorum" } };
              yield { type: "tool_call", name: "shell", status: "running" };
              yield { type: "assistant", message: { content: "bu satır görülmemeli" } };
              return;
            }
            if (scenario === "bypass-bridge") {
              const t = { name: "k8s__resources__delete" };
              // izinli olmayan köprü aracı: host doğrudan protokol üzerinden ister
              process.stdout.write(JSON.stringify({ t: "tool_request", id: "x1", name: "k8s.resources.delete", args: {} }) + "\n");
              await new Promise((r) => setTimeout(r, 5000));
              return;
            }
            if (scenario === "crash") throw new Error("SDK çöktü: gizli-bilgi-sızdırmamalı");
            if (scenario === "hang") { await new Promise(() => {}); }
            // "tools": köprü araçlarını çağırır, cevabı kanıt kimlikleriyle verir
            yield { type: "assistant", message: { content: [{ type: "text", text: "Önce sağlığa bakıyorum. " }] } };
            const health = toolByName(opts, "k8s__workload__health");
            const out1 = await health.execute({ kind: "Deployment", name: "api", namespace: "payments" });
            yield { type: "tool_call", name: `custom-user-tools__${health.name}`, status: "completed" };
            const events = toolByName(opts, "k8s__events__list");
            const out2 = await events.execute({ namespace: "payments", since: "2h", type: "Warning" });
            yield { type: "tool_call", name: events.name, status: "completed" };
            const ids = [...new Set([...(out1 + out2).matchAll(/"id":"(ev-\d+)"/g)].map((m) => m[1]))];
            yield { type: "usage", usage: { input_tokens: 1200, output_tokens: 90, cache_read_tokens: 300 } };
            yield { type: "assistant", message: { content: `api OOMKilled oluyor ${ids.map((i) => `[${i}]`).join(" ")}. Bellek sınırını artırın.` } };
          },
        };
      },
      async close() {},
    };
  },
};
