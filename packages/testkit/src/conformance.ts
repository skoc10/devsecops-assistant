import { describe, expect, it } from "vitest";
import type { Adapter } from "@ops/contracts";
import { checkAdapterStructure } from "./structure.ts";

/**
 * Adapter conformance paketi: her adapter aynı testlerden geçer.
 * Kategori testleri adapter paketlerinde bu girişin üstüne eklenir.
 */
export function adapterConformance(name: string, make: () => Adapter | Promise<Adapter>): void {
  describe(`adapter conformance: ${name}`, () => {
    it("manifest ve araç tanımları yapısal olarak geçerli", async () => {
      const adapter = await make();
      expect(checkAdapterStructure(adapter)).toEqual([]);
    });
  });
}
