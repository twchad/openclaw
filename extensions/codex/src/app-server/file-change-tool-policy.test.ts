import { describe, expect, it } from "vitest";
import {
  buildCodexFileChangeEventPayload,
  buildCodexFileChangeToolParams,
} from "./file-change-tool-policy.js";

describe("Codex file change tool policy normalization", () => {
  it("builds an apply_patch envelope from Codex file change approval params", () => {
    const params = buildCodexFileChangeToolParams({
      itemId: "patch-1",
      changes: [
        {
          path: "src/app.ts",
          kind: { type: "update" },
          diff: "@@\n- old\n+ new",
        },
      ],
    });

    expect(params.input).toContain("*** Begin Patch");
    expect(params.input).toContain("*** Update File: src/app.ts");
    expect(params.input).toContain("@@\n- old\n+ new");
    expect(params.input).toContain("*** End Patch");
    expect(params.changes).toEqual([
      {
        path: "src/app.ts",
        kind: { type: "update" },
        diff: "@@\n- old\n+ new",
      },
    ]);
  });

  it("preserves existing apply_patch envelopes from Codex diffs", () => {
    const patch = "*** Begin Patch\n*** Delete File: secret.txt\n*** End Patch";
    const params = buildCodexFileChangeEventPayload([
      {
        path: "secret.txt",
        kind: "delete",
        diff: patch,
      },
    ]);

    expect(params.input).toBe(patch);
  });
});
