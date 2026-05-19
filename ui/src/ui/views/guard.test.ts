/* @vitest-environment jsdom */

import { render } from "lit";
import { describe, expect, it } from "vitest";
import { renderGuard } from "./guard.ts";

describe("renderGuard", () => {
  it("allows Guard template exports from the embedded frame", () => {
    const container = document.createElement("div");

    render(
      renderGuard({
        connected: true,
        allowExternalEmbedUrls: true,
        endpoint: "http://127.0.0.1:4520",
      }),
      container,
    );

    const iframe = container.querySelector<HTMLIFrameElement>(".guard-card__frame");
    expect(iframe?.getAttribute("src")).toBe("http://127.0.0.1:4520");
    expect(iframe?.getAttribute("sandbox")).toBe(
      "allow-scripts allow-same-origin allow-downloads allow-forms allow-modals",
    );
  });

  it("does not render the external frame when external embeds are disabled", () => {
    const container = document.createElement("div");

    render(renderGuard({ connected: true, allowExternalEmbedUrls: false }), container);

    expect(container.querySelector(".guard-card__frame")).toBeNull();
    expect(container.textContent).toContain("Enable external Control UI embeds");
  });
});
