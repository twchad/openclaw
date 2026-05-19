import { html } from "lit";

type RenderGuardParams = {
  connected: boolean;
  allowExternalEmbedUrls?: boolean;
  endpoint?: string;
};

export function renderGuard(params: RenderGuardParams) {
  const endpoint = (params.endpoint ?? "http://127.0.0.1:4520").trim();
  return html`
    <section class="guard-layout">
      <article class="card guard-card">
        ${!params.connected
          ? html`
              <div class="guard-card__status guard-card__status--warn">
                Connect to the gateway first, then open Guard.
              </div>
            `
          : params.allowExternalEmbedUrls !== true
            ? html`
                <div class="guard-card__status guard-card__status--warn">
                  Enable external Control UI embeds before opening Guard.
                </div>
              `
            : html`<div class="guard-card__frame-wrap">
                <iframe
                  class="guard-card__frame"
                  src=${endpoint}
                  title="Guard UI"
                  loading="lazy"
                  sandbox="allow-scripts allow-same-origin allow-downloads allow-forms allow-modals"
                ></iframe>
              </div>`}
      </article>
    </section>
  `;
}
