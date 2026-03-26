import { html } from "lit";

type RenderGuardParams = {
  connected: boolean;
  endpoint?: string;
};

export function renderGuard(params: RenderGuardParams) {
  const endpoint = (params.endpoint ?? "http://127.0.0.1:4520").trim();
  return html`
    <section class="guard-layout">
      <article class="card guard-card">
        ${
          !params.connected
            ? html`
                <div class="guard-card__status guard-card__status--warn">
                  Connect to the gateway first, then open Guard.
                </div>
              `
            : html`<div class="guard-card__frame-wrap">
                <iframe
                  class="guard-card__frame"
                  src=${endpoint}
                  title="Guard UI"
                  loading="lazy"
                ></iframe>
              </div>`
        }
      </article>
    </section>
  `;
}
