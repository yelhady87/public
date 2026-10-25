# public

Publicly shareable Incorta samples. This branch (`sample-chat-app`) holds one project: **[Chat With Incorta](chat-with-incorta/)**.

## Chat With Incorta

A small Node.js / Express web app that shows how to build a user-aware chat experience on top of Incorta:

- **User login** through any OpenID Connect provider (Keycloak, Okta, Auth0, Microsoft Entra ID), using Authorization Code + PKCE. Incorta also supports SAML 2.0 based SSO; this sample uses OIDC because it is the easier one to set up.
- **Incorta access on the user's behalf**: the app gets an Incorta token with the Client Credentials flow and passes the field mapped to Incorta's `loginName` (e.g. the user's email) as `for_user`. The identity provider's token is never sent to Incorta.
- **Two chat experiences** backed by Incorta's Copilot agent-to-agent (A2A) API:
  - a blocking chat widget on the home page (`POST /api/incorta/chat`);
  - a `/copilot` page that sends a message, polls the task, and shows the agent's "Thoughts" before the final answer.
- A schema-list call to Incorta's REST API (`/api/incorta/schemas/list`) as a plain REST example.

### Architecture

[Open the interactive diagram](.archify/architecture-chat-with-incorta-20261025-231346/chat-with-incorta.html) (standalone HTML, generated with Archify).

```
Browser ──► Auth routes ──► OIDC identity provider        (login: code + PKCE)
   │
   ├──► Chat + schema routes ─┐
   └──► Copilot routes ───────┤
                              ▼
        Incorta OIDC client ──► Incorta token endpoint    (client_credentials + for_user)
        Incorta API clients ──► Incorta REST API / Copilot A2A agent   (Bearer token)
```

### Key files

| Path | Role |
| --- | --- |
| `chat-with-incorta/server.js` | App wiring, session, home page, `/health` |
| `chat-with-incorta/routes/auth.js` | `/login`, `/callback`, `/logout`, `/me` |
| `chat-with-incorta/routes/incorta.js` | Blocking chat and schema list |
| `chat-with-incorta/routes/copilot.js` | Polled Copilot API and page |
| `chat-with-incorta/lib/oidc-provider.js` | OIDC client for user login |
| `chat-with-incorta/lib/oidc-incorta.js` | Incorta client-credentials client with token caching |
| `chat-with-incorta/lib/incorta-a2a*.js` | A2A request builder and transport |
| `chat-with-incorta/lib/incorta-task-view.js` | Trims task responses before they reach the browser |

### Quick start

Requires Node.js 18+.

```bash
cd chat-with-incorta
cp .env.example .env     # fill in the OIDC_* and INCORTA_* values
npm install
npm start                # or: npm run dev
```

Then open <http://localhost:3000>. `npm test` runs a smoke test against mock OIDC and Incorta servers.

You need an OIDC client at your identity provider (redirect URI `${APP_BASE_URL}/callback`) and an OAuth client registered in Incorta. See [`chat-with-incorta/README.md`](chat-with-incorta/README.md) for setup, the routes table and troubleshooting.

## License

[MIT](LICENSE)
