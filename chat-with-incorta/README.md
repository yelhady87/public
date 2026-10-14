# Sample Incorta OAuth App

A sample Node.js web application demonstrating OAuth 2.0 / OpenID Connect authentication flow with any OpenID Connect identity provider (Keycloak, Okta, Auth0, Entra ID, ...) and Incorta.

## Architecture Overview

This app implements a two-step authentication flow:

1. **User Authentication via any OIDC provider** - Authorization Code flow with PKCE to authenticate the user and retrieve their identity (email)
2. **API Authentication with Incorta (OIDC)** - Client Credentials flow using Incorta's OAuth client to obtain an access token for API calls, passing the authenticated user's email as the `for_user` parameter

## Prerequisites

- Node.js v18 or higher
- Running Incorta instance with OAuth enabled at `http://localhost`
- An OpenID Connect identity provider (e.g. Keycloak at `http://localhost:8888`) with a client registered for this app
- Registered confidential OAuth client in Incorta

## Setup Instructions

### 1. Register a Confidential Client in Incorta

1. In Incorta, register/configure an OAuth confidential client for the `demo_sso` context
2. Copy the `Client ID` and `Client Secret`
3. Ensure Incorta's OIDC discovery endpoint is accessible at:
   ```
   http://localhost/incorta/oauth/demo_sso/.well-known/openid-configuration
   ```

### 2. Register a Client in your OIDC provider

Any standards-compliant OpenID Connect provider works; the app only needs its
issuer URL (for discovery) and a client. Steps below use Keycloak as the example.

1. In the Keycloak Admin Console, pick a realm (the examples below use
   `incorta`) and go to **Clients → Create client**
2. **Client type**: `OpenID Connect`; **Client authentication**: `Client
   secret` for a confidential client, or public if you want PKCE-only with no
   secret
3. Add the redirect URI - it is derived from `APP_BASE_URL`:

   ```
   http://localhost:3000/callback
   ```

4. Save, then copy the **Client ID**. If you chose a confidential client, open
   the **Credentials** tab and copy the **Client secret** as well.

Notes:

- The app needs the `email` claim from the ID token, so the user must have an
  email set on their profile at the provider and the `email` scope must be
  granted to the client (in Keycloak: the `email` client scope). Otherwise login
  fails with a message saying no email claim was found. If your provider puts
  the email in a different claim, set `OIDC_EMAIL_CLAIM`.
- That email is passed to Incorta as `for_user`, so it must match the Incorta
  user you want to act as.

### 3. Configure Environment Variables

1. Copy `.env.example` to `.env`:

   ```bash
   cp .env.example .env
   ```

2. Update the `.env` file with your credentials:

   ```env
   # Incorta
   INCORTA_CLIENT_ID=your_incorta_oauth_client_id
   INCORTA_CLIENT_SECRET=your_incorta_oauth_client_secret
   INCORTA_OIDC_ISSUER=http://localhost/incorta/oauth/demo_sso
   INCORTA_BASE_URL=http://localhost
   # Tenant used in the REST API path. Defaults to the last segment of
   # INCORTA_OIDC_ISSUER when left empty.
   INCORTA_TENANT=demo_sso

   # Identity provider (leave OIDC_CLIENT_SECRET empty for a public client)
   OIDC_ISSUER=http://localhost:8888/realms/incorta
   OIDC_CLIENT_ID=your_oidc_client_id
   OIDC_CLIENT_SECRET=
   OIDC_SCOPES=openid profile email
   # Optional: login button / log label (default: SSO)
   OIDC_PROVIDER_LABEL=Keycloak
   # Optional: claim holding the user's email (default: email)
   OIDC_EMAIL_CLAIM=email

   # App
   APP_PORT=3000
   APP_BASE_URL=http://localhost:3000
   SESSION_SECRET=generate_a_random_secret_here
   # Optional: log full access tokens instead of a masked fingerprint
   LOG_ACCESS_TOKENS=false
   ```

   If `OIDC_*` is missing or the provider is unreachable, the app still starts
   and `/login` responds `503`.

### 4. Install Dependencies

```bash
npm install
```

### 5. Run the Application

For development:

```bash
npm run dev
```

For production:

```bash
npm start
```

The app will be available at [http://localhost:3000](http://localhost:3000).

## Usage

1. Navigate to [http://localhost:3000](http://localhost:3000)
2. Click the login button (labelled with `OIDC_PROVIDER_LABEL`, default "Login with SSO")
3. Authenticate with your identity provider
4. After successful login, you'll be redirected to the home page showing your authenticated email and which provider logged you in
5. Click "Call Incorta API" to fetch the schema list from Incorta
6. The API response will be displayed on the page

## Key Implementation Notes

- **OIDC provider**: Authorization Code + PKCE flow, configured through discovery. Supports both confidential and public clients; with a public client no secret is sent, and PKCE is what protects the code exchange. The client sends `iss` on the authorize request when the provider advertises RFC 9207 support (as Keycloak does). Providers only return `email` when the user has one set on their profile.
- **Callback**: the provider is registered with `${APP_BASE_URL}/callback`.
- **Incorta**: Uses Client Credentials flow. The authenticated user's email (from the IdP's ID token) is passed as the `for_user` parameter in the token request.
- **Copilot A2A**: The chat window calls Incorta's agent-to-agent `message/send` JSON-RPC endpoint server-side, reusing the cached Incorta token. The IdP access token is never sent to Incorta.
- **Session Management**: Uses `express-session` to store authentication state. In production, consider using a secure session store.
- **Security**: The app validates ID tokens, uses server-side token exchange, and stores secrets in environment variables.
- **Access token logging**: Every access token the app receives (Incorta and the identity provider) is logged once, when it arrives. By default only a masked fingerprint is printed — enough to see whether a token rotated or the cached one is the one you expect, but not usable as a credential. Set `LOG_ACCESS_TOKENS=true` to log the full value; the app then prints a one-time warning, because tokens in logs are a real credential leak (logs get shipped, attached to bug reports, and kept for months). Keep it off outside local debugging.

## OAuth Redirect URL

Add this exact redirect URI to the identity provider's client (e.g. Keycloak **Valid redirect URIs**):

```
http://localhost:3000/callback
```

It is derived from `APP_BASE_URL` + `/callback`. If you change `APP_BASE_URL`
or `APP_PORT`, update the provider's client to match. The app prints
the value it expects on startup.

## Chat with the Incorta Copilot

The logged-in page has a chat window that posts to Incorta's Copilot A2A
(`agent-to-agent`) endpoint:

```
{INCORTA_BASE_URL}/incorta/api/v2/{INCORTA_TENANT}/copilot/a2a/agent/{INCORTA_A2A_AGENT}
```

The browser posts the message text to `/api/incorta/chat`; the **server** makes
the Incorta call, attaching the Incorta access token obtained from the
Client Credentials exchange. The token never reaches the browser.

That call sends only three headers — `accept`, `content-type`, and
`authorization` — plus `x-a2a-extensions`. The `User-Agent`, `Origin`, `Referer`,
`sec-ch-ua*`, `sec-fetch-*`, and `accept-language` headers in a browser-recorded
curl describe the page that made the request, not the API contract, so none of
them are forwarded. `x-xsrf-token` is deliberately dropped too: it protects
Incorta's cookie-authenticated UI against CSRF, and this call is
Bearer-authenticated with no cookies, so there is no ambient credential to
protect.

| Variable | Default | Purpose |
| --- | --- | --- |
| `INCORTA_A2A_AGENT` | `smart-agent` | Agent name in the URL |
| `INCORTA_A2A_EXTENSIONS` | *(four defaults)* | `x-a2a-extensions` value; set empty to send no header |
| `INCORTA_A2A_VERBOSITY` | `detailed` | Agent verbosity |
| `INCORTA_A2A_ENABLE_SUMMARY` | `true` | Whether the agent may summarize |
| `INCORTA_A2A_TIMEOUT_MS` | `120000` | Per-message timeout |
| `INCORTA_A2A_MAX_MESSAGE_LENGTH` | `8000` | Input length cap |
| `INCORTA_A2A_MODEL_KEY` | *(unset)* | Model to use, sent as `client_context.params` `model_key`; unset uses Incorta's default |
| `INCORTA_COPILOT_POLL_MS` | `2000` | `/copilot` page: how often to poll a task |
| `INCORTA_COPILOT_TIMEOUT_MS` | `300000` | `/copilot` page: how long to wait before giving up |

The conversation id lives in the session, so messages from one browser tab stay
in one Incorta conversation. `current_date` is stamped per message, so relative
dates like "last quarter" resolve against the right day.

The chat window shows only the agent's reply text. If a reply has no text, the
bubble says so; the full request and response bodies are in the server log.
Agent output is inserted as text, never HTML.

## Polled Copilot page (`/copilot`)

A second chat page that works the way Incorta's own Copilot UI does. Instead of
waiting for the answer in one request, it:

1. sends the message without `configuration.blocking`, and gets back a **task**
   (`state: submitted`, a task id and a conversation id);
2. polls `tasks/get` for that task (every `INCORTA_COPILOT_POLL_MS`) until it
   reaches a final state, showing the agent's **Thoughts** (its reasoning steps)
   as they arrive;
3. shows the answer, which Incorta returns in the task's `artifacts` (the
   `status.message` of a finished task is only a note like "Response ready.").

A failed, canceled or rejected task shows an error card with **View Error
Details** and **Retry**.

The server keeps no conversation state. The page holds the conversation id and
the current task id, so a reload or **New chat** starts a fresh conversation. The
page only ever receives a trimmed view of the task (state, step titles/status/
duration, answer, error); the Incorta token, step inputs/outputs and tracebacks
stay on the server, and the full response is in the server log.

Task and conversation ids come from the browser, so who may read a task is
decided by Incorta, which issues the token for the logged-in user.

## Routes

| Method | Path                     | Description                                    |
| ------ | ------------------------ | ---------------------------------------------- |
| GET    | `/`                      | Home page; shows login buttons or user identity |
| GET    | `/login`                 | Starts the OIDC flow (with PKCE)               |
| GET    | `/callback`              | OIDC callback                                 |
| GET    | `/logout`                | Destroys the session                           |
| GET    | `/me`                    | JSON with the current session user             |
| POST   | `/api/incorta/schemas/list` | Calls Incorta's schema list API (auth required) |
| POST   | `/api/incorta/chat`      | Sends one message to the Incorta Copilot A2A agent (auth required) |
| GET    | `/copilot`               | Polled Copilot chat page (redirects to `/` when logged out) |
| POST   | `/api/incorta/copilot/messages` | Starts a task: `{ text, contextId? }` -> `{ taskId, contextId }` (auth required) |
| GET    | `/api/incorta/copilot/tasks/:id` | One poll: `{ state, done, steps, answer, error }` (auth required) |
| GET    | `/health`                | Health check                                   |

`POST /api/incorta/chat` takes `{ "text": "..." }` and returns
`{ reply, contextId, traceId, durationMs }`. On an Incorta error it returns
Incorta's own status, message, and `trace-id`.

## Tests

The smoke test spins up a mock OIDC provider (issuing real RS256-signed ID
tokens) and a mock Incorta, then drives the whole flow:

```bash
npm test
```

It asserts the details that matter: the `openid profile email` scopes, PKCE
S256, the exact `for_user` email on the Incorta token request, the
`Authorization: Bearer` header on the API call, token caching, CSRF state
rejection, and logout. It uses high ports (19011/18080/13000) so it will not
collide with your real identity provider, Incorta, or a running dev instance.

It also covers the chat window: that the A2A request carries the Incorta token
and none of the browser-only headers, that the JSON-RPC envelope is well formed,
that the conversation id persists while the JSON-RPC id increments, that empty
input is rejected before Incorta is called, that a Copilot permission error
surfaces Incorta's own message and `trace-id`, and that the page's inline script
actually parses as JavaScript.

The polled `/copilot` page is covered end to end against a scripted mock Incorta
(submitted, working with growing steps, completed, failed, input-required, a
JSON-RPC error, an expired token mid-task): the request contract (no
`configuration`, no `contextId` on the first message, `model_key`), that the
answer comes from the artifacts, that no token, step output or traceback reaches
the browser, and the page script itself (polling rules, error card and Retry,
New chat) run against a small fake DOM.

On a slow or heavily loaded machine, give the spawned apps longer to start with
`SMOKE_STARTUP_MS=120000 npm test` (default 10000).

## Troubleshooting

- Ensure both discovery endpoints are reachable
- Verify client secrets and IDs are correct
- Check that the identity provider's user has an `email` claim populated. Set the user's email on their profile at the provider, check the `email` scope is granted to the client, and check `OIDC_EMAIL_CLAIM`
- If login returns 503, `OIDC_ISSUER` / `OIDC_CLIENT_ID` are missing or OIDC discovery failed - the startup log says which
- If Incorta returns auth errors, verify the `for_user` parameter is being passed correctly (should be the user's email)
- Check browser console and server logs for detailed error messages

## License

MIT
