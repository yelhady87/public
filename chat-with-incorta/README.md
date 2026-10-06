# Sample Incorta OAuth App

A sample Node.js web application demonstrating OAuth 2.0 / OpenID Connect authentication flow with Keycloak and Incorta.

## Architecture Overview

This app implements a two-step authentication flow:

1. **User Authentication via Keycloak (OIDC)** - Authorization Code flow with PKCE to authenticate the user and retrieve their identity (email)
2. **API Authentication with Incorta (OIDC)** - Client Credentials flow using Incorta's OAuth client to obtain an access token for API calls, passing the authenticated user's email as the `for_user` parameter

## Prerequisites

- Node.js v18 or higher
- Running Incorta instance with OAuth enabled at `http://localhost`
- Running Keycloak instance (e.g. `http://localhost:8888`) with a client registered for this app
- Registered confidential OAuth client in Incorta

## Setup Instructions

### 1. Register a Confidential Client in Incorta

1. In Incorta, register/configure an OAuth confidential client for the `demo_sso` context
2. Copy the `Client ID` and `Client Secret`
3. Ensure Incorta's OIDC discovery endpoint is accessible at:
   ```
   http://localhost/incorta/oauth/demo_sso/.well-known/openid-configuration
   ```

### 2. Register a Client in Keycloak

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

Notes for Keycloak:

- The app needs the `email` claim from the ID token, so the Keycloak user must
  have an **Email** value set on their profile and the `email` client scope must
  be assigned to the client. Otherwise login fails with a message saying no
  email claim was found.
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

   # Keycloak (leave KEYCLOAK_CLIENT_SECRET empty for a public client)
   KEYCLOAK_ISSUER=http://localhost:8888/realms/incorta
   KEYCLOAK_CLIENT_ID=your_keycloak_client_id
   KEYCLOAK_CLIENT_SECRET=
   KEYCLOAK_SCOPES=openid profile email

   # App
   APP_PORT=3000
   APP_BASE_URL=http://localhost:3000
   SESSION_SECRET=generate_a_random_secret_here
   # Optional: log full access tokens instead of a masked fingerprint
   LOG_ACCESS_TOKENS=false
   ```

   If `KEYCLOAK_*` is missing or Keycloak is unreachable, the app still starts
   and `/login-keycloak` responds `503`.

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
2. Click "Login with Keycloak"
3. Authenticate with your Keycloak credentials
4. After successful login, you'll be redirected to the home page showing your authenticated email and which provider logged you in
5. Click "Call Incorta API" to fetch the schema list from Incorta
6. The API response will be displayed on the page

## Key Implementation Notes

- **Keycloak**: Same Authorization Code + PKCE flow. Supports both confidential and public clients; with a public client no secret is sent, and PKCE is what protects the code exchange. Keycloak only returns `email` when the user has one set on their profile.
- **Callback**: Keycloak is registered with `${APP_BASE_URL}/callback`.
- **Incorta**: Uses Client Credentials flow. The authenticated user's email (from the IdP's ID token) is passed as the `for_user` parameter in the token request.
- **Copilot A2A**: The chat window calls Incorta's agent-to-agent `message/send` JSON-RPC endpoint server-side, reusing the cached Incorta token. The IdP access token (Keycloak) is never sent to Incorta.
- **Session Management**: Uses `express-session` to store authentication state. In production, consider using a secure session store.
- **Security**: The app validates ID tokens, uses server-side token exchange, and stores secrets in environment variables.
- **Access token logging**: Every access token the app receives (Incorta, Keycloak) is logged once, when it arrives. By default only a masked fingerprint is printed — enough to see whether a token rotated or the cached one is the one you expect, but not usable as a credential. Set `LOG_ACCESS_TOKENS=true` to log the full value; the app then prints a one-time warning, because tokens in logs are a real credential leak (logs get shipped, attached to bug reports, and kept for months). Keep it off outside local debugging.

## OAuth Redirect URL

Add this exact redirect URI to the Keycloak client (**Valid redirect URIs**):

```
http://localhost:3000/callback
```

It is derived from `APP_BASE_URL` + `/callback`. If you change `APP_BASE_URL`
or `APP_PORT`, update the Keycloak client to match. The app prints
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
| `INCORTA_A2A_DATASETS` | *(empty)* | Dataset grounding, `SCHEMA` or `SCHEMA:TABLE`, comma separated |
| `INCORTA_A2A_EXTENSIONS` | *(four defaults)* | `x-a2a-extensions` value; set empty to send no header |
| `INCORTA_A2A_VERBOSITY` | `detailed` | Agent verbosity |
| `INCORTA_A2A_ENABLE_SUMMARY` | `true` | Whether the agent may summarize |
| `INCORTA_A2A_TIMEOUT_MS` | `120000` | Per-message timeout |
| `INCORTA_A2A_MAX_MESSAGE_LENGTH` | `8000` | Input length cap |

The conversation id lives in the session, so messages from one browser tab stay
in one Incorta conversation. `current_date` is stamped per message, so relative
dates like "last quarter" resolve against the right day.

If a message comes back with a response shape the renderer does not recognize,
the bubble shows the raw JSON instead of appearing empty. Agent output is
inserted as text, never HTML.

## Routes

| Method | Path                     | Description                                    |
| ------ | ------------------------ | ---------------------------------------------- |
| GET    | `/`                      | Home page; shows login buttons or user identity |
| GET    | `/login-keycloak`        | Starts the Keycloak OIDC flow (with PKCE)      |
| GET    | `/callback`              | OIDC callback                                 |
| GET    | `/logout`                | Destroys the session                           |
| GET    | `/me`                    | JSON with the current session user             |
| POST   | `/api/incorta/schemas/list` | Calls Incorta's schema list API (auth required) |
| POST   | `/api/incorta/chat`      | Sends one message to the Incorta Copilot A2A agent (auth required) |
| GET    | `/health`                | Health check                                   |

`POST /api/incorta/chat` takes `{ "text": "..." }` and returns
`{ reply, contextId, traceId, durationMs }`. On an Incorta error it returns
Incorta's own status, message, and `trace-id`.

## Tests

The smoke test spins up a mock Keycloak (issuing real RS256-signed ID
tokens) and a mock Incorta, then drives the whole flow:

```bash
npm test
```

It asserts the details that matter: the `openid profile email` scopes, PKCE
S256, the exact `for_user` email on the Incorta token request, the
`Authorization: Bearer` header on the API call, token caching, CSRF state
rejection, and logout. It uses high ports (19011/18080/13000) so it will not
collide with your real Keycloak, Incorta, or a running dev instance.

It also covers the chat window: that the A2A request carries the Incorta token
and none of the browser-only headers, that the JSON-RPC envelope is well formed,
that the conversation id persists while the JSON-RPC id increments, that empty
input is rejected before Incorta is called, that a Copilot permission error
surfaces Incorta's own message and `trace-id`, and that the page's inline script
actually parses as JavaScript.

## Troubleshooting

- Ensure both discovery endpoints are reachable
- Verify client secrets and IDs are correct
- Check that the identity provider's user has an `email` claim populated. In Keycloak, set the user's Email on their profile and check the `email` client scope is assigned to the client
- If Keycloak login returns 503, `KEYCLOAK_ISSUER` / `KEYCLOAK_CLIENT_ID` are missing or Keycloak discovery failed - the startup log says which
- If Incorta returns auth errors, verify the `for_user` parameter is being passed correctly (should be the user's email)
- Check browser console and server logs for detailed error messages

## License

MIT
