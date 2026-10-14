const { Issuer } = require('openid-client');

/**
 * Generic OpenID Connect client for user authentication.
 *
 * Works with any standards-compliant provider (Keycloak, Okta, Auth0, Entra ID,
 * ...) via OIDC discovery. Uses the Authorization Code + PKCE flow and mounts
 * on `${APP_BASE_URL}/callback`.
 */
const APP_BASE_URL =
  process.env.APP_BASE_URL ||
  `http://localhost:${process.env.APP_PORT || 3000}`;

class OIDCProviderClient {
  constructor() {
    this.issuer = process.env.OIDC_ISSUER;
    this.clientId = process.env.OIDC_CLIENT_ID;
    // Empty for a public client. The "none" token endpoint auth method sends
    // client_id and nothing else - exactly what a public client needs. Sending
    // an empty client_secret would still authenticate the request as
    // confidential and get rejected.
    this.clientSecret = process.env.OIDC_CLIENT_SECRET || undefined;
    this.scopes = (process.env.OIDC_SCOPES || 'openid profile email').split(' ');
    // Shown on the login button and in logs
    this.label = process.env.OIDC_PROVIDER_LABEL || 'SSO';
    // Claim that carries the user's email; becomes `for_user` for Incorta
    this.emailClaim = process.env.OIDC_EMAIL_CLAIM || 'email';
    this.redirectUri = `${APP_BASE_URL}/callback`;
    this.client = null;
  }

  /**
   * Initialize the OIDC client by fetching the discovery document
   */
  async init() {
    if (!this.issuer || !this.clientId) {
      throw new Error(
        'OIDC configuration missing. Please set OIDC_ISSUER and OIDC_CLIENT_ID in .env'
      );
    }

    const issuer = await Issuer.discover(this.issuer);

    // openid-client defaults to token_endpoint_auth_method 'client_secret_basic'
    // and does NOT downgrade to 'none' on its own: its checkBasicSupport() helper
    // only falls back to 'client_secret_post' (node_modules/openid-client/lib/
    // client.js). So a public client with no secret fails before anything is
    // sent:
    //   "client_secret_basic client authentication method requires a client_secret"
    // Set 'none' explicitly for that case. With it, only client_id is sent in
    // the token request body and no Authorization header is added
    // (openid-client/lib/helpers/client.js, case 'none').
    //
    // Note this is set unconditionally rather than only when the issuer
    // advertises 'none', because some providers do NOT list 'none' for a public
    // client. Verified against Keycloak 25, realm incorta, for a public client:
    //   token_endpoint_auth_methods_supported = ['private_key_jwt',
    //     'client_secret_basic', 'client_secret_post', 'tls_client_auth',
    //     'client_secret_jwt']
    // That is inaccurate per RFC 8414 (which says to advertise 'none' when
    // supported), and gating on it would break public-client logins entirely.
    // Such providers accept public-client token requests without it.
    this.client = new issuer.Client({
      client_id: this.clientId,
      client_secret: this.clientSecret,
      redirect_uris: [this.redirectUri],
      response_types: ['code'],
      token_endpoint_auth_method: this.clientSecret
        ? 'client_secret_basic'
        : 'none',
    });

    console.log(`✓ ${this.label} OIDC client initialized (issuer: ${this.issuer})`);
    return this.client;
  }

  /**
   * Generate authorization URL for login
   */
  authorizationUrl(state, nonce, codeChallenge, codeChallengeMethod = 'S256') {
    const params = {
      scope: this.scopes.join(' '),
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
    };

    // RFC 9207 (OAuth 2.0 Authorization Server Issuer Identification).
    //
    // Providers such as Keycloak advertise
    // `authorization_response_iss_parameter_supported: true` in their discovery
    // document, and openid-client v5 reacts to that by
    // REQUIRING `iss` on the authorization response:
    //
    //   if ('iss' in params) { ...validate it... }
    //   else if (this.issuer.authorization_response_iss_parameter_supported
    //            && !('id_token' in params)) {
    //     throw new RPError({ message: 'iss missing from the response' });
    //   }
    //   (node_modules/openid-client/lib/client.js)
    //
    // But openid-client v5 never sends `iss` on the authorization REQUEST, and
    // per RFC 9207 a server only returns `iss` in the response when the client
    // asked for it. Such a provider does not get this automatically, so the flow fails with
    // "Authentication failed: iss missing from the response".
    //
    // Sending it explicitly satisfies both sides: the provider echoes it back, and
    // openid-client validates that the echo matches its discovered issuer.
    //
    // Both halves are required. Sending `iss` without passing the whole callback
    // query to callback() still fails: openid-client runs `parameters` through
    // pickCb() first, so a hand-picked `{ code, state }` drops the echoed `iss`
    // and the very same "iss missing from the response" error is thrown. See
    // getTokenSet() below.
    if (this.client.issuer.metadata.authorization_response_iss_parameter_supported) {
      params.iss = this.client.issuer.issuer;
    }

    return this.client.authorizationUrl(params);
  }

  /**
   * Exchange authorization code for tokens.
   * @param {object} params - the FULL callback query object (req.query), not a
   *   hand-picked subset. See the note below.
   * @param {string} codeVerifier - the PKCE code verifier
   * @param {string} expectedNonce - the nonce sent on the authorize request
   * @param {string} expectedState - the state sent on the authorize request
   */
  async getTokenSet(params, codeVerifier, expectedNonce, expectedState) {
    // `parameters` MUST be the whole callback query object, and
    // `code_verifier` MUST be passed in the third argument (`checks`).
    //
    // openid-client runs `parameters` through pickCb(), which allowlists
    // standard OAuth/OIDC response fields and silently drops everything else.
    // Two consequences, both hit in practice:
    //
    //   1. Passing `{ code, state }` by hand drops the RFC 9207 `iss` that
    //      the provider echoes back. Because it advertises
    //      `authorization_response_iss_parameter_supported`, callback() then
    //      treats the dropped `iss` as absent and throws
    //      "iss missing from the response" - even though the redirect clearly
    //      contained it. Passing req.query through unchanged avoids this:
    //      pickCb() keeps `iss` (it is in the allowlist) along with `code`,
    //      `state`, `session_state` and any `error`.
    //
    //   2. Putting code_verifier in `parameters` instead of `checks` drops it
    //      the same way, and the provider rejects the exchange with
    //      "Invalid parameter: code_verifier".
    //
    // openid-client also validates the ID token signature, issuer, audience,
    // state and nonce, so none of those are re-checked by hand here.
    const tokenSet = await this.client.callback(
      this.redirectUri,
      params,
      { code_verifier: codeVerifier, nonce: expectedNonce, state: expectedState }
    );
    return tokenSet;
  }

  /**
   * Extract user email from the ID token (claim set by OIDC_EMAIL_CLAIM).
   *
   * Providers only include `email` when the user actually has one on their
   * profile, so this can legitimately come back undefined. Callers
   * surface that as a configuration error rather than silently falling back to
   * a username, because the email is what Incorta receives as `for_user`.
   */
  getUserEmail(tokenSet) {
    const claims = tokenSet.claims();
    if (!claims) {
      return null;
    }
    return claims[this.emailClaim];
  }

  /**
   * Get user claims from the ID token
   */
  getUserClaims(tokenSet) {
    return tokenSet.claims();
  }
}

module.exports = { OIDCProviderClient };