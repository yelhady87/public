const { Issuer } = require('openid-client');

/**
 * Fusion Auth OIDC client configuration
 */
const APP_BASE_URL =
  process.env.APP_BASE_URL ||
  `http://localhost:${process.env.APP_PORT || 3000}`;

class FusionAuthClient {
  constructor() {
    this.issuer = process.env.FUSION_AUTH_ISSUER;
    this.clientId = process.env.FUSION_AUTH_CLIENT_ID;
    this.clientSecret = process.env.FUSION_AUTH_CLIENT_SECRET;
    this.scopes = (process.env.FUSION_AUTH_SCOPES || 'openid profile email').split(' ');
    this.redirectUri = `${APP_BASE_URL}/callback`;
    this.client = null;
  }

  /**
   * Initialize the OIDC client by fetching the discovery document
   */
  async init() {
    if (!this.issuer || !this.clientId || !this.clientSecret) {
      throw new Error(
        'Fusion Auth configuration missing. Please set FUSION_AUTH_ISSUER, FUSION_AUTH_CLIENT_ID, and FUSION_AUTH_CLIENT_SECRET in .env'
      );
    }

    const issuer = await Issuer.discover(this.issuer);
    this.client = new issuer.Client({
      client_id: this.clientId,
      client_secret: this.clientSecret,
      redirect_uris: [this.redirectUri],
      response_types: ['code'],
    });

    console.log(`✓ Fusion Auth OIDC client initialized (issuer: ${this.issuer})`);
    return this.client;
  }

  /**
   * Generate authorization URL for login
   */
  authorizationUrl(state, nonce, codeChallenge, codeChallengeMethod = 'S256') {
    return this.client.authorizationUrl({
      scope: this.scopes.join(' '),
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
    });
  }

  /**
   * Exchange authorization code for tokens.
   * @param {object} params - the FULL callback query object (req.query), not a
   *   hand-picked subset. See the note below.
   * @param {string} codeVerifier - the PKCE code verifier
   * @param {string} expectedNonce - the nonce sent on the authorize request
   */
  async getTokenSet(params, codeVerifier, expectedNonce, expectedState) {
    // NOTE: pass the whole callback query through, and pass `code_verifier` in
    // the third argument (`checks`), never in `parameters`.
    //
    // openid-client runs `parameters` through pickCb(), which allowlists
    // standard OAuth/OIDC response fields and silently drops everything else.
    // Two consequences, both hit in practice:
    //
    //   1. Picking `{ code, state }` by hand drops any other response field the
    //      provider sent. With Keycloak that silently dropped the RFC 9207
    //      `iss`, and callback() then threw "iss missing from the response"
    //      because Keycloak advertises
    //      `authorization_response_iss_parameter_supported`.
    //
    //   2. Putting code_verifier in `parameters` drops it the same way, and
    //      Fusion Auth rejects the exchange with:
    //        "A PKCE code_challenge was provided during the authorization
    //         request, but the required code_verifier was omitted from this
    //         request."
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
   * Extract user email from the ID token
   */
  getUserEmail(tokenSet) {
    if (!tokenSet.claims()) {
      return null;
    }
    return tokenSet.claims().email;
  }

  /**
   * Get user claims from the ID token
   */
  getUserClaims(tokenSet) {
    return tokenSet.claims();
  }
}

module.exports = { FusionAuthClient };
