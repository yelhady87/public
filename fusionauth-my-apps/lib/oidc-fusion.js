const { Issuer } = require('openid-client');
const { launcherRedirectUri } = require('./config');

/**
 * FusionAuth OIDC client used to authenticate the person using the launcher.
 *
 * This client only ever establishes *who the user is*. It never mints tokens for
 * the applications it links to - see routes/launcher.js for how a tile launch
 * works.
 */
class FusionAuthOidcClient {
  constructor() {
    this.issuer = process.env.FUSION_AUTH_ISSUER;
    this.clientId = process.env.FUSION_AUTH_CLIENT_ID;
    this.clientSecret = process.env.FUSION_AUTH_CLIENT_SECRET;
    this.scopes = (
      process.env.FUSION_AUTH_SCOPES || 'openid profile email'
    ).split(' ');
    this.redirectUri = launcherRedirectUri();
    this.client = null;
  }

  /**
   * Initialize the OIDC client by fetching the discovery document.
   *
   * The issuer is tenant-scoped (`http://host/<tenantId>`). FusionAuth answers
   * that tenant's discovery document but reports a bare `issuer` value, which
   * openid-client accepts - verified against 1.62.1.
   */
  async init() {
    if (!this.issuer || !this.clientId || !this.clientSecret) {
      throw new Error(
        'FusionAuth OIDC configuration missing. Set FUSION_AUTH_ISSUER, ' +
          'FUSION_AUTH_CLIENT_ID and FUSION_AUTH_CLIENT_SECRET in .env'
      );
    }

    const issuer = await Issuer.discover(this.issuer);
    this.client = new issuer.Client({
      client_id: this.clientId,
      client_secret: this.clientSecret,
      redirect_uris: [this.redirectUri],
      response_types: ['code'],
    });

    console.log(`✓ FusionAuth OIDC client initialized (issuer: ${this.issuer})`);
    return this.client;
  }

  /**
   * Build the authorization URL that starts the login flow.
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
   * Exchange the authorization code for tokens.
   *
   * openid-client validates the ID token signature, issuer, audience, state and
   * nonce as part of this call, so none of those are re-checked by hand.
   */
  async getTokenSet(code, codeVerifier, expectedNonce, expectedState) {
    // NOTE: `code_verifier` MUST go in the third argument (`checks`), not in
    // `parameters`. openid-client passes `parameters` through pickCb(), which
    // allowlists standard OAuth response fields and silently drops code_verifier.
    // Sending it in `parameters` produces a token request with no verifier and
    // FusionAuth rejects it with:
    //   "A PKCE code_challenge was provided during the authorization request,
    //    but the required code_verifier was omitted from this request."
    const tokenSet = await this.client.callback(
      this.redirectUri,
      { code, state: expectedState },
      {
        code_verifier: codeVerifier,
        nonce: expectedNonce,
        state: expectedState,
      }
    );
    return tokenSet;
  }

  /**
   * Claims from the ID token (signature already verified by getTokenSet).
   */
  getUserClaims(tokenSet) {
    return tokenSet.claims();
  }

  /**
   * The tenant's authorize endpoint. Tiles redirect here so the target app runs
   * its own code exchange and benefits from the existing FusionAuth session
   * (silent SSO).
   */
  getAuthorizationEndpoint() {
    return this.client.issuer.metadata.authorization_endpoint;
  }

  getScopes() {
    return this.scopes.slice();
  }
}

module.exports = { FusionAuthOidcClient };
