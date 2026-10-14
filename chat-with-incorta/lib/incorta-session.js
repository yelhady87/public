/**
 * Session-level helpers shared by the Incorta API routers.
 */

/**
 * Middleware: require an authenticated user (JSON 401 for API calls)
 */
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: 'Not authenticated',
      message: 'Login first',
    });
  }
  next();
}

/**
 * Get an Incorta access token for the authenticated user, using the session
 * cache while it is still valid.
 *
 * @param {object} req - express request (needs req.session.user)
 * @param {object} incorta - the IncortaOIDCClient instance
 * @param {object} [options]
 * @param {boolean} [options.force] - ignore the cached token and fetch a new one
 */
async function getIncortaToken(req, incorta, { force = false } = {}) {
  const cached = req.session.incortaToken;

  const now = Math.floor(Date.now() / 1000);
  if (!force && cached && cached.expiresAt && cached.expiresAt > now + 30) {
    return cached.accessToken;
  }

  const tokenData = await incorta.getAccessToken(req.session.user.email);
  req.session.incortaToken = {
    accessToken: tokenData.access_token,
    expiresAt: now + (tokenData.expires_in || 300),
  };
  return tokenData.access_token;
}

module.exports = { requireAuth, getIncortaToken };
