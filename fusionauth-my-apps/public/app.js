/* FusionAuth My Apps launcher - front end.
 *
 * All rendering goes through textContent, never innerHTML, so application names
 * coming out of FusionAuth cannot inject markup.
 */

// Optional per-application overrides. FusionAuth applications have no logoUrl
// field, so tiles fall back to generated initials unless a logo is mapped here.
// Format: { "<applicationId>": { "logo": "/logos/foo.svg", "description": "..." } }
let overrides = {};

async function loadOverrides() {
  try {
    const res = await fetch('/apps.json', { cache: 'no-cache' });
    if (res.ok) overrides = await res.json();
  } catch (err) {
    // Cosmetic only - carry on with initials.
  }
}

function show(id) {
  ['signedOut', 'loading', 'error', 'gridSection'].forEach((name) => {
    document.getElementById(name).hidden = name !== id;
  });
}

function initials(name) {
  const words = String(name || '?')
    .split(/[\s._-]+/)
    .filter(Boolean);
  if (words.length === 0) return '?';
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}

// Deterministic hue so an app keeps the same tile colour across reloads.
function hueFor(id) {
  let hash = 0;
  for (let i = 0; i < id.length; i++) {
    hash = (hash * 31 + id.charCodeAt(i)) % 360;
  }
  return hash;
}

function renderTile(app) {
  const tile = document.createElement('a');
  tile.className = 'tile';
  tile.href = `/launch/${encodeURIComponent(app.applicationId)}`;

  const icon = document.createElement('div');
  icon.className = 'tile-icon';
  const override = overrides[app.applicationId] || {};

  if (override.logo) {
    const img = document.createElement('img');
    img.src = override.logo;
    img.alt = '';
    icon.appendChild(img);
    icon.style.background = '#fff';
  } else {
    icon.style.background = `hsl(${hueFor(app.applicationId)}, 52%, 48%)`;
    icon.textContent = initials(app.name);
  }

  const body = document.createElement('div');
  body.className = 'tile-body';

  const name = document.createElement('p');
  name.className = 'tile-name';
  name.textContent = app.name;
  name.title = app.name;

  const meta = document.createElement('p');
  meta.className = 'tile-meta';
  const roleCount = Array.isArray(app.roles) ? app.roles.length : 0;
  meta.textContent = override.description ||
    (roleCount > 0
      ? `${roleCount} role${roleCount === 1 ? '' : 's'}`
      : 'No extra roles');

  body.appendChild(name);
  body.appendChild(meta);
  tile.appendChild(icon);
  tile.appendChild(body);
  return tile;
}

async function loadApps() {
  show('loading');

  let res;
  try {
    res = await fetch('/api/my-apps', { cache: 'no-cache' });
  } catch (err) {
    document.getElementById('errorDetail').textContent =
      'Could not reach the launcher server.';
    return show('error');
  }

  if (res.status === 401) {
    return show('signedOut');
  }

  let data;
  try {
    data = await res.json();
  } catch (err) {
    document.getElementById('errorDetail').textContent =
      'The launcher server returned an unreadable response.';
    return show('error');
  }

  if (!res.ok) {
    document.getElementById('errorDetail').textContent =
      data.detail || data.error || `Request failed with status ${res.status}.`;
    return show('error');
  }

  const identity = document.getElementById('identity');
  document.getElementById('identityName').textContent = data.user.email;
  identity.hidden = false;

  const grid = document.getElementById('grid');
  grid.replaceChildren();

  const apps = Array.isArray(data.apps) ? data.apps : [];
  apps.forEach((app) => grid.appendChild(renderTile(app)));

  document.getElementById('gridHeading').textContent =
    apps.length === 1 ? 'Your application' : `Your applications (${apps.length})`;

  document.getElementById('empty').hidden = apps.length > 0;

  show('gridSection');
}

(async function init() {
  await loadOverrides();
  await loadApps();
})();
