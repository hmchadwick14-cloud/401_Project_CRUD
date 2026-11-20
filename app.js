require('dotenv').config();
const express = require('express');
const path = require('path');
const { randomBytes, scrypt: scryptCallback } = require('crypto');
const { timingSafeEqual, createHmac } = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(scryptCallback);

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const SESSION_SECRET = process.env.SESSION_SECRET || randomBytes(32).toString('hex');
function signSession(userId) {
  const payload = Buffer.from(JSON.stringify({ userId, expiresAt: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  const signature = createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}
function readSession(token) {
  if (!token) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = createHmac('sha256', SESSION_SECRET).update(payload).digest();
  const actual = Buffer.from(signature, 'base64url');
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return session.expiresAt > Date.now() ? session : null;
  } catch { return null; }
}
app.use((req, res, next) => {
  const cookie = req.headers.cookie?.split(';').map(part => part.trim()).find(part => part.startsWith('homebase_session='));
  req.loginSession = readSession(cookie?.slice('homebase_session='.length));
  next();
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Set these in your hosting provider's environment variables or in a local .env file.
// Keep the service-role key on the server. Never put it in browser-side JavaScript.
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://YOUR_PROJECT_ID.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'YOUR_SUPABASE_SERVICE_ROLE_KEY';
const TABLE = 'admin_users';
const port = process.env.PORT || 3000;

// Store only a salted password hash, never a plaintext password.
async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derivedKey = await scrypt(password, salt, 64);
  return `scrypt$${salt}$${derivedKey.toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
  const [algorithm, salt, keyHex] = (storedHash || '').split('$');
  if (algorithm !== 'scrypt' || !salt || !/^[a-f0-9]{128}$/i.test(keyHex || '')) return false;
  const expected = Buffer.from(keyHex, 'hex');
  const actual = await scrypt(password, salt, expected.length);
  return timingSafeEqual(actual, expected);
}


function ensureConfigured() {
  if (SUPABASE_URL.includes('YOUR_PROJECT_ID') || SUPABASE_SERVICE_ROLE_KEY.includes('YOUR_')) {
    throw new Error('Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY before using the app.');
  }
}

async function supabaseRequest(endpoint, options = {}) {
  ensureConfigured();
  const authHeaders = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    'Content-Type': 'application/json',
    ...options.headers,
  };

  // New sb_secret_* API keys are not JWTs: send them as apikey only.
  // Legacy service_role keys are JWTs and also belong in Authorization.
  if (!SUPABASE_SERVICE_ROLE_KEY.startsWith('sb_')) {
    authHeaders.Authorization = `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`;
  }

  const response = await fetch(`${SUPABASE_URL.replace(/\/$/, '')}/rest/v1/${endpoint}`, {
    ...options,
    headers: authHeaders,
  });

  const responseText = await response.text();
  let data = null;
  if (responseText) {
    try { data = JSON.parse(responseText); }
    catch { data = responseText; }
  }
  if (!response.ok) {
    const detail = data?.message || data?.hint || response.statusText;
    throw new Error(`Supabase request failed (${response.status}): ${detail}`);
  }
  return data;
}

function showError(res, message, status = 500) {
  console.error(message);
  res.status(status).render('error', { message });
}

// Send anyone who hasn't logged in back to the home page
function requireLogin(req, res, next) {
  if (req.loginSession?.userId) return next();
  res.redirect('/login');
}

app.get('/', requireLogin, async (req, res) => {
  try {
    const users = await supabaseRequest(`${TABLE}?select=user_id,username,email&order=username.asc`);
    res.render('index', { users });
  } catch (error) {
    showError(res, error.message);
  }
});

app.get('/login', (req, res) => res.render('login', { error: null }));

app.post('/login', async (req, res) => {
  try {
    const username = req.body.username?.trim();
    const email = req.body.email?.trim().toLowerCase();
    if (!username || !email) return res.status(400).render('login', { error: 'Enter your username and email.' });
    const query = new URLSearchParams({ select: 'user_id', username: `eq.${username}`, email: `eq.${email}`, limit: '1' });
    const rows = await supabaseRequest(`${TABLE}?${query}`);
    if (!rows.length) {
      return res.status(401).render('login', { error: 'That username and email combination was not recognized.' });
    }
    const token = signSession(rows[0].user_id);
    res.setHeader('Set-Cookie', `homebase_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
    res.redirect('/');
  } catch (error) {
    showError(res, error.message);
  }
});

app.get('/addUser', requireLogin, (req, res) => res.render('addUser'));

app.post('/addUser', requireLogin, async (req, res) => {
  try {
    const username = req.body.username?.trim() || null;
    const email = req.body.email?.trim() || null;
    const password = req.body.password || '';
    if (!username || !email || !password) return showError(res, 'Username, email, and password are required.', 400);
    if (password.length < 12) return showError(res, 'Password must contain at least 12 characters.', 400);

    // user_id is generated by the database.
    await supabaseRequest(TABLE, {
      method: 'POST',
      headers: { Prefer: 'return=minimal' },
      body: JSON.stringify({ username, email, password: await hashPassword(password) }),
    });
    res.redirect('/');
  } catch (error) {
    showError(res, error.message);
  }
});

app.get('/index/:user_id/edit', async (req, res) => {
  try {
    const query = new URLSearchParams({
      select: 'user_id,username,email',
      user_id: `eq.${req.params.user_id}`,
      limit: '1',
    });
    const rows = await supabaseRequest(`${TABLE}?${query}`);
    if (!rows.length) return showError(res, 'User not found.', 404);
    res.render('editUser', { item: rows[0] });
  } catch (error) {
    showError(res, error.message);
  }
});

app.post('/editUser/:user_id/edit', async (req, res) => {
  try {
    const username = req.body.username?.trim() || null;
    const email = req.body.email?.trim() || null;
    if (!username || !email) return showError(res, 'Username and email are required.', 400);
    const updates = { username, email };
    // Password is optional when editing: a blank field preserves the existing hash.
    if (req.body.password) {
      if (req.body.password.length < 12) return showError(res, 'New password must contain at least 12 characters.', 400);
      updates.password = await hashPassword(req.body.password);
    }

    const query = new URLSearchParams({ user_id: `eq.${req.params.user_id}` });
    const rows = await supabaseRequest(`${TABLE}?${query}`, {
      method: 'PATCH',
      headers: { Prefer: 'return=representation' },
      body: JSON.stringify(updates),
    });
    if (!rows.length) return showError(res, 'User not found.', 404);
    res.redirect('/');
  } catch (error) {
    showError(res, error.message);
  }
});

app.post('/index/:user_id/delete', async (req, res) => {
  try {
    const query = new URLSearchParams({ user_id: `eq.${req.params.user_id}` });
    await supabaseRequest(`${TABLE}?${query}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } });
    res.redirect('/');
  } catch (error) {
    showError(res, error.message);
  }
});


// Display all appliances
app.get('/appliances', requireLogin, async (req, res) => {
  try {
    const appliances = await supabaseRequest(
      'appliances?select=appliance_id,name,type,brand,model,category,purchase_date&order=appliance_id.desc'
    );

    res.render('appliances', { appliances });
  } catch (error) {
    showError(res, error.message);
  }
});


// Show the Add Appliance form
app.get('/addAppliance', requireLogin, (req, res) => {
  res.render('addAppliance');
});

// Create a new appliance
app.post('/addAppliance', async (req, res) => {
  try {
    const name = req.body.name?.trim();
    const type = req.body.type?.trim();
    const category = req.body.category?.trim();

    if (!name || !type || !category) {
      return showError(res, 'Name, type, and category are required.', 400);
    }

    const appliance = {
      name,
      type,
      category,
      brand: req.body.brand?.trim() || null,
      model: req.body.model?.trim() || null,
      purchase_date: req.body.purchase_date || null,
      last_maintenance_date: req.body.last_maintenance_date || null
    };

    await supabaseRequest('appliances', {
      method: 'POST',
      headers: { Prefer: 'return=minimal' },
      body: JSON.stringify(appliance)
    });

    res.redirect('/appliances');
  } catch (error) {
    showError(res, error.message);
  }
});


// Display the Edit Appliance form
app.get('/appliances/:appliance_id/edit', async (req, res) => {
  try {
    const query = new URLSearchParams({
      select: '*',
      appliance_id: `eq.${req.params.appliance_id}`,
      limit: '1'
    });

    const rows = await supabaseRequest(`appliances?${query}`);

    if (!rows.length) {
      return showError(res, 'Appliance not found.', 404);
    }

    res.render('editAppliance', { item: rows[0] });
  } catch (error) {
    showError(res, error.message);
  }
});

// Update an existing appliance
app.post('/appliances/:appliance_id/edit', async (req, res) => {
  try {
    const name = req.body.name?.trim();
    const type = req.body.type?.trim();
    const category = req.body.category?.trim();

    if (!name || !type || !category) {
      return showError(res, 'Name, type, and category are required.', 400);
    }

    const appliance = {
      name,
      type,
      category,
      brand: req.body.brand?.trim() || null,
      model: req.body.model?.trim() || null,
      purchase_date: req.body.purchase_date || null,
      last_maintenance_date: req.body.last_maintenance_date || null
    };

    const query = new URLSearchParams({
      appliance_id: `eq.${req.params.appliance_id}`
    });

    const rows = await supabaseRequest(`appliances?${query}`, {
      method: 'PATCH',
      headers: { Prefer: 'return=representation' },
      body: JSON.stringify(appliance)
    });

    if (!rows.length) {
      return showError(res, 'Appliance not found.', 404);
    }

    res.redirect('/appliances');
  } catch (error) {
    showError(res, error.message);
  }
});


 // Delete an appliance
app.post('/appliances/:appliance_id/delete', async (req, res) => {
  try {
    const query = new URLSearchParams({
      appliance_id: `eq.${req.params.appliance_id}`
    });

    const rows = await supabaseRequest(`appliances?${query}`, {
      method: 'DELETE',
      headers: { Prefer: 'return=representation' }
    });

    if (!rows.length) {
      return showError(res, 'Appliance not found.', 404);
    }

    res.redirect('/appliances');
  } catch (error) {
    showError(res, error.message);
  }
});

app.listen(port, () => console.log(`Server is listening on port ${port}`));
