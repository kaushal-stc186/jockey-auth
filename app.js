require('dotenv').config();

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const openidConfiguration = require('./openid-configuration.json');

const PORT = Number(process.env.PORT || 3000);
const ISSUER = String(
  process.env.ISSUER || 'https://jockey-auth.onrender.com',
).replace(/\/$/, '');
const CLIENT_ID = process.env.CLIENT_ID || 'jockey-mobile-auth';
const CLIENT_SECRET = process.env.CLIENT_SECRET || '';
const SHOPIFY_CUSTOMER_ACCOUNT_CLIENT_ID =
  process.env.SHOPIFY_CUSTOMER_ACCOUNT_CLIENT_ID || '';
const STATIC_OTP = String(process.env.STATIC_OTP || '');
const REDIRECT_URIS = csv(process.env.REDIRECT_URIS);
const POST_LOGOUT_REDIRECT_URIS = csv(process.env.POST_LOGOUT_REDIRECT_URIS);
const ACCESS_TTL = 3600;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_PATH = path.join(DATA_DIR, 'users.json');
const KEY_PATH = path.join(DATA_DIR, 'private.pem');

fs.mkdirSync(DATA_DIR, { recursive: true });

const privateKey = loadPrivateKey();
const publicJwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
const KID = crypto
  .createHash('sha256')
  .update(JSON.stringify(publicJwk))
  .digest('hex')
  .slice(0, 16);

const users = loadUsers();
const loginSessions = new Map();
const authCodes = new Map();
const refreshTokens = new Map();
const accessTokens = new Map();

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/.well-known/openid-configuration', (_req, res) => {
  res.json(discovery());
});

app.get('/.well-known/jwks.json', (_req, res) => {
  res.json({
    keys: [{ ...publicJwk, kid: KID, use: 'sig', alg: 'RS256' }],
  });
});

app.get('/authorize', (req, res) => {
  const error = validateAuthorize(req.query);
  if (error) return res.status(400).send(page('Sign in', `<p class="error">${esc(error)}</p>`));

  const sid = newSession({
    clientId: req.query.client_id,
    redirectUri: req.query.redirect_uri,
    scope: req.query.scope || 'openid email phone',
    state: req.query.state,
    nonce: req.query.nonce,
    codeChallenge: req.query.code_challenge,
    codeChallengeMethod: req.query.code_challenge_method,
  });

  setSid(res, sid);
  res.send(phonePage());
});

app.post('/authorize/phone', (req, res) => {
  const session = getLoginSession(req, res);
  if (!session) return;
  const phone = normalizePhone(req.body.phone);
  if (!phone) {
    return res.status(400).send(phonePage('Enter a valid mobile number with country code'));
  }

  const otp = STATIC_OTP || String(Math.floor(1000 + Math.random() * 9000));
  session.phone = phone;
  session.otp = otp;
  session.otpExp = Date.now() + 5 * 60 * 1000;
  session.attempts = 0;
  console.log(`[otp] ${phone} ${otp}`);
  res.send(otpPage(phone));
});

app.post('/authorize/verify', (req, res) => {
  const session = getLoginSession(req, res);
  if (!session) return;
  if (!session.phone || !session.otp) return res.redirect('/authorize');
  if (Date.now() > session.otpExp) {
    return res.status(400).send(otpPage(session.phone, 'OTP expired. Go back and request a new one.'));
  }

  session.attempts += 1;
  if (session.attempts > 5) {
    return res.status(429).send(otpPage(session.phone, 'Too many attempts. Request a new OTP.'));
  }
  if (String(req.body.otp || '') !== session.otp) {
    return res.status(401).send(otpPage(session.phone, 'Incorrect OTP'));
  }

  session.verified = true;
  const existing = users[session.phone];
  if (existing?.email) return completeLogin(res, session, existing);
  res.send(emailPage(session.phone));
});

app.post('/authorize/email', (req, res) => {
  const session = getLoginSession(req, res);
  if (!session) return;
  if (!session.verified || !session.phone) {
    return res.status(400).send(phonePage('Verify your mobile number first'));
  }

  const email = String(req.body.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).send(emailPage(session.phone, 'Enter a valid email'));
  }

  const taken = Object.entries(users).find(
    ([phone, user]) => user.email === email && phone !== session.phone,
  );
  if (taken) {
    return res.status(409).send(emailPage(session.phone, 'This email is already linked to another number'));
  }

  const user = {
    sub: users[session.phone]?.sub || crypto.createHash('sha256').update(session.phone).digest('hex').slice(0, 24),
    email,
    phone: session.phone,
  };
  users[session.phone] = user;
  saveUsers();
  completeLogin(res, session, user);
});

app.post('/token', (req, res) => {
  const body = req.body || {};
  if (body.client_id !== CLIENT_ID || body.client_secret !== CLIENT_SECRET) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  if (body.grant_type === 'authorization_code') {
    const record = authCodes.get(body.code);
    authCodes.delete(body.code);
    if (!record || record.exp < Date.now()) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    if (body.redirect_uri && body.redirect_uri !== record.redirectUri) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    if (record.codeChallenge) {
      const method = record.codeChallengeMethod || 'S256';
      if (method !== 'S256' || s256(body.code_verifier) !== record.codeChallenge) {
        return res.status(400).json({ error: 'invalid_grant' });
      }
    }
    return res.json(issueTokens(record));
  }

  if (body.grant_type === 'refresh_token') {
    const record = refreshTokens.get(body.refresh_token);
    if (!record || record.exp < Date.now()) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    refreshTokens.delete(body.refresh_token);
    return res.json(issueTokens(record));
  }

  return res.status(400).json({ error: 'unsupported_grant_type' });
});

app.get('/userinfo', (req, res) => {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const session = accessTokens.get(token);
  if (!session || session.exp < Date.now()) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  res.json(oidcClaims(session.user, session.nonce, session.clientId, false));
});

app.get('/logout', (req, res) => {
  const target = String(req.query.post_logout_redirect_uri || '');
  if (!POST_LOGOUT_REDIRECT_URIS.includes(target)) {
    return res.status(400).json({ error: 'invalid_post_logout_redirect_uri' });
  }
  res.redirect(302, target);
});

app.listen(PORT, () => {
  console.log(`jockey-auth listening on ${ISSUER}`);
});

function completeLogin(res, session, user) {
  const code = randomToken();
  authCodes.set(code, {
    user,
    clientId: session.clientId,
    redirectUri: session.redirectUri,
    scope: session.scope,
    nonce: session.nonce,
    codeChallenge: session.codeChallenge,
    codeChallengeMethod: session.codeChallengeMethod,
    exp: Date.now() + 60_000,
  });

  const target = new URL(session.redirectUri);
  target.searchParams.set('code', code);
  if (session.state) target.searchParams.set('state', session.state);
  loginSessions.delete(session.sid);
  res.redirect(302, target.toString());
}

function issueTokens(record) {
  const access = randomToken();
  const refresh = randomToken();
  accessTokens.set(access, {
    user: record.user,
    clientId: record.clientId,
    nonce: record.nonce,
    exp: Date.now() + ACCESS_TTL * 1000,
  });
  refreshTokens.set(refresh, { ...record, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 });

  return {
    access_token: access,
    token_type: 'Bearer',
    expires_in: ACCESS_TTL,
    refresh_token: refresh,
    id_token: signJwt(oidcClaims(record.user, record.nonce, record.clientId, true)),
    scope: record.scope,
  };
}

function oidcClaims(user, nonce, clientId, includeStandard) {
  const now = Math.floor(Date.now() / 1000);
  return {
    ...(includeStandard
      ? { iss: ISSUER, aud: clientId, iat: now, exp: now + ACCESS_TTL, nonce }
      : {}),
    sub: user.sub,
    email: user.email,
    email_verified: true,
    phone_number: user.phone,
    phone_number_verified: true,
  };
}

function validateAuthorize(params) {
  if (params.response_type !== 'code') return 'response_type must be "code"';
  if (params.client_id !== CLIENT_ID) return 'unknown client_id';
  if (!params.redirect_uri || !REDIRECT_URIS.includes(params.redirect_uri)) {
    return 'redirect_uri is not allowed';
  }
  return null;
}

function discovery() {
  const placeholder = String(openidConfiguration.issuer || '').replace(/\/$/, '');
  return Object.fromEntries(
    Object.entries(openidConfiguration).map(([key, value]) => [
      key,
      typeof value === 'string' && placeholder
        ? value.replaceAll(placeholder, ISSUER)
        : value,
    ]),
  );
}

function getLoginSession(req, res) {
  const sid = readCookies(req).jockey_auth;
  const session = sid ? loginSessions.get(sid) : null;
  if (!session) {
    res.status(400).send(page('Sign in', '<p class="error">Session expired. Start again from the store.</p>'));
    return null;
  }
  session.sid = sid;
  return session;
}

function newSession(oauth) {
  const sid = randomToken();
  loginSessions.set(sid, oauth);
  return sid;
}

function setSid(res, sid) {
  const secure = ISSUER.startsWith('https') ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `jockey_auth=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${secure}`,
  );
}

function phonePage(error) {
  return page(
    'Sign in',
    `${error ? `<p class="error">${esc(error)}</p>` : ''}
     <form method="post" action="/authorize/phone">
       <label>Mobile number</label>
       <input name="phone" type="tel" inputmode="tel" placeholder="+91 98765 43210" required>
       <button type="submit">Send OTP</button>
     </form>`,
  );
}

function otpPage(phone, error) {
  return page(
    'Verify OTP',
    `<p>OTP sent to ${esc(phone)}</p>
     ${error ? `<p class="error">${esc(error)}</p>` : ''}
     <form method="post" action="/authorize/verify">
       <label>4-digit OTP</label>
       <input name="otp" inputmode="numeric" maxlength="4" required>
       <button type="submit">Verify</button>
     </form>
     <form method="post" action="/authorize/phone">
       <input type="hidden" name="phone" value="${esc(phone)}">
       <button type="submit" class="link">Resend OTP</button>
     </form>`,
  );
}

function emailPage(phone, error) {
  return page(
    'Add email',
    `<p>No email is saved for ${esc(phone)}. Add one to continue.</p>
     ${error ? `<p class="error">${esc(error)}</p>` : ''}
     <form method="post" action="/authorize/email">
       <label>Email</label>
       <input name="email" type="email" placeholder="you@example.com" required>
       <button type="submit">Continue</button>
     </form>`,
  );
}

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
  body { font-family: ui-sans-serif, system-ui, sans-serif; background: #111; color: #f5f5f5; display: grid; place-items: center; min-height: 100vh; margin: 0; }
  main { width: min(380px, calc(100vw - 32px)); background: #1c1c1c; padding: 24px; border-radius: 12px; display: grid; gap: 12px; }
  h1 { margin: 0; font-size: 20px; }
  form { display: grid; gap: 12px; }
  input { padding: 12px; border-radius: 8px; border: 1px solid #333; background: #111; color: inherit; }
  button { padding: 12px; border: 0; border-radius: 8px; background: #e10600; color: #fff; font-weight: 600; }
  button.link { background: transparent; color: #bbb; font-weight: 500; }
  .error { color: #ff8a80; margin: 0; }
  p { margin: 0; color: #cfcfcf; }
</style>
<main>
  <h1>${esc(title)}</h1>
  ${body}
</main>
</html>`;
}

function signJwt(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: KID })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const data = `${header}.${body}`;
  const signature = crypto.createSign('RSA-SHA256').update(data).end().sign(privateKey, 'base64url');
  return `${data}.${signature}`;
}

function loadPrivateKey() {
  if (fs.existsSync(KEY_PATH)) return fs.readFileSync(KEY_PATH, 'utf8');
  const { privateKey: pem } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  fs.writeFileSync(KEY_PATH, pem);
  return pem;
}

function loadUsers() {
  if (!fs.existsSync(USERS_PATH)) return {};
  try {
    return JSON.parse(fs.readFileSync(USERS_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function saveUsers() {
  fs.writeFileSync(USERS_PATH, JSON.stringify(users, null, 2));
}

function normalizePhone(input) {
  const digits = String(input || '').replace(/\D/g, '');
  if (digits.length === 10) return `+91${digits}`;
  if (digits.length === 12 && digits.startsWith('91')) return `+${digits}`;
  if (String(input).trim().startsWith('+') && digits.length >= 10) return `+${digits}`;
  return null;
}

function csv(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function s256(verifier) {
  return crypto.createHash('sha256').update(String(verifier || '')).digest('base64url');
}

function readCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function esc(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
