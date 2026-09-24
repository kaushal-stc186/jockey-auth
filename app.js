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
const SHOPIFY_SHOP = String(process.env.SHOPIFY_SHOP || '')
  .replace(/^https?:\/\//, '')
  .replace(/\/$/, '');
const SHOPIFY_ADMIN_ACCESS_TOKEN = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN || '';
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY || '';
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET || '';
const STATIC_OTP = String(process.env.STATIC_OTP || '');
const REDIRECT_URIS = csv(process.env.REDIRECT_URIS);
const POST_LOGOUT_REDIRECT_URIS = csv(process.env.POST_LOGOUT_REDIRECT_URIS);
const ACCESS_TTL = 3600;
const INDIAN_MOBILE_RE = /^[6-9]\d{9}$/;
const EMAIL_RE =
  /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
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
    return res.status(400).send(phonePage('Enter a valid 10-digit Indian mobile number'));
  }

  const otp = STATIC_OTP || String(Math.floor(1000 + Math.random() * 9000));
  session.phone = phone;
  session.otp = otp;
  session.otpExp = Date.now() + 5 * 60 * 1000;
  session.attempts = 0;
  console.log(`[otp] ${phone} ${otp}`);
  res.send(otpPage(phone));
});

app.post('/authorize/verify', async (req, res) => {
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
  const shopifyCustomer = await lookupShopifyCustomer(session.phone);
  const profile = mergedProfile(users[session.phone], shopifyCustomer);
  session.profile = profile;
  if (hasProfile(profile)) {
    return completeLogin(res, session, saveUser(session.phone, profile));
  }
  res.send(profilePage(session.phone, '', profile));
});

app.post('/authorize/email', (req, res) => {
  const session = getLoginSession(req, res);
  if (!session) return;
  if (!session.verified || !session.phone) {
    return res.status(400).send(phonePage('Verify your mobile number first'));
  }

  const known = session.profile || {};
  const askNames = !known.firstName || !known.lastName;
  const askEmail = !known.email;
  const firstName = askNames ? normalizeName(req.body.first_name) : known.firstName;
  const lastName = askNames ? normalizeName(req.body.last_name) : known.lastName;
  const email = askEmail ? String(req.body.email || '').trim().toLowerCase() : known.email;
  const draft = { firstName, lastName, email, askNames, askEmail };
  if (askNames && (!firstName || !lastName)) {
    return res.status(400).send(profilePage(session.phone, 'Enter your first and last name', draft));
  }
  if (askEmail && !EMAIL_RE.test(email)) {
    return res.status(400).send(profilePage(session.phone, 'Enter a valid email', draft));
  }

  if (askEmail) {
    const taken = Object.entries(users).find(
      ([phone, user]) => user.email === email && phone !== session.phone,
    );
    if (taken) {
      return res.status(409).send(profilePage(session.phone, 'This email is already linked to another number', draft));
    }
  }

  completeLogin(res, session, saveUser(session.phone, draft));
});

app.post('/token', (req, res) => {
  const body = req.body || {};
  const client = clientCredentials(req);
  if (client.id !== CLIENT_ID || client.secret !== CLIENT_SECRET) {
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
    ...(user.firstName ? { given_name: user.firstName } : {}),
    ...(user.lastName ? { family_name: user.lastName } : {}),
    ...(user.firstName || user.lastName
      ? { name: [user.firstName, user.lastName].filter(Boolean).join(' ') }
      : {}),
  };
}

function clientCredentials(req) {
  const header = String(req.headers.authorization || '');
  const basic = header.match(/^Basic\s+(.+)$/i);
  if (basic) {
    const decoded = Buffer.from(basic[1], 'base64').toString('utf8');
    const sep = decoded.indexOf(':');
    if (sep !== -1) {
      return {
        id: safeDecode(decoded.slice(0, sep)),
        secret: safeDecode(decoded.slice(sep + 1)),
      };
    }
  }

  const body = req.body || {};
  return { id: body.client_id, secret: body.client_secret };
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
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
     <form id="phone-form" method="post" action="/authorize/phone">
       <label for="phone">Mobile number</label>
       <div class="phone">
         <span>IN (+91)</span>
         <input id="phone" name="phone" type="tel" inputmode="numeric" autocomplete="tel" placeholder="Enter Phone No." required>
       </div>
       <button type="submit">Send OTP</button>
     </form>
     <script>
       const form = document.getElementById('phone-form');
       const input = document.getElementById('phone');
       const indianMobile = /^[6-9]\\d{9}$/;
       let previous = '';
       let lastAutoSent = '';

       function normalizeIndianMobile(text) {
         let digits = String(text || '').replace(/[^0-9]/g, '');
         if (digits.length === 12 && digits.startsWith('91')) digits = digits.slice(2);
         else if (digits.length === 11 && digits.startsWith('0')) digits = digits.slice(1);
         else if (digits.length > 10) digits = digits.slice(-10);
         return digits;
       }

       input.addEventListener('input', () => {
         const raw = input.value;
         const previousLength = previous.length;
         const inputDigits = raw.replace(/[^0-9]/g, '');
         const appendingPastLimit = previousLength === 10 && inputDigits.length > 10 && inputDigits.startsWith(previous);
         const updated = appendingPastLimit ? previous : normalizeIndianMobile(raw);
         input.value = updated;
         previous = updated;
         if (!indianMobile.test(updated)) {
           lastAutoSent = '';
           return;
         }
         const arrivedInOneShot = updated.length - previousLength > 1 || /[^\\d]/.test(raw);
         if (arrivedInOneShot && lastAutoSent !== updated) {
           lastAutoSent = updated;
           form.requestSubmit();
         }
       });

       form.addEventListener('submit', (event) => {
         if (!indianMobile.test(input.value)) {
           event.preventDefault();
         }
       });
     </script>`,
  );
}

function otpPage(phone, error) {
  const national = nationalNumber(phone);
  return page(
    'Verify OTP',
    `<p>OTP sent to +91 ${esc(national)}</p>
     ${error ? `<p class="error">${esc(error)}</p>` : ''}
     <form id="otp-form" method="post" action="/authorize/verify">
       <label for="otp">4-digit OTP</label>
       <input id="otp" name="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="4" required>
       <button type="submit">Verify</button>
     </form>
     <form method="post" action="/authorize/phone">
       <input type="hidden" name="phone" value="${esc(national)}">
       <button type="submit" class="link">Resend OTP</button>
     </form>
     <script>
       const otp = document.getElementById('otp');
       otp.addEventListener('input', () => {
         otp.value = otp.value.replace(/\\D/g, '').slice(0, 4);
         if (/^\\d{4}$/.test(otp.value)) otp.form.requestSubmit();
       });
     </script>`,
  );
}

function profilePage(phone, error, values) {
  const profile = values || {};
  const askNames = profile.askNames !== undefined ? profile.askNames : !profile.firstName || !profile.lastName;
  const askEmail = profile.askEmail !== undefined ? profile.askEmail : !profile.email;
  const title = askNames && askEmail ? 'Your details' : askNames ? 'Your name' : 'Your email';
  const intro = askNames && askEmail
    ? 'Add your name and email'
    : askNames
      ? 'Add your first and last name'
      : 'Add your email';
  return page(
    title,
    `<p>${intro} for +91 ${esc(nationalNumber(phone))}.</p>
     ${error ? `<p class="error">${esc(error)}</p>` : ''}
     <form method="post" action="/authorize/email">
       ${askNames ? `<label for="first_name">First name</label>
       <input id="first_name" name="first_name" autocomplete="given-name" autocapitalize="words" value="${esc(profile.firstName)}" required>
       <label for="last_name">Last name</label>
       <input id="last_name" name="last_name" autocomplete="family-name" autocapitalize="words" value="${esc(profile.lastName)}" required>` : ''}
       ${askEmail ? `<label for="email">Email</label>
       <input id="email" name="email" type="email" autocomplete="email" value="${esc(profile.email)}" required>` : ''}
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
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100dvh;
    display: grid;
    place-items: center;
    padding: max(16px, env(safe-area-inset-top)) max(16px, env(safe-area-inset-right)) max(16px, env(safe-area-inset-bottom)) max(16px, env(safe-area-inset-left));
    background: #f6f6f6;
    color: #221f20;
    font-family: ui-sans-serif, system-ui, sans-serif;
  }
  main {
    width: min(420px, 100%);
    display: grid;
    align-content: start;
    gap: 16px;
    padding: 28px 20px;
    background: #fff;
    border: 1px solid #ececec;
    border-radius: 16px;
  }
  h1 { margin: 0; font-size: 1.375rem; line-height: 1.3; }
  p { margin: 0; color: #5c5859; line-height: 1.45; }
  form { display: grid; align-content: start; gap: 8px; }
  label { font-size: 0.875rem; font-weight: 600; }
  input {
    width: 100%;
    min-height: 48px;
    padding: 12px 14px;
    border: 1px solid #d9d9d9;
    border-radius: 10px;
    background: #fff;
    color: #221f20;
    font-size: 16px;
  }
  input:focus { outline: 2px solid #221f20; outline-offset: 1px; }
  .phone {
    display: flex;
    align-items: center;
    gap: 10px;
    min-height: 48px;
    padding: 0 14px;
    border: 1px solid #d9d9d9;
    border-radius: 10px;
    background: #fff;
  }
  .phone:focus-within { outline: 2px solid #221f20; outline-offset: 1px; }
  .phone span { font-weight: 600; white-space: nowrap; }
  .phone input { flex: 1; min-width: 0; min-height: 46px; padding: 12px 0; border: 0; }
  .phone input:focus { outline: none; }
  input[name="otp"] {
    font-size: 1.5rem;
    font-weight: 600;
    letter-spacing: 0.4em;
    text-align: center;
  }
  button {
    min-height: 48px;
    margin-top: 8px;
    padding: 12px 16px;
    border: 0;
    border-radius: 10px;
    background: #221f20;
    color: #fff;
    font-size: 16px;
    font-weight: 600;
  }
  button.link {
    margin-top: 0;
    background: transparent;
    color: #221f20;
    font-weight: 500;
    text-decoration: underline;
  }
  .error { color: #c62828; }
  @media (max-width: 480px) {
    body { place-items: stretch; align-items: start; }
    main {
      width: 100%;
      min-height: calc(100dvh - 32px - env(safe-area-inset-top) - env(safe-area-inset-bottom));
      border: 0;
      border-radius: 0;
    }
  }
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

function normalizeIndianMobile(text) {
  let digits = String(text || '').replace(/[^0-9]/g, '');
  if (digits.length === 12 && digits.startsWith('91')) {
    digits = digits.slice(2);
  } else if (digits.length === 11 && digits.startsWith('0')) {
    digits = digits.slice(1);
  } else if (digits.length > 10) {
    digits = digits.slice(-10);
  }
  return digits;
}

function normalizePhone(input) {
  const digits = normalizeIndianMobile(input);
  if (!INDIAN_MOBILE_RE.test(digits)) return null;
  return `+91${digits}`;
}

function nationalNumber(phone) {
  return normalizeIndianMobile(phone);
}

function normalizeName(value) {
  return String(value || '')
    .replace(/[^a-zA-Z\s\-']/g, '')
    .trim()
    .replace(/\s+/g, ' ');
}

function hasProfile(user) {
  return Boolean(user?.email && user?.firstName && user?.lastName);
}

function mergedProfile(local, shopify) {
  return {
    firstName: local?.firstName || shopify?.firstName || '',
    lastName: local?.lastName || shopify?.lastName || '',
    email: local?.email || shopify?.email || '',
  };
}

function saveUser(phone, profile) {
  const user = {
    sub: users[phone]?.sub || crypto.createHash('sha256').update(phone).digest('hex').slice(0, 24),
    email: profile.email,
    firstName: profile.firstName,
    lastName: profile.lastName,
    phone,
  };
  users[phone] = user;
  saveUsers();
  return user;
}

async function lookupShopifyCustomer(phone) {
  if (!SHOPIFY_SHOP || !SHOPIFY_ADMIN_ACCESS_TOKEN) return null;
  try {
    const response = await fetch(`https://${SHOPIFY_SHOP}/admin/api/2026-07/graphql.json`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': SHOPIFY_ADMIN_ACCESS_TOKEN,
      },
      body: JSON.stringify({
        query: `query($identifier: CustomerIdentifierInput!) {
          customer: customerByIdentifier(identifier: $identifier) {
            firstName
            lastName
            email
            defaultEmailAddress { emailAddress }
          }
        }`,
        variables: { identifier: { phoneNumber: phone } },
      }),
    });
    const json = await response.json();
    const customer = json?.data?.customer;
    if (!response.ok || json?.errors) {
      console.log(`[shopify] lookup ${response.status}`);
      return null;
    }
    if (!customer) return null;
    return {
      firstName: normalizeName(customer.firstName),
      lastName: normalizeName(customer.lastName),
      email: String(customer.email || customer.defaultEmailAddress?.emailAddress || '').trim().toLowerCase(),
    };
  } catch (error) {
    console.log(`[shopify] lookup failed ${error.message}`);
    return null;
  }
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
