require('dotenv').config();

const express = require('express');
const openidConfiguration = require('./openid-configuration.json');

const PORT = Number(process.env.PORT || 3000);
const ISSUER = String(
  process.env.ISSUER || 'https://jockey-auth.onrender.com',
).replace(/\/$/, '');

const app = express();

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/.well-known/openid-configuration', (_req, res) => {
  const placeholder = String(openidConfiguration.issuer || '').replace(/\/$/, '');
  const config = Object.fromEntries(
    Object.entries(openidConfiguration).map(([key, value]) => [
      key,
      typeof value === 'string' && placeholder
        ? value.replaceAll(placeholder, ISSUER)
        : value,
    ]),
  );

  res.json(config);
});

app.listen(PORT, () => {
  console.log(`jockey-auth listening on ${ISSUER}`);
});
