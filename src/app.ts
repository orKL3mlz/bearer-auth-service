import express from 'express';
import crypto from 'crypto';
import helmet from 'helmet';
import morgan from 'morgan';
// Optionnel: import rateLimit from 'express-rate-limit';

const app = express();

// Sécurité minimale des headers et logs
app.disable('x-powered-by');
app.use(helmet());
app.use(morgan('combined'));

// Si derrière un reverse proxy (nginx/traefik), garder l’IP réelle
app.set('trust proxy', 1);

// --- Chargement et validation des tokens ---
const rawTokensEnv = process.env.BEARER_TOKENS || '';
const TOKENS: string[] = rawTokensEnv
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

if (TOKENS.length === 0) {
  console.error('FATAL: No token found. Please set tokens inside environement variable BEARER_TOKENS separated by comma.');
  process.exit(1);
}

// Prépare des buffers pour comparaisons en temps constant
const TOKEN_BUFFERS = TOKENS.map(t => Buffer.from(t, 'utf8'));

// --- Middleware d’auth Bearer (multi-tokens) ---
function requireBearerToken(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  const rawAuth = req.headers['authorization'];
  if (!rawAuth || typeof rawAuth !== 'string') {
    // res.set('WWW-Authenticate', 'Bearer realm="bearer-auth-service", error="invalid_token", error_description="Missing Authorization header"');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const match = rawAuth.trim().match(/^Bearer\s+(.+)$/i);
  if (!match) {
    // res.set('WWW-Authenticate', 'Bearer realm="bearer-auth-service", error="invalid_request", error_description="Malformed Authorization header"');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = match[1].trim();
  if (token.length === 0) {
    // res.set('WWW-Authenticate', 'Bearer realm="bearer-auth-service", error="invalid_token", error_description="Empty token"');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const receivedBuf = Buffer.from(token, 'utf8');
  const candidates = TOKEN_BUFFERS.filter(b => b.length === receivedBuf.length);

  let ok = false;
  for (const candidate of candidates) {
    if (crypto.timingSafeEqual(receivedBuf, candidate)) {
      ok = true;
      break;
    }
  }

  if (!ok) {
    // res.set('WWW-Authenticate', 'Bearer realm="bearer-auth-service", error="invalid_token"');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  return next();
}

// --- Routes ---
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok', ts: new Date().toISOString() });
});

app.get('/auth-check', requireBearerToken, (_req, res) => {
  res.status(200).send('OK');
});

const port = Number(process.env.PORT) || 80;
app.listen(port, () => console.log(`Auth service listening on port ${port}`));
