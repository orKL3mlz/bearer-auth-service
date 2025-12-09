
import express from 'express';
import crypto from 'crypto';
import helmet from 'helmet';
// morgan removed to disable Apache-style access logs
import fs from 'node:fs';
import path from 'node:path';
import { Console } from 'node:console';

/**
 * ============================
 * Logging setup with rotation
 * ============================
 *
 * - Supports writing "stdout" and "stderr" to file paths via ENV:
 * - APP_LOG_STDOUT_PATH: path to file for info/debug logs
 * - APP_LOG_STDERR_PATH: path to file for error logs
 * If not set, defaults to process.stdout and process.stderr.
 * 
 * - Supports logrotate by handling SIGUSR1:
 *   On SIGUSR1, we close and reopen the file streams so that the app writes
 *   to the new files created by rotation.
 */

// ENV names for log paths
const LOG_OUT_ENV = process.env.APP_LOG_STDOUT_PATH; // e.g., /var/log/auth-service/out.log
const LOG_ERR_ENV = process.env.APP_LOG_STDERR_PATH; // e.g., /var/log/auth-service/err.log

// Maintain current streams (can be process stdio or fs.WriteStream)
let outStream: NodeJS.WritableStream = process.stdout;
let errStream: NodeJS.WritableStream = process.stderr;
let outFileStream: fs.WriteStream | null = null;
let errFileStream: fs.WriteStream | null = null;

/**
 * Create/refresh log streams based on ENV.
 * If paths are defined, open append-mode streams; otherwise use stdio.
 */
function openLogStreams() {
  // Close previous file streams if any (safe no-op for stdio)
  outFileStream?.close();
  errFileStream?.close();
  outFileStream = null;
  errFileStream = null;

  if (LOG_OUT_ENV && LOG_OUT_ENV.trim().length > 0) {
    // Ensure directory exists
    fs.mkdirSync(path.dirname(LOG_OUT_ENV), { recursive: true });
    outFileStream = fs.createWriteStream(LOG_OUT_ENV, { flags: 'a' });
    outStream = outFileStream;
  } else {
    outStream = process.stdout;
  }

  if (LOG_ERR_ENV && LOG_ERR_ENV.trim().length > 0) {
    fs.mkdirSync(path.dirname(LOG_ERR_ENV), { recursive: true });
    errFileStream = fs.createWriteStream(LOG_ERR_ENV, { flags: 'a' });
    errStream = errFileStream;
  } else {
    errStream = process.stderr;
  }
}

// Initialize streams on startup
openLogStreams();

// Bind a Console to our current streams.
const logger = new Console({ stdout: outStream, stderr: errStream });

// Utility: emit JSON logs consistently
type LogLevel = 'info' | 'error';
function jsonLog(
  event: string,
  payload: Record<string, unknown>,
  level: LogLevel = 'info'
) {
  const base = {
    ts: new Date().toISOString(),
    event,
    ...payload,
  };
  const line = JSON.stringify(base);
  if (level === 'error') {
    errStream.write(line + '\n');
  } else {
    outStream.write(line + '\n');
  }
}

// Support logrotate: USR1 tells the app to reopen its log files.
process.on('SIGUSR1', () => {
  // Reopen to pick up new files after rotation
  openLogStreams();
  // Re-bind Console to new streams
  (logger as any)._stdout = outStream;
  (logger as any)._stderr = errStream;
  jsonLog('logrotate_reopen', { message: 'USR1 received — log streams reopened' });
});

/**
 * ============================
 * Token loading and validation
 * ============================
 *
 * - Tokens from ENV variables matching /^TOKEN_[A-Za-z0-9]+$/ with values as the token.
 * 
 * - We maintain buffers for timing-safe equal comparison and a map to names.
 * - On startup, we log the count of discovered tokens.
 * - When a token is successfully used, we log the token name and a masked value.
 */

// Helper to mask a token for logs: show first 3 chars then "..." if length > 3
function maskToken(token: string): string {
  if (token.length <= 3) return token;
  return `${token.slice(0, 3)}...`;
}

// Discover tokens from ENV
type TokenRecord = {
  name: string;
  value: string;
  buffer: Buffer;
};

// Collect from TOKEN_<NAME>
const tokenEnvPattern = /^TOKEN_([A-Za-z0-9]+)$/;
const tokensFromEnvVars: TokenRecord[] = Object.entries(process.env)
  .filter(([key, val]) => tokenEnvPattern.test(key) && typeof val === 'string' && val.trim().length > 0)
  .map(([key, val]) => {
    const name = key.match(tokenEnvPattern)![1];
    const tokenValue = (val || '').trim();
    return { name, value: tokenValue, buffer: Buffer.from(tokenValue, 'utf8') };
  });

// Merge, de-duplicate by exact value
const tokenMapByValue = new Map<string, TokenRecord>();
for (const t of tokensFromEnvVars) {
  if (!tokenMapByValue.has(t.value)) {
    tokenMapByValue.set(t.value, t);
  }
}
const TOKENS: TokenRecord[] = Array.from(tokenMapByValue.values());

if (TOKENS.length === 0) {
  const msg =
    'No tokens found. Please set tokens as environment variables: TOKEN_<NAME>=<value> (NAME: alphanumeric).';
  jsonLog('fatal_no_tokens', { error: msg }, 'error');
  process.exit(1);
}

// Pre-log the number of tokens found at startup
jsonLog('tokens_loaded', { count: TOKENS.length });

// Build buffers array for timing-safe comparison
const TOKEN_BUFFERS = TOKENS.map(t => t.buffer);

/**
 * ============================
 * Express application
 * ============================
 */

const app = express();

// Security & ops headers
app.disable('x-powered-by');
app.use(helmet());

// If behind reverse proxy (e.g., Traefik). You can tune this via ENV if needed.
const TRUST_PROXY = process.env.TRUST_PROXY?.trim();
if (TRUST_PROXY && TRUST_PROXY.length > 0) {
  // Allows values like "1", "true", "loopback", "127.0.0.1", etc.
  app.set('trust proxy', TRUST_PROXY === 'true' ? 1 : TRUST_PROXY);
} else {
  // Keep a safe default; you can change with TRUST_PROXY env.
  app.set('trust proxy', 1);
}

/**
 * Helper: get client IP considering reverse proxies.
 * - Prefer X-Forwarded-For (first IP)
 * - Fallback to remoteAddress
 * - Normalize IPv6-mapped IPv4 (strip ::ffff:)
 */
function normalizeIp(ip?: string | null): string | null {
  if (!ip) return null;
  // Remove IPv6-mapped IPv4 prefix
  if (ip.startsWith('::ffff:')) {
    return ip.replace('::ffff:', '');
  }
  // Remove surrounding spaces
  return ip.trim();
}

function getSourceIp(req: express.Request): string | null {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    const first = xff.split(',')[0]?.trim();
    if (first) return normalizeIp(first);
  }
  // If trust proxy is enabled, req.ip could be the client; but we still fallback to socket
  const sock = req.socket?.remoteAddress || (req.connection as any)?.remoteAddress;
  return normalizeIp(sock || null);
}

/**
 * Middleware: Require Bearer token with JSON logging
 * - Validates Authorization: Bearer <token>
 * - Compares against known tokens using crypto.timingSafeEqual
 * - On success: logs masked token and token name
 * - On failure: 401 Unauthorized
 */
function requireBearerToken(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  const sourceIp = getSourceIp(req);
  const userAgent = req.get('user-agent') || null;
  const rawAuth = req.headers['authorization'];

  // Missing Authorization header
  if (!rawAuth || typeof rawAuth !== 'string') {
    jsonLog('auth_failure', {
      reason: 'missing_authorization_header',
      source_ip: sourceIp,
      user_agent: userAgent,
      token_name: null,
      token_value_masked: null,
      path: req.originalUrl,
      method: req.method,
      status: 401,
    }, 'error');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Malformed Authorization header
  const match = rawAuth.trim().match(/^Bearer\s+(.+)$/i);
  if (!match) {
    jsonLog('auth_failure', {
      reason: 'malformed_authorization_header',
      source_ip: sourceIp,
      user_agent: userAgent,
      token_name: null,
      token_value_masked: null,
      path: req.originalUrl,
      method: req.method,
      status: 401,
    }, 'error');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Empty token
  const token = match[1].trim();
  if (token.length === 0) {
    jsonLog('auth_failure', {
      reason: 'empty_token',
      source_ip: sourceIp,
      user_agent: userAgent,
      token_name: null,
      token_value_masked: null,
      path: req.originalUrl,
      method: req.method,
      status: 401,
    }, 'error');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const receivedBuf = Buffer.from(token, 'utf8');

  // Only candidates of same length can match
  const candidates = TOKEN_BUFFERS.filter(b => b.length === receivedBuf.length);

  let ok = false;
  let matchedRecord: TokenRecord | null = null;

  for (const candidate of candidates) {
    if (crypto.timingSafeEqual(receivedBuf, candidate)) {
      ok = true;
      // Find the corresponding record (by value string)
      for (const rec of TOKENS) {
        if (
          rec.buffer.length === candidate.length &&
          crypto.timingSafeEqual(rec.buffer, candidate)
        ) {
          matchedRecord = rec;
          break;
        }
      }
      break;
    }
  }

  if (!ok || !matchedRecord) {
    jsonLog('auth_failure', {
      reason: 'invalid_token',
      source_ip: sourceIp,
      user_agent: userAgent,
      token_name: null,
      token_value_masked: maskToken(token),
      path: req.originalUrl,
      method: req.method,
      status: 401,
    }, 'error');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Success: log token usage with masking and metadata
  jsonLog('auth_success', {
    source_ip: sourceIp,
    user_agent: userAgent,
    token_name: matchedRecord.name,
    token_value_masked: maskToken(matchedRecord.value),
    path: req.originalUrl,
    method: req.method,
    status: 200,
  });

  return next();
}

/**
 * Routes
 */
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok', ts: new Date().toISOString() });
});

app.get('/auth-check', requireBearerToken, (_req, res) => {
  res.status(200).send('OK');
});

/**
 * Server startup
 */
const port = 80;
app.listen(port, () => {
  jsonLog('service_listen', { port });
});
