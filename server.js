import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import crypto from 'node:crypto'
import pg from 'pg'

const {
  PORT = '3000',
  DATABASE_URL,
  ALCHEMY_SIGNING_KEY, // from the Alchemy webhook page in the dashboard
  BLOCKDAEMON_SECRET, // the `secret` you set when creating the Blockdaemon target (10+ chars)
  VIEW_TOKEN, // optional: protects /events and /stats (?key=...)
} = process.env

if (!DATABASE_URL) {
  console.error('DATABASE_URL is required')
  process.exit(1)
}

const pool = new pg.Pool({ connectionString: DATABASE_URL })

await pool.query(`
  CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    provider    TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified    BOOLEAN,
    event_type  TEXT,
    body        JSONB,
    raw         TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS events_provider_time ON events (provider, received_at);
`)

const safeEqual = (a, b) => {
  const x = Buffer.from(a || '')
  const y = Buffer.from(b || '')
  return x.length === y.length && crypto.timingSafeEqual(x, y)
}

async function store(provider, raw, verified, eventType, body) {
  await pool.query(
    'INSERT INTO events (provider, verified, event_type, body, raw) VALUES ($1,$2,$3,$4,$5)',
    [provider, verified, eventType, body, raw],
  )
}

const parse = (raw) => {
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

const app = new Hono()

app.get('/health', (c) => c.text('ok'))

// ---- Alchemy ---------------------------------------------------------------
// Signature: X-Alchemy-Signature = hex( HMAC_SHA256(signing_key, rawBody) )
app.post('/alchemy', async (c) => {
  const raw = await c.req.text()
  const body = parse(raw)
  let verified = null
  if (ALCHEMY_SIGNING_KEY) {
    const expected = crypto.createHmac('sha256', ALCHEMY_SIGNING_KEY).update(raw).digest('hex')
    verified = safeEqual(expected, c.req.header('x-alchemy-signature'))
  }
  await store('alchemy', raw, verified, body?.type ?? null, body)
  console.log(`[alchemy] ${raw.length}b verified=${verified}`)
  return c.text('ok') // always 200 so we log everything; check the `verified` column
})

// ---- Blockdaemon -----------------------------------------------------------
// 1) CRC check: GET ?token=... -> {"response_token": "sha256=" + base64(HMAC(secret, token))}
app.get('/blockdaemon', (c) => {
  const token = c.req.query('token')
  if (!token || !BLOCKDAEMON_SECRET) return c.text('bad request', 400)
  const sig = crypto.createHmac('sha256', BLOCKDAEMON_SECRET).update(token).digest('base64')
  return c.json({ response_token: `sha256=${sig}` })
})

// 2) Events: x-bd-webhooks-signature = "sha256=" + base64( HMAC_SHA256(secret, rawBody) )
app.post('/blockdaemon', async (c) => {
  const raw = await c.req.text()
  const body = parse(raw)
  let verified = null
  if (BLOCKDAEMON_SECRET) {
    const expected =
      'sha256=' + crypto.createHmac('sha256', BLOCKDAEMON_SECRET).update(raw).digest('base64')
    verified = safeEqual(expected, c.req.header('x-bd-webhooks-signature'))
  }
  await store('blockdaemon', raw, verified, body?.event_type ?? null, body)
  console.log(`[blockdaemon] ${body?.event_type} verified=${verified}`)
  return c.text('ok')
})

// ---- Viewing ---------------------------------------------------------------
const guard = (c) => !VIEW_TOKEN || c.req.query('key') === VIEW_TOKEN

app.get('/events', async (c) => {
  if (!guard(c)) return c.text('forbidden', 403)
  const limit = Math.min(Number(c.req.query('limit') ?? 50), 500)
  const provider = c.req.query('provider')
  const { rows } = await pool.query(
    `SELECT id, provider, received_at, verified, event_type, body
       FROM events
      WHERE ($1::text IS NULL OR provider = $1)
      ORDER BY id DESC LIMIT $2`,
    [provider ?? null, limit],
  )
  return c.json(rows)
})

app.get('/stats', async (c) => {
  if (!guard(c)) return c.text('forbidden', 403)
  const { rows } = await pool.query(
    `SELECT provider, event_type, verified, count(*)::int AS n,
            min(received_at) AS first_seen, max(received_at) AS last_seen
       FROM events GROUP BY 1,2,3 ORDER BY 1,2,3`,
  )
  return c.json(rows)
})

serve({ fetch: app.fetch, port: Number(PORT), hostname: '0.0.0.0' }, (i) =>
  console.log(`listening on :${i.port}`),
)
