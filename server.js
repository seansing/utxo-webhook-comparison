import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import crypto from 'node:crypto'
import pg from 'pg'

const {
  PORT = '3000',
  DATABASE_URL,
  ALCHEMY_SIGNING_KEY, // from the Alchemy webhook page in the dashboard
  BLOCKDAEMON_SECRET, // the `secret` you set when creating the Blockdaemon target (10+ chars)
  VIEW_TOKEN, // optional: protects /events, /stats and /compare (?key=...)
} = process.env

if (!DATABASE_URL) {
  console.error('DATABASE_URL is required')
  process.exit(1)
}

const pool = new pg.Pool({ connectionString: DATABASE_URL })

// Safe to run on every start: creates tables, adds any new columns to the old `events` table.
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
  ALTER TABLE events
    ADD COLUMN IF NOT EXISTS body_sha256        TEXT,
    ADD COLUMN IF NOT EXISTS source_ip          TEXT,
    ADD COLUMN IF NOT EXISTS headers            JSONB,
    ADD COLUMN IF NOT EXISTS parse_ok           BOOLEAN,
    ADD COLUMN IF NOT EXISTS provider_event_id  TEXT,
    ADD COLUMN IF NOT EXISTS dup_of             BIGINT,
    ADD COLUMN IF NOT EXISTS note               TEXT;
  CREATE INDEX IF NOT EXISTS events_provider_time ON events (provider, received_at);
  CREATE INDEX IF NOT EXISTS events_provider_hash ON events (provider, body_sha256);

  -- One row per (transaction, tracked address) for Alchemy, one row per transaction for Blockdaemon.
  CREATE TABLE IF NOT EXISTS tx_events (
    id           BIGSERIAL PRIMARY KEY,
    event_id     BIGINT NOT NULL REFERENCES events(id),
    provider     TEXT NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL,
    tx_id        TEXT NOT NULL,
    block_height BIGINT,
    block_hash   TEXT,
    status       TEXT,
    address      TEXT,
    addresses    TEXT[],
    direction    TEXT,
    net_value    NUMERIC,
    block_time   TIMESTAMPTZ
  );
  CREATE INDEX IF NOT EXISTS tx_events_tx ON tx_events (tx_id);
  CREATE INDEX IF NOT EXISTS tx_events_provider_tx ON tx_events (provider, tx_id);

  -- Proves when OUR receiver was up, so a gap in events can be blamed on us vs the provider.
  CREATE TABLE IF NOT EXISTS heartbeats (
    ts   TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS heartbeats_ts ON heartbeats (ts);
`)

await pool.query("INSERT INTO heartbeats (kind) VALUES ('boot')")
setInterval(
  () =>
    pool
      .query("INSERT INTO heartbeats (kind) VALUES ('beat')")
      .catch((e) => console.error('heartbeat failed', e.message)),
  30_000,
)

// ---- Helpers ---------------------------------------------------------------
const safeEqual = (a, b) => {
  const x = Buffer.from(a || '')
  const y = Buffer.from(b || '')
  return x.length === y.length && crypto.timingSafeEqual(x, y)
}

const parse = (raw) => {
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

const toNum = (v) => {
  const n = Number(v)
  return v != null && Number.isFinite(n) ? n : null
}

const toDate = (v) => {
  if (v == null) return null
  const d = typeof v === 'number' ? new Date(v < 1e12 ? v * 1000 : v) : new Date(v)
  return Number.isNaN(d.getTime()) ? null : d
}

const sourceIp = (c) =>
  (c.req.header('x-forwarded-for') || c.req.header('x-real-ip') || '').split(',')[0].trim() || null

const cleanHeaders = (c) => {
  const h = Object.fromEntries(c.req.raw.headers)
  delete h.cookie
  delete h.authorization
  return h
}

// Pull the comparable fields out of each provider's payload.
function extractAlchemy(body) {
  const acts = body?.event?.activity
  if (!Array.isArray(acts)) return []
  return acts
    .filter((a) => a?.txid)
    .map((a) => ({
      tx_id: a.txid,
      block_height: toNum(a.blockHeight),
      block_hash: a.blockHash ?? null,
      status: a.status ?? null, // confirmed | removed
      address: a.address ?? null,
      addresses: a.address ? [a.address] : [],
      direction: a.direction ?? null,
      net_value: /^-?\d+$/.test(String(a.netValue)) ? String(a.netValue) : null,
      block_time: toDate(a.blockTimestamp),
    }))
}

function extractBlockdaemon(body) {
  if (body?.event_type !== 'unified_confirmed_tx' || !body.data?.tx_id) return []
  const d = body.data
  // Blockdaemon doesn't say which address matched, so keep every address in the transfers.
  const addrs = new Set()
  for (const t of d.transfers ?? []) {
    for (const k of ['from', 'to']) if (typeof t?.[k] === 'string') addrs.add(t[k])
  }
  return [
    {
      tx_id: d.tx_id,
      block_height: toNum(d.block_number),
      block_hash: d.block_hash ?? null,
      status: d.status ?? null,
      address: null,
      addresses: [...addrs],
      direction: null,
      net_value: null,
      block_time: toDate(d.timestamp),
    },
  ]
}

// Store one delivery. Throws if the DB write of the raw event fails.
async function record(c, { provider, receivedAt, raw, body, verified, eventType, eventId, extract }) {
  const sha = crypto.createHash('sha256').update(raw).digest('hex')
  const dup = await pool.query(
    'SELECT id FROM events WHERE provider = $1 AND body_sha256 = $2 ORDER BY id LIMIT 1',
    [provider, sha],
  )

  let rows = []
  let note = body === null ? 'invalid_json' : null
  try {
    rows = body ? extract(body) : []
  } catch (e) {
    note = `extract_failed: ${e.message}`
  }

  const {
    rows: [ev],
  } = await pool.query(
    `INSERT INTO events
       (provider, received_at, verified, event_type, body, raw,
        body_sha256, source_ip, headers, parse_ok, provider_event_id, dup_of, note)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     RETURNING id`,
    [
      provider,
      receivedAt,
      verified,
      eventType,
      body,
      raw,
      sha,
      sourceIp(c),
      cleanHeaders(c),
      body !== null,
      eventId,
      dup.rows[0]?.id ?? null,
      note,
    ],
  )

  for (const r of rows) {
    try {
      await pool.query(
        `INSERT INTO tx_events
           (event_id, provider, received_at, tx_id, block_height, block_hash, status,
            address, addresses, direction, net_value, block_time)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [
          ev.id,
          provider,
          receivedAt,
          r.tx_id,
          r.block_height,
          r.block_hash,
          r.status,
          r.address,
          r.addresses,
          r.direction,
          r.net_value,
          r.block_time,
        ],
      )
    } catch (e) {
      await pool.query("UPDATE events SET note = concat_ws('; ', note, $2::text) WHERE id = $1", [
        ev.id,
        `tx_insert_failed: ${e.message}`,
      ])
    }
  }
}

// Shared handler. We ALWAYS answer 200 for anything we managed to store, so the provider never
// retries because of us (a retry would look like a provider duplicate or a late delivery).
// If the DB write itself fails we answer 500 and log the raw body, so the provider retries.
async function ingest(c, opts) {
  const receivedAt = new Date() // captured first, before any parsing or DB work
  const raw = await c.req.text()
  const body = parse(raw)
  try {
    await record(c, {
      ...opts,
      receivedAt,
      raw,
      body,
      verified: opts.check(c, raw),
      eventType: body ? opts.typeOf(body) : null,
      eventId: body ? opts.idOf(body) : null,
    })
  } catch (e) {
    console.error(`[${opts.provider}] DB write failed: ${e.message} RAW=${raw}`)
    return c.text('db error', 500)
  }
  return c.text('ok')
}

const app = new Hono()

app.get('/health', (c) => c.text('ok'))

// ---- Alchemy ---------------------------------------------------------------
// Signature: X-Alchemy-Signature = hex( HMAC_SHA256(signing_key, rawBody) )
app.post('/alchemy', (c) =>
  ingest(c, {
    provider: 'alchemy',
    extract: extractAlchemy,
    typeOf: (b) => b.type ?? null,
    idOf: (b) => b.id ?? null,
    check: (c, raw) => {
      if (!ALCHEMY_SIGNING_KEY) return null
      const expected = crypto.createHmac('sha256', ALCHEMY_SIGNING_KEY).update(raw).digest('hex')
      return safeEqual(expected, c.req.header('x-alchemy-signature'))
    },
  }),
)

// ---- Blockdaemon -----------------------------------------------------------
// 1) CRC check: GET ?token=... -> {"response_token": "sha256=" + base64(HMAC(secret, token))}
app.get('/blockdaemon', (c) => {
  const token = c.req.query('token')
  if (!token || !BLOCKDAEMON_SECRET) return c.text('bad request', 400)
  const sig = crypto.createHmac('sha256', BLOCKDAEMON_SECRET).update(token).digest('base64')
  return c.json({ response_token: `sha256=${sig}` })
})

// 2) Events: x-bd-webhooks-signature = "sha256=" + base64( HMAC_SHA256(secret, rawBody) )
app.post('/blockdaemon', (c) =>
  ingest(c, {
    provider: 'blockdaemon',
    extract: extractBlockdaemon,
    typeOf: (b) => b.event_type ?? null,
    idOf: () => null,
    check: (c, raw) => {
      if (!BLOCKDAEMON_SECRET) return null
      const expected =
        'sha256=' + crypto.createHmac('sha256', BLOCKDAEMON_SECRET).update(raw).digest('base64')
      return safeEqual(expected, c.req.header('x-bd-webhooks-signature'))
    },
  }),
)

// ---- Viewing ---------------------------------------------------------------
const guard = (c) => !VIEW_TOKEN || c.req.query('key') === VIEW_TOKEN

app.get('/events', async (c) => {
  if (!guard(c)) return c.text('forbidden', 403)
  const limit = Math.min(Number(c.req.query('limit') ?? 50), 500)
  const provider = c.req.query('provider')
  const { rows } = await pool.query(
    `SELECT id, provider, received_at, verified, event_type, dup_of, note, body
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

// Live comparison. ?grace=10 ignores transactions first seen in the last N minutes (still in flight).
app.get('/compare', async (c) => {
  if (!guard(c)) return c.text('forbidden', 403)
  const g = Number(c.req.query('grace') ?? 10)
  const grace = Number.isFinite(g) ? Math.floor(g) : 10

  const joined = `
    WITH a AS (
      SELECT tx_id, min(received_at) AS t FROM tx_events
       WHERE provider = 'alchemy' AND coalesce(status, '') <> 'removed' GROUP BY 1),
    b AS (
      SELECT tx_id, min(received_at) AS t FROM tx_events
       WHERE provider = 'blockdaemon' GROUP BY 1),
    j AS (
      SELECT coalesce(a.tx_id, b.tx_id) AS tx_id, a.t AS alchemy_first, b.t AS blockdaemon_first
        FROM a FULL JOIN b ON a.tx_id = b.tx_id
       WHERE least(a.t, b.t) < now() - make_interval(mins => $1::int))`
  const q = (sql) => pool.query(joined + sql, [grace]).then((r) => r.rows)

  const [summary, mismatches, deliveries, gaps] = await Promise.all([
    q(`SELECT count(*)::int AS txs_seen,
              count(*) FILTER (WHERE alchemy_first IS NOT NULL AND blockdaemon_first IS NOT NULL)::int AS both,
              count(*) FILTER (WHERE blockdaemon_first IS NULL)::int AS alchemy_only,
              count(*) FILTER (WHERE alchemy_first IS NULL)::int AS blockdaemon_only,
              percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM alchemy_first - blockdaemon_first)) AS median_alchemy_minus_blockdaemon_sec,
              percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM alchemy_first - blockdaemon_first)) AS p95_alchemy_minus_blockdaemon_sec
         FROM j`),
    q(`SELECT tx_id, alchemy_first, blockdaemon_first FROM j
        WHERE alchemy_first IS NULL OR blockdaemon_first IS NULL
        ORDER BY coalesce(alchemy_first, blockdaemon_first) DESC LIMIT 50`),
    pool
      .query(
        `SELECT provider, count(*)::int AS deliveries,
                count(*) FILTER (WHERE verified IS FALSE)::int AS bad_signature,
                count(*) FILTER (WHERE dup_of IS NOT NULL)::int AS exact_duplicates,
                count(*) FILTER (WHERE note IS NOT NULL)::int AS with_notes
           FROM events GROUP BY 1 ORDER BY 1`,
      )
      .then((r) => r.rows),
    pool
      .query(
        `SELECT ts AS down_from, next_ts AS back_at FROM (
           SELECT ts, lead(ts) OVER (ORDER BY ts) AS next_ts FROM heartbeats) h
          WHERE next_ts - ts > interval '90 seconds' ORDER BY ts DESC LIMIT 50`,
      )
      .then((r) => r.rows),
  ])

  return c.json({
    grace_minutes: grace,
    note: 'positive *_sec = Alchemy received later than Blockdaemon',
    summary: summary[0],
    mismatches,
    deliveries,
    receiver_gaps: gaps,
  })
})

serve({ fetch: app.fetch, port: Number(PORT), hostname: '0.0.0.0' }, (i) =>
  console.log(`listening on :${i.port}`),
)
