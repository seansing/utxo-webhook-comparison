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

// Safe to run on every start: creates tables, adds any new columns to existing tables.
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

  -- Alchemy: one row per (transaction, tracked address).
  -- Blockdaemon: one row per transaction INPUT or OUTPUT that touches a tracked address.
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
  ALTER TABLE tx_events
    ADD COLUMN IF NOT EXISTS leg        TEXT,     -- Blockdaemon only: 'input' | 'output'
    ADD COLUMN IF NOT EXISTS value_sats NUMERIC,  -- Blockdaemon only: amount of that input/output
    ADD COLUMN IF NOT EXISTS n          INTEGER,  -- output index (or, for inputs, the spent output's index)
    ADD COLUMN IF NOT EXISTS coinbase   BOOLEAN;  -- Alchemy only: is this a miner reward (coinbase) transaction
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

// Blockdaemon sends BTC as decimals (0.0923855); Alchemy sends satoshis as strings.
const btcToSats = (v) => {
  const n = Number(v)
  return v != null && Number.isFinite(n) ? String(Math.round(n * 1e8)) : null
}

// The addresses we track (same five on both providers). Blockdaemon's whole-transaction events
// list every address in the tx, so we need this list to keep only ours.
const TRACKED_NAMES = {
  bc1quhruqrghgcca950rvhtrg7cpd7u8k6svpzgzmrjy8xyukacl5lkq0r8l2d: 'OKX',
  bc1qtm7ye0wm085hhv88japwkalmwkt3amec5z9c7a3unv05tfg6y2pstr3xfz: 'Foundry',
  '37jKPSmbEGwgfacCr2nayn1wTaqMAbA94Z': 'AntPool',
  '1K6KoYC69NnafWJ7YgtrpwJxBLiijWqwa6': 'F2Pool',
  '1Ay8vMC7R1UbyCCZRVULMV7iQpHSAbguJP': 'Upbit',
}
const TRACKED = new Set(Object.keys(TRACKED_NAMES))

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
      leg: null,
      value_sats: null,
      n: null,
      coinbase: typeof a.coinbase === 'boolean' ? a.coinbase : null,
    }))
}

// Blockdaemon (UNIFIED_V1, Bitcoin) sends one event per input and per output that touches a
// tracked address: unified_confirmed_input / unified_confirmed_output. The transaction they belong
// to is `data.enclosing_tx_id`. (An older `unified_confirmed_tx` shape is also handled.)
function extractBlockdaemon(body) {
  const d = body?.data
  if (!d) return []
  const base = {
    block_height: toNum(d.block_number),
    block_hash: d.block_hash ?? null,
    status: 'confirmed',
    block_time: toDate(d.block_timestamp),
    direction: null,
    net_value: null,
  }

  if (body.event_type === 'unified_confirmed_output' && d.enclosing_tx_id) {
    const a = d.scriptPubKey?.address ?? null
    return [
      {
        ...base,
        tx_id: d.enclosing_tx_id,
        address: a,
        addresses: a ? [a] : [],
        leg: 'output',
        value_sats: btcToSats(d.value),
        n: toNum(d.n),
      },
    ]
  }

  if (body.event_type === 'unified_confirmed_input' && d.enclosing_tx_id) {
    const a = d.prevout?.scriptPubKey?.address ?? null
    return [
      {
        ...base,
        tx_id: d.enclosing_tx_id,
        address: a,
        addresses: a ? [a] : [],
        leg: 'input',
        value_sats: btcToSats(d.prevout?.value),
        n: toNum(d.vout),
      },
    ]
  }

  // Whole-transaction event. For Bitcoin, `transfers` lists every input (event_name "vin") and
  // output ("vout"); the address is in `from` (also for outputs) and `value` is in satoshis.
  // We keep only the addresses we track, as one row per input/output, the same shape as above.
  // unified_pending_tx is the same event sent earlier, while the transaction is still in the
  // mempool (no block yet). We store it with status 'pending'; the comparison ignores it and a
  // separate "pending" section of /compare reports on it.
  if ((body.event_type === 'unified_confirmed_tx' || body.event_type === 'unified_pending_tx') && d.tx_id) {
    const pending = body.event_type === 'unified_pending_tx'
    const out = []
    let vin = 0
    let vout = 0
    for (const t of d.transfers ?? []) {
      const isIn = t?.event_name === 'vin'
      const isOut = t?.event_name === 'vout'
      if (!isIn && !isOut) continue
      const n = isIn ? vin++ : vout++
      const a = typeof t.from === 'string' ? t.from : null
      if (!a || !TRACKED.has(a)) continue
      out.push({
        ...base,
        tx_id: d.tx_id,
        status: pending ? 'pending' : 'confirmed',
        block_time: pending ? null : toDate(d.timestamp),
        address: a,
        addresses: [a],
        leg: isIn ? 'input' : 'output',
        value_sats: /^\d+$/.test(String(t.value)) ? String(t.value) : null,
        n,
      })
    }
    return out
  }

  return []
}

async function insertTx(eventId, provider, receivedAt, r) {
  await pool.query(
    `INSERT INTO tx_events
       (event_id, provider, received_at, tx_id, block_height, block_hash, status,
        address, addresses, direction, net_value, block_time, leg, value_sats, n, coinbase)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
    [
      eventId,
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
      r.leg,
      r.value_sats,
      r.n,
      r.coinbase ?? null,
    ],
  )
}

// Earlier deliveries that arrived before we understood Blockdaemon's input/output events were
// stored raw but never extracted. Extract them now (runs on every start, does nothing once done).
async function backfillBlockdaemon() {
  // Older versions saved whole-transaction events as one row with no address; redo those properly.
  await pool.query(
    `DELETE FROM tx_events WHERE provider = 'blockdaemon' AND leg IS NULL AND address IS NULL`,
  )
  const { rows } = await pool.query(
    `SELECT e.id, e.received_at, e.body FROM events e
      WHERE e.provider = 'blockdaemon' AND e.body IS NOT NULL
        AND e.event_type IN ('unified_confirmed_input', 'unified_confirmed_output',
                             'unified_confirmed_tx', 'unified_pending_tx')
        AND NOT EXISTS (SELECT 1 FROM tx_events t WHERE t.event_id = e.id)
      ORDER BY e.id`,
  )
  for (const r of rows) {
    for (const x of extractBlockdaemon(r.body)) await insertTx(r.id, 'blockdaemon', r.received_at, x)
  }
  if (rows.length) console.log(`backfilled ${rows.length} blockdaemon events into tx_events`)
}
await backfillBlockdaemon()

// Alchemy rows saved before we recorded the `coinbase` flag: fill it in from the stored payloads.
await pool.query(`
  UPDATE tx_events t
     SET coinbase = (a ->> 'coinbase')::boolean
    FROM events e, jsonb_array_elements(e.body -> 'event' -> 'activity') a
   WHERE t.provider = 'alchemy' AND t.coinbase IS NULL
     AND e.id = t.event_id AND jsonb_typeof(e.body -> 'event' -> 'activity') = 'array'
     AND a ->> 'txid' = t.tx_id AND a ->> 'address' = t.address
     AND a ->> 'coinbase' IN ('true', 'false')`)

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
      await insertTx(ev.id, provider, receivedAt, r)
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
    idOf: (b) => b.id ?? null, // Blockdaemon's per-event uuid
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

// ---- Comparison ------------------------------------------------------------
// Everything is matched on (transaction, tracked address).
//   ?grace=10   ignore pairs first seen in the last N minutes (still in flight)
//   ?since=ISO  ignore pairs first seen before this time
// Alchemy gives netValue directly; for Blockdaemon we compute it as (sum of outputs to the address)
// minus (sum of inputs from the address), so the two can be checked against each other.
// delay_sec = (when Alchemy's alert arrived) minus (when Blockdaemon's CONFIRMED alert arrived).
//   positive = Alchemy later, negative = Alchemy first.
// had_pending = Blockdaemon sent a pending (mempool) alert for it before its confirmed alert.
const JOINED = `
  WITH a AS (
    SELECT tx_id, address, min(received_at) AS t, (array_agg(net_value ORDER BY id))[1] AS net,
           (array_agg(event_id ORDER BY id))[1] AS ev, coalesce(bool_or(coinbase), false) AS cb
      FROM tx_events
     WHERE provider = 'alchemy' AND coalesce(status, '') <> 'removed' AND address IS NOT NULL
     GROUP BY 1, 2),
  ae AS (
    SELECT event_id, count(*)::int AS n FROM tx_events WHERE provider = 'alchemy' GROUP BY 1),
  bd AS (
    SELECT DISTINCT ON (tx_id, address, leg, n) tx_id, address, leg, n, value_sats, received_at
      FROM tx_events
     WHERE provider = 'blockdaemon' AND address IS NOT NULL AND coalesce(status, '') <> 'pending'
     ORDER BY tx_id, address, leg, n, received_at),
  b AS (
    SELECT tx_id, address, min(received_at) AS t,
           sum(CASE leg WHEN 'output' THEN value_sats WHEN 'input' THEN -value_sats ELSE 0 END) AS net
      FROM bd GROUP BY 1, 2),
  p AS (
    SELECT tx_id, address, min(received_at) AS t FROM tx_events
     WHERE provider = 'blockdaemon' AND status = 'pending' AND address IS NOT NULL GROUP BY 1, 2),
  j AS (
    SELECT coalesce(a.tx_id, b.tx_id) AS tx_id, coalesce(a.address, b.address) AS address,
           a.t AS alchemy_first, b.t AS blockdaemon_first,
           a.net AS alchemy_net, b.net AS blockdaemon_net,
           p.t AS pending_first, ae.n AS alchemy_entries, a.cb AS coinbase,
           extract(epoch FROM a.t - b.t) AS delay_sec,
           (p.t IS NOT NULL AND b.t IS NOT NULL AND p.t < b.t) AS had_pending,
           extract(epoch FROM b.t - p.t) AS pending_lead_sec
      FROM a FULL JOIN b ON a.tx_id = b.tx_id AND a.address = b.address
      LEFT JOIN p ON p.tx_id = coalesce(a.tx_id, b.tx_id) AND p.address = coalesce(a.address, b.address)
      LEFT JOIN ae ON ae.event_id = a.ev
     WHERE least(a.t, b.t) < now() - make_interval(mins => $1::int)
       AND ($2::timestamptz IS NULL OR least(a.t, b.t) >= $2))`

function windowParams(c) {
  const g = Number(c.req.query('grace') ?? 10)
  const grace = Number.isFinite(g) ? Math.floor(g) : 10
  const s = c.req.query('since') ? new Date(c.req.query('since')) : null
  const since = s && !Number.isNaN(s.getTime()) ? s : null
  return { grace, since }
}

// The tracked addresses as a SQL VALUES list (constants from this file, not user input).
const TRACKED_VALUES = Object.entries(TRACKED_NAMES)
  .map(([addr, name]) => `('${addr.replace(/'/g, "''")}', '${name.replace(/'/g, "''")}')`)
  .join(', ')

app.get('/compare', async (c) => {
  if (!guard(c)) return c.text('forbidden', 403)
  const { grace, since } = windowParams(c)
  const q = (sql) => pool.query(JOINED + sql, [grace, since]).then((r) => r.rows)

  // Blockdaemon pending (mempool) notifications over ALL pending alerts (also ones not yet confirmed).
  const pendingSql = `
    WITH p AS (
      SELECT tx_id, address, min(received_at) AS t FROM tx_events
       WHERE provider = 'blockdaemon' AND status = 'pending' AND address IS NOT NULL GROUP BY 1, 2),
    cf AS (
      SELECT tx_id, address, min(received_at) AS t FROM tx_events
       WHERE provider = 'blockdaemon' AND status = 'confirmed' AND address IS NOT NULL GROUP BY 1, 2),
    pj AS (
      SELECT coalesce(p.tx_id, cf.tx_id) AS tx_id, coalesce(p.address, cf.address) AS address,
             p.t AS pending_at, cf.t AS confirmed_at
        FROM p FULL JOIN cf ON p.tx_id = cf.tx_id AND p.address = cf.address
       WHERE least(p.t, cf.t) < now() - make_interval(mins => $1::int)
         AND ($2::timestamptz IS NULL OR least(p.t, cf.t) >= $2))
    SELECT count(*) FILTER (WHERE pending_at IS NOT NULL)::int AS pending_pairs,
           count(*) FILTER (WHERE pending_at IS NOT NULL AND confirmed_at IS NOT NULL)::int AS pending_then_confirmed,
           count(*) FILTER (WHERE pending_at IS NOT NULL AND confirmed_at IS NULL
                              AND pending_at < now() - interval '60 minutes')::int AS pending_not_confirmed_after_60min,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM confirmed_at - pending_at)) AS median_pending_lead_sec,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM confirmed_at - pending_at)) AS p95_pending_lead_sec,
           max(extract(epoch FROM confirmed_at - pending_at))::float8 AS max_pending_lead_sec
      FROM pj`

  const [summary, mismatches, labels, byAddress, byBatch, byCoinbase, deliveries, gaps, pendingRows] =
    await Promise.all([
      q(`SELECT count(*)::int AS pairs_seen,
                count(*) FILTER (WHERE alchemy_first IS NOT NULL AND blockdaemon_first IS NOT NULL)::int AS both,
                count(*) FILTER (WHERE blockdaemon_first IS NULL)::int AS alchemy_only,
                count(*) FILTER (WHERE alchemy_first IS NULL)::int AS blockdaemon_only,
                count(*) FILTER (WHERE alchemy_first IS NOT NULL AND blockdaemon_first IS NOT NULL
                                   AND alchemy_net IS DISTINCT FROM blockdaemon_net)::int AS net_differs,
                percentile_cont(0.5) WITHIN GROUP (ORDER BY delay_sec) AS median_alchemy_minus_blockdaemon_sec,
                percentile_cont(0.95) WITHIN GROUP (ORDER BY delay_sec) AS p95_alchemy_minus_blockdaemon_sec,
                min(delay_sec)::float8 AS min_alchemy_minus_blockdaemon_sec,
                max(delay_sec)::float8 AS max_alchemy_minus_blockdaemon_sec,
                count(*) FILTER (WHERE delay_sec < 0)::int AS alchemy_first_count,
                round(100.0 * count(*) FILTER (WHERE delay_sec < 0) / nullif(count(delay_sec), 0), 1)::float8 AS alchemy_first_pct
           FROM j`),
      q(`SELECT tx_id, address, alchemy_first, blockdaemon_first, alchemy_net, blockdaemon_net,
                CASE WHEN blockdaemon_first IS NULL THEN 'alchemy_only'
                     WHEN alchemy_first IS NULL THEN 'blockdaemon_only'
                     ELSE 'net_differs' END AS kind
           FROM j
          WHERE blockdaemon_first IS NULL OR alchemy_first IS NULL
             OR alchemy_net IS DISTINCT FROM blockdaemon_net
          ORDER BY coalesce(alchemy_first, blockdaemon_first) DESC LIMIT 50`),
      // Of the transactions Blockdaemon confirmed: how many had a pending alert first, and why not?
      q(`SELECT count(*) FILTER (WHERE blockdaemon_first IS NOT NULL)::int AS blockdaemon_confirmed,
                count(*) FILTER (WHERE had_pending)::int AS had_pending,
                count(*) FILTER (WHERE blockdaemon_first IS NOT NULL AND NOT had_pending)::int AS no_pending,
                count(*) FILTER (WHERE blockdaemon_first IS NOT NULL AND NOT had_pending AND coinbase)::int AS no_pending_and_coinbase,
                count(*) FILTER (WHERE blockdaemon_first IS NOT NULL AND NOT had_pending
                                   AND NOT coalesce(coinbase, false))::int AS no_pending_and_not_coinbase,
                percentile_cont(0.5) WITHIN GROUP (ORDER BY pending_lead_sec) FILTER (WHERE had_pending) AS median_pending_lead_sec
           FROM j`),
      pool
        .query(
          JOINED +
            `, tr(address, name) AS (VALUES ${TRACKED_VALUES})
             SELECT tr.name, tr.address, count(x.tx_id)::int AS pairs,
                    count(*) FILTER (WHERE x.alchemy_first IS NOT NULL AND x.blockdaemon_first IS NOT NULL)::int AS both,
                    count(*) FILTER (WHERE x.tx_id IS NOT NULL AND x.blockdaemon_first IS NULL)::int AS alchemy_only,
                    count(*) FILTER (WHERE x.tx_id IS NOT NULL AND x.alchemy_first IS NULL)::int AS blockdaemon_only,
                    count(*) FILTER (WHERE x.had_pending)::int AS had_pending,
                    percentile_cont(0.5) WITHIN GROUP (ORDER BY x.delay_sec) AS median_delay_sec,
                    max(coalesce(x.alchemy_first, x.blockdaemon_first)) AS last_seen
               FROM tr LEFT JOIN j x ON x.address = tr.address
              GROUP BY tr.name, tr.address ORDER BY pairs DESC`,
          [grace, since],
        )
        .then((r) => r.rows),
      // Does a bigger Alchemy delivery (more tracked activity in the same block) arrive later?
      q(`SELECT CASE WHEN alchemy_entries = 1 THEN '1' WHEN alchemy_entries <= 3 THEN '2-3'
                     WHEN alchemy_entries <= 9 THEN '4-9' ELSE '10+' END AS alchemy_delivery_entries,
                count(*)::int AS pairs, percentile_cont(0.5) WITHIN GROUP (ORDER BY delay_sec) AS median_delay_sec
           FROM j WHERE delay_sec IS NOT NULL AND alchemy_entries IS NOT NULL
          GROUP BY 1 ORDER BY min(alchemy_entries)`),
      q(`SELECT coalesce(coinbase, false) AS coinbase, count(*)::int AS pairs,
                percentile_cont(0.5) WITHIN GROUP (ORDER BY delay_sec) AS median_delay_sec
           FROM j WHERE delay_sec IS NOT NULL GROUP BY 1 ORDER BY 1`),
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
      pool.query(pendingSql, [grace, since]).then((r) => r.rows),
    ])

  return c.json({
    grace_minutes: grace,
    since: since?.toISOString() ?? null,
    note: 'delay = Alchemy arrival minus Blockdaemon CONFIRMED arrival (seconds): positive = Alchemy later, negative = Alchemy first. nets are in satoshis',
    summary: summary[0],
    mismatches,
    pending_labels: labels[0],
    blockdaemon_pending: pendingRows[0],
    by_address: byAddress,
    delay_by_alchemy_delivery_size: byBatch,
    delay_by_coinbase: byCoinbase,
    deliveries,
    receiver_gaps: gaps,
  })
})

// One row per (transaction, address) so you can sort and filter it yourself.
//   ?limit=50 (max 1000)  ?only=mismatch | no_pending | alchemy_first   plus ?since= and ?grace=
app.get('/pairs', async (c) => {
  if (!guard(c)) return c.text('forbidden', 403)
  const { grace, since } = windowParams(c)
  const limit = Math.min(Math.max(Number(c.req.query('limit') ?? 50) || 50, 1), 1000)
  const only = c.req.query('only')
  const where =
    only === 'mismatch'
      ? 'WHERE blockdaemon_first IS NULL OR alchemy_first IS NULL OR alchemy_net IS DISTINCT FROM blockdaemon_net'
      : only === 'no_pending'
        ? 'WHERE blockdaemon_first IS NOT NULL AND NOT had_pending'
        : only === 'alchemy_first'
          ? 'WHERE delay_sec < 0'
          : ''
  const { rows } = await pool.query(
    JOINED +
      ` SELECT tx_id, address, had_pending, round(delay_sec::numeric, 2)::float8 AS delay_sec,
               round(pending_lead_sec::numeric, 1)::float8 AS pending_lead_sec, coinbase, alchemy_entries,
               alchemy_first, blockdaemon_first, pending_first, alchemy_net, blockdaemon_net
          FROM j ${where}
         ORDER BY coalesce(alchemy_first, blockdaemon_first) DESC LIMIT ${limit}`,
    [grace, since],
  )
  return c.json(rows)
})

serve({ fetch: app.fetch, port: Number(PORT), hostname: '0.0.0.0' }, (i) =>
  console.log(`listening on :${i.port}`),
)
