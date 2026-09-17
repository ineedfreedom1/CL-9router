// Optional encrypted configuration snapshots for ephemeral single-instance hosts.
// Never enable without first seeding config.enc.json. No telemetry is exported.
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { TABLES, SCHEMA_VERSION } from './schema.js';

export const CONFIG_TABLES = ['settings', 'providerConnections', 'providerNodes', 'proxyPools', 'apiKeys', 'combos', 'kv'];
const LIMIT = 8 * 1024 * 1024;
const ENVELOPE_LIMIT = 900000; // GitHub Contents inline response limit is 1MB.
const AAD = Buffer.from('9router-config-snapshot-v1');
function fail(message) { throw new Error(`[RemoteBackup] ${message}`); }
function keyBytes(key) {
  if (typeof key !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(key)) fail('Invalid encryption key');
  const b = Buffer.from(key, 'base64');
  if (b.length !== 32) fail('Invalid encryption key');
  return b;
}
export function validateSnapshot(s) {
  if (!s || s.version !== 1 || s.schemaVersion !== SCHEMA_VERSION || !s.tables || Array.isArray(s.tables)) fail('Unsupported snapshot format/schema');
  if (Object.keys(s.tables).sort().join() !== [...CONFIG_TABLES].sort().join()) fail('Invalid snapshot tables');
  for (const table of CONFIG_TABLES) {
    const rows = s.tables[table];
    const columns = Object.keys(TABLES[table].columns).sort();
    if (!Array.isArray(rows) || rows.length > 50000) fail('Invalid snapshot rows');
    for (const row of rows) {
      if (!row || Array.isArray(row) || Object.keys(row).sort().join() !== columns.join()) fail('Invalid snapshot columns');
      for (const v of Object.values(row)) if (!(v === null || typeof v === 'string' || (typeof v === 'number' && Number.isFinite(v)))) fail('Invalid snapshot cell');
    }
  }
  if (Buffer.byteLength(JSON.stringify(s)) > LIMIT) fail('Snapshot too large');
  return s;
}
export function captureSnapshot(db) {
  return db.transaction(() => {
    const tables = {};
    for (const t of CONFIG_TABLES) {
      const cols = Object.keys(TABLES[t].columns);
      // Stable ordering means unchanged data does not create commits.
      tables[t] = db.all(`SELECT ${cols.join(',')} FROM ${t} ORDER BY ${cols.join(',')}`).map(row => ({ ...row }));
    }
    return validateSnapshot({ version: 1, schemaVersion: SCHEMA_VERSION, tables });
  });
}
export function restoreSnapshot(db, snapshot) {
  validateSnapshot(snapshot);
  db.transaction(() => {
    for (const t of CONFIG_TABLES) {
      db.run(`DELETE FROM ${t}`);
      const cols = Object.keys(TABLES[t].columns);
      for (const row of snapshot.tables[t]) db.run(`INSERT INTO ${t} (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`, cols.map(c => row[c]));
    }
  });
}
export function encodeSnapshot(snapshot, key) {
  const plaintext = Buffer.from(JSON.stringify(validateSnapshot(snapshot)));
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', keyBytes(key), iv);
  cipher.setAAD(AAD);
  const data = Buffer.concat([cipher.update(gzipSync(plaintext)), cipher.final()]);
  const result = JSON.stringify({ version: 1, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') });
  if (Buffer.byteLength(result) > ENVELOPE_LIMIT) fail('Encrypted snapshot exceeds storage limit');
  return result;
}
export function decodeSnapshot(text, key) {
  try {
    if (typeof text !== 'string' || Buffer.byteLength(text) > ENVELOPE_LIMIT) fail('Invalid envelope size');
    const e = JSON.parse(text);
    if (e.version !== 1 || typeof e.data !== 'string') fail('Invalid envelope');
    const iv = Buffer.from(e.iv, 'base64'), tag = Buffer.from(e.tag, 'base64');
    if (iv.length !== 12 || tag.length !== 16) fail('Invalid envelope');
    const cipher = createDecipheriv('aes-256-gcm', keyBytes(key), iv);
    cipher.setAAD(AAD); cipher.setAuthTag(tag);
    const data = Buffer.concat([cipher.update(Buffer.from(e.data, 'base64')), cipher.final()]);
    return validateSnapshot(JSON.parse(gunzipSync(data, { maxOutputLength: LIMIT }).toString('utf8')));
  } catch { fail('Snapshot validation/decryption failed'); }
}
function digest(s) { return createHash('sha256').update(JSON.stringify(s)).digest('hex'); }

export async function initializeRemoteBackup(db, env = process.env, fetchFn = globalThis.fetch) {
  const repo = env.REMOTE_BACKUP_REPO;
  if (!repo && !env.REMOTE_BACKUP_TOKEN && !env.REMOTE_BACKUP_KEY) return null;
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo || '') || !env.REMOTE_BACKUP_TOKEN) fail('Incomplete configuration');
  const key = env.REMOTE_BACKUP_KEY;
  keyBytes(key);
  const root = `https://api.github.com/repos/${repo}`;
  const endpoint = `${root}/contents/config.enc.json`;
  const headers = { Authorization: `Bearer ${env.REMOTE_BACKUP_TOKEN}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': '9router-config-backup' };
  async function request(url, options = {}) {
    let r;
    try { r = await fetchFn(url, { ...options, headers: { ...headers, 'Content-Type': 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(20000) }); }
    catch { fail('Network request failed'); }
    if (!r.ok) { const error = new Error(`[RemoteBackup] GitHub HTTP ${r.status}`); error.status = r.status; throw error; }
    const text = await r.text();
    if (Buffer.byteLength(text) > 2 * LIMIT) fail('Remote response too large');
    try { return JSON.parse(text); } catch { fail('Invalid remote response'); }
  }
  async function checkPrivate() {
    const metadata = await request(root);
    if (metadata.private !== true || metadata.full_name.toLowerCase() !== repo.toLowerCase()) fail('Backup repository must be private');
  }
  await checkPrivate();
  const file = await request(`${endpoint}?ref=main`);
  if (file.encoding !== 'base64' || typeof file.content !== 'string' || !/^[a-f0-9]{40}$/.test(file.sha || '')) fail('Invalid remote file');
  const snapshot = decodeSnapshot(Buffer.from(file.content, 'base64').toString('utf8'), key);
  restoreSnapshot(db, snapshot);
  let sha = file.sha, lastHash = digest(captureSnapshot(db)), pending = null, stopped = false, timer;
  console.log('[RemoteBackup] Configuration restored successfully');
  async function upload() {
    if (stopped) fail('Backup writer stopped; restart required');
    const next = captureSnapshot(db), hash = digest(next);
    if (hash === lastHash) return false;
    const content = encodeSnapshot(next, key);
    await checkPrivate();
    try {
      const updated = await request(endpoint, { method: 'PUT', body: JSON.stringify({ branch: 'main', message: 'Update encrypted configuration snapshot', sha, content: Buffer.from(content).toString('base64') }) });
      if (!/^[a-f0-9]{40}$/.test(updated.content?.sha || '')) fail('Invalid commit response');
      sha = updated.content.sha; lastHash = hash;
      console.log('[RemoteBackup] Encrypted configuration saved');
      return true;
    } catch (e) {
      // Never fetch a newer SHA and overwrite another instance's changes.
      if (e.status === 409 || e.status === 422) { stopped = true; clearInterval(timer); }
      throw e;
    }
  }
  function flush() {
    if (!pending) pending = upload().finally(() => { pending = null; });
    return pending;
  }
  timer = setInterval(() => { flush().catch(e => console.error(e.message.startsWith('[RemoteBackup]') ? e.message : '[RemoteBackup] Snapshot failed')); }, 60000);
  timer.unref?.();
  return { flush, stop() { stopped = true; clearInterval(timer); } };
}
