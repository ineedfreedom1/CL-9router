import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { TABLES, buildCreateTableSql } from '../src/lib/db/schema.js';
import { captureSnapshot, encodeSnapshot, decodeSnapshot, restoreSnapshot, initializeRemoteBackup } from '../src/lib/db/remoteBackup.js';
function adapter(file=':memory:') {
 const raw = new DatabaseSync(file);
 for(const [t,d] of Object.entries(TABLES)) raw.exec(buildCreateTableSql(t,d));
 return {raw, all:(s,p=[])=>raw.prepare(s).all(...p), run:(s,p=[])=>raw.prepare(s).run(...p), transaction(fn){raw.exec('BEGIN');try{const r=fn();raw.exec('COMMIT');return r;}catch(e){raw.exec('ROLLBACK');throw e;}}, close:()=>raw.close()};
}
function fixture(db) {
 db.run('INSERT INTO settings VALUES (1,?)',[JSON.stringify({stickyRoundRobinLimit:7})]);
 db.run('INSERT INTO combos VALUES (?,?,?,?,?,?)',['combo-id','fixture-combo',null,'["example/model"]','2026-01-01','2026-01-01']);
 db.run('INSERT INTO providerConnections (id,provider,authType,data,createdAt,updatedAt) VALUES (?,?,?,?,?,?)',['provider-id','example','apikey','{"apiKey":"TEST_ONLY_NOT_A_REAL_SECRET"}','2026-01-01','2026-01-01']);
}
function remote(snapshot,key) {
 let text=encodeSnapshot(snapshot,key), puts=0, status=0, privateRepo=true;
 const sha=()=>createHash('sha1').update(text).digest('hex');
 const fetch=async(url,opt={})=>{
  if(status)return new Response('{}',{status});
  if(!url.includes('/contents/'))return Response.json({private:privateRepo,full_name:'test/backups'});
  if(opt.method==='PUT') {const body=JSON.parse(opt.body);if(body.sha!==sha())return new Response('{}',{status:409});text=Buffer.from(body.content,'base64').toString();puts++;return Response.json({content:{sha:sha()}});}
  return Response.json({encoding:'base64',sha:sha(),content:Buffer.from(text).toString('base64')});
 };
 return {fetch, get puts(){return puts;}, set status(v){status=v;}, set privateRepo(v){privateRepo=v;}, change(){text=encodeSnapshot(snapshot,key);}, get snapshot(){return decodeSnapshot(text,key);}};
}
const key=randomBytes(32).toString('base64');
const env={REMOTE_BACKUP_KEY:key,REMOTE_BACKUP_TOKEN:'TEST_ONLY',REMOTE_BACKUP_REPO:'test/backups'};
test('SQLite retained across process-equivalent reopen, lost after file removal, restored from encrypted remote',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'9router-restore-')),file=join(dir,'data.sqlite');let db=adapter(file),b;
 try{fixture(db);const expected=captureSnapshot(db),r=remote(expected,key);db.close();db=adapter(file);assert.deepEqual(captureSnapshot(db),expected);db.close();rmSync(file);db=adapter(file);assert.equal(db.all('SELECT * FROM combos').length,0);b=await initializeRemoteBackup(db,env,r.fetch);assert.deepEqual(captureSnapshot(db),expected);assert.equal(await b.flush(),false);assert.equal(r.puts,0);db.run('UPDATE combos SET name=?',['updated']);assert.equal(await b.flush(),true);assert.equal(r.puts,1);b.stop();db.close();rmSync(file);db=adapter(file);b=await initializeRemoteBackup(db,env,r.fetch);assert.equal(db.all('SELECT name FROM combos')[0].name,'updated');}finally{b?.stop();db.close();rmSync(dir,{recursive:true,force:true});}
});
test('AES-GCM is randomized, secret not plaintext; tamper and wrong key rejected',()=>{
 const db=adapter();try{fixture(db);const s=captureSnapshot(db),e=encodeSnapshot(s,key);assert.ok(!e.includes('TEST_ONLY_NOT_A_REAL_SECRET'));assert.notEqual(e,encodeSnapshot(s,key));assert.deepEqual(decodeSnapshot(e,key),s);assert.throws(()=>decodeSnapshot(e,randomBytes(32).toString('base64')));const x=JSON.parse(e);x.tag=Buffer.alloc(16).toString('base64');assert.throws(()=>decodeSnapshot(JSON.stringify(x),key));}finally{db.close();}
});
for(const status of [401,404,500])test(`HTTP ${status} fails closed without mutations or uploads`,async()=>{
 const db=adapter();try{fixture(db);const s=captureSnapshot(db),r=remote(s,key);r.status=status;await assert.rejects(initializeRemoteBackup(db,env,r.fetch));assert.deepEqual(captureSnapshot(db),s);assert.equal(r.puts,0);}finally{db.close();}
});
test('conflicting SHA stops writer rather than overwrite',async()=>{
 const db=adapter();let b;try{fixture(db);const r=remote(captureSnapshot(db),key);b=await initializeRemoteBackup(db,env,r.fetch);r.change();db.run('UPDATE combos SET name=?',['local']);await assert.rejects(b.flush(),/409/);await assert.rejects(b.flush(),/stopped/);assert.equal(r.puts,0);}finally{b?.stop();db.close();}
});
test('public repositories and invalid schema rejected',async()=>{
 const db=adapter();try{fixture(db);const s=captureSnapshot(db),r=remote(s,key);r.privateRepo=false;await assert.rejects(initializeRemoteBackup(db,env,r.fetch),/private/);const invalid=structuredClone(s);invalid.tables.combos[0].unexpected='bad';assert.throws(()=>restoreSnapshot(db,invalid));assert.deepEqual(captureSnapshot(db),s);}finally{db.close();}
});
test('restore constraint violation rolls back every table',()=>{
 const db=adapter();try{fixture(db);const s=captureSnapshot(db),invalid=structuredClone(s);invalid.tables.combos.push({...invalid.tables.combos[0],id:'second'});invalid.tables.settings[0].data='{}';assert.throws(()=>restoreSnapshot(db,invalid));assert.deepEqual(captureSnapshot(db),s);}finally{db.close();}
});
test('temporary upload failure retries; no overlapping commits',async()=>{
 const db=adapter();let b;try{fixture(db);const r=remote(captureSnapshot(db),key);b=await initializeRemoteBackup(db,env,r.fetch);db.run('UPDATE combos SET name=?',['new']);r.status=500;await assert.rejects(b.flush());r.status=0;await Promise.all([b.flush(),b.flush()]);assert.equal(r.puts,1);}finally{b?.stop();db.close();}
});
