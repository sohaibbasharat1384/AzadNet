const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const {OfflineTransfer}=require('../desktop/lib/offline-transfer.cjs');
const Service=require('../desktop/lib/service.cjs');
const uuid='fae18768-5eb1-47c1-83b5-293e45994fdc';
const proxy={name:'Offline fixture',type:'vless',server:'fixture.example',port:443,uuid,tls:true};
async function fixture(fn){const root=path.resolve(__dirname,'../.tools/tmp');await fs.mkdir(root,{recursive:true});const dir=await fs.mkdtemp(path.join(root,'offline-transfer-'));try{await fn(dir);}finally{assert.ok(path.resolve(dir).startsWith(root+path.sep));await fs.rm(dir,{recursive:true,force:true});}}
async function bundle(dir){let time=Date.now();const now=()=>time;const windows=new OfflineTransfer({dataDir:path.join(dir,'windows'),now}),ubuntu=new OfflineTransfer({dataDir:path.join(dir,'ubuntu'),now});const request=await ubuntu.request(),expiresAt=Math.floor(time/1000)+30*86400;const exported=await windows.export(request,{license:{active:true,expiresAt,planName:'Fixture30'},proxies:[proxy]});return {windows,ubuntu,request,exported,expiresAt,advance:n=>{time+=n;}};}
test('encrypted installation-bound transfer keeps original expiry, excludes clear credentials and persists trust',()=>fixture(async dir=>{
  const f=await bundle(dir);assert.ok(!f.exported.text.includes(uuid));assert.ok(!f.exported.text.includes('fixture.example'));
  assert.equal(f.exported.summary.expiresAt,f.expiresAt);const preview=await f.ubuntu.preview(f.exported.text);assert.equal(preview.count,1);
  await assert.rejects(f.ubuntu.accept(f.exported.text,'wrong-fingerprint'),/تأیید/);assert.equal((await f.ubuntu.status()).active,false);
  await f.ubuntu.accept(f.exported.text,preview.issuerFingerprint);let status=await f.ubuntu.status();assert.equal(status.active,true);assert.equal(status.expiresAt,f.expiresAt);
  f.advance(100);status=await f.ubuntu.status();assert.equal(status.active,true);
  const restarted=new OfflineTransfer({dataDir:path.join(dir,'ubuntu')});assert.equal((await restarted.status()).active,true);assert.equal(await restarted.request(),f.request);
}));
test('a package cannot be moved to a different installation or altered in transit',()=>fixture(async dir=>{
  const f=await bundle(dir),other=new OfflineTransfer({dataDir:path.join(dir,'other')});await other.request();
  await assert.rejects(other.preview(f.exported.text),/نصب دیگری/);
  for(const property of ['ciphertext','tag','signature']){const changed=JSON.parse(f.exported.text);changed[property]=(changed[property][0]==='A'?'B':'A')+changed[property].slice(1);await assert.rejects(f.ubuntu.preview(JSON.stringify(changed)),/امضای/);}
}));
test('expiry and backward clock changes disable the offline receipt without resetting the license period',()=>fixture(async dir=>{
  const f=await bundle(dir);await f.ubuntu.accept(f.exported.text,f.exported.summary.issuerFingerprint);f.advance(31*86400000);
  assert.equal((await f.ubuntu.status()).active,false);await assert.rejects(f.ubuntu.preview(f.exported.text),/اعتبار/);
  const g=await bundle(path.join(dir,'second'));await g.ubuntu.accept(g.exported.text,g.exported.summary.issuerFingerprint);g.advance(4*3600000);assert.equal((await g.ubuntu.status()).active,true);g.advance(-2*3600000);assert.equal((await g.ubuntu.status()).active,false);
}));
test('editing the stored receipt or clock state is detected',()=>fixture(async dir=>{
  const f=await bundle(dir);await f.ubuntu.accept(f.exported.text,f.exported.summary.issuerFingerprint);
  const clock=path.join(dir,'ubuntu/offline-transfer/clock.json');await fs.writeFile(clock,JSON.stringify({at:Date.now(),mac:'fake'}));assert.equal((await f.ubuntu.status()).active,false);
  await f.ubuntu.accept(f.exported.text,f.exported.summary.issuerFingerprint);const file=path.join(dir,'ubuntu/offline-transfer/accepted.json'),record=JSON.parse(await fs.readFile(file));record.trustedFingerprint='changed';await fs.writeFile(file,JSON.stringify(record));assert.equal((await f.ubuntu.status()).active,false);
}));
test('export refuses inactive or expired vendor status and malformed requests',()=>fixture(async dir=>{
  const f=await bundle(dir);await assert.rejects(f.windows.export(f.request,{license:{active:false},proxies:[proxy]}),/لایسنس.*فعال/);
  await assert.rejects(f.windows.export(f.request,{license:{active:true,expiresAt:1},proxies:[proxy]}),/اعتبار/);
  await assert.rejects(f.windows.export('{}',{license:{active:true,expiresAt:f.expiresAt},proxies:[proxy]}),/درخواست/);
  await assert.rejects(f.windows.export(f.request,{license:{active:true,expiresAt:Math.floor(Date.now()/1000)+400*86400},proxies:[proxy]}),/اعتبار/);
}));
test('Ubuntu service works from its accepted receipt with zero Windows checker calls and stops after expiry',()=>fixture(async dir=>{
  const f=await bundle(dir);let windowsCalls=0;const svc=new Service({dataDir:path.join(dir,'ubuntu'),officialLicense:{status:async()=>{windowsCalls++;throw new Error('Windows unavailable');}}});await svc.init();svc.offlineTransfer=f.ubuntu;
  const imported=await svc.importOffline(f.exported.text,f.exported.summary.issuerFingerprint);assert.equal(imported.count,1);assert.equal(svc.subscriptions[0].source,'offline-transfer');
  await svc.requireOfficialLicense();assert.equal(windowsCalls,0);assert.equal((await svc.checkOfflineLicense()).expiresAt,f.expiresAt);
  const loaded=new Service({dataDir:path.join(dir,'ubuntu')});await loaded.init();assert.equal(loaded.serverSource(),'offline-transfer');
  svc.status='connected';let terminated=false;svc.terminate=async()=>{terminated=true;};f.advance(31*86400000);await svc.enforceOfficialLicense();assert.equal(terminated,true);assert.equal(svc.status,'disconnected');assert.equal(windowsCalls,0);
  await assert.rejects(svc.requireOfficialLicense(),/آفلاین/);await assert.rejects(svc.refreshSubscription(imported.id),/بسته/);await svc.shutdown();
}));
test('Windows export checks current vendor validity and uses its unchanged expiry rather than a new activation period',()=>fixture(async dir=>{
  const expiry=Math.floor(Date.now()/1000)+7*86400;let active=true,calls=0;
  const svc=new Service({dataDir:path.join(dir,'windows'),officialLicense:{servers:async()=>{calls++;return {license:{active,expiresAt:expiry,planName:'Existing'},configs:[{remarks:'Fixture',outbounds:[{protocol:'trojan',settings:{servers:[{address:'fixture.example',port:443,password:'fixture-pass'}]},streamSettings:{network:'tcp',security:'tls'}}]}]};}}});
  await svc.init();const recipient=new OfflineTransfer({dataDir:path.join(dir,'ubuntu')});const request=await recipient.request();
  const exported=await svc.exportOffline(request);assert.equal(exported.summary.expiresAt,expiry);assert.equal(exported.summary.count,1);
  active=false;await assert.rejects(svc.exportOffline(request),/لایسنس فعال/);assert.equal(calls,2);await svc.shutdown();
}));
