const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const {OfficialLicense,sanitizeLicense}=require('../desktop/lib/official-license.cjs');
const Service=require('../desktop/lib/service.cjs');
const uuid='fae18768-5eb1-47c1-83b5-293e45994fdc';
const config={remarks:'Official fixture',outbounds:[{protocol:'vless',settings:{vnext:[{address:'fixture.example',port:443,users:[{id:uuid,encryption:'none'}]}]},streamSettings:{network:'tcp',security:'tls',tlsSettings:{serverName:'fixture.example'}}}]};
test('official status strips key/HWID and refuses stale active flags without extending expiry',()=>{
  const expires_at=Math.floor(Date.now()/1000)+3600;
  const safe=sanitizeLicense({active:true,expires_at,plan_name:'Fixture',key:'never-return',hwid:'private'});
  assert.equal(safe.active,true);assert.equal(safe.expiresAt,expires_at);assert.equal(safe.daysLeft,1);assert.equal(safe.key,undefined);assert.equal(safe.hwid,undefined);
  assert.equal(sanitizeLicense({active:true,expires_at:1}).active,false);assert.equal(sanitizeLicense({active:true}).active,false);
});
test('Windows activation cannot be borrowed on Ubuntu',async()=>{
  const bridge=new OfficialLicense({platform:'linux',spawnProcess:()=>{throw new Error('Must not execute Windows checker');}});
  assert.deepEqual(await bridge.status(),{available:false,active:false,reason:'windows_only'});
});
test('official imports keep source identity and cannot connect or test after expiry',async()=>{
  const root=path.resolve(__dirname,'../.tools/tmp');await fs.mkdir(root,{recursive:true});const dir=await fs.mkdtemp(path.join(root,'official-license-'));
  let active=true;
  const license=()=>({available:true,active,planName:'Fixture',daysLeft:active?30:0,expiresAt:active?Math.floor(Date.now()/1000)+2592000:1});
  const checker={status:async()=>license(),servers:async()=>({license:license(),configs:[config],cachedAt:1})};
  const svc=new Service({dataDir:dir,officialLicense:checker,spawnProcess:()=>{throw new Error('Expired activation must not launch the core');}});
  try{
    await svc.init();const first=await svc.importOfficialServers();assert.equal(first.count,1);assert.equal(svc.subscriptions[0].source,'official-windows');assert.equal(svc.getState().subscriptions[0].source,'official-windows');
    const expiry=svc.officialLicenseStatus.expiresAt;await svc.refreshSubscription(first.id);assert.equal(svc.subscriptions.length,1);assert.equal(svc.subscriptions[0].id,first.id);assert.equal(svc.officialLicenseStatus.expiresAt,expiry);
    active=false;await assert.rejects(svc.importOfficialServers(),/لایسنس/);await assert.rejects(svc.start(),/لایسنس/);await assert.rejects(svc.testServers(),/لایسنس/);
    svc.status='connected';let terminated=false;svc.terminate=async()=>{terminated=true;};await svc.enforceOfficialLicense();assert.equal(terminated,true);assert.equal(svc.status,'disconnected');
    const restored=new Service({dataDir:dir,officialLicense:checker});await restored.init();assert.equal(restored.isOfficialServer(),true);
  }finally{await svc.shutdown();assert.ok(path.resolve(dir).startsWith(root+path.sep));await fs.rm(dir,{recursive:true,force:true});}
});
test('personal configurations keep working independently of the installed Windows license',async()=>{
  const root=path.resolve(__dirname,'../.tools/tmp');await fs.mkdir(root,{recursive:true});const dir=await fs.mkdtemp(path.join(root,'personal-license-'));
  const svc=new Service({dataDir:dir,officialLicense:{status:async()=>{throw new Error('Do not check license for personal node');}}});
  try{await svc.init();await svc.importText(`vless://${uuid}@personal.example:443?security=tls#Personal`);await svc.requireOfficialLicense();svc.status='connected';await svc.enforceOfficialLicense();assert.equal(svc.status,'connected');}
  finally{await svc.shutdown();assert.ok(path.resolve(dir).startsWith(root+path.sep));await fs.rm(dir,{recursive:true,force:true});}
});
