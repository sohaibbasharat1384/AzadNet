const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const Service=require('../desktop/lib/service.cjs');
const {sharingInfo,sharingText,privateIPv4}=require('../desktop/lib/sharing.cjs');
const {DEFAULT_SETTINGS,generateConfig}=require('../desktop/lib/config.cjs');
test('sharing publishes only deduplicated private IPv4 NICs, including hotspot and CGNAT',()=>{
  const info=sharingInfo({...DEFAULT_SETTINGS,allowLan:true,mixedPort:2080,lanPassword:'fixture-pass'},'connected',{
    WiFi:[{address:'192.168.1.20',internal:false},{address:'2001:db8::1',internal:false}],
    Hotspot:[{address:'192.168.137.1',internal:false}],VPN:[{address:'198.18.0.1',internal:false}],
    Other:[{address:'192.168.1.20',internal:false},{address:'8.8.8.8',internal:false},{address:'100.64.1.2',internal:false}],Loopback:[{address:'127.0.0.1',internal:true}]
  });
  assert.equal(info.active,true);assert.deepEqual(info.addresses.map(x=>x.address).sort(),['100.64.1.2','192.168.1.20','192.168.137.1']);
  assert.equal(privateIPv4('172.31.1.1'),true);assert.equal(privateIPv4('172.32.1.1'),false);
  assert.match(sharingText(info),/192\.168\.137\.1:2080/);assert.match(sharingText(info),/fixture-pass/);
  assert.throws(()=>sharingText({...info,enabled:false}),/روشن/);assert.throws(()=>sharingText({...info,addresses:[]}),/آدرس/);
  assert.doesNotMatch(sharingText({...info,requiresPassword:false}),/fixture-pass/);
});
test('sharing authentication preserves localhost exemption and never exposes the controller',()=>{
  const cfg=generateConfig({...DEFAULT_SETTINGS,allowLan:true,lanPassword:'fixture-pass'},[],'controller-secret');
  assert.equal(cfg['bind-address'],'0.0.0.0');assert.deepEqual(cfg.authentication,['whitedns:fixture-pass']);
  assert.deepEqual(cfg['skip-auth-prefixes'],['127.0.0.0/8']);assert.equal(cfg['external-controller'],'127.0.0.1:9097');
  const open=generateConfig({...DEFAULT_SETTINGS,allowLan:true,lanPasswordRequired:false},[],'secret');assert.equal(open.authentication,undefined);
});
test('live sharing changes restart the owned session and a failed restart restores previous settings',async()=>{
  const root=path.resolve(__dirname,'../.tools/tmp');await fs.mkdir(root,{recursive:true});const dir=await fs.mkdtemp(path.join(root,'sharing-'));
  const svc=new Service({dataDir:dir});await svc.init();const calls=[];
  svc.status='connected';svc.stop=async()=>{calls.push('stop');svc.status='disconnected';};svc.start=async()=>{calls.push('start');svc.status='connected';};
  try{
    await assert.rejects(svc.updateSharing({allowLan:true,lanPassword:'short'}),/۸/);assert.deepEqual(calls,[]);
    await svc.updateSharing({allowLan:true});assert.deepEqual(calls,['stop','start']);assert.equal(svc.getSharing().active,true);
    const previousPassword=svc.settings.lanPassword;await svc.updateSharing({}, {regeneratePassword:true});assert.notEqual(svc.settings.lanPassword,previousPassword);
    let attempts=0;svc.start=async()=>{if(++attempts===1)throw new Error('Fixture restart failed');svc.status='connected';};
    await assert.rejects(svc.updateSharing({allowLan:false}),/Fixture restart failed/);assert.equal(svc.settings.allowLan,true);assert.equal(svc.status,'connected');assert.equal(svc.sharingUpdating,false);
    await assert.rejects(svc.updateSharing({controllerPort:9999}),/نامعتبر/);
    svc.testing=true;await assert.rejects(svc.updateSharing({allowLan:false}),/عملیات/);
  }finally{svc.status='disconnected';await fs.rm(dir,{recursive:true,force:true});}
});
