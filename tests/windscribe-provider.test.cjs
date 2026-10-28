'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {WindscribeAccount,WindscribeError}=require('../desktop/lib/windscribe-account.cjs');
const {WindscribeProvider,parseCatalog,parsePorts,adaptOpenVPNTemplate}=require('../desktop/lib/windscribe-provider.cjs');
const {createDevice,validateDevice,hashedAddress,wireguardProfile}=require('../desktop/lib/windscribe-wireguard.cjs');
const Service=require('../desktop/lib/service.cjs');
const peer=Buffer.alloc(32,3).toString('base64'),psk=Buffer.alloc(32,4).toString('base64');
const session={session_auth_hash:'fixture-session',user_id:'fixture-user-id',username:'fixture-user',status:1,is_premium:0,traffic_used:0,traffic_max:10000};
const locations={locations:[{id:1,name:'Fixture Country',country_code:'NL',datacenters:[
  {id:10,city:'Amsterdam',nick:'Allowed',status:1,premium:0,wg_pubkey:peer,ovpn_x509:'ams-10.windscribe.test'},
  {id:11,city:'Rotterdam',nick:'Locked',status:1,premium:1,wg_pubkey:peer,ovpn_x509:'rtm-11.windscribe.test'},
  {id:12,city:'Offline',nick:'Offline',status:0,premium:0,wg_pubkey:peer,ovpn_x509:'offline.windscribe.test'},
]}]};
const servers={servers:[{id:1,dc_id:10,host:'nl-001.windscribe.test',ip:'203.0.113.1',ip2:'203.0.113.2',ip3:'203.0.113.3',weight:10,net_load:30},{id:2,dc_id:10,host:'nl-002.windscribe.test',ip:'203.0.113.4',ip2:'203.0.113.5',ip3:'203.0.113.6',weight:5,net_load:80}]};
const ports={portmap:[['wg','ip3',[443,80]],['udp','ip2',[443,1194]],['tcp','ip2',[443]],['ikev2','hostname',[500]],['stunnel','ip3',[443,8443]],['wstunnel','hostname',[443]]].map(([protocol,use,ports])=>({protocol,use,ports:ports.map(String)}))};
const template='client\ndev tun\nauth-user-pass\nreneg-sec 432000\nremote-cert-tls server\nkey-direction 1\n<ca>\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n</ca>\n<tls-auth>\nfixture-static-tls-auth\n</tls-auth>\n';
function vault(){const key=crypto.randomBytes(32);return {available:()=>true,encrypt(text){const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);return Buffer.concat([iv,cipher.update(text),cipher.final(),cipher.getAuthTag()]);},decrypt(bytes){const cipher=crypto.createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));cipher.setAuthTag(bytes.subarray(-16));return Buffer.concat([cipher.update(bytes.subarray(12,-16)),cipher.final()]).toString();}};}
async function fixture(custom){
  const root=path.resolve(__dirname,'../.tools/tmp');await fs.mkdir(root,{recursive:true});const dir=await fs.mkdtemp(path.join(root,'windscribe-provider-')),codec=vault(),calls=[];
  const runtime={recover:async()=>{},stop:async()=>{},availability:async()=>({wireguard:true,udp:true,tcp:true,ikev2:true,stealth:true,wstunnel:true})};
  const service=new Service({dataDir:dir,windscribeRuntime:runtime,openvpnIdentitySupported:true});await service.init();
  service.start=async()=>{service.status='connected';service.publish();return service.getState();};
  const request=async r=>{calls.push({...r,parameters:{...r.parameters}});if(custom){const result=await custom(r);if(result!==undefined)return result;}
    if(r.endpoint==='AuthToken/login')return {token:'fixture-security'};
    if(r.endpoint==='Session')return {...session};
    if(r.endpoint==='Inventory/locations')return structuredClone(locations);
    if(r.endpoint==='Inventory/servers')return structuredClone(servers);
    if(r.endpoint==='PortMap')return structuredClone(ports);
    if(r.endpoint==='ServerConfigs')return {openvpn:template};
    if(r.endpoint==='ServerCredentials')return {username:Buffer.from('fixture-config-user').toString('base64'),password:Buffer.from('fixture-config-password').toString('base64')};
    if(r.endpoint==='WgConfigs/init')return {config:{PresharedKey:psk,AllowedIPs:'0.0.0.0/0',AllowedIPsV6:'::/0',HashedCIDR:['100.64.0.0/10'],HashedCIDRv6:['fd00:abcd::/64']}};
    throw Error('Unexpected fixture endpoint');};
  let provider;const account=new WindscribeAccount({dataDir:dir,vault:codec,request,onForget:identity=>provider?.forget(identity)});provider=new WindscribeProvider({account,service});
  await account.begin({username:session.username,password:'fixture-account-password',remember:true});
  return {dir,account,provider,service,codec,calls,request,async close(){account.shutdown();await service.shutdown();assert.ok(dir.startsWith(root+path.sep));await fs.rm(dir,{recursive:true,force:true});}};
}
test('catalog uses authenticated inventory scope, reports six protocol port maps and never exposes key material or raw nodes',async()=>{
  const f=await fixture();try{
    const view=await f.provider.catalog();assert.equal(view.locations.length,3);assert.equal(view.locations[0].available,true);assert.equal(view.locations[1].available,false);assert.equal(view.locations[2].available,false);assert.equal(view.locations[0].nodeCount,2);assert.equal(Object.keys(view.ports).length,6);
    for(const secret of ['fixture-session',peer,'nl-001','203.0.113.1'])assert.equal(JSON.stringify(view).includes(secret),false);
    assert.ok(f.calls.filter(x=>x.endpoint.startsWith('Inventory/')).every(x=>x.token==='fixture-session'));
    const before=f.calls.length;await f.provider.catalog();assert.equal(f.calls.length,before);
  }finally{await f.close();}
});
test('all six account connection modes prepare native profiles with official endpoints, credentials and certificate identity',async()=>{
  const f=await fixture();try{
    for(const protocol of ['wireguard','udp','tcp','ikev2','stealth','wstunnel']){
      await f.provider.connect({locationId:'10',protocol});const proxy=f.service.proxyList()[0];
      assert.equal(f.service.status,'connected');assert.equal(f.service.serverSource(),'windscribe-account');
      if(protocol==='wireguard'){assert.equal(proxy.server,'203.0.113.3');assert.equal(proxy['public-key'],peer);assert.equal(proxy['pre-shared-key'],psk);assert.ok(proxy.ip.endsWith('/32'));}
      else{
        assert.equal(proxy.username,'fixture-config-user');assert.equal(proxy.password,'fixture-config-password');
        if(protocol==='ikev2'){assert.equal(proxy.server,'ams-10.windscribe.test');assert.equal(proxy.port,500);}
        else{assert.equal(proxy['verify-x509-name'],'ams-10.windscribe.test');assert.equal(proxy['verify-x509-name-type'],'name');assert.equal(proxy['tls-auth'],'fixture-static-tls-auth\n');assert.ok(proxy.ca.includes('BEGIN CERTIFICATE'));assert.equal(proxy.proto,protocol==='udp'?'udp':'tcp');}
        if(protocol==='stealth')assert.equal(proxy['outer-server'],'203.0.113.3');
        if(protocol==='wstunnel')assert.equal(proxy['outer-server'],'nl-001.windscribe.test');
      }
      const disk=await fs.readFile(f.service.file,'utf8');assert.equal(disk.includes('fixture-config-password'),false);assert.equal(disk.includes('windscribe-account'),false);assert.equal(f.service.subscriptions.length,1);
      for(const secret of ['fixture-config-password',psk,f.account.device?.privateKey].filter(Boolean))assert.equal(JSON.stringify(f.service.getState()).includes(secret),false);
    }
    assert.equal(f.calls.filter(x=>x.endpoint==='WgConfigs/init').length,1);
    assert.ok(f.calls.filter(x=>x.endpoint==='ServerCredentials').some(x=>x.parameters.type==='ikev2'));
  }finally{await f.close();}
});
test('forged location/port or inaccessible membership cannot fetch credentials or register keys',async()=>{
  const f=await fixture();try{
    for(const input of [{locationId:'11',protocol:'wireguard'},{locationId:'12',protocol:'tcp'},{locationId:'10',protocol:'udp',port:22},{locationId:'https://outside.test',protocol:'wireguard'}])await assert.rejects(f.provider.connect(input));
    assert.equal(f.calls.some(x=>['ServerCredentials','WgConfigs/init'].includes(x.endpoint)),false);assert.equal(f.service.status,'disconnected');
  }finally{await f.close();}
});
test('changing a connection prepares first; API failure preserves the existing connection and key limits never delete older keys',async()=>{
  let rejectWG=false;const f=await fixture(r=>{if(rejectWG&&r.endpoint==='WgConfigs/init')throw new WindscribeError(1313);});try{
    await f.provider.connect({locationId:'10',protocol:'udp'});const selected=f.service.selectedServer;rejectWG=true;
    await assert.rejects(f.provider.connect({locationId:'10',protocol:'wireguard'}),/ظرفیت/);assert.equal(f.service.status,'connected');assert.equal(f.service.selectedServer,selected);
    assert.ok(f.calls.filter(x=>x.endpoint==='WgConfigs/init').every(x=>x.parameters.force_init===undefined));
  }finally{await f.close();}
});
test('remembered WireGuard key is encrypted, reused after restart, and absent from renderer state',async()=>{
  const f=await fixture();let restored;try{
    await f.provider.connect({locationId:'10',protocol:'wireguard'});const device={...f.account.device};
    const encrypted=await fs.readFile(f.account.file);assert.equal(encrypted.includes(Buffer.from(device.privateKey)),false);assert.equal(JSON.stringify(f.account.state()).includes(device.privateKey),false);
    restored=new WindscribeAccount({dataDir:f.dir,vault:f.codec,request:f.request});await restored.init();assert.deepEqual(restored.device,device);
    const provider=new WindscribeProvider({account:restored,service:f.service});await provider.connect({locationId:'10',protocol:'wireguard'});
    assert.deepEqual(f.calls.filter(x=>x.endpoint==='WgConfigs/init').map(x=>x.parameters.wg_pubkey),[device.publicKey,device.publicKey]);
  }finally{restored?.shutdown();await f.close();}
});
test('logout removes only account profiles, stops their connection and erases the generated runtime file',async()=>{
  const f=await fixture();try{
    await f.service.importText('proxies:\n - {name: Manual, type: http, server: 127.0.0.1, port: 8080}\n','Manual');
    await f.provider.connect({locationId:'10',protocol:'udp'});await fs.writeFile(path.join(f.dir,'runtime.yaml'),'fixture-config-password');
    await f.account.logout();assert.equal(f.account.state().loggedIn,false);assert.equal(f.service.status,'disconnected');assert.equal(f.service.subscriptions.length,1);assert.equal(f.service.proxyList()[0].name,'Manual');assert.equal(f.provider.snapshot().loaded,false);await assert.rejects(fs.access(path.join(f.dir,'runtime.yaml')),{code:'ENOENT'});
  }finally{await f.close();}
});
test('revoked account fails closed and cleans its ephemeral connection without an API retry loop',async()=>{
  let revoked=false;const f=await fixture(r=>{if(revoked&&r.endpoint==='Session'&&r.method==='GET')throw new WindscribeError(701);});try{
    await f.provider.connect({locationId:'10',protocol:'udp'});revoked=true;await assert.rejects(f.provider.reconnect(),{code:701});assert.equal(f.account.state().loggedIn,false);assert.equal(f.service.proxyList().length,0);assert.equal(f.service.status,'disconnected');
  }finally{await f.close();}
});
test('invalid endpoint metadata and injected directives cannot become account connection profiles',()=>{
  const data=structuredClone(locations);data.locations[0].datacenters[0].ovpn_x509='node\nscript-security 2';assert.throws(()=>parseCatalog(data,servers,ports));
  const local=structuredClone(servers);local.servers.forEach(n=>n.ip='127.0.0.1');assert.equal(parseCatalog(locations,local,ports).rows[0].nodes.length,0);
  assert.throws(()=>parsePorts({portmap:[{protocol:'tcp',use:'url',ports:['443']}]}));assert.throws(()=>parsePorts({portmap:[{protocol:'tcp',use:'ip',ports:['65536']}]}));
});
test('provider legacy port subsets prevent offering incompatible obfuscated OpenVPN ports',()=>{
  const data={portmap:[{protocol:'tcp',use:'ip2',ports:['443','1194'],legacy_ports:['1194']},{protocol:'stunnel',use:'ip3',ports:['443','8443'],legacy_ports:['8443']}]};
  assert.deepEqual(parsePorts(data).tcp.ports,[1194]);assert.deepEqual(parsePorts(data).stealth.ports,[8443]);
  data.portmap[0].legacy_ports=['22'];assert.throws(()=>parsePorts(data));
});
test('WireGuard address derivation follows the official SHA256 key hash, supports v6 and rejects corrupt saved pairs',()=>{
  const device=createDevice();assert.deepEqual(validateDevice(device),device);const hash=crypto.createHash('sha256').update(Buffer.from(device.publicKey,'base64')).digest();
  assert.equal(hashedAddress('10.0.0.0/8',device.publicKey),'10.'+[hash[1],hash[2],hash[3]].join('.')+'/32');assert.ok(hashedAddress('fd00:abcd::/64',device.publicKey).startsWith('fd00:abcd:0:0:'));
  assert.throws(()=>validateDevice({...device,publicKey:peer}));assert.throws(()=>hashedAddress('invalid/24',device.publicKey));
  const proxy=wireguardProfile({device,config:{PresharedKey:psk,AllowedIPs:'0.0.0.0/0',AllowedIPsV6:'::/0',HashedCIDR:['100.64.0.0/10'],HashedCIDRv6:['fd00::/64']},peerKey:peer,host:'203.0.113.3',port:443,name:'Fixture',ipv6:true});assert.ok(proxy.ipv6.endsWith('/128'));assert.deepEqual(proxy['allowed-ips'],['0.0.0.0/0','::/0']);
});
test('OpenVPN template adaptation preserves key lifetime through a disconnect deadline while retaining CA and TLS-auth',async()=>{
  const adapted=adaptOpenVPNTemplate(template);assert.equal(adapted.maxSessionSeconds,432000);assert.ok(adapted.text.includes('reneg-sec 0'));assert.ok(adapted.text.includes('fixture-static-tls-auth'));assert.throws(()=>adaptOpenVPNTemplate('reneg-sec 9999999999999999'));
  const f=await fixture();try{
    await f.provider.connect({locationId:'10',protocol:'tcp'});const profile=f.service.subscriptions[0];assert.ok(profile.expiresAt>Date.now());
    profile.expiresAt=Date.now()-1;f.service.startAccountExpiryMonitor();await new Promise(r=>setTimeout(r,60));assert.equal(f.service.status,'disconnected');assert.match(f.service.error,/نوسازی/);
  }finally{await f.close();}
});
test('a second connect/logout cannot race an in-flight account connection preparation',async()=>{
  let release,started;const arrived=new Promise(r=>started=r);let hold=true;
  const f=await fixture(r=>{if(hold&&r.endpoint==='Inventory/locations'){started();return new Promise(resolve=>release=resolve);}});try{
    const pending=f.provider.connect({locationId:'10',protocol:'tcp'});await arrived;
    await assert.rejects(f.provider.connect({locationId:'10',protocol:'tcp'}));await assert.rejects(f.account.logout(),/در حال/);assert.equal(f.service.status,'disconnected');
    hold=false;release(structuredClone(locations));await pending;assert.equal(f.service.status,'connected');
  }finally{await f.close();}
});
test('exhausted account status closes its previous automatic connection before rejecting another attempt',async()=>{
  let exhausted=false;const f=await fixture(r=>exhausted&&r.endpoint==='Session'&&r.method==='GET'?{...session,status:2}:undefined);try{
    await f.provider.connect({locationId:'10',protocol:'tcp'});exhausted=true;await assert.rejects(f.provider.connect({locationId:'10',protocol:'tcp'}),/اجازه/);assert.equal(f.service.status,'disconnected');assert.equal(f.service.proxyList().length,0);assert.equal(f.account.state().loggedIn,true);
  }finally{await f.close();}
});
test('memory-only account connection writes no WireGuard receipt and stale generated runtime is removed on startup',async()=>{
  const f=await fixture();try{
    f.account.remembered=false;await f.account.save();await f.provider.connect({locationId:'10',protocol:'wireguard'});await assert.rejects(fs.access(f.account.file),{code:'ENOENT'});
    await f.service.stop();await fs.writeFile(path.join(f.dir,'runtime.yaml'),'fixture-private-key');await f.service.init();await assert.rejects(fs.access(path.join(f.dir,'runtime.yaml')),{code:'ENOENT'});
  }finally{await f.close();}
});
