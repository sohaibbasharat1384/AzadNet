'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const Service=require('../desktop/lib/service.cjs');
const {parseWindscribeImport,PROTOCOLS}=require('../desktop/lib/windscribe-import.cjs');
const key=Buffer.alloc(32,7).toString('base64');
const wg=`[Interface]\nPrivateKey=${key}\nAddress=10.1.1.2/32\nDNS=10.1.1.1\n[Peer]\nPublicKey=${key}\nAllowedIPs=0.0.0.0/0, ::/0\nEndpoint=node.example:443\n`;
const ovpn='client\ndev tun\nproto tcp-client\nremote node.example 443\nauth-user-pass\nremote-cert-tls server\nverify-x509-name node name\n<ca>\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n</ca>\n';
const credentials={username:'fixture-user',password:'fixture-secret'};
test('all six modes produce distinct profiles and keep inner OpenVPN identity constraints',()=>{
  assert.equal(PROTOCOLS.length,6);
  for(const protocol of PROTOCOLS){
    const options={protocol,...credentials,name:'IKE',server:'node.example'};
    const files=[{name:protocol+'.conf',text:protocol==='wireguard'?wg:protocol==='udp'?ovpn.replace('tcp-client','udp'):ovpn}];
    const [{proxies:[p]}]=parseWindscribeImport(files,options);
    assert.equal(p.type,protocol==='wireguard'?'wireguard':protocol==='ikev2'?'ikev2':'openvpn');
    if(p.type==='openvpn')assert.equal(p['verify-x509-name'],'node');
    if(['stealth','wstunnel'].includes(protocol)){assert.equal(p['outer-server'],'node.example');assert.equal(p['outer-port'],443);assert.equal(p['windscribe-mode'],protocol);}
  }
});
test('mismatched transports, duplicate filenames and executable profile directives fail the whole import',()=>{
  assert.throws(()=>parseWindscribeImport([{name:'A.ovpn',text:ovpn}],{protocol:'udp',...credentials}),/does not match/);
  assert.throws(()=>parseWindscribeImport([{name:'A.conf',text:wg},{name:'a.conf',text:wg}],{protocol:'wireguard'}),/different/);
  assert.throws(()=>parseWindscribeImport([{name:'A.ovpn',text:ovpn+'up malicious'}],{protocol:'stealth',...credentials}),/Unsupported directive/);
});
test('provider import is atomic, reimport preserves selection, state omits credentials, and expiry of another provider is irrelevant',async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'azadnet-windscribe-test-'));let licenseCalls=0;
  const service=new Service({dataDir:dir,officialLicense:{async status(){licenseCalls++;throw Error('unrelated provider');}}});
  try{
    await service.init();await service.importText('proxies:\n - {name: Existing, type: http, server: old.example, port: 8080}');
    const imported=await service.importWindscribe([{name:'Canada.conf',text:wg}],{protocol:'wireguard'});assert.equal(imported.added,1);
    const sub=service.subscriptions.find(s=>s.source==='windscribe'),name=sub.proxies[0].name;await service.selectServer(name);await service.requireOfficialLicense();assert.equal(licenseCalls,0);
    const before=await fs.readFile(service.file,'utf8');await assert.rejects(service.importWindscribe([{name:'Good.conf',text:wg},{name:'Bad.conf',text:'broken'}],{protocol:'wireguard'}));assert.equal(await fs.readFile(service.file,'utf8'),before);
    const result=await service.importWindscribe([{name:'canada.conf',text:wg.replace('node.example','renewed.example')}],{protocol:'wireguard'});assert.equal(result.updated,1);assert.equal(service.selectedServer,name);assert.equal(service.subscriptions.find(s=>s.source==='windscribe').id,sub.id);
    assert.equal(JSON.stringify(service.getState()).includes(key),false);
    const loaded=new Service({dataDir:dir});await loaded.init();assert.equal(loaded.selectedServer,name);assert.equal(loaded.proxyList().find(p=>p.name===name).server,'renewed.example');
    // Multi-remote profiles duplicate inline material; never write state that cannot reload.
    const huge=ovpn.replace('AA==','A'.repeat(200000)).replace('remote node.example 443',Array.from({length:64},(_,i)=>`remote n${i}.example 443`).join('\n'));
    const checkpoint=await fs.readFile(service.file,'utf8');await assert.rejects(service.importWindscribe([{name:'Huge1.ovpn',text:huge},{name:'Huge2.ovpn',text:huge}],{protocol:'tcp',...credentials}),/16 MiB/);assert.equal(await fs.readFile(service.file,'utf8'),checkpoint);
  }finally{await service.shutdown();assert.ok(dir.startsWith(os.tmpdir()+path.sep));await fs.rm(dir,{recursive:true,force:true});}
});
