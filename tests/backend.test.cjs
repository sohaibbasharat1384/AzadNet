'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const http=require('node:http');
const {EventEmitter}=require('node:events');
const {PassThrough}=require('node:stream');
const {parse}=require('yaml');
const {parseSubscription}=require('../desktop/lib/subscriptions.cjs');
const {DEFAULT_SETTINGS,validateSettings,generateConfig}=require('../desktop/lib/config.cjs');
const {Controller}=require('../desktop/lib/controller.cjs');
const Service=require('../desktop/lib/service.cjs');
const UUID='fae18768-5eb1-47c1-83b5-293e45994fdc';
const VLESS=`vless://${UUID}@test.example:443?security=reality&type=ws&path=%2Fvpn&host=cdn.example&sni=test.example&pbk=public-key&sid=abcd#Test`;
async function unusedPort(){const s=http.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
test('URI parsing preserves reality and websocket details without disabling TLS checks',()=>{
  const {proxies,warnings}=parseSubscription(VLESS);assert.equal(warnings.length,0);const p=proxies[0];
  assert.equal(p.uuid,UUID);assert.equal(p.server,'test.example');assert.equal(p['ws-opts'].path,'/vpn');assert.equal(p['ws-opts'].headers.Host,'cdn.example');assert.equal(p['reality-opts']['short-id'],'abcd');assert.equal(p['skip-cert-verify'],false);
});
test('VMess Base64, Shadowsocks SIP002, Hysteria2, TUIC and authenticated SOCKS import',()=>{
  const vmess='vmess://'+Buffer.from(JSON.stringify({v:'2',ps:'VM',add:'vm.example',port:'443',id:UUID,aid:'0',net:'grpc',path:'/',tls:'tls',sni:'vm.example'})).toString('base64');
  const ss='ss://'+Buffer.from('aes-128-gcm:pass:with:colons').toString('base64')+'@ss.example:8388#SS';
  const text=[vmess,ss,'hy2://pass@hy.example:443?sni=hy.example#HY',`tuic://${UUID}:pass@tuic.example:443#TUIC`,'socks5://user:pass@[::1]:1080#SOCKS'].join('\n');
  const {proxies,warnings}=parseSubscription(Buffer.from(text).toString('base64'));assert.equal(proxies.length,5);assert.equal(warnings.length,0);assert.equal(proxies[1].password,'pass:with:colons');assert.equal(proxies[4].server,'::1');
});
test('invalid and unsupported URIs are reported; YAML types and ports are validated',()=>{
  assert.throws(()=>parseSubscription(`vless://bad@a.example:443`),/UUID/);
  assert.throws(()=>parseSubscription('proxies:\n - {name: bad, type: vless, server: a.example, port: 99999, uuid: test}'),/port/);
  assert.throws(()=>parseSubscription(`vless://${UUID}@test.example:443?type=unknown-transport`),/Unsupported transport/);
  assert.throws(()=>parseSubscription('proxies:\n - {name: bad, type: unknown, server: a.example, port: 443}'),/Unsupported/);
  const result=parseSubscription(VLESS+'\nunsupported://something');assert.equal(result.proxies.length,1);assert.equal(result.warnings.length,1);
});
test('extra protocol helper integrates with the public subscription parser and Base64 lists',()=>{
  const anytls='anytls://pass@example.org:443#AnyTLS',xhttp=`vless://${UUID}@test.example:443?security=tls&type=xhttp&path=%2Fstream&host=cdn.example&mode=auto#XHTTP`;
  const {proxies}=parseSubscription(Buffer.from([anytls,xhttp].join('\n')).toString('base64'));assert.equal(proxies[0].type,'anytls');assert.equal(proxies[1].network,'xhttp');assert.equal(proxies[1]['xhttp-opts'].path,'/stream');
  const json=JSON.stringify({outbounds:[{protocol:'vless',tag:'Xray',settings:{vnext:[{address:'example.org',port:443,users:[{id:UUID,encryption:'none'}]}]},streamSettings:{network:'tcp',security:'tls',tlsSettings:{serverName:'front.example'}}}]});assert.equal(parseSubscription(json).proxies[0].servername,'front.example');
});
test('settings refuse unsafe values and config replaces imported listeners with controlled loopback listeners',()=>{
  assert.throws(()=>validateSettings({mixedPort:80}),/1024/);assert.throws(()=>validateSettings({mixedPort:9097}),/differ/);assert.throws(()=>validateSettings({directDomains:['bad,DIRECT']}),/domain/);assert.throws(()=>validateSettings({unknown:1}),/Unknown/);
  const cfg=generateConfig({...DEFAULT_SETTINGS,directDomains:['example.org']},parseSubscription(VLESS).proxies,'secret','Test');
  assert.equal(cfg['external-controller'],'127.0.0.1:9097');assert.equal(cfg['bind-address'],'127.0.0.1');assert.equal(cfg['allow-lan'],false);assert.equal(cfg.tun,undefined);assert.ok(cfg.rules.includes('DOMAIN-SUFFIX,example.org,DIRECT'));assert.equal(cfg.rules.at(-1),'MATCH,AZADNET');assert.deepEqual(cfg.dns.nameserver,DEFAULT_SETTINGS.dnsServers);
  const tun=generateConfig({...DEFAULT_SETTINGS,tun:true},[], 'secret');assert.equal(tun.tun['auto-route'],true);
  const global=generateConfig({...DEFAULT_SETTINGS,routingMode:'global'},parseSubscription(VLESS).proxies,'secret','Test');assert.equal(global.mode,'rule');assert.equal(global.rules.at(-1),'MATCH,AZADNET');
  assert.throws(()=>generateConfig({...DEFAULT_SETTINGS,fragmentsEnabled:true},parseSubscription(VLESS).proxies,'secret','Test'),/custom|fragment/i);
  const fragmented=generateConfig({...DEFAULT_SETTINGS,fragmentsEnabled:true},parseSubscription(VLESS).proxies,'secret','Test',{fragmentsSupported:true});assert.equal(fragmented.proxies[0].fragments.length,2);
});
test('controller sends secret, encodes server names, rejects HTTP errors and aggregates real traffic totals',async()=>{
  const seen=[];const server=http.createServer((req,res)=>{seen.push([req.method,req.url,req.headers.authorization]);if(req.url==='/version'){res.end('{"version":"test"}');}else if(req.url==='/connections')res.end('{"uploadTotal":12,"downloadTotal":34,"connections":[{}]}');else if(req.url.startsWith('/proxies/'))res.end('{"delay":42}');else{res.writeHead(403);res.end('{}');}});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));try{const c=new Controller(server.address().port,'token');assert.deepEqual(await c.version(),{version:'test'});assert.deepEqual(await c.traffic(),{upload:12,download:34,connections:1});assert.equal((await c.delay('A / B')).delay,42);assert.equal(seen[2][1].startsWith('/proxies/A%20%2F%20B/delay'),true);assert.equal(new URL(seen[2][1],'http://localhost').searchParams.get('url'),'https://cp.cloudflare.com/generate_204');assert.equal(seen[0][2],'Bearer token');await assert.rejects(c.request('GET','/forbidden'),/403/);}finally{await new Promise(r=>server.close(r));}
});
test('service persists imports privately, redacts credentials and handles failed validation without claiming connection',async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'azadnet-test-'));try{
    const spawnProcess=()=>{const p=new EventEmitter();p.stdout=new PassThrough();p.stderr=new PassThrough();p.kill=()=>true;setImmediate(()=>p.emit('exit',1,null));return p;};
    const svc=new Service({dataDir:dir,corePath:process.execPath,spawnProcess});await svc.init();await svc.importText(VLESS,'First');await svc.importText(VLESS,'Second');assert.equal(svc.getState().servers[1].name,'Test (2)');assert.equal(svc.getState().servers[0].uuid,undefined);assert.equal(svc.getState().subscriptions[0].proxies,undefined);
    svc.log('uuid='+UUID);assert.equal(svc.getLogs().at(-1).message.includes(UUID),false);
    await svc.saveSettings({mixedPort:await unusedPort(),controllerPort:await unusedPort()});await assert.rejects(svc.start(),/rejected configuration/);assert.equal(svc.status,'disconnected');assert.equal(svc.process,null);
    const restored=new Service({dataDir:dir});await restored.init();assert.equal(restored.getState().servers.length,2);await restored.removeSubscription(restored.getState().subscriptions[0].id);assert.equal(restored.getState().servers.length,1);
  }finally{await fs.rm(dir,{recursive:true,force:true});}
});
test('service owns process lifecycle and authenticates readiness before reporting connected',async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'azadnet-lifecycle-'));let server,live;let killed=0;let versionReads=0;
  async function freePort(){const s=http.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
  try{
    const cp=await freePort(),mp=await freePort();
    const spawnProcess=(_exe,args)=>{
      const p=new EventEmitter();p.stdout=new PassThrough();p.stderr=new PassThrough();p.exitCode=null;
      p.kill=()=>{killed++;if(server)server.close();p.exitCode=0;setImmediate(()=>p.emit('exit',0,null));return true;};
      if(args.includes('-t'))setImmediate(()=>{p.exitCode=0;p.emit('exit',0,null);});else{
        live=p;setImmediate(async()=>{const cfg=parse(await fs.readFile(path.join(dir,'runtime.yaml'),'utf8'));server=http.createServer((req,res)=>{
          if(req.headers.authorization!==`Bearer ${cfg.secret}`){res.writeHead(403);res.end();return;}
          if(req.url==='/version'){versionReads++;res.end('{"version":"vtest"}');}
          else if(req.url==='/connections')res.end('{"uploadTotal":4,"downloadTotal":9,"connections":[]}');
          else if(req.url.includes('/delay?'))res.end('{"delay":8}');else{res.writeHead(204);res.end();}
        });server.listen(cp,'127.0.0.1');});
      }return p;
    };
    const svc=new Service({dataDir:dir,corePath:process.execPath,spawnProcess});await svc.init();await svc.saveSettings({controllerPort:cp,mixedPort:mp});await svc.importText(VLESS,'Live');await svc.start();assert.equal(svc.status,'connected');assert.equal(svc.coreVersion,'vtest');assert.ok(versionReads>0);assert.deepEqual(await svc.traffic(),{upload:4,download:9,connections:0});await assert.rejects(svc.saveSettings({tun:true}),/Disconnect/);await svc.testServers();assert.equal(svc.getState().servers[0].delay,8);await svc.stop();assert.equal(svc.status,'disconnected');assert.equal(svc.process,null);assert.equal(killed,1);assert.equal(live.exitCode,0);
  }finally{if(server?.listening)await new Promise(r=>server.close(r));await fs.rm(dir,{recursive:true,force:true});}
});
test('subscription refresh preserves ID and selected endpoint names and locks concurrent changes',async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'azadnet-refresh-'));try{
    let body=VLESS,release;const svc=new Service({dataDir:dir,fetchText:async()=>body});await svc.init();const first=await svc.importUrl('https://example.org/sub?token=private','Remote');await svc.selectServer('Test');
    body=VLESS.replace('#Test','#Renamed');const refreshed=await svc.refreshSubscription(first.id);assert.equal(refreshed.id,first.id);assert.equal(svc.getState().subscriptions.length,1);assert.equal(svc.selectedServer,'Test');assert.equal(svc.getState().subscriptions[0].url,'https://example.org');
    svc.fetchText=()=>new Promise(r=>{release=r;});const pending=svc.refreshSubscription(first.id);await assert.rejects(svc.removeSubscription(first.id),/Disconnect/);release(body);await pending;
    const local=await svc.importText(VLESS,'Local');await assert.rejects(svc.refreshSubscription(local.id),/no refresh URL/);
  }finally{await fs.rm(dir,{recursive:true,force:true});}
});
test('shutdown during config validation cannot launch or leak a live core',async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'azadnet-shutdown-'));try{
    let validations=0,live=0,killed=0;
    const spawnProcess=(_exe,args)=>{const p=new EventEmitter();p.stdout=new PassThrough();p.stderr=new PassThrough();p.kill=()=>{killed++;setImmediate(()=>p.emit('exit',null,'SIGTERM'));return true;};if(args.includes('-t'))validations++;else live++;return p;};
    const svc=new Service({dataDir:dir,corePath:process.execPath,spawnProcess});await svc.init();await svc.saveSettings({mixedPort:await unusedPort(),controllerPort:await unusedPort()});await svc.importText(VLESS,'Remote');const pending=svc.start().catch(e=>e);for(let i=0;i<100&&!validations;i++)await new Promise(r=>setTimeout(r,5));assert.equal(validations,1);await svc.shutdown();const result=await pending;assert.ok(result instanceof Error);assert.equal(killed,1);assert.equal(live,0);assert.equal(svc.process,null);assert.equal(svc.status,'disconnected');await assert.rejects(svc.start(),/shutting down/);
  }finally{await fs.rm(dir,{recursive:true,force:true});}
});
