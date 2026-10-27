'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {parseExtraInput,augmentTransport}=require('../desktop/lib/subscription-extra.cjs');
const UUID='11111111-2222-3333-4444-555555555555';
const PRIVATE='0HWFA24ETSHemoGTj2ZDbhL0VrUEef50y2q6FlLPgF8=';
const PUBLIC='vUdHmo14D+Ye7tJO5yj+09LOzM1g0/8NJ0aytxQMawQ=';
const enc=encodeURIComponent;
function vless(stream={}) {return {protocol:'vless',tag:'proxy',settings:{vnext:[{address:'example.workers.dev',port:443,users:[{id:UUID,encryption:'none'}]}]},streamSettings:stream};}

test('declines other formats so the main parser retains ownership',()=>{
  for(const input of ['proxies:\n - name: proxy','vless://id@example.com:443','[{"name":"A","type":"direct"}]','{"proxies":[]}','anytls://x@a:443\nvless://id@b:443']) assert.equal(parseExtraInput(input),null);
});
test('AnyTLS authority splitting preserves encoded colons and user/password form',()=>{
  assert.equal(parseExtraInput('anytls://pa%3Assword@node.example.com:443#Encoded').proxies[0].password,'pa:ssword');
  const {proxies:[p],warnings}=parseExtraInput('anytls://user:s3cret@node.example.com:8443/?peer=front.example.com&insecure=1&alpn=h2,http%2F1.1&hpkp=deadbeef#DE%20One');
  assert.deepEqual(p,{name:'DE One',type:'anytls',server:'node.example.com',port:8443,udp:true,password:'s3cret',sni:'front.example.com',alpn:['h2','http/1.1'],fingerprint:'deadbeef','skip-cert-verify':false});
  assert.match(warnings[0],/verification remains enabled/);
  assert.equal(p['client-fingerprint'],undefined);
  assert.throws(()=>parseExtraInput('anytls://node.example.com:443#Bare'),/password/);
});
test('WireGuard URI preserves real key material, dual-stack addresses and peer options',()=>{
  // The public upstream wireguard_test.go example uses this exact pair and URI shape.
  const link=`wireguard://${enc(PRIVATE)}@node.example.com:51820?address=10.0.0.2%2F32%2Cfd00%3A%3A2%2F128&mtu=1420&publickey=${enc(PUBLIC)}&reserved=0%2C2%2C255&persistentkeepalive=25#wg`;
  const {proxies:[p],warnings}=parseExtraInput(link);
  assert.deepEqual(p,{name:'wg',type:'wireguard',server:'node.example.com',port:51820,udp:true,'private-key':PRIVATE,'public-key':PUBLIC,ip:'10.0.0.2/32',ipv6:'fd00::2/128',mtu:1420,'persistent-keepalive':25,reserved:[0,2,255]});
  assert.deepEqual(warnings,[]);
});
test('WireGuard alternate names and IPv6 peer are supported; malformed reserved is reported',()=>{
  const {proxies:[p],warnings}=parseExtraInput(`wg://[2001:db8::2]:51820?private_key=${enc(PRIVATE)}&peer_public_key=${enc(PUBLIC)}&ip=10.7.0.2&psk=${enc(PRIVATE)}&allowed_ips=0.0.0.0%2F0%2C%3A%3A%2F0&reserved=1%2C2%2C300#Alt`);
  assert.equal(p.server,'2001:db8::2');assert.equal(p['pre-shared-key'],PRIVATE);
  assert.deepEqual(p['allowed-ips'],['0.0.0.0/0','::/0']);assert.equal(p.reserved,undefined);
  assert.match(warnings[0],/reserved bytes/);
});
test('WireGuard rejects missing/invalid keys, addresses and ports instead of emitting unusable nodes',()=>{
  for(const query of [`address=10.0.0.2&publickey=${enc(PUBLIC)}`,`address=10.0.0.2&privatekey=short&publickey=${enc(PUBLIC)}`,`privatekey=${enc(PRIVATE)}&publickey=${enc(PUBLIC)}`,`address=10.0.0.2/99&privatekey=${enc(PRIVATE)}&publickey=${enc(PUBLIC)}`])assert.throws(()=>parseExtraInput(`wg://host.example:51820?${query}`));
  assert.throws(()=>parseExtraInput(`wg://${enc(PRIVATE)}@host.example?address=10.0.0.2&publickey=${enc(PUBLIC)}`),/port/);
});
test('HTTP upgrade maps early-data semantics to fast-open, not WebSocket max-early-data',()=>{
  const p={type:'vless'};
  assert.equal(augmentTransport(p,new URLSearchParams({type:'httpupgrade',path:'/up',host:'cdn.example.com',ed:'2048',eh:'Custom-Early'})),true);
  assert.deepEqual(p,{type:'vless',network:'httpupgrade','ws-opts':{path:'/up',headers:{Host:'cdn.example.com'},'v2ray-http-upgrade-fast-open':true,'early-data-header-name':'Custom-Early'}});
  assert.equal(augmentTransport({},new URLSearchParams({type:'ws'})),false);
});
test('XHTTP maps nested reuse/download options, preserving TLS verification at both layers',()=>{
  const extra={noGRPCHeader:true,xPaddingBytes:'100-200',xPaddingObfsMode:false,scMaxEachPostBytes:1000000,xmux:{maxConnections:4,hMaxRequestTimes:'600-900',hKeepAlivePeriod:30},downloadSettings:{address:'download.example',port:443,network:'xhttp',security:'tls',tlsSettings:{serverName:'front.example',fingerprint:'chrome',alpn:['h2'],allowInsecure:true},xhttpSettings:{path:'/download',host:'front.example',headers:{'X-Test':'one'},noGRPCHeader:true}}};
  const p={};assert.equal(augmentTransport(p,new URLSearchParams({type:'splithttp',path:'/up',host:'up.example',mode:'packet-up',extra:JSON.stringify(extra)})),true);
  assert.equal(p.network,'xhttp');const opts=p['xhttp-opts'];
  assert.equal(opts['x-padding-bytes'],'100-200');assert.equal(opts['x-padding-obfs-mode'],false);
  assert.deepEqual(opts['reuse-settings'],{'max-connections':'4','h-max-request-times':'600-900','h-keep-alive-period':30});
  assert.deepEqual(opts['download-settings'],{server:'download.example',port:443,tls:true,'skip-cert-verify':false,servername:'front.example','client-fingerprint':'chrome',alpn:['h2'],path:'/download',host:'front.example',headers:{'X-Test':'one'},'no-grpc-header':true});
});
test('malformed and unknown XHTTP settings fail visibly rather than being silently discarded',()=>{
  for(const extra of ['no-json','[]','{"unrecognizedSetting":true}','{"xmux":{"notSupported":1}}','{"downloadSettings":{"network":"quic"}}'])assert.throws(()=>augmentTransport({},new URLSearchParams({type:'xhttp',extra})),/XHTTP|Xray/);
  assert.throws(()=>augmentTransport({},new URLSearchParams({type:'xhttp',mode:'invented'})),/mode/);
  assert.throws(()=>augmentTransport({},new URLSearchParams({type:'httpupgrade',host:'bad\r\nheader'})),/Invalid/);
});
test('Xray config-list names come from remarks and nested VMess/Trojan settings survive conversion',()=>{
  const configs=[{remarks:'VMess example',inbounds:[],routing:{},outbounds:[{protocol:'freedom'}, {protocol:'vmess',settings:{vnext:[{address:'vm.example',port:'443',users:[{id:UUID,alterId:0,security:'auto'}]}]},streamSettings:{network:'ws',wsSettings:{path:'/ws',headers:{Host:'cdn.example','X-Key':'value'}},security:'tls',tlsSettings:{serverName:'tls.example',alpn:['http/1.1'],fingerprint:'chrome',allowInsecure:true}}}]},{remarks:'Trojan example',outbounds:[{protocol:'trojan',settings:{servers:[{address:'tr.example',port:443,password:'pass'}]},streamSettings:{network:'grpc',grpcSettings:{serviceName:'grpc-service'},security:'tls',tlsSettings:{serverName:'tr-front.example'}}}]}];
  const {proxies:[vm,tr],warnings}=parseExtraInput(JSON.stringify(configs));
  assert.equal(vm.name,'VMess example');assert.equal(vm.uuid,UUID);assert.equal(vm.cipher,'auto');assert.equal(vm.alterId,0);
  assert.deepEqual(vm['ws-opts'],{path:'/ws',headers:{Host:'cdn.example','X-Key':'value'}});assert.equal(vm['skip-cert-verify'],false);
  assert.equal(tr.name,'Trojan example');assert.equal(tr.sni,'tr-front.example');assert.deepEqual(tr['grpc-opts'],{'grpc-service-name':'grpc-service'});
  assert.ok(warnings.some(w=>w.includes('routing')));assert.ok(warnings.some(w=>w.includes('allowInsecure')));
});
test('Xray Reality and XHTTP options retain security and protocol-specific settings',()=>{
  const outbound=vless({network:'splithttp',splithttpSettings:{path:'/x',host:'cdn.example',mode:'stream-one',extra:{uplinkHttpMethod:'POST',xmux:{maxConcurrency:'8-16'}}},security:'reality',realitySettings:{publicKey:'public-key-from-server',shortId:'00ff',serverName:'www.example.com',fingerprint:'chrome'}});
  outbound.settings.vnext[0].users[0].flow='XTLS-RPRX-VISION';
  const p=parseExtraInput(JSON.stringify({outbounds:[outbound]})).proxies[0];
  assert.equal(p.flow,'xtls-rprx-vision');assert.equal(p.tls,true);assert.equal(p.servername,'www.example.com');
  assert.deepEqual(p['reality-opts'],{'public-key':'public-key-from-server','short-id':'00ff'});
  assert.deepEqual(p['xhttp-opts'],{path:'/x',host:'cdn.example',mode:'stream-one','uplink-http-method':'POST','reuse-settings':{'max-concurrency':'8-16'}});
});
test('unsupported Xray transports, chaining and multiple users are warnings when another node survives',()=>{
  const multi=vless();multi.settings.vnext[0].users.push({id:UUID});
  const linked=vless();linked.proxySettings={tag:'other'};
  const {proxies,warnings}=parseExtraInput(JSON.stringify({remarks:'same',outbounds:[vless({network:'kcp'}),multi,linked,vless(),vless()]}));
  assert.equal(proxies.length,2);assert.deepEqual(proxies.map(p=>p.name),['same','same (2)']);
  assert.ok(warnings.some(w=>w.includes('Unsupported Xray transport: kcp')));assert.ok(warnings.some(w=>w.includes('one server and user')));assert.ok(warnings.some(w=>w.includes('dependency')));
  assert.throws(()=>parseExtraInput(JSON.stringify({outbounds:[vless({network:'quic'})]})),/Unsupported Xray transport/);
});
test('Xray WireGuard preserves peer/tunnel fields and rejects unrepresentable chaining',()=>{
  const outbound={protocol:'wireguard',tag:'WARP',settings:{secretKey:PRIVATE,address:['172.16.0.2/32','2606:4700:110:1234::2/128'],mtu:1280,reserved:[1,2,3],peers:[{publicKey:PUBLIC,endpoint:'[2606:4700:d0::a29f:c001]:2408',allowedIPs:['0.0.0.0/0','::/0'],keepAlive:25}]}};
  const p=parseExtraInput(JSON.stringify({outbounds:[outbound]})).proxies[0];
  assert.equal(p.name,'WARP');assert.equal(p.server,'2606:4700:d0::a29f:c001');assert.equal(p.ip,'172.16.0.2/32');assert.deepEqual(p.reserved,[1,2,3]);
  assert.equal(p['persistent-keepalive'],25);assert.equal(p['private-key'],PRIVATE);
  outbound.settings.peers[0].endpoint='node.example:80';
  assert.equal(parseExtraInput(JSON.stringify({outbounds:[outbound]})).proxies[0].port,80);
  outbound.streamSettings={sockopt:{dialerProxy:'first-warp'}};
  assert.throws(()=>parseExtraInput(JSON.stringify({outbounds:[outbound]})),/chaining/);
});
test('Xray invalid TLS and HTTP/2 host data never becomes a silently downgraded node',()=>{
  assert.throws(()=>parseExtraInput(JSON.stringify({outbounds:[vless({security:'reality',realitySettings:{serverName:'a.example'}})]})),/public key/);
  assert.throws(()=>parseExtraInput(JSON.stringify({outbounds:[vless({network:'h2',httpSettings:{host:'expected-an-array'}})]})),/host list/);
  assert.throws(()=>parseExtraInput('x'.repeat(8*1024*1024+1)),/8 MiB/);
});
