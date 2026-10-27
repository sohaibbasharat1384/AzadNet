'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {ADVANCED_DEFAULTS, FRAGMENT_PRESETS, parseFragments, parseFrontingEndpoint, validateAdvanced, applyAdvanced} = require('../desktop/lib/advanced.cjs');
const base = () => ({'mixed-port':2080,'allow-lan':false,proxies:[{name:'Test',type:'vless',server:'origin.example',port:443,tls:true,servername:'sni.example','reality-opts':{'public-key':'test'},'client-fingerprint':'none'}],'proxy-groups':[{name:'AZADNET',type:'select',proxies:['Test']}],rules:['IP-CIDR,10.0.0.0/8,DIRECT,no-resolve','MATCH,AZADNET'],dns:{enable:true,nameserver:['https://1.1.1.1/dns-query']}});
test('APK preset serializes to exact flattened Mihomo fragments while preserving string ranges', () => {
  assert.deepEqual(parseFragments(ADVANCED_DEFAULTS.fragmentJson), [{packets:'tlshello',lengths:['13-23'],delays:['0'],maxSplit:'256'},{packets:'1-5',lengths:['7-17'],delays:['1-4'],maxSplit:'256'}]);
  for (const preset of FRAGMENT_PRESETS) assert.equal(parseFragments(JSON.stringify(preset)).length, 2);
});
test('fragment aliases and zero maxSplit normalization match APK', () => {
  assert.deepEqual(parseFragments(JSON.stringify({tcp:[{type:'fragment',settings:{length:'5-10',interval:3,'max-split':0}}]})), [{length:'5-10',interval:'3','max-split':'256'}]);
});
test('invalid fragment combinations reject before config generation', () => {
  const raw = settings => JSON.stringify({tcp:[{type:'fragment',settings}]});
  for (const settings of [{length:1,lengths:[2]},{lengths:[]},{length:0},{length:1,delay:1001},{length:1,maxSplit:257},{length:1,unknown:1},{length:1,packets:'0'},{length:1,packets:'tlshello\n'+'oops'}]) assert.throws(() => parseFragments(raw(settings)));
  assert.throws(() => parseFragments('{"tcp":[]}'));
  assert.throws(() => parseFragments('{"tcp":'+JSON.stringify(Array(9).fill({type:'fragment',settings:{length:1}}))+'}'));
});
test('fronting validates IPv4/IPv6 ports and rejects hostnames, zones and injection', () => {
  assert.deepEqual(parseFrontingEndpoint('1.1.1.1:8443'), {ip:'1.1.1.1',port:8443});
  assert.deepEqual(parseFrontingEndpoint('[2606:4700::1111]:443'), {ip:'2606:4700::1111',port:443});
  assert.deepEqual(parseFrontingEndpoint('2606:4700::1111'), {ip:'2606:4700::1111',port:undefined});
  for (const v of ['domain.example:443','1.1.1.1:0','1.1.1.1:65536','1.1.1.1\nrules:','[fe80::1%eth0]:443',' 1.1.1.1']) assert.throws(() => parseFrontingEndpoint(v));
});
test('advanced transforms preserve input, TLS host, references and existing transport-specific ALPN', () => {
  const original = base();
  const output = applyAdvanced(original,{fragmentsEnabled:true,frontingEndpoints:['1.1.1.1:8443','8.8.8.8'],fragmentAlpn:'h2,http/1.1'},{fragmentsSupported:true});
  assert.equal(original.proxies[0].server,'origin.example');
  assert.equal(original.proxies[0].fragments,undefined);
  assert.equal(output.proxies[0].server,'1.1.1.1');
  assert.equal(output.proxies[0].port,8443);
  assert.equal(output.proxies[0].servername,'sni.example');
  assert.equal(output.proxies[0]['client-fingerprint'],'chrome');
  assert.deepEqual(output.proxies[0].alpn,['h2','http/1.1']);
  assert.deepEqual(output['proxy-groups'][0].proxies,['Test']);
  const grpc = base(); grpc.proxies[0].network='grpc';
  assert.equal(applyAdvanced(grpc,{fragmentsEnabled:true,fragmentAlpn:'h2'},{fragmentsSupported:true}).proxies[0].alpn,undefined);
  assert.equal(applyAdvanced(original,{frontingEndpoints:['1.1.1.1','8.8.8.8']},{frontingIndex:1}).proxies[0].server,'8.8.8.8');
});
test('public desktop core cannot silently accept an unsupported fragmentation setting', () => {
  assert.throws(()=>applyAdvanced(base(),{fragmentsEnabled:true}),/does not support the Android fragments extension/);
  assert.throws(()=>applyAdvanced(base(),{fragmentsEnabled:true},{fragmentsSupported:false}),/compatible custom core/);
});
test('Iran remote rules are opt-in and GEOIP rule requires packaged data', () => {
  const limited = applyAdvanced(base(),{});
  assert.ok(limited.rules.includes('DOMAIN-SUFFIX,ir,DIRECT'));
  assert.ok(!limited.rules.some(r=>r.startsWith('GEOIP')));
  assert.equal(limited['rule-providers'],undefined);
  assert.equal(limited['geo-auto-update'],false);
  const full = applyAdvanced(base(),{iranRemoteRules:true},{geoipAvailable:true});
  assert.ok(full.rules.includes('GEOIP,IR,DIRECT,no-resolve'));
  assert.ok(full.rules.indexOf('RULE-SET,whitedns-iran,DIRECT')<full.rules.indexOf('MATCH,AZADNET'));
  assert.equal(full['rule-providers']['whitedns-iran'].proxy,'AZADNET');
});
test('LAN authentication cannot be silently disabled or configured with delimiter injection', () => {
  const config=base(); config['allow-lan']=true;
  assert.throws(()=>applyAdvanced(config,{}),/password/);
  assert.throws(()=>validateAdvanced({lanPassword:'secret:bad'}),/password/);
  assert.throws(()=>validateAdvanced({lanUsername:'name:password'}),/username/);
  const out=applyAdvanced(config,{lanPassword:'long-password'});
  assert.deepEqual(out.authentication,['whitedns:long-password']);
  assert.deepEqual(out['skip-auth-prefixes'],['127.0.0.0/8']);
  assert.ok(out['lan-allowed-ips'].includes('192.168.0.0/16'));
});
test('Amnezia changes only WireGuard and rejects inconsistent noise sizes', () => {
  const config=base(); config.proxies.push({name:'WG',type:'wireguard',server:'wg.example',port:51820});
  const out=applyAdvanced(config,{amneziaNoiseEnabled:true});
  assert.equal(out.proxies[0]['amnezia-wg-option'],undefined);
  assert.deepEqual(out.proxies[1]['amnezia-wg-option'],{jc:5,jmin:50,jmax:100});
  assert.throws(()=>validateAdvanced({noiseMinSize:200,noiseMaxSize:100}));
  assert.throws(()=>validateAdvanced({__bad:true}));
});

test('fronting leaves WireGuard and plain HTTP endpoint addresses intact',()=>{
  const config=base();config.proxies.push({name:'WG',type:'wireguard',server:'wg.example',port:51820},{name:'Plain',type:'http',server:'plain.example',port:8080});
  const out=applyAdvanced(config,{frontingEndpoints:['1.1.1.1:443']});
  assert.equal(out.proxies[0].server,'1.1.1.1');assert.equal(out.proxies[1].server,'wg.example');assert.equal(out.proxies[2].server,'plain.example');
});
