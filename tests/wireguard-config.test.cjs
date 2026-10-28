'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {parseWireGuardConfig,isWireGuardConfig,MAX_WIREGUARD_BYTES}=require('../desktop/lib/wireguard-config.cjs');
const {parseSubscription}=require('../desktop/lib/subscriptions.cjs');
const secret=()=>crypto.randomBytes(32).toString('base64');
function fixture(){
  const privateKey=secret(),publicKey=secret(),psk=secret();
  return {privateKey,publicKey,psk,text:`# local synthetic profile\n[Interface]\nPrivateKey = ${privateKey}\nAddress = 10.9.0.2/32, fd12::2/128\nDNS = 10.9.0.1, fd12::1\nMTU = 1420\n\n[Peer]\nPublicKey = ${publicKey}\nPresharedKey = ${psk}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = node.example:443\nPersistentKeepalive = 25\n`};
}
test('native WireGuard import preserves tunnel keys, dual-stack addresses and tunneled DNS',()=>{
  const f=fixture(),{proxies:[p],warnings}=parseWireGuardConfig(f.text,{name:'Windscribe · Fixture'});
  assert.equal(p.type,'wireguard');assert.equal(p.name,'Windscribe · Fixture');assert.equal(p.port,443);
  assert.equal(p['private-key'],f.privateKey);assert.equal(p['public-key'],f.publicKey);assert.equal(p['pre-shared-key'],f.psk);
  assert.equal(p.ip,'10.9.0.2/32');assert.equal(p.ipv6,'fd12::2/128');assert.equal(p['persistent-keepalive'],25);
  assert.deepEqual(p['allowed-ips'],['0.0.0.0/0','::/0']);assert.deepEqual(p.dns,['10.9.0.1','fd12::1']);assert.equal(p['remote-dns-resolve'],true);assert.deepEqual(warnings,[]);
});
test('generic profile import recognizes BOM, CRLF, comments and IPv6 endpoints without interpreting as YAML',()=>{
  const f=fixture();const text='\uFEFF'+f.text.replace('node.example:443','[2001:db8::1]:443 # endpoint').replaceAll('\n','\r\n');
  assert.equal(isWireGuardConfig(text),true);const {proxies:[p]}=parseSubscription(text);assert.equal(p.server,'2001:db8::1');assert.equal(p.port,443);
  assert.equal(isWireGuardConfig('proxies:\n - {name: test}'),false);
});
test('repeated address/DNS fields are supported and search domains are explicitly reported',()=>{
  const f=fixture(),text=f.text.replace('Address = 10.9.0.2/32, fd12::2/128','Address = 10.9.0.2\nAddress = fd12::2').replace('DNS = 10.9.0.1, fd12::1','DNS = 10.9.0.1\nDNS = example.test');
  const {proxies:[p],warnings}=parseWireGuardConfig(text);assert.equal(p.ip,'10.9.0.2/32');assert.equal(p.ipv6,'fd12::2/128');assert.deepEqual(p.dns,['10.9.0.1']);assert.match(warnings[0],/search domains/);
});
test('executable hooks and unrepresentable routing/peer/address options are rejected',()=>{
  const f=fixture();for(const [text,error]of [
    [f.text.replace('[Peer]','PostUp = echo not-executed\n[Peer]'),/hooks/],
    [f.text+'\n[Peer]\nPublicKey = ignored',/one Interface/],
    [f.text.replace('[Peer]','Table = off\n[Peer]'),/Table/],
    [f.text.replace('[Peer]','SaveConfig = true\n[Peer]'),/SaveConfig/],
    [f.text.replace('Address =','Address = 10.9.0.3\nAddress ='),/Multiple addresses/],
    [f.text.replace('[Peer]','FwMark = 42\n[Peer]'),/Unsupported field/],
  ])assert.throws(()=>parseWireGuardConfig(text),error);
});
test('invalid endpoints, prefixes, keys, MTU and keepalive fail without exposing configuration values',()=>{
  const f=fixture();for(const text of [
    f.text.replace('node.example:443','user:password@node.example:443'),
    f.text.replace('node.example:443','node.example:0'),
    f.text.replace('10.9.0.2/32','10.9.0.2/33'),
    f.text.replace(f.privateKey,'PRIVATE-VALUE-THAT-MUST-NOT-BE-LOGGED'),
    f.text.replace('MTU = 1420','MTU = 900'),
    f.text.replace('PersistentKeepalive = 25','PersistentKeepalive = 65536'),
    f.text.replace('PublicKey =','PublicKey = '+f.publicKey+'\nPublicKey ='),
  ]){
    let error;try{parseWireGuardConfig(text);}catch(e){error=e;}assert.ok(error);assert.equal(error.message.includes(f.privateKey),false);assert.equal(error.message.includes('PRIVATE-VALUE-THAT-MUST-NOT-BE-LOGGED'),false);
  }
  assert.throws(()=>parseWireGuardConfig('x'.repeat(MAX_WIREGUARD_BYTES+1)),/64 KiB/);
});
